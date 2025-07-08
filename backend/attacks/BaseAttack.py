"""
Base Attack Class for Airstrike WiFi Penetration Testing Framework

This class provides common functionality for all attack types:
- Interface management (monitor/managed mode)
- Status tracking and statistics
- Error handling and logging
- WebSocket communication
- Thread management
- Resource cleanup

All attack classes should inherit from this base class.
"""

import subprocess
import time
import threading
import asyncio
import json
import os
from datetime import datetime
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List

class BaseAttack(ABC):
    """
    Abstract base class for all attack types in Airstrike
    
    Provides common functionality:
    - Interface management
    - Status tracking
    - Error handling
    - WebSocket communication
    - Thread management
    - Resource cleanup
    """
    
    def __init__(self, interface: str, websocket=None, attack_type: str = "base"):
        """
        Initialize base attack
        
        Args:
            interface: Network interface name
            websocket: WebSocket connection for real-time updates
            attack_type: Type of attack for logging
        """
        self.interface = interface
        self.websocket = websocket
        self.attack_type = attack_type
        
        # Attack state
        self.running = False
        self.stop_signal = threading.Event()
        self.original_interface_mode = None
        
        # Statistics and tracking
        self.stats = {
            'packets_sent': 0,
            'start_time': None,
            'duration': 0,
            'errors': 0,
            'progress': 0
        }
        
        # Error handling
        self.error_log = []
        self.active_threads = []
        
        # Interface state
        self.interface_modified = False
        
    async def send_status_update(self, message_type: str, data: Dict[str, Any]):
        """Send status update via WebSocket with enhanced logging"""
        if self.websocket:
            try:
                message = {
                    'type': message_type,
                    'timestamp': datetime.now().isoformat(),
                    'attack_type': self.attack_type,
                    'data': data
                }
                await self.websocket.send_text(json.dumps(message))
                print(f"[{self.attack_type}] WebSocket update: {message_type} - {data}")
            except Exception as e:
                print(f"[{self.attack_type}] WebSocket error: {e}")
    
    def log_subprocess_result(self, cmd: List[str], result: subprocess.CompletedProcess, operation: str):
        """Log subprocess execution results with detailed information"""
        if result.returncode == 0:
            print(f"[{self.attack_type}] {operation} successful: {' '.join(cmd)}")
        else:
            error_msg = f"{operation} failed (code {result.returncode}): {' '.join(cmd)}"
            if result.stderr:
                error_msg += f" - Error: {result.stderr.strip()}"
            print(f"[{self.attack_type}] {error_msg}")
            self.error_log.append(error_msg)
    
    def get_interface_mode(self) -> str:
        """Get current interface mode (managed/monitor)"""
        try:
            result = subprocess.run(['iw', self.interface, 'info'], 
                                  capture_output=True, text=True, check=False)
            if result.returncode == 0:
                if "type monitor" in result.stdout:
                    return "monitor"
                elif "type managed" in result.stdout:
                    return "managed"
            return "unknown"
        except Exception as e:
            self.error_log.append(f"Error getting interface mode: {e}")
            return "unknown"
    
    def set_monitor_mode(self) -> bool:
        """Set interface to monitor mode with enhanced error handling"""
        try:
            print(f"[{self.attack_type}] Setting monitor mode for {self.interface}")
            
            # Check current mode
            current_mode = self.get_interface_mode()
            if current_mode == "monitor":
                print(f"[{self.attack_type}] Interface {self.interface} already in monitor mode")
                return True
            elif current_mode == "managed":
                self.original_interface_mode = "managed"
                print(f"[{self.attack_type}] Interface {self.interface} currently in managed mode")
            
            # Kill interfering processes
            print(f"[{self.attack_type}] Killing interfering processes...")
            result = subprocess.run(['airmon-ng', 'check', 'kill'], 
                                  capture_output=True, text=True, check=False)
            self.log_subprocess_result(['airmon-ng', 'check', 'kill'], result, "Kill processes")
            
            # Set interface down
            print(f"[{self.attack_type}] Setting interface down...")
            result = subprocess.run(['ip', 'link', 'set', self.interface, 'down'], 
                                  capture_output=True, text=True, check=False)
            self.log_subprocess_result(['ip', 'link', 'set', self.interface, 'down'], result, "Interface down")
            
            # Set monitor mode
            print(f"[{self.attack_type}] Setting monitor mode...")
            result = subprocess.run(['iw', self.interface, 'set', 'monitor', 'control'], 
                                  capture_output=True, text=True, check=False)
            self.log_subprocess_result(['iw', self.interface, 'set', 'monitor', 'control'], result, "Monitor mode")
            
            # Set interface up
            print(f"[{self.attack_type}] Setting interface up...")
            result = subprocess.run(['ip', 'link', 'set', self.interface, 'up'], 
                                  capture_output=True, text=True, check=False)
            self.log_subprocess_result(['ip', 'link', 'set', self.interface, 'up'], result, "Interface up")
            
            # Verify monitor mode was set
            time.sleep(1)  # Give interface time to settle
            final_mode = self.get_interface_mode()
            if final_mode == "monitor":
                print(f"[{self.attack_type}] Monitor mode set successfully for {self.interface}")
                self.interface_modified = True
                return True
            else:
                print(f"[{self.attack_type}] Monitor mode verification failed - current mode: {final_mode}")
                return False
                
        except Exception as e:
            error_msg = f"Monitor mode setup failed: {e}"
            print(f"[{self.attack_type}] {error_msg}")
            self.error_log.append(error_msg)
            return False
    
    def set_managed_mode(self) -> bool:
        """Restore interface to managed mode"""
        if not self.original_interface_mode or not self.interface_modified:
            return True
            
        try:
            print(f"[{self.attack_type}] Restoring {self.interface} to managed mode...")
            
            # Set interface down
            result = subprocess.run(['ip', 'link', 'set', self.interface, 'down'], 
                                  capture_output=True, text=True, check=False)
            self.log_subprocess_result(['ip', 'link', 'set', self.interface, 'down'], result, "Interface down")
            
            # Set managed mode
            result = subprocess.run(['iw', self.interface, 'set', 'type', 'managed'], 
                                  capture_output=True, text=True, check=False)
            self.log_subprocess_result(['iw', self.interface, 'set', 'type', 'managed'], result, "Managed mode")
            
            # Set interface up
            result = subprocess.run(['ip', 'link', 'set', self.interface, 'up'], 
                                  capture_output=True, text=True, check=False)
            self.log_subprocess_result(['ip', 'link', 'set', self.interface, 'up'], result, "Interface up")
            
            # Verify managed mode
            time.sleep(1)
            final_mode = self.get_interface_mode()
            if final_mode == "managed":
                print(f"[{self.attack_type}] Managed mode restored successfully for {self.interface}")
                self.interface_modified = False
                return True
            else:
                print(f"[{self.attack_type}] Managed mode restoration failed - current mode: {final_mode}")
                return False
                
        except Exception as e:
            error_msg = f"Managed mode restoration failed: {e}"
            print(f"[{self.attack_type}] {error_msg}")
            self.error_log.append(error_msg)
            return False
    
    def set_channel(self, channel: int) -> bool:
        """Set interface to specific channel with enhanced verification"""
        try:
            print(f"[{self.attack_type}] Setting channel to {channel}")
            
            # Check if channel is already set correctly
            result = subprocess.run(['iw', self.interface, 'info'], 
                                  capture_output=True, text=True, check=False)
            if result.returncode == 0 and f"channel {channel}" in result.stdout:
                print(f"[{self.attack_type}] Interface {self.interface} already on channel {channel}")
                return True
            
            # Set channel
            result = subprocess.run(['iw', self.interface, 'set', 'channel', str(channel)], 
                                  capture_output=True, text=True, check=False)
            self.log_subprocess_result(['iw', self.interface, 'set', 'channel', str(channel)], result, "Channel set")
            
            if result.returncode != 0:
                return False
            
            # Verify channel was set
            time.sleep(0.5)  # Give interface time to switch
            result = subprocess.run(['iw', self.interface, 'info'], 
                                  capture_output=True, text=True, check=False)
            if result.returncode == 0 and f"channel {channel}" in result.stdout:
                print(f"[{self.attack_type}] Channel {channel} set successfully for {self.interface}")
                return True
            else:
                print(f"[{self.attack_type}] Channel verification failed for {self.interface}")
                return False
                
        except Exception as e:
            error_msg = f"Channel setting failed: {e}"
            print(f"[{self.attack_type}] {error_msg}")
            self.error_log.append(error_msg)
            return False
    
    def add_thread(self, thread: threading.Thread):
        """Add a thread to the active threads list for cleanup"""
        self.active_threads.append(thread)
    
    def cleanup_threads(self):
        """Clean up all active threads"""
        print(f"[{self.attack_type}] Cleaning up {len(self.active_threads)} threads")
        for thread in self.active_threads:
            if thread.is_alive():
                print(f"[{self.attack_type}] Waiting for thread {thread.name} to finish")
                thread.join(timeout=5)
                if thread.is_alive():
                    print(f"[{self.attack_type}] Thread {thread.name} did not finish gracefully")
        self.active_threads.clear()
    
    def get_current_stats(self) -> Dict[str, Any]:
        """Get current attack statistics with enhanced information"""
        if self.stats['start_time']:
            self.stats['duration'] = int(time.time() - self.stats['start_time'])
        
        return {
            'attack_type': self.attack_type,
            'interface': self.interface,
            'running': self.running,
            'progress': self.stats['progress'],
            'packets_sent': self.stats['packets_sent'],
            'start_time': self.stats['start_time'],
            'duration': self.stats['duration'],
            'errors': self.stats['errors'],
            'active_threads': len(self.active_threads)
        }
    
    def log_error(self, error: str):
        """Log an error with timestamp"""
        timestamp = datetime.now().isoformat()
        error_entry = f"[{timestamp}] {error}"
        self.error_log.append(error_entry)
        self.stats['errors'] += 1
        print(f"[{self.attack_type}] ERROR: {error}")
    
    def log_info(self, message: str):
        """Log an info message with timestamp"""
        timestamp = datetime.now().isoformat()
        print(f"[{self.attack_type}] INFO: {message}")
    
    def log_success(self, message: str):
        """Log a success message with timestamp"""
        timestamp = datetime.now().isoformat()
        print(f"[{self.attack_type}] SUCCESS: {message}")
    
    @abstractmethod
    async def start_attack(self) -> bool:
        """Start the attack - must be implemented by subclasses"""
        pass
    
    @abstractmethod
    async def stop_attack(self) -> Dict[str, Any]:
        """Stop the attack - must be implemented by subclasses"""
        pass
    
    def cleanup(self):
        """Clean up resources - called when attack is stopped"""
        print(f"[{self.attack_type}] Starting cleanup")
        
        # Stop all threads
        self.cleanup_threads()
        
        # Restore interface if modified
        if self.interface_modified:
            self.set_managed_mode()
        
        print(f"[{self.attack_type}] Cleanup completed")
    
    def __del__(self):
        """Destructor to ensure cleanup"""
        if self.running:
            print(f"[{self.attack_type}] WARNING: Attack was not properly stopped before destruction")
            self.cleanup() 