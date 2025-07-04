#!/usr/bin/env python3
"""
Attack Monitor - Test if clients are blocked
"""

import subprocess
import time
import threading
import sys
from datetime import datetime

class AttackMonitor:
    def __init__(self, targets):
        self.targets = targets if isinstance(targets, list) else [targets]
        self.running = True
        
    def test_connectivity(self, ip):
        """Test if client has internet access"""
        tests = {
            'ping': ['ping', '-c', '1', '-W', '2', '8.8.8.8'],
            'dns': ['nslookup', 'google.com'],
            'http': ['curl', '-s', '--max-time', '3', 'http://google.com']
        }
        
        results = {}
        for test, cmd in tests.items():
            try:
                result = subprocess.run(cmd, capture_output=True, timeout=5)
                results[test] = result.returncode == 0
            except:
                results[test] = False
        
        return any(results.values())
    
    def monitor_target(self, ip):
        """Monitor single target"""
        while self.running:
            timestamp = datetime.now().strftime("%H:%M:%S")
            has_internet = self.test_connectivity(ip)
            
            status = "🟢 ONLINE" if has_internet else "🔴 BLOCKED"
            print(f"[{timestamp}] {ip:<15} {status}")
            
            time.sleep(5)
    
    def start_monitoring(self):
        """Start monitoring all targets"""
        print("🔍 Attack Monitor")
        print("=" * 40)
        print(f"Monitoring {len(self.targets)} targets:")
        for ip in self.targets:
            print(f"  📱 {ip}")
        print()
        
        # Start monitoring threads
        for ip in self.targets:
            thread = threading.Thread(target=self.monitor_target, args=(ip,))
            thread.daemon = True
            thread.start()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Monitoring stopped")
            self.running = False

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 monitor.py <ip1> [ip2] ...")
        print("Example: python3 monitor.py 192.168.100.54")
        sys.exit(1)
    
    targets = sys.argv[1:]
    monitor = AttackMonitor(targets)
    monitor.start_monitoring()

if __name__ == "__main__":
    main()
