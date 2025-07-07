import subprocess
import re
import time
from scapy.all import *

def scan_access_points_basic(interface):
    """Basic AP scan using iwlist"""
    try:
        result = subprocess.run(['iwlist', interface, 'scan'], 
                              capture_output=True, text=True, timeout=30)
        
        access_points = []
        current_ap = {}
        
        for line in result.stdout.split('\n'):
            line = line.strip()
            
            if 'Cell' in line and 'Address:' in line:
                if current_ap:
                    access_points.append(current_ap)
                current_ap = {'bssid': line.split('Address: ')[1]}
            
            elif 'ESSID:' in line:
                essid = line.split('ESSID:')[1].strip('"')
                current_ap['ssid'] = essid if essid != '' else '<Hidden>'
            
            elif 'Channel:' in line:
                current_ap['channel'] = line.split('Channel:')[1]
            
            elif 'Signal level=' in line:
                signal = re.search(r'Signal level=(-?\d+)', line)
                if signal:
                    current_ap['signal'] = int(signal.group(1))
            
            elif 'Encryption key:' in line:
                current_ap['encrypted'] = 'on' in line.lower()
        
        if current_ap:
            access_points.append(current_ap)
        
        return access_points
    
    except Exception as e:
        print(f"Error scanning APs: {e}")
        return []

def scan_access_points_advanced(interface, duration=30):
    """Advanced AP scan using airodump-ng"""
    print(f"[*] Scanning for access points on {interface} for {duration}s...")
    
    # Create temporary files
    temp_prefix = f"/tmp/apscan_{int(time.time())}"
    
    try:
        # Run airodump-ng
        cmd = ['airodump-ng', '--write', temp_prefix, '--output-format', 'csv', interface]
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        time.sleep(duration)
        proc.terminate()
        proc.wait(timeout=5)
        
        # Parse CSV results
        csv_file = f"{temp_prefix}-01.csv"
        access_points = []
        
        if os.path.exists(csv_file):
            with open(csv_file, 'r') as f:
                lines = f.readlines()
            
            # Find the AP section
            ap_section = False
            for line in lines:
                if 'BSSID' in line and 'ESSID' in line:
                    ap_section = True
                    continue
                
                if ap_section and line.strip() and not line.startswith('Station MAC'):
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 14:
                        ap = {
                            'bssid': parts[0],
                            'first_seen': parts[1],
                            'last_seen': parts[2],
                            'channel': parts[3],
                            'speed': parts[4],
                            'privacy': parts[5],
                            'cipher': parts[6],
                            'auth': parts[7],
                            'power': int(parts[8]) if parts[8].lstrip('-').isdigit() else 0,
                            'beacons': int(parts[9]) if parts[9].isdigit() else 0,
                            'data': int(parts[10]) if parts[10].isdigit() else 0,
                            'ssid': parts[13] if parts[13] else '<Hidden>'
                        }
                        access_points.append(ap)
        
        # Cleanup
        for ext in ['-01.csv', '-01.cap', '-01.kismet.csv', '-01.kismet.netxml']:
            try:
                os.remove(f"{temp_prefix}{ext}")
            except:
                pass
        
        return access_points
    
    except Exception as e:
        print(f"Error in advanced AP scan: {e}")
        return []

def display_access_points(access_points):
    """Display discovered access points in a formatted table"""
    if not access_points:
        print("No access points found.")
        return
    
    print("\n" + "="*80)
    print("DISCOVERED ACCESS POINTS")
    print("="*80)
    print(f"{'ID':<3} {'BSSID':<18} {'SSID':<25} {'CH':<3} {'PWR':<4} {'SEC':<10}")
    print("-"*80)
    
    for i, ap in enumerate(access_points):
        ssid = ap.get('ssid', 'Unknown')[:24]
        bssid = ap.get('bssid', 'Unknown')
        channel = ap.get('channel', '?')
        power = ap.get('power', ap.get('signal', 0))
        
        # Determine security
        if ap.get('encrypted', True) or ap.get('privacy', '') != 'OPN':
            security = ap.get('privacy', 'WPA/WPA2')[:9]
        else:
            security = 'Open'
        
        print(f"{i:<3} {bssid:<18} {ssid:<25} {channel:<3} {power:<4} {security:<10}")
    
    print("="*80)
    return access_points

def select_target_ap(access_points):
    """Interactive AP selection"""
    while True:
        try:
            choice = input("\nSelect target AP ID (or 'q' to quit): ").strip()
            if choice.lower() == 'q':
                return None
            
            ap_id = int(choice)
            if 0 <= ap_id < len(access_points):
                return access_points[ap_id]
            else:
                print("Invalid ID. Try again.")
        except ValueError:
            print("Please enter a valid number.")
        except KeyboardInterrupt:
            return None
