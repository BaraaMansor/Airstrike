import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from helpers.scanner import scan_access_points_advanced, display_access_points, select_target_ap
from helpers.adapter import set_monitor_mode
import argparse

def main():
    parser = argparse.ArgumentParser(description='WiFi Access Point Discovery')
    parser.add_argument('-i', '--interface', required=True, help='WiFi interface')
    parser.add_argument('-t', '--time', type=int, default=30, help='Scan duration in seconds')
    parser.add_argument('--monitor', action='store_true', help='Set interface to monitor mode')
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("❌ This script requires root privileges!")
        sys.exit(1)
    
    print("🔍 WiFi Access Point Discovery")
    print("=" * 40)
    
    # Set monitor mode if requested
    if args.monitor:
        print(f"[*] Setting {args.interface} to monitor mode...")
        set_monitor_mode(args.interface)
    
    # Scan for access points
    access_points = scan_access_points_advanced(args.interface, args.time)
    
    # Display results
    display_access_points(access_points)
    
    # Interactive selection
    if access_points:
        selected_ap = select_target_ap(access_points)
        if selected_ap:
            print(f"\n✅ Selected: {selected_ap['ssid']} ({selected_ap['bssid']})")
            return selected_ap
    
    return None

if __name__ == "__main__":
    main()
