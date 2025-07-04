import sys
import subprocess
import threading
from helpers.utils import run_cmd, get_wireless_interfaces, start_monitor_mode
from modules.sniffer import sniff_probes, channel_hopper

def main():
    if not run_cmd("which airmon-ng"):
        print("[!] airmon-ng not found. Install it with: sudo apt install aircrack-ng")
        sys.exit(1)

    interfaces = get_wireless_interfaces()
    if not interfaces:
        print("[!] No wireless interfaces found.")
        sys.exit(1)

    print("[i] Available wireless interfaces:")
    for idx, iface in enumerate(interfaces):
        print(f"   {idx + 1}. {iface}")

    selected = interfaces[0]
    print(f"[i] Using interface: {selected}")

    try:
        monitor_iface = start_monitor_mode(selected)
        threading.Thread(target=channel_hopper, args=(monitor_iface,), daemon=True).start()
        sniff_probes(monitor_iface)
    except KeyboardInterrupt:
        print("\n[!] Sniffing stopped by user.")
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        print("[i] Restoring network services...")
        run_cmd("service NetworkManager restart")

if __name__ == "__main__":
    if not sys.platform.startswith("linux"):
        print("[!] This script is only for Linux.")
        sys.exit(1)
    if subprocess.getoutput("whoami") != "root":
        print("[!] Run this script with sudo/root.")
        sys.exit(1)

    main()
