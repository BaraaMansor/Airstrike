import os
from helpers.utils import is_sudo
from helpers.network import get_interface_names, get_interface_ip
from modules.icmp_flood import arp_scan, print_arp_res, run_hping3

def main():
    if not is_sudo():
        print("Please run this program with sudo.")
        exit()

    interfaces = [i for i in get_interface_names() if i not in ["lo", "docker0"]]
    if "wlan0" in interfaces:
        main_iface = "wlan0"
    elif interfaces:
        main_iface = interfaces[0]
    else:
        print("No valid network interface found.")
        exit()

    ip_range = get_interface_ip(main_iface)
    print(f"\n[*] Scanning network on interface '{main_iface}' with range {ip_range}")

    arp_res = arp_scan(ip_range)
    if not arp_res:
        print("No live hosts found.")
        exit()

    target_ip = print_arp_res(arp_res)
    run_hping3(target_ip)

if __name__ == "__main__":
    main()
