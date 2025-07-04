import time
import random
import subprocess
from scapy.all import sniff, Dot11

def handle_probe(pkt):
    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 4:
        mac = pkt.addr2
        ssid = pkt.info.decode(errors='ignore')
        if ssid:
            print(f"[+] Probe Request from {mac} for SSID: '{ssid}'")
        else:
            print(f"[-] Probe Request from {mac} for hidden SSID or Broadcast")

def sniff_probes(interface):
    print(f"[i] Sniffing on {interface}... Press Ctrl+C to stop.")
    sniff(iface=interface, prn=handle_probe, store=0)

def channel_hopper(interface):
    channels = list(range(1, 14))
    while True:
        channel = random.choice(channels)
        subprocess.call(f"iw dev {interface} set channel {channel}", shell=True,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)
