import subprocess

def set_monitor_mode(interface):
    print("Putting WiFi adapter into monitored mode...")
    subprocess.run(["ip", "link", "set", interface, "down"])
    subprocess.run(["airmon-ng", "check", "kill"])
    subprocess.run(["iw", interface, "set", "monitor", "none"])
    subprocess.run(["ip", "link", "set", interface, "up"])

def start_channel(interface, channel):
    print(f"Switching to channel {channel}...")
    subprocess.run(["airmon-ng", "start", interface, channel])

def start_monitor_mode(interface):
    print(f"[+] Enabling monitor mode on {interface}...")
    run_cmd("airmon-ng check kill")
    time.sleep(1)
    run_cmd(f"ip link set {interface} down")
    run_cmd(f"iw {interface} set monitor control")
    run_cmd(f"ip link set {interface} up")
    return interface
