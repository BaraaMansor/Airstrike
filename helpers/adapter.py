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
