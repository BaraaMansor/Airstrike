import subprocess
import re
import os

def get_interface_ip(interface):
    try:
        output = subprocess.check_output(f"ip addr show {interface}", shell=True).decode()
        match = re.search(r"inet (\d+\.\d+\.\d+)\.\d+/\d+", output)
        if match:
            base_ip = match.group(1)
            return f"{base_ip}.0/24"
    except Exception as e:
        print(f"Error getting IP for {interface}: {e}")
        exit()

def get_interface_names():
    return os.listdir("/sys/class/net")
