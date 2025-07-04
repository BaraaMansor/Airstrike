import os
import shutil
from datetime import datetime
import subprocess
import time

def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()
    except subprocess.CalledProcessError:
        return ""

def get_wireless_interfaces():
    output = run_cmd("iwconfig")
    interfaces = []
    for line in output.splitlines():
        if "IEEE 802.11" in line:
            iface = line.split()[0]
            interfaces.append(iface)
    return interfaces

def start_monitor_mode(interface):
    print(f"[+] Enabling monitor mode on {interface}...")
    run_cmd("airmon-ng check kill")
    time.sleep(1)
    run_cmd(f"ip link set {interface} down")
    run_cmd(f"iw {interface} set monitor control")
    run_cmd(f"ip link set {interface} up")
    return interface


def clear_csv_backup():
    for file_name in os.listdir():
        if ".csv" in file_name:
            print("Found .csv file. Moving to backup...")
            directory = os.getcwd()
            try:
                os.mkdir(f"{directory}/backup/")
            except:
                print("Backup folder exists.")
            timestamp = datetime.now()
            shutil.move(file_name, f"{directory}/backup/{timestamp}-{file_name}")

def is_sudo():
    return 'SUDO_UID' in os.environ.keys()

