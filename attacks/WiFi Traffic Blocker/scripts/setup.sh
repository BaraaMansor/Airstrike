#!/bin/bash
# Setup script

echo "🔧 Setting up WiFi Traffic Blocker..."

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Run as root: sudo bash setup.sh"
    exit 1
fi

# Update and install packages
apt update
apt install -y python3-pip nmap net-tools iptables

# Install Python packages
pip3 install scapy netifaces

# Enable IP forwarding
sysctl net.ipv4.ip_forward=1

# Backup iptables
iptables-save > /tmp/iptables_backup.rules

echo "✅ Setup complete!"
echo ""
echo "Usage:"
echo "  Scan clients:    python3 wifi-blocker.py -i wlan0 --scan"
echo "  Attack single:   python3 wifi-blocker.py -i wlan0 -t 192.168.100.54"
echo "  Attack all:      python3 attack-all.py -i wlan0"
echo "  Monitor:         python3 monitor.py 192.168.100.54"
