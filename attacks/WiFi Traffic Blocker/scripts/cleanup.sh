#!/bin/bash
# Cleanup script

echo "🧹 Cleaning up..."

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Run as root: sudo bash cleanup.sh"
    exit 1
fi

# Restore iptables
if [ -f /tmp/iptables_backup.rules ]; then
    iptables-restore < /tmp/iptables_backup.rules
else
    iptables -F
    iptables -X
fi

# Disable IP forwarding
sysctl net.ipv4.ip_forward=0

# Clear ARP cache
ip -s -s neigh flush all

echo "✅ Cleanup complete!"
