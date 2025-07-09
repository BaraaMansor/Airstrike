import os
import re
import signal
import subprocess
import time
import threading
from typing import Dict, List
from collections import defaultdict, deque

PROBE_SNIFFER_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(PROBE_SNIFFER_DIR, "probe_sniffer.log")
PID_FILE = os.path.join(PROBE_SNIFFER_DIR, "probe_sniffer.pid")

# Global variables for the attack
detected_ssids = defaultdict(lambda: [0, '', 0])  # ssid: [count, mac, last_seen]
unique_ssid_count = 0
unique_clients = set()
wildcard_probe_count = 0
running_process = None
attack_thread = None
attack_running = False

class ProbeRequestSniffer:
    def __init__(self, interface: str, tshark_path: str = '/usr/bin/tshark'):
        self.interface = interface
        self.tshark_path = tshark_path
        self.process = None
        self.running = False
        self.logs = deque(maxlen=10)  # Only keep last 10 unique probe logs
        self.wildcard_probe_count = 0
        self.unique_clients = set()
        self.unique_ssids = set()
        self.lock = threading.Lock()
        self.last_summary = ""
        
    def start_sniffing(self):
        try:
            self.process = subprocess.Popen(
                [self.tshark_path, '-i', self.interface, '-n', '-l', 'subtype', 'probereq'],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )
            self.running = True
            threading.Thread(target=self._monitor_output, daemon=True).start()
            return True
        except Exception as e:
            with self.lock:
                self.logs.append(f"[!] Error starting sniffer: {e}")
            return False
    
    def stop_sniffing(self):
        self.running = False
        if self.process:
            self.process.terminate()
            self.process = None
        with self.lock:
            self.logs.append(f"[*] Stopped Probe Request Sniffer")
    
    def _monitor_output(self):
        ssid_regex = re.compile(r"([a-zA-Z0-9:]{17}).+SSID=([^\r\n]+)")
        while self.running and self.process and self.process.stdout:
            line = self.process.stdout.readline()
            if not line:
                break
            match = ssid_regex.search(line)
            if match:
                mac = match.group(1).strip()
                ssid = match.group(2).strip()
                timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

                # Suppress wildcard/broadcast/empty SSID logs, but count them
                if ssid.lower() == "broadcast" or ssid.lower() == "wildcard" or ssid == "":
                    with self.lock:
                        self.wildcard_probe_count += 1
                    continue

                # Only log unique (MAC, SSID) pairs
                key = (mac, ssid)
                with self.lock:
                    if key not in self.logs:
                        self.logs.appendleft({
                            "timestamp": timestamp,
                            "mac": mac,
                            "ssid": ssid
                        })
                    self.unique_clients.add(mac)
                    self.unique_ssids.add(ssid)

    def get_logs(self, lines: int = 10) -> List[str]:
        with self.lock:
            # Prepare summary
            summary = (
                f"{len(self.unique_clients)} unique clients, "
                f"{len(self.unique_ssids)} unique SSIDs, "
                f"{self.wildcard_probe_count} wildcard/broadcast probes suppressed"
            )
            # Prepare last N unique probe logs
            log_lines = []
            for entry in list(self.logs)[:lines]:
                if isinstance(entry, dict):
                    log_lines.append(
                        f"[{entry['timestamp']}] {entry['mac']} → SSID: '{entry['ssid']}'"
                    )
                else:
                    log_lines.append(str(entry))
            # Return summary + logs
            return [summary, "--- Last unique probe requests ---"] + log_lines
    
    def get_stats(self) -> Dict:
        with self.lock:
            return {
                'unique_clients': len(self.unique_clients),
                'unique_ssids': len(self.unique_ssids),
                'wildcard_probe_count': self.wildcard_probe_count,
                'running': self.running
            }

def start_probe_sniffer(interface: str) -> Dict:
    global running_process, attack_running
    if attack_running:
        return {"error": "Probe Request Sniffer is already running."}
    for f in [LOG_FILE, PID_FILE]:
        try:
            os.remove(f)
        except FileNotFoundError:
            pass
    try:
        sniffer = ProbeRequestSniffer(interface)
        if sniffer.start_sniffing():
            running_process = sniffer
            attack_running = True
            with open(PID_FILE, "w") as f:
                f.write(str(os.getpid()))
            return {
                "running": True,
                "pid": os.getpid(),
                "message": f"Started probe request sniffer on interface {interface}"
            }
        else:
            return {"error": "Failed to start probe request sniffer."}
    except Exception as e:
        return {"error": f"Failed to start attack: {str(e)}"}

def stop_probe_sniffer() -> Dict:
    global running_process, attack_running
    if not attack_running or not running_process:
        return {"running": False, "error": "No running Probe Request Sniffer found."}
    try:
        running_process.stop_sniffing()
        running_process = None
        attack_running = False
        try:
            os.remove(PID_FILE)
        except FileNotFoundError:
            pass
        return {"running": False, "message": "Probe Request Sniffer stopped successfully"}
    except Exception as e:
        return {"error": f"Failed to stop attack: {str(e)}"}

def is_running() -> bool:
    return attack_running

def get_status() -> Dict:
    running = is_running()
    pid = None
    stats = {}
    if running and running_process:
        pid = os.getpid()
        stats = running_process.get_stats()
    return {
        "running": running, 
        "pid": pid,
        "stats": stats
    }

def get_logs(lines: int = 10) -> List[str]:
    if running_process:
        return running_process.get_logs(lines)
    return []

def list_interfaces() -> List[str]:
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