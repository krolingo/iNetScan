

#!/usr/bin/env python3

import re
import socket
import subprocess
import os
import shutil
import json
from PyQt6.QtCore import QThread, pyqtSignal

# Initialize manuf parser if available
try:
    from manuf import MacParser
    mac_parser = MacParser()
except ImportError:
    mac_parser = None

# Load extra OUI overrides
script_dir = os.path.dirname(os.path.abspath(__file__))
extra_oui = {}
for fname in ('oui_extra.json', 'mac_overrides.json'):
    path = os.path.join(script_dir, fname)
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            for k, v in data.items():
                extra_oui[k.upper().replace('-', '').replace(':', '')] = v
    except:
        continue

# Load Apple OUI-to-model map
apple_model_map = {}
try:
    with open(os.path.join(script_dir, 'apple_models.json'), 'r', encoding='utf-8') as f:
        apple_model_map = {
            k.upper().replace('-', '').replace(':', ''): v
            for k, v in json.load(f).items()
        }
except:
    pass

def get_privilege_wrapper():
    """Return 'doas' or 'sudo' if not running as root, else None."""
    return shutil.which('doas') or shutil.which('sudo') if os.geteuid() != 0 else None

class ScanThread(QThread):
    result = pyqtSignal(dict)
    error = pyqtSignal(str)
    discovery_finished = pyqtSignal()
    discovery_update = pyqtSignal(str)

    def __init__(self, subnet, rs_path, nmap_path, scan_flags=None):
        super().__init__()
        self.subnet = subnet
        self.rs_path = rs_path
        self.nmap_path = nmap_path
        # Custom probe flags for this scan pass
        self.scan_flags = scan_flags
        self.wrapper = get_privilege_wrapper()
        self.hosts = []
        self.seen_ips = set()

    def run(self):
        try:
            # Build the discovery command
            cmd = [self.nmap_path, '-sn']
            if self.scan_flags:
                # use only the provided probe flags
                cmd += self.scan_flags
            else:
                # default: ICMP, SYN, UDP, and ARP probes
                cmd += ['-PE', '-PS80,443', '-PU53', '-PR']
            cmd.append(self.subnet)
            if self.wrapper:
                cmd = [self.wrapper] + cmd
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, bufsize=1)
        except Exception as e:
            self.error.emit(f"Nmap discovery failed: {e}")
            return

        for line in proc.stdout:
            m = re.match(
                r"Nmap scan report for (?P<host>[^ ]+)"
                r"(?: \((?P<ip>[\d\.]+)\))?", line
            )
            if m:
                raw = m.group('host')
                ip = (m.group('ip') or raw).strip()
                if ip not in self.seen_ips:
                    self.seen_ips.add(ip)
                    try:
                        rdns = socket.gethostbyaddr(ip)[0]
                    except:
                        rdns = ''
                    host = {
                        'ip': ip,
                        'hostname': rdns,
                        'mac': '',
                        'ports': [],
                        'vendor': '',
                        'model': ''
                    }
                    self.hosts.append(host)
                    self.result.emit({'hosts': self.hosts.copy()})
                    self.discovery_update.emit(f"Discovered {ip} ({rdns})")

            m2 = re.search(
                r"MAC Address:\s*([0-9A-F:]+)"
                r"(?:\s*\(([^)]+)\))?", line
            )
            if m2 and self.hosts:
                mac = m2.group(1)
                host = self.hosts[-1]
                host['mac'] = mac
                # Vendor lookup
                vendor_inline = m2.group(2)
                vendor = vendor_inline or (mac_parser.get_manufacturer(mac)
                                          if mac_parser else '')
                prefix = mac.replace(':', '').upper()[:6]
                if not vendor:
                    vendor = extra_oui.get(prefix, '')
                if not vendor:
                    vendor = host.get('mdns_props', {}).get('vn', '')
                if not vendor and prefix in apple_model_map:
                    vendor = 'Apple'
                host['vendor'] = vendor
                # Model lookup
                model = host.get('mdns_props', {}).get('model', '')
                if not model and prefix in apple_model_map:
                    model = apple_model_map[prefix]
                host['model'] = model or ''
                self.result.emit({'hosts': self.hosts.copy()})

        proc.wait()
        self.discovery_finished.emit()