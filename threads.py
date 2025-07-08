import os
import re
import socket
import subprocess
import shutil
import logging
from PyQt6.QtCore import QThread, pyqtSignal

log = logging.getLogger(__name__)

# Dynamic port list loading using nmap-services, fallback to full TCP range if not found
import os
import logging

def load_top_ports():
    """Load ports from nmap-services; return (all_ports, service_names)"""
    ports = []
    names = {}
    service_paths = [
        '/usr/share/nmap/nmap-services',
        '/usr/local/share/nmap/nmap-services',
        '/opt/homebrew/share/nmap/nmap-services'
    ]
    svc_file = next((p for p in service_paths if os.path.exists(p)), None)
    if not svc_file:
        logging.warning("nmap-services file not found; using full TCP range")
        return list(range(1, 65536)), {}
    try:
        with open(svc_file) as f:
            for line in f:
                if line.startswith('#'):
                    continue
                parts = line.split()
                if len(parts) < 2 or '/tcp' not in parts[1]:
                    continue
                port = int(parts[1].split('/')[0])
                ports.append(port)
                names[port] = parts[0]
    except Exception as e:
        logging.warning(f"Failed to read {svc_file}: {e}")
        return list(range(1, 65536)), {}
    return ports, names

# Initialize port lists: all common ports and quick top-1000 slice
COMMON_PORTS, SERVICE_NAMES = load_top_ports()
QUICK_PORTS = COMMON_PORTS[:1000]

def get_privilege_wrapper():
    return shutil.which('doas') or shutil.which('sudo') if os.geteuid() != 0 else None


class OSDetectThread(QThread):
    result = pyqtSignal(str, dict)
    error  = pyqtSignal(str)

    def __init__(self, ip, nmap_path, parent=None):
        super().__init__(parent)
        self.ip = ip.strip()
        self.nmap_path = nmap_path
        self.wrapper = get_privilege_wrapper()

    def run(self):
        cmd = [self.nmap_path, '-O', '-oX', '-', self.ip]
        if self.wrapper:
            cmd = [self.wrapper] + cmd
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if proc.returncode != 0:
                raise RuntimeError(proc.stderr.strip())
            # parse XML for OS match
            from xml.etree import ElementTree as ET
            root = ET.fromstring(proc.stdout)
            match = root.find("host/os/osmatch")
            if match is not None:
                name = match.attrib.get("name","Unknown")
                accuracy = match.attrib.get("accuracy","")
                self.result.emit(self.ip, {"os":name,"accuracy":accuracy})
                return
            self.result.emit(self.ip, {"os":"Unknown","accuracy":""})
        except Exception as e:
            self.error.emit(f"OS detection failed for {self.ip}: {e}")

class HostPortThread(QThread):
    result = pyqtSignal(str, list)   # ip, [ {port:,name:}, ... ]
    error  = pyqtSignal(str)

    def __init__(self, ip, rs_path, parent=None, quick=False, custom_ports=None):
        super().__init__(parent)
        self.ip = ip.strip()
        self.rs_path = rs_path
        self.wrapper = get_privilege_wrapper()
        self.quick = quick
        self.custom_ports = custom_ports

    def run(self):
        clean_ip = self.ip
        parent = self.parent()
        # decide ports: custom overrides UI; then advanced/quick based on radio buttons
        if self.custom_ports is not None:
            ports = self.custom_ports
        elif hasattr(parent, 'advanced_rb') and parent.advanced_rb.isChecked():
            ports = COMMON_PORTS
        elif hasattr(parent, 'quick_rb') and parent.quick_rb.isChecked():
            ports = QUICK_PORTS
        else:
            # fallback to top 1000 if UI widgets not found
            ports = QUICK_PORTS
        # build cmd
        base = [self.rs_path, "--accessible", "-a", clean_ip, "--ulimit", "5000"]
        base += ["--ports", ",".join(str(p) for p in ports)]
        cmd = ([self.wrapper] + base) if self.wrapper else base
        log.debug("PortThread CMD: " + " ".join(cmd))
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if proc.returncode != 0:
                raise RuntimeError(proc.stderr.strip())
            found = []
            for line in proc.stdout.splitlines():
                m = re.search(r"Discovered open port (\d+)/tcp", line)
                if m:
                    p = int(m.group(1))
                    found.append(p)
            # lookup service names
            services = []
            for p in sorted(set(found)):
                try:
                    name = socket.getservbyport(p)
                except:
                    name = ''
                services.append({"port":p, "name":name})
            self.result.emit(clean_ip, services)
        except Exception as e:
            self.error.emit(f"Port scan failed for {clean_ip}: {e}")
    # Accept either a dict with "ports" or a raw list
    def on_host_ports_multi(self, ip, data):
        # Accept either a dict with "ports" or a raw list
        if isinstance(data, dict) and 'ports' in data:
            ports = data['ports']
        else:
            ports = data or []