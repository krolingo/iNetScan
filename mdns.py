#!/usr/bin/env python3

import time
from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
from PyQt6.QtCore import QThread, pyqtSignal

class TypeListener(ServiceListener):
    """Collects all advertised service types."""
    def __init__(self):
        self.types = set()

    def add_service(self, zeroconf, svc_type, name):
        self.types.add(name)

    def remove_service(self, zeroconf, svc_type, name):
        pass

    def update_service(self, zeroconf, svc_type, name):
        pass

class HostListener(ServiceListener):
    """Collects ServiceInfo objects for each discovered service instance."""
    def __init__(self):
        self.hosts = {}

    def add_service(self, zeroconf, svc_type, name):
        # Only record the service name; lookup deferred to worker thread
        self.hosts[name] = None

    def remove_service(self, zeroconf, svc_type, name):
        self.hosts.pop(name, None)

    def update_service(self, zeroconf, svc_type, name):
        # Ignore updates to avoid blocking mDNS thread
        pass

def discover_all_mdns(timeout: float = 5.0):
    """
    Discover all mDNS services on the local network.

    :param timeout: seconds to wait for each discovery phase
    :return: dict mapping service names to ServiceInfo
    """
    zc = Zeroconf()
    # Phase 1: discover service types
    type_listener = TypeListener()
    ServiceBrowser(zc, "_services._dns-sd._udp.local.", type_listener)
    time.sleep(timeout)

    # Phase 2: browse each type for instances
    host_listener = HostListener()
    for svc_type in type_listener.types:
        ServiceBrowser(zc, svc_type, host_listener)
    time.sleep(timeout)

    zc.close()
    return host_listener.hosts

class MDNSWorker(QThread):
    """
    QThread that performs mDNS discovery and emits found ServiceInfo.
    """
    host_found = pyqtSignal(str, object)  # service name and ServiceInfo
    discovery_finished = pyqtSignal()
    mdns_done = pyqtSignal(dict)  # emit the complete host info dict

    def __init__(self, timeout: float = 5.0):
        super().__init__()
        self.timeout = timeout

    def run(self):
        zc = Zeroconf()
        # Phase 1: Discover service types
        type_listener = TypeListener()
        ServiceBrowser(zc, "_services._dns-sd._udp.local.", type_listener)
        time.sleep(self.timeout)

        # Debug: show discovered service types
        print(f"[DEBUG] Discovered service types: {type_listener.types}")

        # Phase 2: Discover instances for each type
        instance_listener = HostListener()
        for svc_type in type_listener.types:
            ServiceBrowser(zc, svc_type, instance_listener)
        time.sleep(self.timeout)

        # Debug: show discovered service names before lookup
        print(f"[DEBUG] Discovered service names: {list(instance_listener.hosts.keys())}")

        # Phase 3: Deferred lookups under timeout
        for svc_type in list(type_listener.types):
            for name in list(instance_listener.hosts.keys()):
                try:
                    info = zc.get_service_info(svc_type, name, timeout=int(self.timeout * 1000))
                except Exception:
                    continue
                if info:
                    instance_listener.hosts[name] = info

        # Skip entries with no lookup info
        hosts = {}
        for name, info in instance_listener.hosts.items():
            if info is None or not getattr(info, 'addresses', None):
                continue
            ip = ".".join(str(b) for b in info.addresses[0])
            hostname = info.server.rstrip('.')
            # Collect TXT properties
            props = {}
            for k, v in (info.properties or {}).items():
                if k is None or v is None:
                    continue
                key = k.decode('utf-8', errors='ignore') if isinstance(k, bytes) else str(k)
                val = v.decode('utf-8', errors='ignore') if isinstance(v, bytes) else str(v)
                props[key] = val

            entry = hosts.setdefault(ip, {
                'hostname': hostname,
                'services': [],
                'mdns_props': {}
            })
            entry['services'].append(info.type)
            entry['mdns_props'].update(props)

        # Emit the complete mapping
        self.mdns_done.emit(hosts)
        zc.close()
        self.discovery_finished.emit()