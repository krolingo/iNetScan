#!/usr/bin/env python3

# --- Standard library imports ---
import csv
import html
import ipaddress
import json
import logging
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET

# --- Third-party PyQt6 imports ---
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTreeWidget, QTreeWidgetItem,
    QScrollArea, QSplitter, QToolBar, QLineEdit, QPushButton,
    QLabel, QFormLayout, QVBoxLayout, QHBoxLayout, QGridLayout,
    QGroupBox, QMenuBar, QMessageBox, QDialog, QDialogButtonBox,
    QProgressBar, QSizePolicy, QRadioButton, QButtonGroup, QScrollBar,
    QFileDialog, QFrame, QListWidget, QListWidgetItem, QTextEdit,
    QTabWidget, QStyle, QSizePolicy, QPushButton
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, pyqtSlot, QSize, QSettings, QEvent, QTimer, QObject,
    QProcess
)
from PyQt6.QtGui import (
    QIcon, QAction, QTextCursor, QFont, QDesktopServices
)

# --- ElidedLabel subclass for eliding long text with "…"
from PyQt6.QtGui import QPainter, QFontMetrics
from PyQt6.QtCore import Qt

class ElidedLabel(QLabel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Allow the label to expand horizontally
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
    def paintEvent(self, event):
        painter = QPainter(self)
        fm = QFontMetrics(self.font())
        # Compute elided text based on current width
        elided = fm.elidedText(self.text(), Qt.TextElideMode.ElideRight, self.width())
        painter.drawText(self.rect(), self.alignment(), elided)
from bonjour_gui import BonjourWindow

# --- Local imports ---
from ansi_style_map import style_map
from threads import OSDetectThread, HostPortThread
from scanning import ScanThread, get_privilege_wrapper
from mdns import MDNSWorker

# --- Optional dependencies ---
try:
    import pandas as pd
except ImportError:
    pd = None

try:
    from manuf import MacParser
    mac_parser = MacParser()
except ImportError:
    mac_parser = None
    logging.warning("manuf not installed; run 'pip install manuf' for vendor lookup")

# --- Helpers ---

def _remove_empty_mdns_model_keys(host):
    if '' in host.get('mdns_props', {}):
        host['mdns_props'].pop('', None)

# --- Logging setup ---
logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')
log = logging.getLogger(__name__)
DEBUG = True  # Set to False to disable logging




# --- Subclass for log area with double-click-to-bottom ---
class LogTextEdit(QTextEdit):
    def mouseDoubleClickEvent(self, event):
        super().mouseDoubleClickEvent(event)
        sb = self.verticalScrollBar()
        sb.setValue(sb.maximum())
def sip_deleted(obj):
    try:
        return obj is None or obj.parent() is None
    except RuntimeError:
        return True

# Pattern-based ANSI codes for additional highlighting
pattern_ansi_map = {
    r"Starting OS detection": "91",     # "91": "color:lightcoral",
    r"Detected OS": "33",               # yellow for OS detection messages
    r"failed": "31",                    # red for failure keywords
    r"Ping completed": "92",            # lightgreen for successful ping messages
    r"Showing details for host": "93",  # "93": "color:lightyellow",

    # add more patterns here as needed
}

# ── Additional JSON key/value highlighting ──
# Color JSON keys (ip, hostname, mac, etc.) in green
pattern_ansi_map.update({
    r"'ip':": "92",
    r"'hostname':": "92",
    r"'mac':": "92",
    r"'ports':": "92",
    r"'vendor':": "92",
    r"'model':": "92",
    r"'mdns_name':": "92",
    r"'mdns_services':": "92",
    r"'mdns_props':": "92",
})
# Color any single-quoted value in light cyan
pattern_ansi_map.update({
    r":\s*'[^']*'": "96",
})

# --- ConnectDialog definition ---
class ConnectDialog(QDialog):
    def __init__(self, parent, ip, ports):
        super().__init__(parent)
        self.setWindowTitle(f"Connect to {ip}")
        self.setModal(True)
        self.resize(300, 200)
        layout = QVBoxLayout(self)

        self.list = QListWidget(self)
        for entry in ports:
            port = entry['port'] if isinstance(entry, dict) else entry
            name = entry.get('name', '') if isinstance(entry, dict) else ''
            if port in (80, 443):
                label = f"{name or 'HTTP'} ({port}) → Open in Browser"
            elif port == 22:
                label = f"{name or 'SSH'} ({port}) → Open in Terminal"
            elif port in (139, 445):
                label = f"SMB Share ({port}) → Open File Browser"
            elif port == 5900:
                label = f"VNC (Screen Share) ({port}) → Open VNC"
            elif port == 3389:
                label = f"RDP (Remote Desktop) ({port}) → Open RDP"
            elif port == 10000:
                label = f"Webmin ({port}) → Open in Browser"
            else:
                continue
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, port)
            self.list.addItem(item)

        layout.addWidget(self.list)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Open | QDialogButtonBox.StandardButton.Cancel, self)
        buttons.accepted.connect(self.on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.list.itemActivated.connect(self.on_item)

    def on_accept(self):
        item = self.list.currentItem()
        if item:
            self.on_item(item)
        else:
            self.reject()

    def on_item(self, item):
        port = item.data(Qt.ItemDataRole.UserRole)
        ip = self.windowTitle().split()[-1]
        if port in (80, 443):
            url = f"http://{ip}:{port}"
            QDesktopServices.openUrl(QUrl(url))
        elif port == 22:
            QProcess.startDetached("x-terminal-emulator", ["-e", f"ssh {ip}"])
        elif port in (139, 445):
            QDesktopServices.openUrl(QUrl(f"smb://{ip}"))
        elif port == 5900:
            QDesktopServices.openUrl(QUrl(f"vnc://{ip}:{port}"))
        elif port == 3389:
            QDesktopServices.openUrl(QUrl(f"rdp://{ip}:{port}"))
        elif port == 10000:
            QDesktopServices.openUrl(QUrl(f"https://{ip}:{port}"))
        self.accept()
# --- vendor lookup via MAC OUI ---
# --- supplemental OUI vendor overrides (including custom mac_overrides.json) ---
script_dir = os.path.dirname(os.path.abspath(__file__))
extra_oui = {}
for fname in ('oui_extra.json', 'mac_overrides.json'):
    path = os.path.join(script_dir, fname)
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        log.debug(f"OUI overrides file not found: {path}")
        continue
    except json.JSONDecodeError as e:
        log.warning(f"Failed to parse {path}: {e}")
        continue
    except Exception as e:
        log.error(f"Error loading {path}: {e}")
        continue
    # if we reach here, data is loaded
    log.debug(f"Loaded {len(data)} entries from {path}")
    for k, v in data.items():
        key = k.upper().replace('-', '').replace(':', '')
        extra_oui[key] = v

# --- supplemental Apple OUI-to-model mapping for HomePod detection ---
script_dir = os.path.dirname(os.path.abspath(__file__))
apple_models_path = os.path.join(script_dir, 'apple_models.json')
try:
    with open(apple_models_path, 'r', encoding='utf-8') as f:
        apple_model_map = {
            k.upper().replace('-', '').replace(':', ''): v
            for k, v in json.load(f).items()
        }
except Exception:
    apple_model_map = {}

# --- supplemental Bonjour model → icon mapping ---
mdns_models_path = os.path.join(script_dir, 'mdns_models.json')
try:
    with open(mdns_models_path, 'r', encoding='utf-8') as f:
        mdns_model_map = {k: v for k, v in json.load(f).items()}
except Exception:
    mdns_model_map = {}

# --- supplemental explicit icon filename mapping ---
icon_map_path = os.path.join(script_dir, 'icon_map.json')
try:
    with open(icon_map_path, 'r', encoding='utf-8') as f:
        icon_map = json.load(f)
except Exception:
    icon_map = {}

# Remove any empty-string model keys from mdns_props
class QTextEditLogger(logging.Handler):
    def __init__(self, widget):
        super().__init__()
        self.widget = widget

    def emit(self, record):
        msg = self.format(record)
        # Inject ANSI codes for log level if present
        code = None
        if hasattr(record, 'levelno'):
            if record.levelno >= logging.ERROR:
                code = "91"  # lightcoral
            elif record.levelno == logging.WARNING:
                code = "33"  # yellow
            elif record.levelno == logging.INFO:
                code = "94"  # lightblue
            elif record.levelno == logging.DEBUG:
                code = "90"  # gray
        if code:
            msg = f"\x1b[{code}m{msg}\x1b[0m"

        # Highlight the OS string in Detected OS messages
        if "Detected OS for" in msg:
            try:
                m = re.search(r"Detected OS for [^:]+: (.+)", msg)
                if m:
                    os_str = m.group(1)
                    # Wrap just the OS name/details in yellow
                    msg = msg.replace(os_str, f"\x1b[33m{os_str}\x1b[0m", 1)
            except re.error:
                pass

        # Apply pattern-based ANSI highlighting
        for pat, pcode in pattern_ansi_map.items():
            try:
                msg = re.sub(pat, lambda m: f"\x1b[{pcode}m{m.group(0)}\x1b[0m", msg, flags=re.IGNORECASE)
            except re.error:
                pass

        html_msg = html.escape(msg)
        ansi_escape = re.compile(r'\x1b\[([0-9;]+)m')

        def _ansi_to_html(match):
            codes = match.group(1).split(';')
            if '0' in codes:
                return '</span>'
            styles = [style_map[c] for c in codes if c in style_map]
            if styles:
                return f'<span style="{";".join(styles)}">'
            return ''

        html_msg = ansi_escape.sub(_ansi_to_html, html_msg)
        # Ensure monospaced font for HTML
        #html_msg = f'<span style="font-family: monospace;">{html_msg}</span>'
        html_msg = f'<span style="font-family: monospace; font-size:10pt;">{html_msg}</span>'

        # Trim old lines if document grows too large
        doc = self.widget.document()
        if doc.blockCount() > 500:
            cursor = QTextCursor(doc)
            cursor.movePosition(QTextCursor.Start)
            cursor.select(QTextCursor.LineUnderCursor)
            cursor.removeSelectedText()
            cursor.deleteChar()
        # Schedule UI update on the main thread to prevent crashes
        def append_and_scroll(msg=html_msg):
            self.widget.insertHtml(msg + '<br>')
            # Move cursor to the end to ensure new text is visible
            cursor = self.widget.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self.widget.setTextCursor(cursor)
            self.widget.ensureCursorVisible()
            # Scroll to the bottom after inserting
            sb = self.widget.verticalScrollBar()
            sb.setValue(sb.maximum())
        QTimer.singleShot(0, append_and_scroll)



# Load up to 1000 ports and their names from nmap-services

def load_top_ports():
    import os
    ports = []
    names = {}
    service_paths = [
        '/usr/share/nmap/nmap-services',
        '/usr/local/share/nmap/nmap-services',
        '/opt/homebrew/share/nmap/nmap-services'
    ]
    svc_file = next((p for p in service_paths if os.path.exists(p)), None)
    if not svc_file:
        if DEBUG:
            logging.warning("nmap-services file not found; default RustScan port list will be used")
        return [], {}
    try:
        with open(svc_file, 'r') as f:
            for line in f:
                if line.startswith('#'):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                name = parts[0]
                port_proto = parts[1]
                if '/tcp' not in port_proto:
                    continue
                port = int(port_proto.split('/')[0])
                ports.append(port)
                names[port] = name
    except Exception:
        if DEBUG:
            logging.warning(f"failed to read {svc_file}; using default RustScan ports")
        return [], {}
    return ports, names

COMMON_PORTS, SERVICE_NAMES = load_top_ports()
# Top 1000 common ports for Quick scan
QUICK_PORTS = COMMON_PORTS[:1000]


ICON_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icons", "png")
DEFAULT_ICON = os.path.join(ICON_PATH, "network-server.png")

class ScannerWindow(QMainWindow):
    def normalize_host_metadata(self, host):
        # Guard for invalid host
        if not host or not isinstance(host, dict):
            log.warning(f"Skipping invalid host: {host}")
            return
        # Clean up and enforce consistent format
        if not host.get('hostname'):
            host['hostname'] = host.get('local_name', '')
        # Skip bad model values
        bad_models = {'0', '0,1,2', '', None}
        if host.get('model') in bad_models:
            host['model'] = ''
        if host.get('vendor') == 'Unknown' and host.get('mac'):
            if 'lookup_vendor' in globals():
                host['vendor'] = lookup_vendor(host['mac'])
        # Removed stray debug print for icon_path assignment.
    def assign_icon_to_host(self, host):
        # Robust multi-tier fallback: model-specific, vendor-generic, vendor-printer generic, then default
        if 'icon_path' in host and host['icon_path']:
            return  # Icon already set
        model_key = (host.get('model') or "").lower().replace(" ", "_")
        vendor_key = (host.get('vendor') or "").lower()
        icon_candidates = [
            f"{model_key}.png" if model_key else None,
            f"{vendor_key}.png" if vendor_key else None,
            f"{vendor_key}_printer.png" if vendor_key else None,
            "network-server.png"
        ]
        for icon_name in icon_candidates:
            if icon_name and os.path.exists(os.path.join(ICON_PATH, icon_name)):
                icon_path = os.path.join(ICON_PATH, icon_name)
                break
        else:
            icon_path = os.path.join(ICON_PATH, "network-server.png")
        host['icon_path'] = icon_path

    def get_icon_path(self, host):
        # Return Apple icon if vendor is Apple
        if host.get("vendor", "").lower() == "apple":
            return "icons/png/apple.png"
        # fallback to default icon
        return DEFAULT_ICON

    def refresh_host_display(self):
        self.update_host_list()
        self.details_card.setVisible(False)
    def __init__(self):
        super().__init__()
        self.setWindowTitle("iNet-style Scanner")
        self.resize(900, 600)
        self.hosts = []
        # Lock to prevent race conditions when modifying hosts list
        self._hosts_lock = threading.Lock()
        # Temporary file for scan results
        self._temp_file = tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8')
        # Start with an empty JSON array
        self._temp_file.write('[]')
        self._temp_file.flush()
        # For asynchronous ping
        self.ping_proc = None
        # Track OS detection threads by IP
        self._os_threads = {}

        mb = QMenuBar(self)
        self.setMenuBar(mb)
        file_menu = mb.addMenu("File")
        exit_act = QAction("Exit", self)
        exit_act.triggered.connect(self.close)
        file_menu.addAction(exit_act)
        export_act = QAction("Export Scan Results", self)
        export_act.triggered.connect(self.export_scan_results)
        file_menu.addAction(export_act)

        st = mb.addMenu("Settings")
        set_act = QAction("Settings...", self)
        set_act.triggered.connect(self.open_settings)
        st.addAction(set_act)
        
        # Help menu with About (native placement on macOS)
        help_menu = mb.addMenu("Help")
        about_act = QAction("About", self)
        about_act.setMenuRole(QAction.MenuRole.AboutRole)
        about_act.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_act)        

        self.settings = QSettings("iNetScan", "ScannerApp")
        default_rs = shutil.which('rustscan') or 'rustscan'
        self.rs_path = self.settings.value('rustscan_path', default_rs)
        default_nmap = self.settings.value('nmap_path', shutil.which('nmap') or 'nmap')
        self.nmap_path = default_nmap

        tb = QToolBar()
        tb.setMovable(False)
        self.addToolBar(tb)

        # Qt already imported at top.
        subnet_label = QLabel("Subnet:")
        subnet_label.setContentsMargins(10, 0, 4, 0)
        subnet_label.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.subnet_edit = QLineEdit()
        self.subnet_edit.setFixedWidth(200)
        self.subnet_edit.setPlaceholderText("e.g. 192.168.69.0/24")
        self.subnet_edit.setFrame(True)
        # Fixed width for subnet input to prevent it stretching
        self.subnet_edit.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        # Use a left-aligned fixed horizontal layout for subnet label and input
        subnet_widget = QWidget()
        subnet_layout = QHBoxLayout(subnet_widget)
        subnet_layout.setContentsMargins(0, 0, 0, 0)
        subnet_layout.setSpacing(4)
        subnet_layout.setAlignment(Qt.AlignmentFlag.AlignLeft)
        subnet_layout.addWidget(subnet_label)
        subnet_layout.addWidget(self.subnet_edit)

        self.scan_btn = QPushButton("Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        self.advanced_scan_btn = QPushButton("Deep Scan")
        self.advanced_scan_btn.clicked.connect(self.start_advanced_scan)
        filter_label = QLabel("Filter:")
        self.filter_edit = QLineEdit()
        self.filter_edit.setFixedWidth(200)
        self.filter_edit.setPlaceholderText("Search hosts…")
        self.filter_edit.setFrame(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        # Combine subnet, Scan, Deep Scan, and Filter controls into one toolbar group
        combo_widget = QWidget()
        combo_layout = QHBoxLayout(combo_widget)
        combo_layout.setContentsMargins(0, 0, 0, 0)
        combo_layout.setSpacing(4)
        # Use fixed size for the buttons so they don’t stretch
        self.scan_btn.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.advanced_scan_btn.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        # Remove setAlignment; use stretch for left alignment below
        # combo_layout.setAlignment(Qt.AlignmentFlag.AlignLeft)
        combo_layout.addWidget(subnet_widget)
        combo_layout.addSpacing(18)   # add 18px space before Scan button
        combo_layout.addWidget(self.scan_btn)
        combo_layout.addWidget(self.advanced_scan_btn)
        combo_layout.addWidget(filter_label)
        combo_layout.addWidget(self.filter_edit)
        # Push all controls to the left
        combo_layout.addStretch()
        # Ensure combo_widget does not expand horizontally
        combo_widget.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        tb.addWidget(combo_widget)

        # Right-align and add a real QPushButton with globe icon
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        tb.addWidget(spacer)

        globe_btn = QPushButton(self)
        globe_icon = self.style().standardIcon(QStyle.StandardPixmap.SP_DriveNetIcon)
        globe_btn.setIcon(globe_icon)
        # Set icon and button sizes for a consistent globe appearance
        globe_btn.setIconSize(QSize(24, 24))       # adjust 24x24 as desired
        globe_btn.setFixedSize(32, 32)             # button area size (icon + padding)
        # Add internal padding around the icon
        globe_btn.setStyleSheet("padding:4px;")    # adjusts space around icon
        globe_btn.setToolTip("Open Bonjour service browser")
        globe_btn.setFlat(True)
        globe_btn.clicked.connect(self.open_bonjour_window)
        tb.addWidget(globe_btn)

        # Add a bit of right padding
        tb.setContentsMargins(0, 0, 4, 0)   # increase right padding to 16px

        self.tree = QTreeWidget()
        # Restore default larger host list icon size
        self.tree.setIconSize(QSize(48, 48))
        self.tree.setColumnCount(1)
        # Hide the redundant tree header now that the tab provides the label
        self.tree.setHeaderHidden(True)
        self.tree.currentItemChanged.connect(self.show_details)
        self.tree.setMaximumWidth(380)
        self.tree.setColumnWidth(0, 180)

        # --- Permanent log area (persistent, always at bottom of right pane)
        self.log_area = LogTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setMinimumHeight(100)
        self.log_area.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.log_area.setStyleSheet("QTextEdit { border: none; }")
        self.log_area.setPlaceholderText("Log output will appear here...")

        # ── Hook Python logging into the log_area ──
        log_handler = QTextEditLogger(self.log_area)
        log_handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
        log_handler.setLevel(logging.DEBUG)
        logging.getLogger().addHandler(log_handler)
        # Ensure root logger captures debug-level messages
        logging.getLogger().setLevel(logging.DEBUG)

        # Use a monospaced font for log output
        font = QFont("Consolas")
        if not font.exactMatch():
            font = QFont("SF Mono")
        if not font.exactMatch():
            font = QFont("Menlo")
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.log_area.setFont(font)

        self.tabs = QTabWidget()
        self.info_tab = QWidget()
        # Use a persistent QVBoxLayout for info_tab
        self.info_layout = QVBoxLayout(self.info_tab)
        self.info_layout.setContentsMargins(20,0,16,0)
        self.info_layout.setSpacing(8)
        self.info_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.tabs.addTab(self.info_tab, "Info")

        self.ports_tab = QWidget()
        self.ports_layout = QVBoxLayout(self.ports_tab)
        self.ports_layout.setContentsMargins(16,16,16,16)
        self.ports_layout.setSpacing(8)
        self.ports_list = QListWidget()
        self.ports_layout.addWidget(self.ports_list)
        self.tabs.addTab(self.ports_tab, "Ports")

        # Right pane: use a vertical splitter to allow resizing between details and log area
        self.detail_pane = QSplitter(Qt.Orientation.Vertical)
        # Details area: put tabs directly in a container
        self.detail_area = QWidget()
        detail_layout = QVBoxLayout(self.detail_area)
        detail_layout.setContentsMargins(0,0,0,0)
        detail_layout.setSpacing(0)
        detail_layout.addWidget(self.tabs)
        detail_layout.addStretch()
        self.detail_pane.addWidget(self.detail_area)
        # Log area in splitter for adjustable height
        self.log_area.setMinimumHeight(100)  # initial height
        self.detail_pane.addWidget(self.log_area)

        # make the top (detail_area) non-stretching, and the bottom (log_area) take all the extra
        self.detail_pane.setStretchFactor(0, 0)   # detail_area gets 0× of the extra space
        self.detail_pane.setStretchFactor(1, 1)   # log_area  gets 1× of the extra space


        # Prevent the details area from collapsing below its minimum height
        self.info_tab.setMinimumHeight(375)
        # self.detail_pane.setCollapsible(0, False)  # Collapsibility still works with the new widget
        self.detail_pane.setCollapsible(1, True)
        # Optionally set initial splitter sizes (detail_area larger, log_area smaller)
        self.detail_pane.setSizes([self.height() - 200, 200])

        # Wrap host list in a native tab for "Host"
        self.left_tabs = QTabWidget()
        self.left_tabs.setTabPosition(QTabWidget.TabPosition.North)
        self.left_tabs.addTab(self.tree, "Host")
        # Constrain left column width to prevent it expanding past its scrollbar
        self.left_tabs.setMaximumWidth(self.tree.maximumWidth())
        self.left_tabs.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self.left_tabs)
        splitter.addWidget(self.detail_pane)
        splitter.setStretchFactor(0,0)
        splitter.setStretchFactor(1,3)
        splitter.setSizes([380, 520])

        container = QWidget()
        main_layout = QVBoxLayout(container)
        main_layout.setContentsMargins(8,8,8,8)
        main_layout.addWidget(splitter)
        self.setCentralWidget(container)

        self.host_port_threads = {}
        self.scan_thread = None
        self.statusBar().showMessage("Ready to scan – click ‘Scan’ or ‘Deep Scan’ to begin")

        self.progress = QProgressBar(self)
        self.progress.hide()
        self.statusBar().addPermanentWidget(self.progress)
        self.host_count_label = QLabel("Hosts: 0")
        self.statusBar().addPermanentWidget(self.host_count_label)
   

        # Spinner indicator for host discovery
        self.spinner_label = QLabel("", self)
        self.spinner_label.setFixedWidth(12)  # small width for spinner char
        self.spinner_label.hide()
        self._spinner_index = 0
        self._spinner_chars = ['|', '/', '-', '\\']
        self.spinner_timer = QTimer(self)
        self.spinner_timer.timeout.connect(self._update_spinner)
        self.statusBar().addPermanentWidget(self.spinner_label)

        # Muted sans-serif status bar font for unified appearance
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.statusBar().setFont(font)
        self.statusBar().setStyleSheet("color: #999999;")  # muted gray text

        self.host_count_label.setFont(font)
        self.host_count_label.setStyleSheet("color: #999999;")

        self.spinner_label.setFont(font)
        self.spinner_label.setStyleSheet("color: #999999;")

        # Animation timer for indeterminate scan progress
        self.progress_anim_timer = QTimer(self)
        self._anim_step = 5
        self._anim_max = 505  # number of steps for full sweep (~2s at 100ms)
        self.progress_anim_timer.timeout.connect(self._update_progress_anim)
        # Multi-phase progress setup: unified discovery + mDNS
        self._total_phases = 2  # Unified phases: discovery + mDNS
        self._segment_size = self._anim_max // self._total_phases
        self._current_phase = 0
    def _update_progress_anim(self):
        # Unified multi-phase animation within current phase
        self._anim_step = (self._anim_step + 1) % self._segment_size
        base = (self._current_phase - 1) * self._segment_size
        self.progress.setValue(base + self._anim_step)

    def open_bonjour_window(self):
        """
        Open the Bonjour service browser in-process.
        """
        # Keep a reference so it isn't garbage-collected
        self.bonjour_win = BonjourWindow()
        self.bonjour_win.show()
#############################################################  end of __init__.

    def show_about_dialog(self):
        # Display an About dialog
        QMessageBox.about(
            self,
            f"About {QApplication.applicationName()}",
            "iNetScan\nVersion 0.4.5\n© 2025 iNetScan Contributors"
        )

    def reenable_scan_buttons(self):
        """Re-enable both scan controls."""
        # Ensure animation finishes at 100% when scan completes
        self.progress_anim_timer.stop()
        self.progress.setValue(self._anim_max)
        # Hide progress bar after reaching 100%
        QTimer.singleShot(1000, self.progress.hide)
        self.scan_btn.setEnabled(True)
        self.advanced_scan_btn.setEnabled(True)
        self.advanced_mode = False


    def start_scan(self):
        """
        Start a quick scan of the specified subnet.
        """
        # Reset unified phase tracking
        self._current_phase = 1
        # Disable scan buttons during quick scan
        self.scan_btn.setEnabled(False)
        self.advanced_scan_btn.setEnabled(False)
        # Reset temporary results file
        self._temp_file.seek(0)
        self._temp_file.truncate()
        self._temp_file.write('[]')
        self._temp_file.flush()
        # Clear the log area at the start of a new scan
        self.log_area.clear()
        subnet = self.subnet_edit.text().strip()
        if not subnet:
            QMessageBox.warning(self, "Input Required", "Enter a subnet to scan.")
            self.scan_btn.setEnabled(True)
            self.advanced_scan_btn.setEnabled(True)
            return
        if not self.is_valid_subnet(subnet):
            QMessageBox.warning(self, "Invalid subnet", "Please enter a valid CIDR subnet like 192.168.1.0/24.")
            self.scan_btn.setEnabled(True)
            self.advanced_scan_btn.setEnabled(True)
            return

        # Clear previous data
        self.tree.clear()
        self.hosts.clear()
        self.host_count_label.setText("Hosts: 0")
        self.clear_details()
        self.statusBar().showMessage(f"Scanning {subnet}...")

        # Launch thread
        self.scan_thread = ScanThread(subnet, self.rs_path, self.nmap_path)
        self.scan_thread.result.connect(self.populate)
        self.scan_thread.error.connect(self.on_error)
        self.scan_thread.discovery_finished.connect(self._on_discovery_finished)
        self.scan_thread.discovery_update.connect(self._on_discovery_update)
        # Show progress bar during scan
        self.progress.show()
        # Animate progress bar over _anim_max steps
        self.progress.setRange(0, self._anim_max)
        self._anim_step = 0
        self.progress.setValue(0)
        self.progress_anim_timer.start(100)
        # Show spinner during initial host discovery
        self.spinner_label.show()
        self.spinner_timer.start(100)
        # self.scan_thread.finished.connect(self._on_scan_finished)

        self.scan_thread.start()
        # --- mDNS resolution now started after discovery is finished ---

    def start_advanced_scan(self):
        """
        Perform a thorough, multipass host discovery and extended mDNS aggregation.
        """
        subnet = self.subnet_edit.text().strip()
        # Reset unified phase tracking
        self._current_phase = 1
        if not subnet:
            QMessageBox.warning(self, "Input Required", "Enter a subnet to scan.")
            return
        if not self.is_valid_subnet(subnet):
            QMessageBox.warning(self, "Invalid subnet", "Please enter a valid CIDR subnet like 192.168.1.0/24.")
            return
        # Reset phase counter for a fresh multi-pass scan
        # self._current_phase = 0
        self.advanced_mode = True
        self.scan_btn.setEnabled(False)
        self.advanced_scan_btn.setEnabled(False)
        # Clear previous results
        self.tree.clear()
        self.hosts.clear()
        self.host_count_label.setText("Hosts: 0")
        # Clear the GUI log area for a fresh scan
        self.log_area.clear()
        # Show spinner during deep scan discovery phases
        self.spinner_label.show()
        self.spinner_timer.start(100)
        # Start deep scan passes (no progress_anim_timer here)
        self._execute_scan_passes(0)

    def _execute_scan_passes(self, index=0):
        """
        Sequentially run scanning passes: ARP, ICMP, and TCP/UDP probes.
        """
        # Phase start: increment and configure progress slice
        self._current_phase += 1
        start_val = (self._current_phase - 1) * self._segment_size
        end_val = self._current_phase * self._segment_size
        self.progress.setRange(start_val, end_val)
        self._anim_step = 0
        self.progress.setValue(start_val)
        self.progress.show()
        self.progress_anim_timer.start(100)
        # Ensure spinner is visible for each scan pass
        self.spinner_label.show()
        self.spinner_timer.start(100)
        passes = [
            (['-PR'], 'ARP pass'),
            (['-PE'], 'ICMP pass'),
            (['-PS80,443', '-PU53'], 'TCP/UDP pass'),
        ]
        if index < len(passes):
            flags, label = passes[index]
            # Update status
            self.statusBar().showMessage(f"{label}...")
            # Launch ScanThread with custom flags
            self.scan_thread = ScanThread(
                self.subnet_edit.text().strip(),
                self.rs_path,
                self.nmap_path,
                scan_flags=flags
            )
            self.scan_thread.result.connect(self.populate)
            self.scan_thread.error.connect(self.on_error)
            self.scan_thread.discovery_update.connect(self._on_discovery_update)
            # On pass completion, trigger next pass
            self.scan_thread.discovery_finished.connect(
                lambda idx=index: self._on_scan_pass_finished(idx)
            )
            self.scan_thread.start()
        else:
            # All passes done: soft delay then mDNS
            QTimer.singleShot(1000, self._start_mdns)

    def _on_scan_pass_finished(self, index):
        # Merge UI and host count, then next pass
        self.progress.hide()
        # Update progress bar for completed pass
        total_passes = 3
        self.progress.setValue(index + 1)
        if index + 1 >= total_passes:
            # All passes done: hide progress bar after mDNS begins
            QTimer.singleShot(500, self.progress.hide)
        self.host_count_label.setText(f"Hosts: {len(self.hosts)}")
        # Small pause before next pass
        QTimer.singleShot(200, lambda: self._execute_scan_passes(index + 1))

    def _start_mdns(self):
        # During advanced scan’s Bonjour, show spinner; otherwise hide it
        if self.advanced_mode:
            self.spinner_label.show()
            self.spinner_timer.start(100)
        else:
            self.spinner_timer.stop()
            self.spinner_label.hide()
        self.statusBar().showMessage("Resolving Bonjour/mDNS services…")
        # Final phase (mDNS): configure progress slice
        self._current_phase += 1
        start_val = (self._current_phase - 1) * self._segment_size
        end_val = self._current_phase * self._segment_size
        self.progress.setRange(start_val, end_val)
        self.progress.show()
        timeout = 2.0 if self.advanced_mode else 1.0
        # Launch mDNS resolution in a QThread for thread-safe UI updates
        self.mdns_worker = MDNSWorker(timeout=timeout)
        # Only connect mdns_done to _on_mdns_done; do not re-enable scan controls here
        self.mdns_worker.mdns_done.connect(self._on_mdns_done)
        self.mdns_worker.host_found.connect(self._on_mdns_partial)
        self.mdns_worker.start()

    # elsewhere in the code, when connecting HostPortThread.result:
    # t.result.connect(lambda data, ip=clean_ip: self.on_host_ports_multi(ip, data))
    # should be replaced by:
    # t.result.connect(lambda ip, ports: self.on_host_ports_multi(ip, ports))
        
        
    def _on_discovery_finished(self):
        # Phase 2 (mDNS) unified progress
        self._current_phase = 2
        start_val = (self._current_phase - 1) * self._segment_size
        end_val   = self._current_phase * self._segment_size
        self.progress.setRange(start_val, end_val)
        self.progress.show()
        self.mdns_worker = MDNSWorker(timeout=2.0)
        # Only connect mdns_done to _on_mdns_done; do not re-enable scan controls here
        self.mdns_worker.mdns_done.connect(self._on_mdns_done)
        self.mdns_worker.host_found.connect(self._on_mdns_partial)
        log.debug(f"Launching MDNSWorker with timeout={self.mdns_worker.timeout}")
        self.mdns_worker.start()
        

    def _on_mdns_done(self, results):
        self.progress_anim_timer.stop()
        # Stop and hide spinner when mDNS completes
        self.spinner_timer.stop()
        self.spinner_label.hide()
        log.info(f"mDNS complete with results: {results}")
        import copy
        updated = 0
        with self._hosts_lock:
            for host in self.hosts:
                ip = host.get('ip')
                mdns = results.get(ip)
                if mdns:
                    host['mdns_name'] = mdns.get('hostname', '')
                    host['mdns_services'] = mdns.get('services', [])
                    if 'mdns_props' in mdns:
                        host['mdns_props'] = copy.deepcopy(mdns['mdns_props'])
                        # Merge mDNS model into host['model']
                        md_val = (
                            host['mdns_props'].get('model')
                            or host['mdns_props'].get('md')
                            or host['mdns_props'].get('am')     # Apple Bonjour key
                            or host['mdns_props'].get('ty')     # e.g. 'XEROX WorkCentre 3335'
                            or host['mdns_props'].get('product')  # optional fallback
                            or ''
                        )
                        vendor_prefix = host.get('vendor', '').upper() + ' '
                        if md_val.upper().startswith(vendor_prefix):
                            md_val = md_val[len(vendor_prefix):]
                        if md_val and md_val not in {'0', '0,1,2'}:
                            host['model'] = md_val
                else:
                    host['mdns_name'] = ''
                    host['mdns_services'] = []
                    host['mdns_props'] = {}
                self.assign_icon_to_host(host)
                # --- Begin ICON SUGGESTED LOGGING BLOCK ---
                # Log which icon the system intended to use (even if default)
                icon_name_suggested = "unknown"
                # Improved normalization: strip, lowercase, replace commas and spaces with underscores
                model = (host.get("model") or "").strip().lower().replace(",", "_").replace(" ", "_")
                vendor = (host.get("vendor") or "").strip().lower().replace(",", "_").replace(" ", "_")
                used_icon = None
                if model and os.path.exists(os.path.join("icons", "png", f"{model}.png")):
                    icon_name_suggested = f"{model}.png"
                    used_icon = os.path.join("icons", "png", f"{model}.png")
                elif vendor and os.path.exists(os.path.join("icons", "png", f"{vendor}.png")):
                    icon_name_suggested = f"{vendor}.png"
                    used_icon = os.path.join("icons", "png", f"{vendor}.png")
                elif vendor and os.path.exists(os.path.join("icons", "png", f"{vendor}_printer.png")):
                    icon_name_suggested = f"{vendor}_printer.png"
                    used_icon = os.path.join("icons", "png", f"{vendor}_printer.png")
                else:
                    icon_name_suggested = "network-server.png"
                #log.debug(f"[ICON] Host {host.get('ip')} would have used: icons/png/{icon_name_suggested}")
                # --- End ICON SUGGESTED LOGGING BLOCK ---
                host["icon_path"] = host.get("icon_path", self.get_icon_path(host))
                # Retry fallback icon assignment if icon_path used network-server.png but we now have a valid icon
                if host.get("icon_path", "").endswith("network-server.png") and used_icon and os.path.exists(used_icon):
                    host["icon_path"] = used_icon
                    log.debug(f"[ICON] Reassigned valid icon after fallback: {used_icon}")
                # Immediately refresh the icon in the UI after icon_path is set
                self.set_icon_for_host(ip)
                # Update icon if icon_path changed and item exists
                for i in range(self.tree.topLevelItemCount()):
                    item = self.tree.topLevelItem(i)
                    ip_item = item.data(0, Qt.ItemDataRole.UserRole)
                    if ip_item == host['ip']:
                        new_icon_path = host['icon_path']
                        if new_icon_path and os.path.exists(new_icon_path):
                            item.setIcon(0, QIcon(new_icon_path))
                        break
                updated += 1
        self.tree.clear()
        with self._hosts_lock:
            for h in self.hosts:
                self._add_host_item(h)
        current = self.tree.currentItem()
        if current:
            self.show_details(current, None)
        self.statusBar().showMessage(f"Scan complete — {len(self.hosts)} hosts, mDNS merged")
        # Finalize progress on mDNS completion
        self.progress_anim_timer.stop()
        self.progress.setValue(self._anim_max)
        QTimer.singleShot(1000, self.progress.hide)
        # Re-enable scan controls after mDNS merge truly finishes
        self.scan_btn.setEnabled(True)
        self.advanced_scan_btn.setEnabled(True)

    def _on_mdns_partial(self, ip, mdns):
        log.info(f"mDNS partial update for {ip}: {mdns}")
        """
        Handle incremental mDNS updates for a single host.
        """
        with self._hosts_lock:
            # Find the matching host entry
            host = next((h for h in self.hosts if h.get('ip') == ip), None)
            if not host:
                return
            # Merge properties
            host['mdns_name'] = mdns.get('hostname', '')
            host['mdns_services'] = mdns.get('services', [])
            host['mdns_props'] = mdns.get('mdns_props', {})
            # Reassign icon
            self.assign_icon_to_host(host)
            # Refresh the icon in the UI
            self.set_icon_for_host(ip)

    def set_icon_for_host(self, ip):
        """
        Refresh the icon for the host with the given IP in the UI, based on host['icon_path'].
        """
        host_data = next((h for h in self.hosts if h.get('ip') == ip), None)
        if not host_data:
            return
        new_icon_path = host_data.get('icon_path', '')
        for i in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(i)
            ip_item = item.data(0, Qt.ItemDataRole.UserRole)
            if ip_item == ip:
                if new_icon_path and os.path.exists(new_icon_path):
                    item.setIcon(0, QIcon(new_icon_path))
                break


    def _update_spinner(self):
        # Cycle through spinner characters
        self._spinner_index = (self._spinner_index + 1) % len(self._spinner_chars)
        self.spinner_label.setText(self._spinner_chars[self._spinner_index])

    def _on_discovery_update(self, msg):
        # Show ongoing discovery details in status bar
        self.statusBar().showMessage(msg)

    def open_settings(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("Settings")
        form = QFormLayout(dlg)

        rs_edit = QLineEdit(self.rs_path, dlg)
        form.addRow("RustScan path:", rs_edit)

        nmap_edit = QLineEdit(self.nmap_path, dlg)
        form.addRow("Nmap path:", nmap_edit)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
            dlg
        )
        form.addRow(buttons)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)

        if dlg.exec() == QDialog.DialogCode.Accepted:
            # Save RustScan path
            new_rs = rs_edit.text().strip()
            if new_rs:
                self.rs_path = new_rs
                self.settings.setValue('rustscan_path', self.rs_path)
            # Save Nmap path
            new_nmap = nmap_edit.text().strip()
            if new_nmap:
                self.nmap_path = new_nmap
                self.settings.setValue('nmap_path', self.nmap_path)

    def _add_host_item(self, host):
        # Remove any empty-string model keys from mdns_props
        _remove_empty_mdns_model_keys(host)
        # Compute absolute icons directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        icons_dir = os.path.join(script_dir, 'icons')
        ip = host['ip']
        rdns = host.get('hostname', '').strip()
        mdns = host.get('mdns_name', '').strip()

        # Determine primary display name: DNS > mDNS > placeholder
        if rdns:
            line1 = rdns
        elif mdns:
            line1 = mdns
        else:
            line1 = '—'
        line2 = ip

        # Show mDNS line only if both DNS and mDNS exist
        line3 = mdns if rdns and mdns else ''

        label_text = f"{line1}\n{line2}"
        if line3:
            label_text += f"\n{line3}"

        item = QTreeWidgetItem(self.tree)
        # Use server.svg as default
        default_icon = QIcon(os.path.join(icons_dir, 'server.svg'))
        mdns_props = host.get('mdns_props', {})
        # Use host['model'] (cleaned of vendor prefix) before falling back to raw mDNS props
        model = host.get('model') or mdns_props.get('model') or mdns_props.get('md', '')
        vendor = host.get('vendor', '') or mdns_props.get('vn', '')
        mac = host.get('mac', '')

        # --- Begin new prioritized icon selection logic ---
        # Lookup order:
        # 0. OUI/mac-prefix specific icon (highest priority)
        # 1. model-based (e.g. appletv14,1.svg)
        # 2. mdns_models and apple_models dicts
        # 4. vendor name image (e.g. eero.png)
        # 5. hostname/localhostname
        # 6. default icon (network-server.svg)
        apple_models = apple_model_map
        vendor_icons = {k.lower(): k.lower() for k in set(icon_map.keys())}
        mdns_models = mdns_model_map

        icon_name = None

        # Normalize inputs
        mac_prefix = mac.upper().replace(":", "")[:6] if mac else ""
        vendor_key = vendor.strip() if vendor else ""
        model_key = model.strip() if model else ""

        # 0. OUI/mac-prefix specific icon (highest priority)
        if mac_prefix:
            mac_png = os.path.join(icons_dir, "png", f"{mac_prefix.lower()}.png")
            if os.path.exists(mac_png):
                icon_name = mac_prefix.lower()

        # 1. Model-based (direct filename match, e.g. appletv14,1.svg)
        if not icon_name and model_key:
            # Direct filename match (case-insensitive)
            model_filename = model_key.lower().replace(',', '_').replace(' ', '_')
            # Check for svg/png in icons/svg or icons/png
            svg_path = os.path.join(icons_dir, "svg", f"{model_filename}.svg")
            png_path = os.path.join(icons_dir, "png", f"{model_filename}.png")
            if os.path.exists(svg_path) or os.path.exists(png_path):
                icon_name = model_filename

        # 2. mdns_models dict (underscore-normalized), then case-insensitive, then apple_models
        if not icon_name:
            # normalize spaces to underscores for lookup
            norm_key = model_key.lower().replace(" ", "_")
            if norm_key in mdns_models:
                icon_name = mdns_models[norm_key]
            else:
                # fallback to case-insensitive match of original model
                for mk, val in mdns_models.items():
                    if mk.lower() == model_key.lower():
                        icon_name = val
                        break
        if not icon_name and mac_prefix in apple_models:
            icon_name = apple_models[mac_prefix]

        # 4. Vendor name image (e.g. eero, raspberry_pi, raspberry_pi_foundation)
        if not icon_name and vendor_key:
            # Sanitize to a base filename
            vendor_filename = vendor_key.lower().replace(' ', '_')
            vendor_filename = re.sub(r'[^a-z0-9_]', '_', vendor_filename)
            vendor_filename = re.sub(r'_+', '_', vendor_filename).strip('_')

            # Try PNG then SVG
            png_path = os.path.join(icons_dir, "png", f"{vendor_filename}.png")
            svg_path = os.path.join(icons_dir, "svg", f"{vendor_filename}.svg")
            if os.path.exists(png_path) or os.path.exists(svg_path):
                icon_name = vendor_filename
            else:
                # Strip common suffixes and retry
                for suffix in ('_foundation', '_trading', '_inc', '_llc'):
                    if vendor_filename.endswith(suffix):
                        alt = vendor_filename[: -len(suffix)]
                        alt_png = os.path.join(icons_dir, "png", f"{alt}.png")
                        alt_svg = os.path.join(icons_dir, "svg", f"{alt}.svg")
                        if os.path.exists(alt_png) or os.path.exists(alt_svg):
                            icon_name = alt
                            break

        # 5. Hostname/localhostname fallback (e.g. eero-pro-6e-0naw.png)
        if not icon_name:
            # Try sanitized hostname and mdns_name
            hostnames_to_try = []
            if rdns:
                hostnames_to_try.append(rdns)
            if mdns and mdns not in hostnames_to_try:
                hostnames_to_try.append(mdns)
            for hn in hostnames_to_try:
                # Sanitize: lowercase, replace spaces with underscores, strip domain parts
                base = hn.split('.')[0]
                sanitized = base.lower().replace(' ', '_')
                sanitized = re.sub(r'[^a-z0-9_-]', '_', sanitized)
                sanitized = re.sub(r'_+', '_', sanitized).strip('_')
                hostname_png = os.path.join(icons_dir, "png", f"{sanitized}.png")
                if os.path.exists(hostname_png):
                    icon_name = sanitized
                    break

        # 6. Default fallback
        if not icon_name:
            icon_name = "network-server"
        # --- End new prioritized icon selection logic ---

        # Apply explicit icon filename mapping if present
        mapped_name = icon_map.get(icon_name, icon_name)
        # --- SVG/PNG fallback logic with normalized vendor string ---
        icon_path = os.path.join(icons_dir, "svg", f"{mapped_name}.svg")
        if not os.path.exists(icon_path):
            icon_path = os.path.join(icons_dir, "png", f"{mapped_name}.png")
        if os.path.exists(icon_path):
            icon = QIcon(icon_path)
        else:
            # Fallback to other possible locations/extensions as before
            svg_root = os.path.join(icons_dir, 'svg', f"{mapped_name}.svg")
            svg_sub  = os.path.join(icons_dir, 'svg', f"{mapped_name}.svg")
            png_root = os.path.join(icons_dir, 'png', f"{mapped_name}.png")
            png_sub  = os.path.join(icons_dir, 'png', f"{mapped_name}.png")
            jpeg_root = os.path.join(icons_dir, f"{mapped_name}.jpeg")
            jpg_root  = os.path.join(icons_dir, f"{mapped_name}.jpg")
            jpeg_sub  = os.path.join(icons_dir, 'png', f"{mapped_name}.jpeg")
            jpg_sub   = os.path.join(icons_dir, 'png', f"{mapped_name}.jpg")
            if os.path.exists(svg_root):
                icon = QIcon(svg_root)
            elif os.path.exists(svg_sub):
                icon = QIcon(svg_sub)
            elif os.path.exists(png_root):
                icon = QIcon(png_root)
            elif os.path.exists(png_sub):
                icon = QIcon(png_sub)
            elif os.path.exists(jpeg_root):
                icon = QIcon(jpeg_root)
            elif os.path.exists(jpg_root):
                icon = QIcon(jpg_root)
            elif os.path.exists(jpeg_sub):
                icon = QIcon(jpeg_sub)
            elif os.path.exists(jpg_sub):
                icon = QIcon(jpg_sub)
            else:
                icon = default_icon
        item.setIcon(0, icon)
        # Force a redraw of the icon in the tree view
        self.tree.viewport().update()
        item.setText(0, label_text)
        item.setData(0, Qt.ItemDataRole.UserRole, ip)

    def populate(self, data):
        new_hosts = data.get('hosts', [])
        # If first batch, clear and add all
        if not self.hosts:
            self.tree.clear()
            self.hosts = []
            for host in new_hosts:
                self.hosts.append(host)
                self._add_host_item(host)
        else:
            # Append any additional hosts
            for host in new_hosts[len(self.hosts):]:
                self.hosts.append(host)
                self._add_host_item(host)
        # Save current hosts list to temp file
        self._temp_file.seek(0)
        json.dump(self.hosts, self._temp_file)
        self._temp_file.truncate()
        self._temp_file.flush()
        # Select first item on first populate
        if self.tree.topLevelItemCount() and self.tree.currentItem() is None:
            self.tree.setCurrentItem(self.tree.topLevelItem(0))
        self.statusBar().showMessage(f"Found {len(self.hosts)} hosts")
        # Update progress bar with number of hosts discovered
        self.progress.setValue(len(self.hosts))
        # ←——– update the Hosts: # label
        self.host_count_label.setText(f"Hosts: {len(self.hosts)}")

    def apply_filter(self, text):
        t = text.lower()
        for i in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(i)
            name = item.text(0).lower()
            # ip = item.text(1)
            item.setHidden(t not in name)

    def show_details(self, current, _):
        if not current:
            return
        ip = current.data(0, Qt.ItemDataRole.UserRole)
        host = next((h for h in self.hosts if h['ip'] == ip), {})
        # [DETAIL] Print showing details for host and its ports at INFO level
        log.info(f"[DETAIL] Showing details for host: {host}")
        ip = host.get('ip', '—')
        hostname = host.get('hostname', '—')
        mac = host.get('mac', '—')
        vendor = host.get('vendor', '—')

        # Preserve last scan mode selection
        if hasattr(self, 'quick_rb'):
            # Safely check the radio buttons in case they've been deleted
            try:
                custom_checked = self.custom_rb.isChecked()
            except RuntimeError:
                custom_checked = False
            try:
                advanced_checked = self.advanced_rb.isChecked()
            except RuntimeError:
                advanced_checked = False
            if custom_checked:
                self.last_scan_mode = 'custom'
            elif advanced_checked:
                self.last_scan_mode = 'advanced'
            else:
                self.last_scan_mode = 'quick'

        self.clear_details()

        # 1. Decoration icon at top (placeholder)
#        icon = QIcon.fromTheme('user-identity')
#        pixmap = icon.pixmap(48, 48) if not icon.isNull() else None
#        # Only add the deco_icon if the theme icon is available
#        if pixmap and not pixmap.isNull():
#            deco_icon = QLabel()
#            deco_icon.setAlignment(Qt.AlignmentFlag.AlignHCenter)
#            deco_icon.setPixmap(pixmap)
#            deco_icon.setFixedHeight(56)

        # 2. Host Details group, now use QFrame to remove header space
        # Use a frameless panel instead of a group box to remove header space
        details_group = QFrame()
        details_group.setFrameShape(QFrame.Shape.NoFrame)
        details_group.setFrameShadow(QFrame.Shadow.Raised)
        details_group.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        details_group_layout = QVBoxLayout(details_group)
        
        # Apply internal margins to layout: left=18px, top=20px, right=18px, bottom=5px
        details_group_layout.setContentsMargins(18, 20, 18, 5)
        details_group_layout.setSpacing(12)
        details_group_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        #if pixmap and not pixmap.isNull():
        #    details_group_layout.addWidget(deco_icon)

        details_group.setSizePolicy(QSizePolicy.Policy.Expanding,
                           QSizePolicy.Policy.Minimum)


        # Centered grid for host info
        grid = QGridLayout()
        grid.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignHCenter)
        grid.setHorizontalSpacing(24)
        grid.setVerticalSpacing(8)
        # IP, Hostname, MAC, Ports (centered)
        ip_lbl = QLabel("<b>IP:</b>")
        ip_val = ElidedLabel(ip)
        ip_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        ip_val.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        ip_val.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        hn_lbl = QLabel("<b>Hostname:</b>")
        hn_val = ElidedLabel(hostname)
        hn_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        hn_val.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        hn_val.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        # LocalHostname (mDNS)
        mdns = host.get('mdns_name', '').strip()
        lh_lbl = QLabel("<b>LocalHostname:</b>")
        lh_val = ElidedLabel(mdns or '—')
        lh_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        lh_val.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        lh_val.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        mac_lbl = QLabel("<b>MAC:</b>")
        mac_val = ElidedLabel(mac)
        mac_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        mac_val.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        mac_val.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        vendor_lbl = QLabel("<b>Vendor:</b>")
        vendor_val = ElidedLabel(vendor)
        vendor_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        vendor_val.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        vendor_val.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard
        )

        ports_scanned = len(COMMON_PORTS)
        open_ports = [entry['port'] if isinstance(entry, dict) and 'port' in entry else entry for entry in host.get('ports', [])]
        ports_open = len(open_ports)
        ports_lbl = QLabel("<b>Open Ports:</b>")
        ports_val = ElidedLabel(f"{ports_open} of {ports_scanned} scanned")
        ports_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        ports_val.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        ports_val.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard
        )

        grid.addWidget(ip_lbl, 0, 0)
        grid.addWidget(ip_val, 0, 1)
        grid.addWidget(hn_lbl, 1, 0)
        grid.addWidget(hn_val, 1, 1)
        grid.addWidget(lh_lbl, 2, 0)
        grid.addWidget(lh_val, 2, 1)
        grid.addWidget(mac_lbl, 3, 0)
        grid.addWidget(mac_val, 3, 1)
        grid.addWidget(vendor_lbl, 4, 0)
        grid.addWidget(vendor_val, 4, 1)
        # Determine the model: host['model'], then Bonjour 'am', then mDNS 'model'
        mdns_props = host.get('mdns_props', {})
        model_prop = host.get('model') or mdns_props.get('am') or mdns_props.get('model', '')
        model_lbl = QLabel("<b>Model:</b>")
        model_val = ElidedLabel(model_prop or "—")
        model_val.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse |
            Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        model_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        model_val.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        grid.addWidget(model_lbl, 5, 0)
        grid.addWidget(model_val, 5, 1)
        # OS label and value
        os_lbl = QLabel("<b>OS:</b>")
        os_val = ElidedLabel(host.get("os", "—"))
        os_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        os_val.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        os_val.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        grid.addWidget(os_lbl, 6, 0)
        grid.addWidget(os_val, 6, 1)
        grid.addWidget(ports_lbl, 7, 0)
        grid.addWidget(ports_val, 7, 1)
        details_group_layout.addLayout(grid)

        # Ports list row (centered)
        port_entries = host.get('ports', [])
        open_ports = [entry['port'] if isinstance(entry, dict) and 'port' in entry else entry for entry in port_entries]
        # PATCH: update ports list label logic to always show even a single port
        ports_list_lbl = QLabel("<b>Ports List:</b>")
        ports_list_val = ElidedLabel(', '.join(str(p) for p in open_ports) if open_ports else "—")
        ports_list_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        ports_list_val.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        ports_list_val.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        ports_list_row = QHBoxLayout()
        ports_list_row.addWidget(ports_list_lbl)
        ports_list_row.addWidget(ports_list_val)
        ports_list_row.addStretch()
        details_group_layout.addLayout(ports_list_row)

        # 3. Action button row: Scan Ports, Ping, Connect (centered)
        btn_row = QWidget()
        btn_hl = QHBoxLayout(btn_row)
        btn_hl.setContentsMargins(0, 0, 0, 0)
        btn_hl.setSpacing(16)
        self.port_scan_btn = QPushButton("Scan Ports", btn_row)
        self.port_scan_btn.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.port_scan_btn.clicked.connect(self.start_host_port_scan)
        ping_btn = QPushButton("Ping", btn_row)
        ping_btn.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        ping_btn.clicked.connect(self.start_host_ping)
        connect_btn = QPushButton("Connect", btn_row)
        connect_btn.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        connect_btn.clicked.connect(self.connect_to_host)
        btn_hl.addWidget(self.port_scan_btn)
        btn_hl.addWidget(ping_btn)
        btn_hl.addWidget(connect_btn)
        # OS Detection Button
        os_btn = QPushButton("Detect OS", btn_row)
        os_btn.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        os_btn.clicked.connect(self.start_os_detection)
        btn_hl.addWidget(os_btn)
        # Toggle log visibility
        #toggle_log_btn = QPushButton("Toggle Log", btn_row)
        toggle_log_btn = QPushButton("Log", btn_row)
        toggle_log_btn.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        toggle_log_btn.clicked.connect(self.toggle_log)
        btn_hl.addWidget(toggle_log_btn)
        btn_hl.addStretch()

        # 4. Per-host scan progress bar (hidden until scan starts)
        self.port_prog = QProgressBar(self.info_tab)
        self.port_prog.setRange(0, 0)  # indeterminate
        self.port_prog.hide()

        # Add widgets directly to persistent self.info_layout
        self.info_layout.addWidget(details_group, 1)
        # Scan mode selection row (radio buttons + ports input)
        scan_mode_row = QWidget()
        sm_layout = QHBoxLayout(scan_mode_row)
        sm_layout.setContentsMargins(0, 0, 0, 0)
        sm_layout.setSpacing(8)
        # Mode selectors
        mode_label = QLabel("Scan Mode:")
        sm_layout.addWidget(mode_label)
        self.quick_rb = QRadioButton("Quick")
        self.advanced_rb = QRadioButton("Advanced")
        self.custom_rb = QRadioButton("Custom")
        self.quick_rb.setChecked(True)
        mode_group = QButtonGroup(self)
        for rb in (self.quick_rb, self.advanced_rb, self.custom_rb):
            mode_group.addButton(rb)
            sm_layout.addWidget(rb)
        # Ports input (only for Custom mode)
        self.ports_input = QLineEdit()
        self.ports_input.setPlaceholderText("e.g. 22,80,443")
        self.ports_input.setFixedWidth(100)
        self.ports_input.setEnabled(False)
        self.ports_input.setFrame(True)
        sm_layout.addWidget(self.ports_input)
        sm_layout.addStretch()
        # Toggle ports_input based on Custom selection
        def toggle_ports():
            self.ports_input.setEnabled(self.custom_rb.isChecked())
        self.quick_rb.toggled.connect(toggle_ports)
        self.advanced_rb.toggled.connect(toggle_ports)
        self.custom_rb.toggled.connect(toggle_ports)
        # Restore previous selection and update ports_input state
        if getattr(self, 'last_scan_mode', 'quick') == 'custom':
            self.custom_rb.setChecked(True)
        elif getattr(self, 'last_scan_mode', 'quick') == 'advanced':
            self.advanced_rb.setChecked(True)
        else:
            self.quick_rb.setChecked(True)
        toggle_ports()

        # Move scan_mode_row, btn_row, and self.port_prog inside the details_group
        # so that scan controls and buttons are framed together
        details_group_layout.addWidget(scan_mode_row)
        details_group_layout.addWidget(btn_row)
        details_group_layout.addWidget(self.port_prog)
        details_group_layout.addStretch()

        # Ports tab: list each port entry
        for entry in host.get('ports', []):
            port = entry['port'] if isinstance(entry, dict) and 'port' in entry else entry
            name = entry['name'] if isinstance(entry, dict) and 'name' in entry else ""
            item = QListWidgetItem(f"{port} {name}".strip())
            self.ports_list.addItem(item)

        # Add mDNS hostname to details text if present
        if hasattr(self, 'details_text'):
            if host.get("mdns_name"):
                self.details_text.append(f"mDNS Hostname: {host['mdns_name']}")
    def start_os_detection(self):
        current = self.tree.currentItem()
        if not current:
            return
        ip = current.data(0, Qt.ItemDataRole.UserRole)
        if not ip:
            return
        log.info(f"Starting OS detection for {ip}...")
        thread = OSDetectThread(ip, self.nmap_path)
        self._os_threads[ip] = thread
        thread.result.connect(self.on_os_result)
        thread.error.connect(self.on_error)
        thread.finished.connect(lambda: self._os_threads.pop(ip, None))
        thread.start()

    def on_os_result(self, ip, os_info):
        log.info(f"Detected OS for {ip}: {os_info.get('os')} (accuracy {os_info.get('accuracy')}%)")
        for h in self.hosts:
            if h['ip'] == ip:
                h['os'] = os_info.get('os')
                break
        current = self.tree.currentItem()
        if current and current.data(0, Qt.ItemDataRole.UserRole) == ip:
            self.show_details(current, None)
    def start_host_ping(self):
        current = self.tree.currentItem()
        if not current:
            return
        ip = current.data(0, Qt.ItemDataRole.UserRole)
        if not ip:
            return

        # Prevent overlapping pings
        if self.ping_proc and self.ping_proc.state() != QProcess.ProcessState.NotRunning:
            return

        log.info(f"=== Pinging {ip} ===")
        sender = self.sender()
        sender.setEnabled(False)

        self.ping_proc = QProcess(self)
        self.ping_proc.readyReadStandardOutput.connect(self._handle_ping_output)
        self.ping_proc.finished.connect(
            lambda code, status, s=sender: self._handle_ping_finished(s, code, status)
        )
        self.ping_proc.start('ping', ['-c', '4', ip])

    def _handle_ping_output(self):
        data = bytes(self.ping_proc.readAllStandardOutput()).decode('utf-8')
        for line in data.splitlines():
            log.info(line)

    def _handle_ping_finished(self, button, exit_code, exit_status):
        if exit_status != QProcess.ExitStatus.NormalExit or exit_code != 0:
            log.warning("Ping failed or host did not respond.")
        else:
            log.info("Ping completed.")
        # QPushButton already imported at top.
        # Safe guard for re-enabling the button
        if button is not None and isinstance(button, QPushButton):
            try:
                button.setEnabled(True)
            except RuntimeError:
                pass

    def start_host_port_scan(self):
        current = self.tree.currentItem()
        if not current:
            return
        ip = current.data(0, Qt.ItemDataRole.UserRole)
        if not ip:
            return
        clean_ip = ip.strip()
        host = next((h for h in self.hosts if h['ip'] == clean_ip), {})

        if DEBUG:
            logging.debug(f"Active threads: {list(self.host_port_threads.keys())}")
            logging.debug(f"Requested scan for: {clean_ip}")
        # Launch per-host port scan thread if not already running
        if clean_ip in self.host_port_threads:
            return
        t = HostPortThread(clean_ip, self.rs_path, self)
        # Pass custom ports to thread if Custom mode is selected
        if self.custom_rb.isChecked():
            text = self.ports_input.text().strip()
            parsed = []
            for part in text.split(','):
                try:
                    num = int(part.strip())
                    parsed.append(num)
                except ValueError:
                    pass
            t.custom_ports = parsed
        else:
            t.custom_ports = None
        self.host_port_threads[clean_ip] = t
        # Bind result/error to methods that handle per-host update
        t.result.connect(lambda ip, ports: self.on_host_ports_multi(ip, ports))
        t.error.connect(self.on_error)
        t.ip = clean_ip
        t.finished.connect(self.on_thread_finished)
        t.start()
        # Disable scan button and show progress immediately, but only for the currently selected host
        self.port_scan_btn.setEnabled(False)
        self.port_scan_btn.setText("Scanning...")
        self.port_prog.show()

    def on_thread_finished(self):
        thread = self.sender()
        # Ensure the thread has fully terminated before cleanup
        try:
            thread.wait()
        except Exception:
            pass
        ip = getattr(thread, "ip", None)
        clean_ip = ip.strip() if isinstance(ip, str) else ip
        if clean_ip and clean_ip in self.host_port_threads:
            self.host_port_threads.pop(clean_ip)
        # Re-enable Scan Ports button and reset its text
        if hasattr(self, 'port_scan_btn'):
            self.port_scan_btn.setEnabled(True)
            self.port_scan_btn.setText("Scan Ports")
        # Hide the per-host port progress bar
        if hasattr(self, 'port_prog'):
            self.port_prog.hide()

    def on_host_ports_multi(self, ip, ports):
        # Always use stripped IP for consistency
        clean_ip = ip.strip() if isinstance(ip, str) else ip
        # Update the matching host entry
        # 'ports' is already the list of port entries
        # # Ensure all port entries are dicts for GUI compatibility
        ports = [{'port': p, 'name': SERVICE_NAMES.get(p, '')} if isinstance(p, int) else p for p in ports]
        for h in self.hosts:
            if h['ip'] == clean_ip:
                h['ports'] = ports
                break
        # Save updated hosts list including ports to temp file
        self._temp_file.seek(0)
        json.dump(self.hosts, self._temp_file)
        self._temp_file.truncate()
        self._temp_file.flush()
        # If this host is currently selected, refresh its details
        current = self.tree.currentItem()
        if current:
            value = current.data(0, Qt.ItemDataRole.UserRole)
            if isinstance(value, str) and value.strip() == clean_ip:
                self.show_details(current, None)
                if hasattr(self, 'port_scan_btn'):
                    self.port_scan_btn.setEnabled(True)
                    self.port_scan_btn.setText("Scan Ports")
                if hasattr(self, 'port_prog'):
                    self.port_prog.hide()

    # --- Export scan results method ---
    def export_scan_results(self):
        # Prompt user to save the temp file contents
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Scan Results", "",
            "JSON Files (*.json);;CSV Files (*.csv);;Excel Files (*.xlsx);;All Files (*)"
        )
        if path:
            # Ensure temp file is flushed
            self._temp_file.flush()
            ext = os.path.splitext(path)[1].lower()
            # Prepare data
            data = self._temp_file.readable() and None  # not used
            hosts = self.hosts
            if ext == '.json' or ext == "":
                # Copy temp file to chosen location
                shutil.copy(self._temp_file.name, path)
            elif ext == '.csv':
                with open(path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=['ip','hostname','mac','vendor','ports'])
                    writer.writeheader()
                    for h in hosts:
                        # Flatten ports list to semicolon-separated string of ports
                        ports_str = ';'.join(str(p['port']) if isinstance(p, dict) else str(p) for p in h.get('ports', []))
                        row = {
                            'ip': h.get('ip',''),
                            'hostname': h.get('hostname',''),
                            'mac': h.get('mac',''),
                            'vendor': h.get('vendor',''),
                            'ports': ports_str
                        }
                        writer.writerow(row)
            elif ext == '.xlsx':
                if pd:
                    df = pd.DataFrame([
                        {
                            'ip': h.get('ip',''),
                            'hostname': h.get('hostname',''),
                            'mac': h.get('mac',''),
                            'vendor': h.get('vendor',''),
                            'ports': ';'.join(str(p['port']) if isinstance(p, dict) else str(p) for p in h.get('ports', []))
                        } for h in hosts
                    ])
                    df.to_excel(path, index=False)
                else:
                    QMessageBox.warning(self, "Missing Dependency", "Pandas is required to export Excel files. Please install pandas and try again.")
                    return
            else:
                # Default: treat as JSON
                shutil.copy(self._temp_file.name, path)
            os.chmod(path, 0o644)
            QMessageBox.information(self, "Export Complete", f"Scan results saved to {path}")


    def clear_details(self):
        # Safely remove widgets from the persistent info_layout
        old_layout = self.info_layout
        if old_layout is not None:
            while old_layout.count():
                child = old_layout.takeAt(0)
                if child.widget():
                    child.widget().setParent(None)
                elif child.layout():
                    child.layout().setParent(None)
        # Clear Ports tab list
        self.ports_list.clear()

    def on_error(self, msg):
        log.error(f"[ERROR] {msg}")
        try:
            if not hasattr(self, '_tray'):
                self._tray = QSystemTrayIcon(self)
                self._tray.setIcon(QIcon.fromTheme("dialog-warning") or self.windowIcon())
                self._tray.setVisible(True)
            self._tray.showMessage("Scan Error", msg, QSystemTrayIcon.MessageIcon.Warning)
        except Exception as e:
            log.warning(f"Notification failed: {e}")
        self.statusBar().showMessage("Error")
        self.reenable_scan_buttons()

    def on_host_ports(self, data):
        ip = data['ip']
        ports = data['ports']
        # Ensure all port entries are dicts for GUI compatibility
        ports = [{'port': p, 'name': SERVICE_NAMES.get(p, '')} if isinstance(p, int) else p for p in ports]
        # Update the matching host entry
        for h in self.hosts:
            if h['ip'] == ip:
                h['ports'] = ports
                break
        # Refresh detail pane if this host is selected
        current = self.tree.currentItem()
        # Keep ports results displayed persistently (do not clear on scan)
        if current and current.data(0, Qt.ItemDataRole.UserRole) == ip:
            self.show_details(current, None)
        # Re-enable button and hide port progress bar
        if hasattr(self, 'scan_btn'):
            self.scan_btn.setEnabled(True)
            self.scan_btn.setText("Scan Ports")
        if hasattr(self, 'port_prog'):
            self.port_prog.hide()

    def toggle_log(self):
        """
        Toggle the visibility of the log window in the detail pane splitter.
        """
        if self.log_area.isVisible():
            self.log_area.hide()
        else:
            self.log_area.show()

    def connect_to_host(self):
        current = self.tree.currentItem()
        if not current:
            return
        ip = current.data(0, Qt.ItemDataRole.UserRole)
        if not ip:
            return
        host = next((h for h in self.hosts if h['ip'] == ip), {})
        # Prefer domain (hostname or mDNS) when opening web ports
        display = host.get('hostname') or host.get('mdns_name') or ip
        ports = host.get('ports', [])
        dlg = ConnectDialog(self, display, ports)
        dlg.exec()

    def is_valid_subnet(self, subnet):
        pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$")
        if not pattern.match(subnet):
            return False
        try:
            ip = ipaddress.ip_network(subnet, strict=False)
            return True
        except ValueError:
            return False

if __name__ == '__main__':
    import os
    # Ensure we have root-level privileges for ARP scanning
    if os.geteuid() != 0:
        # Try doas, then sudo
        wrapper = shutil.which('doas') or shutil.which('sudo')
        if wrapper:
            os.execvp(wrapper, [wrapper, sys.executable] + sys.argv)
        else:
            QMessageBox.critical(None, "Permission Denied", "Root privileges are required for ARP scanning. Please install doas or sudo and rerun.")
            sys.exit(1)
    app = QApplication(sys.argv)
    win = ScannerWindow()
    win.show()
    sys.exit(app.exec())
