#!/usr/bin/env python3
import sys
import socket   

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTreeWidget, QTreeWidgetItem, QHeaderView,
    QStyledItemDelegate
)
from PyQt6.QtGui import QFont, QPainter, QKeySequence
from PyQt6.QtCore import QRect, Qt, QThread, pyqtSignal, QObject

from zeroconf import Zeroconf, ServiceBrowser, ServiceListener

from service_labels import labels as human_labels


class BoldParenthesisDelegate(QStyledItemDelegate):
    def paint(self, painter, option, index):
        text = index.data()
        if not text:
            return super().paint(painter, option, index)
        i = text.find('(')
        if i < 0:
            return super().paint(painter, option, index)
        before = text[:i]
        paren = text[i:]
        painter.save()
        painter.setFont(option.font)
        rect = option.rect
        fm = painter.fontMetrics()
        x = rect.x()
        y = rect.y() + fm.ascent() + (rect.height() - fm.height()) // 2
        # Draw before
        painter.setPen(option.palette.text().color())
        painter.drawText(x, y, before)
        width_before = fm.horizontalAdvance(before)
        # Bold for (parenthesis)
        bold_font = QFont(option.font)
        bold_font.setBold(True)
        painter.setFont(bold_font)
        painter.drawText(x + width_before, y, paren)
        painter.restore()
    def sizeHint(self, option, index):
        return super().sizeHint(option, index)

# ---- Zeroconf Thread ----

class MDNSListener(QObject, ServiceListener):
    update = pyqtSignal(dict)  # {stype: {name: info}}

    def __init__(self):
        QObject.__init__(self)
        ServiceListener.__init__(self)
        self.services = {}

    def add_service(self, zc, stype, name):
        info = zc.get_service_info(stype, name)
        if info:
            self.services.setdefault(stype, {})[name] = info
            self.update.emit(self.services.copy())

    def remove_service(self, zc, stype, name):
        if stype in self.services and name in self.services[stype]:
            del self.services[stype][name]
            self.update.emit(self.services.copy())

    def update_service(self, zc, stype, name):
        self.add_service(zc, stype, name)

class ZeroconfThread(QThread):
    services_updated = pyqtSignal(dict)

    def run(self):
        # Requires python-zeroconf ≥0.38
        zc = Zeroconf()
        listener = MDNSListener()
        listener.update.connect(self.emit_update)
        from time import sleep
        class TypeListener(ServiceListener):
            def __init__(self): self.types = set()
            def add_service(self, zc, st, name): self.types.add(name)
            def remove_service(self, zc, st, name): pass
            def update_service(self, zc, st, name): pass

        type_listener = TypeListener()
        ServiceBrowser(zc, "_services._dns-sd._udp.local.", type_listener)
        sleep(.5)
        types = sorted(type_listener.types)
        for t in types:
            ServiceBrowser(zc, t, listener)
        self.exec()

    def emit_update(self, services):
        self.services_updated.emit(services)

# ---- Qt GUI ----

class BonjourWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Discover")
        self.setMinimumSize(340, 480)
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setAlternatingRowColors(True)
        self.setCentralWidget(self.tree)

        # Add "File" menu with Quit
        file_menu = self.menuBar().addMenu("File")

        # Add menu for theme switching
        menu = self.menuBar().addMenu("View")
        refresh_menu = self.menuBar().addMenu("Network")
        theme_menu = menu.addMenu("Theme")
        dark_action = theme_menu.addAction("Dark Mode")
        light_action = theme_menu.addAction("Light Mode")
        dark_action.triggered.connect(lambda: self.set_theme("dark"))
        light_action.triggered.connect(lambda: self.set_theme("light"))
        system_action = theme_menu.addAction("System")
        system_action.triggered.connect(lambda: self.set_theme("system"))

        # Add menu for font magnification
        font_menu = menu.addMenu("Font Size")
        small_font_action = font_menu.addAction("Small")
        medium_font_action = font_menu.addAction("Medium")
        large_font_action = font_menu.addAction("Large")
        small_font_action.triggered.connect(lambda: self.set_font_size(10))
        medium_font_action.triggered.connect(lambda: self.set_font_size(12))
        large_font_action.triggered.connect(lambda: self.set_font_size(14))

        refresh_action = refresh_menu.addAction("Refresh Network")
        refresh_action.triggered.connect(self.restart_discovery)
        refresh_action.setShortcuts([QKeySequence("Ctrl+R"), QKeySequence("Meta+R")])

        quit_action = file_menu.addAction("Quit")
        import platform
        quit_action.setShortcut(QKeySequence("Ctrl+Q" if platform.system() != "Darwin" else "Meta+Q"))
        quit_action.triggered.connect(QApplication.quit)

        self.set_theme("system")  # Default

        # Set custom delegate for column 0
        self.tree.setItemDelegateForColumn(0, BoldParenthesisDelegate(self.tree))

        self.tree.setColumnCount(1)

        self.zc_thread = ZeroconfThread()
        self.zc_thread.services_updated.connect(self.update_services)
        self.zc_thread.start()

    def set_theme(self, mode):
        if mode == "dark":
            self.tree.setStyleSheet(
                """
                QTreeWidget {
                    background-color: #222;
                    alternate-background-color: #333;
                    border: 1px solid #555;
                    border-radius: 0;
                    padding: 8px;
                    margin-top: 2px;
                    color: #fafafa;
                }
                QHeaderView::section { background-color: #222; color: #fafafa; }
                """
            )
        elif mode == "light":
            self.tree.setStyleSheet(
                """
                QTreeWidget {
                    background-color: #fafafa;
                    alternate-background-color: #f0f0f0;
                    border: 1px solid #bbb;
                    border-radius: 0;
                    padding: 8px;
                    margin-top: 2px;
                    color: #222;
                }
                QHeaderView::section {
                    background-color: #fafafa;
                    color: #222;
                }
                QTreeView::branch {
                    color: black;
                }
                QTreeView::branch:closed:has-children:!has-siblings,
                QTreeView::branch:closed:has-children:has-siblings {
                    border-image: none;
                    image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='10' height='10'><polygon points='3,2 7,5 3,8' fill='black'/></svg>");
                }
                QTreeView::branch:open:has-children:!has-siblings,
                QTreeView::branch:open:has-children:has-siblings {
                    border-image: none;
                    image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='10' height='10'><polygon points='2,3 5,7 8,3' fill='black'/></svg>");
                }
                QTreeWidget::item {
                    padding-left: 4px;
                    padding-right: 4px;
                    font-weight: normal;
                }
                QTreeWidget::item:selected {
                    background-color: #cceeff;
                }
                """
            )
        elif mode == "system":
            self.tree.setStyleSheet(
                """
                QTreeWidget {
                    border: 1px solid #555;
                    border-radius: 0;
                    padding: 8px;
                    margin-top: 2px;
                }
                """
            )

    def set_font_size(self, size):
        font = self.tree.font()
        font.setPointSize(size)
        self.tree.setFont(font)

    def get_expanded_paths(self, item=None, path=()):
        """Recursively collect expanded item paths."""
        if item is None:
            expanded = set()
            for i in range(self.tree.topLevelItemCount()):
                expanded |= self.get_expanded_paths(self.tree.topLevelItem(i), ())
            return expanded
        expanded = set()
        if item.isExpanded():
            expanded.add(path + (item.text(0),))
        for i in range(item.childCount()):
            expanded |= self.get_expanded_paths(item.child(i), path + (item.text(0),))
        return expanded

    def restore_expanded_paths(self, expanded_paths, item=None, path=()):
        """Recursively restore expanded state based on saved paths."""
        if item is None:
            for i in range(self.tree.topLevelItemCount()):
                self.restore_expanded_paths(expanded_paths, self.tree.topLevelItem(i), ())
            return
        if path + (item.text(0),) in expanded_paths:
            item.setExpanded(True)
        for i in range(item.childCount()):
            self.restore_expanded_paths(expanded_paths, item.child(i), path + (item.text(0),))

    def update_services(self, services):
        # --- Save expanded state before clearing ---
        expanded_paths = self.get_expanded_paths()

        self.tree.clear()

        # Top level: 'local'
        local_item = QTreeWidgetItem(["local"])
        local_font = QFont()
        local_font.setBold(True)
        local_item.setFont(0, local_font)
        self.tree.addTopLevelItem(local_item)

        for stype in sorted(services):
            label = human_labels.get(stype, "")
            if label:
                combined_text = f"{stype} ({label})"
            else:
                combined_text = stype
            type_item = QTreeWidgetItem([combined_text])
            if label:
                font = QFont()
                font.setBold(True)
                type_item.setFont(0, font)
            local_item.addChild(type_item)
            for name, info in sorted(services[stype].items()):
                instance_item = QTreeWidgetItem([name])
                type_item.addChild(instance_item)
                host_item = QTreeWidgetItem([f"Host: {info.server}"])
                instance_item.addChild(host_item)
                for addr in info.addresses:
                    import socket
                    try:
                        if len(addr) == 4:
                            ip_str = socket.inet_ntoa(addr)
                        elif len(addr) == 16:
                            ip_str = socket.inet_ntop(socket.AF_INET6, addr)
                        else:
                            ip_str = str(addr)
                    except Exception:
                        ip_str = str(addr)
                    ip_item = QTreeWidgetItem([f"IP: {ip_str}"])
                    instance_item.addChild(ip_item)
                port_item = QTreeWidgetItem([f"Port: {info.port}"])
                instance_item.addChild(port_item)
                for k, v in info.properties.items():
                    def safe_decode(x):
                        if isinstance(x, bytes):
                            try:
                                return x.decode("utf-8")
                            except Exception:
                                return "0x" + x.hex()
                        return x or ""
                    key = safe_decode(k)
                    value = safe_decode(v)
                    if key or value:
                        txt_str = f"{key} = {value}"
                        txt_item = QTreeWidgetItem([txt_str])
                        instance_item.addChild(txt_item)
        local_item.setExpanded(True)

        # --- Restore expanded state after rebuilding ---
        self.restore_expanded_paths(expanded_paths)

    def restart_discovery(self):
        self.zc_thread.quit()
        self.zc_thread.wait()
        self.zc_thread = ZeroconfThread()
        self.zc_thread.services_updated.connect(self.update_services)
        self.zc_thread.start()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = BonjourWindow()
    win.show()
    sys.exit(app.exec())