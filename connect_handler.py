#!/usr/bin/env python3
import sys
import webbrowser
import subprocess

def main(ip):
    """
    Present a simple text menu to choose how to connect to the host.
    """
    def raw_socket(host):
        port = input("Enter port for raw socket: ").strip()
        if port.isdigit():
            subprocess.run(["x-terminal-emulator", "-e", f"nc {host} {port}"])
        else:
            print("Invalid port.")

    options = [
        ("HTTP", 80, lambda: webbrowser.open(f"http://{ip}")),
        ("HTTPS", 443, lambda: webbrowser.open(f"https://{ip}")),
        ("SSH", 22, lambda: subprocess.run(["x-terminal-emulator", "-e", f"ssh {ip}"])),
        ("SFTP", 22, lambda: subprocess.run(["x-terminal-emulator", "-e", f"sftp {ip}"])),
        ("SMB Share", 445, lambda: webbrowser.open(f"smb://{ip}")),
        ("CUPS (Printer)", 631, lambda: webbrowser.open(f"http://{ip}:631")),
        ("VNC (Screen Share)", 5900, lambda: webbrowser.open(f"vnc://{ip}")),
        ("RDP (Remote Desktop)", 3389, lambda: webbrowser.open(f"rdp://{ip}")),
        ("Webmin", 10000, lambda: webbrowser.open(f"https://{ip}:10000")),
        ("Raw Socket (nc)", None, lambda: raw_socket(ip)),
    ]

    print(f"\nConnect to {ip}:")
    for idx, (name, port, _) in enumerate(options, start=1):
        if port:
            print(f" {idx}) {name}  (port {port})")
        else:
            print(f" {idx}) {name}")
    choice = input("\nSelect an option [1-{}]: ".format(len(options))).strip()

    try:
        idx = int(choice) - 1
        if 0 <= idx < len(options):
            _, port, action = options[idx]
            action()
        else:
            print("Invalid selection.")
    except ValueError:
        print("Invalid input. Please enter a number.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: connect_handler.py <IP>")
        sys.exit(1)
    main(sys.argv[1])