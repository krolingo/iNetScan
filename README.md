# iNetScan
![Main UI FreeBSD](images/screenshot_freebsd.png)


**iNetScan** is a graphical network scanner inspired by macOS iNet. It performs fast and intelligent host discovery on local subnets, showing detailed metadata, icons, and service info for each device it finds.

## Features

- ⚡ Fast subnet scans using RustScan and Nmap  
- 🌐 Bonjour/mDNS discovery with metadata merge  
- ☎️ Vendor and model detection via MAC and mDNS  
- 💻 Smart icon assignment based on model/vendor/hostname  
- 🕵🏼‍♂️ OS detection per-host (via Nmap)  
- 🔌 Click-to-connect: SSH, HTTP, SMB, VNC, RDP, Webmin  
- 📦 Export to JSON, CSV, or Excel  
- 📝 Live color-coded log output  
- 💈 Qt6 GUI with real-time scan feedback and progress bar  
- 🧪 Per-host port scan with selectable modes (Quick / Advanced / Custom)  

## Disclaimer

> **This is a work-in-progress app.**  
> iNetScan is under active development and is not yet considered a mature or production-grade tool and it may never be. You may encounter bugs, missing features, or visual quirks and stupid mistakes.  
> Feedback, ideas, and pull requests are welcome!

## How to use

### FreeBSD

Install dependencies:

```sh
pkg install py311-qt6-pyqt nmap rustscan py311-pandas py311-manuf
```

Then:

```sh
git clone https://github.com/YOUR_USERNAME/inet-scan.git
cd inet-scan
doas python3 inetscan-v0.4.5.py
```
### macOS (via Homebrew)

Install dependencies:

```sh
brew install nmap rustscan python3
pip3 install PyQt6 pandas manuf
```

Then:

```sh
git clone https://github.com/YOUR_USERNAME/inet-scan.git
cd inet-scan
sudo python3 inetscan-v0.4.5.py
```

## ⚙️ Configuring Nmap and RustScan Paths

By default, iNetScan attempts to auto-detect `nmap` and `rustscan` using your system’s PATH.

If your tools are installed in non-standard locations or not detected correctly:

1. Launch iNetScan.
2. From the menu bar, choose **Settings → Settings...**
3. Set the full path to the `nmap` and `rustscan` binaries (e.g., `/usr/local/bin/nmap` or `/opt/homebrew/bin/rustscan`).
4. Click **OK** to save and continue.

Settings are saved persistently between runs using `QSettings`.

## Optional Data Files

These optional JSON files enhance vendor/model/icon accuracy:

- `oui_extra.json`, `mac_overrides.json` – Extra MAC vendor mappings  
- `apple_models.json` – Apple MAC prefixes → product models  
- `mdns_models.json` – mDNS model → icon mapping  
- `icon_map.json` – Override final icon file name  

Place icons in: `icons/png/` or `icons/svg/`

## Export Formats

- `.json`, `.csv`, `.xlsx` (requires `pandas`)

## License

MIT © 2025 iNetScan Contributors
