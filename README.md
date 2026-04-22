# NetScan-WoL

**ARP-based network discovery and Wake-on-LAN tool for Linux with an interactive CLI and optional web dashboard.**

NetScan-WoL scans your broadcast domain at Layer 2 using ARP, discovers every host with its IP, MAC address, vendor, and hostname, and lets you send Wake-on-LAN magic packets to bring machines online. It features persistent saved hosts, online/offline status checking, scan history, and an optional Flask-based web UI that can be deployed as a systemd service.

Works on Ubuntu, Fedora, RHEL, Rocky, Alma, Arch, openSUSE, and other mainstream Linux distributions. The script auto-detects your distro and package manager.

---

## Features

- **Layer 2 ARP scanning** discovers all hosts on the broadcast domain, including those that block ICMP ping
- **Hostname resolution** cascades through reverse DNS, mDNS (Avahi), and NetBIOS (nbtscan)
- **Wake-on-LAN** from scan results, saved favorites, manual MAC entry, or broadcast to all saved hosts
- **Online/offline status** via `arping` (Layer 2) with ICMP ping fallback
- **Saved hosts** persist across sessions with labels, last known IP, and timestamps
- **Scan history** stored as timestamped TSV files for browsing past results
- **Multi-distro support** with automatic package manager detection (apt, dnf, yum, pacman, zypper)
- **Self-installing dependencies** for both required and optional packages
- **Web UI** with a dark-themed dashboard deployable as a systemd service
- **Shared data** between CLI and web UI via `~/.netscan-wol/`

---

## Quick Start

```bash
cd netscan-wol
chmod +x netscan-wol.sh

# Install dependencies automatically
sudo ./netscan-wol.sh --install

# Launch the interactive menu
sudo ./netscan-wol.sh
```

Root privileges are required because ARP scanning operates at the raw socket level.

---

## Requirements

**Required** (installed automatically via `--install`):

| Package | Purpose |
|---------|---------|
| `arp-scan` | Layer 2 ARP network scanning |
| `wakeonlan` | Sending WoL magic packets |

**Optional** (offered during install for enhanced functionality):

| Package | Purpose |
|---------|---------|
| `avahi-utils` / `avahi-tools` | mDNS/Bonjour hostname resolution |
| `nbtscan` | NetBIOS/SMB hostname resolution |
| `arping` | Layer 2 ARP host status checking |

**Web UI** additionally requires:

| Package | Purpose |
|---------|---------|
| `python3` | Runtime for the Flask web server |
| `flask` | Web framework (installed via pip) |

---

## Usage

### CLI

```bash
# Launch interactive menu (auto-detect interface)
sudo ./netscan-wol.sh

# Specify interface and subnet
sudo ./netscan-wol.sh -i ens18 -s 10.0.50.0/24

# Install all dependencies and exit
sudo ./netscan-wol.sh --install

# Show help
./netscan-wol.sh --help
```

### CLI Menu Options

| # | Option | Description |
|---|--------|-------------|
| 1 | Scan Network | Run ARP scan, resolve hostnames, save hosts |
| 2 | View Last Scan | Redisplay previous scan results |
| 3 | WoL from Scan | Wake a discovered host |
| 4 | Saved Hosts | Manage favorites, check status, add/delete |
| 5 | Quick WoL | Status-checked list, wake one or all |
| 6 | Manual WoL | Enter any MAC, optional custom broadcast IP |
| 7 | Scan History | Browse past scan results |
| 8 | Settings | Interface, subnet, dependencies, web service |

### Web UI Service

```bash
# Install and enable as a systemd service (prints access URLs)
sudo ./netscan-wol.sh --web-install

# Custom port and interface
sudo ./netscan-wol.sh --web-install --web-port 9090 -i ens18

# Check service status
sudo ./netscan-wol.sh --web-status

# Uninstall (preserves saved hosts and scan history)
sudo ./netscan-wol.sh --web-uninstall
```

The web service can also be managed from the interactive menu under Settings > Web UI Service.

### Running the Web UI Manually

If you prefer to run the web server directly without systemd:

```bash
pip3 install flask
sudo python3 netscan-web.py --port 8888 --host 0.0.0.0
```

---

## File Structure

```
netscan-wol/
├── netscan-wol.sh          # Main CLI tool
├── netscan-web.py          # Flask web UI server
└── README.md

~/.netscan-wol/             # Data directory (created at runtime)
├── saved_macs.conf         # Saved hosts (MAC|Label|IP|Timestamp)
├── last_scan.tsv           # Most recent scan results
├── netscan-wol.log         # CLI log file
├── netscan-wol-web.log     # Web UI log file
└── history/                # Timestamped scan history
    ├── scan_20250330_141500.tsv
    └── ...
```

When the web service is installed via `--web-install`:

```
/opt/netscan-wol/
└── netscan-web.py          # Deployed copy of the web server

/etc/systemd/system/
└── netscan-wol-web.service # systemd unit file
```

---

## Web UI Dashboard

The web dashboard provides five sections that mirror the CLI functionality:

| Section | Description |
|---------|-------------|
| Network Scan | Run scans, view results, save hosts, send WoL |
| Saved Hosts | Manage saved MACs, check online/offline status |
| Wake-on-LAN | Manual WoL by MAC, quick WoL from saved hosts |
| Scan History | Browse and inspect past scan results |
| Dependencies | View installed/missing packages and versions |

Both CLI and web UI read from and write to the same `~/.netscan-wol/` directory, so saved hosts and scan history stay in sync regardless of which interface you use.

---

## How It Works

### Why ARP Instead of Ping

Ping sweeping sends ICMP echo requests and waits for replies. Many hosts, especially Windows machines, have their firewall configured to drop ICMP, making them invisible to ping-based scanners.

ARP operates at Layer 2. Every host on the broadcast domain must respond to ARP requests to participate in the network. There is no firewall rule that blocks ARP without also breaking the host's network connectivity entirely. This means `arp-scan` discovers everything on the segment: firewalled workstations, IoT devices, printers, and anything else with an IP address.

### Status Checking

Online/offline status checks use `arping` first (Layer 2 ARP probe to the host's last known IP), which has the same firewall-bypass advantage as the initial scan. If `arping` is not installed, it falls back to standard ICMP ping.

### Wake-on-LAN

WoL sends a "magic packet" containing the target's MAC address repeated 16 times, preceded by 6 bytes of `0xFF`. The target machine's network interface, even while the machine is powered off, listens for this pattern and triggers a boot. The target machine must have WoL enabled in its BIOS/UEFI and network adapter settings.

---

## Supported Distributions

| Distro | Package Manager | Tested |
|--------|----------------|--------|
| Ubuntu / Debian | apt | ✓ |
| Fedora | dnf | x |
| RHEL / Rocky / Alma | dnf / yum | x |
| Arch / Manjaro | pacman | x |
| openSUSE | zypper | x |

Package names are automatically mapped to distro-specific equivalents (e.g., `avahi-utils` becomes `avahi-tools` on Fedora, `arping` maps to `iputils` on Fedora/Arch).

---

## Command Reference

```
Usage:  sudo ./netscan-wol.sh [OPTIONS]

Options:
  -i, --interface <iface>   Network interface (auto-detected if omitted)
  -s, --subnet <cidr>       Subnet to scan (default: --localnet)
      --install              Install all dependencies and exit
  -h, --help                Show help

Web UI Service:
      --web-install          Install & enable the web UI as a systemd service
      --web-uninstall        Stop, disable & remove the web UI service
      --web-status           Show web UI service status
      --web-port <port>      Set web UI port (default: 8888)
```

---
## Wiki

https://github.com/fqazzazee/NetScan-WoL/wiki/NetScan%E2%80%90WoL-Wiki

---

## License

MIT

---

## Contributing

Contributions, issues, and feature requests are welcome. Feel free to open an issue or submit a pull request.
