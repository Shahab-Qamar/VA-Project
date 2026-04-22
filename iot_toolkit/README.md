# IoT Security Toolkit

**Ethical Penetration Testing Framework for IoT Devices**

> ⚠ **For authorized penetration testing only.**
> Use only on networks and devices you own or have explicit written permission to test.
> Unauthorized use may violate the Computer Fraud and Abuse Act (CFAA) and similar laws.

---

## Features

| Module | Description |
|--------|-------------|
| 1. Discovery | ARP scan (LAN) + WiFi beacon capture (proximity) |
| 2. OUI Lookup | MAC → Vendor + device classification (Camera / Router / Smart Home…) |
| 3. Port Scanner | Multi-threaded scan with banner grabbing & version detection |
| 4. Credential Tester | Telnet / SSH / HTTP default credential testing |
| 5. CVE Matcher | NVD API lookup with local cache + offline fallback DB |
| 6. Reporter | HTML dashboard + JSON export |
| Bonus | MQTT wildcard topic enumerator (unauthenticated broker detection) |

---

## Quick Start

```bash
# 1. Install dependencies
python setup.py

# 2. Run a basic network scan (requires sudo for ARP/raw sockets)
sudo python main.py --target 192.168.1.0/24

# 3. Full scan, HTML report only
sudo python main.py --target 192.168.1.0/24 --format html -v

# 4. Dry-run (no active credential attempts)
sudo python main.py --target 192.168.1.0/24 --dry-run

# 5. Proximity WiFi scan (monitor mode required)
sudo python main.py --mode proximity --interface wlan0mon

# 6. Scope-restricted scan
echo "192.168.1.50" > targets.txt
echo "192.168.1.51" >> targets.txt
sudo python main.py --scope targets.txt
```

---

## CLI Reference

```
usage: main.py [-h] [--mode {network,proximity,both}] [--target TARGET]
               [--interface INTERFACE] [--ports PORTS] [--creds CREDS]
               [--timeout TIMEOUT] [--threads THREADS] [--output OUTPUT]
               [--format {html,json,both}] [--skip-creds] [--skip-cve]
               [--dry-run] [--scope SCOPE] [--verbose]

Options:
  --mode          network | proximity | both  (default: network)
  --target        CIDR range or single IP (e.g. 192.168.1.0/24)
  --interface     Network interface (eth0, wlan0, wlan0mon)
  --ports         Comma-separated ports (default: common IoT ports)
  --creds         Path to credentials JSON (default: data/default_credentials.json)
  --timeout       Connection timeout in seconds (default: 3)
  --threads       Thread count (default: 20)
  --output        Report output directory (default: output/)
  --format        html | json | both (default: both)
  --skip-creds    Skip credential testing
  --skip-cve      Skip CVE lookup
  --dry-run       List what would be tested without sending credentials
  --scope         File with allowed IPs (one per line)
  -v / --verbose  Verbose logging
```

---

## Output

Reports are saved to `output/` by default:

```
output/
  iot_scan_20240115_143022.html   ← Interactive HTML dashboard
  iot_scan_20240115_143022.json   ← Machine-readable JSON export
```

The HTML report includes:
- Summary statistics (devices, risk levels, CVEs, weak credentials)
- Risk distribution bar chart
- Per-device collapsible cards with ports, banners, CVE table, credential findings

---

## Project Structure

```
iot_toolkit/
├── main.py                   ← Entry point & pipeline
├── setup.py                  ← Dependency installer
├── modules/
│   ├── discovery.py          ← Module 1: ARP + WiFi beacon
│   ├── oui.py                ← Module 2: MAC → vendor classification
│   ├── scanner.py            ← Module 3: Port scan + banner grab
│   ├── credentials.py        ← Module 4: Default cred testing
│   ├── cve.py                ← Module 5: NVD CVE matching
│   ├── reporter.py           ← Module 6: HTML + JSON reports
│   └── mqtt_enum.py          ← Bonus: MQTT topic enumeration
├── utils/
│   ├── logger.py             ← Coloured logger
│   └── banner.py             ← ASCII art banner
└── data/
    ├── default_credentials.json
    ├── oui_database.json     ← Downloaded by setup.py (optional)
    └── cve_cache/            ← NVD API response cache
```

---

## Dependencies

### Python packages
```bash
pip install paramiko        # SSH credential testing
pip install scapy           # Optional: advanced packet crafting
```

### System tools
```bash
sudo apt install arp-scan   # LAN device discovery
sudo apt install nmap       # Optional: OS fingerprinting
sudo apt install tshark     # WiFi beacon capture
```

### Monitor mode (for proximity scan)
```bash
sudo airmon-ng start wlan0  # Creates wlan0mon
sudo python main.py --mode proximity --interface wlan0mon
```

---

## Ethical Use Policy

This toolkit is designed for:
- Network administrators auditing their own infrastructure
- Penetration testers with written client authorization
- Security researchers in controlled lab environments
- Students learning IoT security concepts

**Always obtain written authorization before scanning any network or device.**
Log all testing activity for accountability. Report findings responsibly.

---

## Known IoT Ports Scanned

| Port  | Service       | Risk     | Notes |
|-------|---------------|----------|-------|
| 23    | Telnet        | CRITICAL | Cleartext credentials |
| 2323  | Telnet-alt    | CRITICAL | Common IoT default |
| 7547  | TR-069        | CRITICAL | ISP remote management |
| 554   | RTSP          | HIGH     | Live video stream |
| 1883  | MQTT          | HIGH     | Unauthenticated message broker |
| 5683  | CoAP          | HIGH     | Constrained IoT protocol |
| 1900  | UPnP/SSDP     | HIGH     | Universal Plug and Play |
| 22    | SSH           | LOW      | Secure shell |
| 80    | HTTP          | MEDIUM   | Web management panel |
| 443   | HTTPS         | LOW      | Encrypted web panel |
| 8080  | HTTP-alt      | MEDIUM   | Alternate web panel |

---

*IoT Security Toolkit v1.0 — Built for ethical security research*
