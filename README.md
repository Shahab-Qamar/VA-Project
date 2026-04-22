# IoTGuard

WiFi and IoT vulnerability assessment tool with a PyQt6 dashboard, automated
risk scoring, and professional report export.

Built as a BS Cybersecurity semester project — Faculty of Computing, Riphah
International University.

## What it does

* Scans nearby **WiFi networks** (encryption, hidden SSIDs, rogue-AP heuristic, signal)
* Discovers **same-subnet devices** via ARP, mDNS/Bonjour, and SSDP/UPnP
* Scans **nearby Bluetooth / BLE peripherals** through the built-in adapter (auto-skipped if no adapter)
* Performs **port and service scanning** (nmap when available, pure-socket fallback)
* Optional **Lab Mode** — active default-credential testing for FTP, Telnet, SSH, and HTTP
* Enriches findings with the **NVD CVE database** (cached locally)
* Computes **CVSS 3.1 base scores** for every finding
* Maps each finding to the **OWASP IoT Top 10 (2018)** category
* Stores **scan history** in SQLite and shows device-level diffs between scans
* Exports **HTML, PDF, and JSON** reports
* Ships with a **demo mode** for reliable presentations (no lab gear required)

### Fing-style features

* **Device cards view** — visual grid with SVG icon per device type (camera, router, phone, TV, printer, NAS, etc.), risk-tinted borders, online/offline presence dot, gateway marker
* **Cards / Table toggle** — switch between visual cards and dense sortable table with one click
* **Search and filter** — filter devices by name, IP, MAC, vendor, type, or risk level
* **Custom names and notes** — rename any device ("Dad's Galaxy", "Kitchen Hue") and add free-form notes. Persists across scans via SQLite, keyed by MAC
* **First-seen / last-seen tracking** — the store remembers when each MAC first appeared on your network
* **Intruder alert banner** — red banner lights up when a new device joins between scans, listing names and IPs
* **Auto-rescan mode** — toolbar toggle runs discovery every 60s in the background, automatically catching phones connecting/disconnecting
* **Per-device actions** — ping, traceroute, Wake-on-LAN, open web UI, copy IP/MAC directly from the detail dialog
* **Right-click context menu** — quick rename, copy IP/MAC, open details from any card or row

### Network Health tab

* **Public IP, ISP, and location** via ip-api.com (free, no key)
* **Gateway IP, local IP, DNS servers** detected from the system
* **Internet latency** probed against Cloudflare (1.1.1.1) and Google (8.8.8.8)
* **Shodan internet-exposure check** — scans your public IP against the Shodan index to flag externally-visible open ports and known CVEs on your router (requires free API key)
* **DNS hijack detection** — compares your router's DNS answers against Cloudflare for 5 high-signal domains; mismatches indicate a compromised router

## Screens

The GUI has seven tabs:

| Tab            | Shows                                                                 |
| -------------- | --------------------------------------------------------------------- |
| Dashboard      | Risk-distribution bar, device-type donut, top-5 CVSS bar              |
| Devices        | **Fing-style card grid (default)** or sortable table — switch with toggle. Icons, risk badges, presence dots, right-click menu, double-click for detail |
| WiFi           | Nearby SSIDs with encryption and findings                             |
| Findings       | Flat, sortable list of every finding across the scan                  |
| Network Health | Public IP / ISP / gateway / DNS / latency + Shodan exposure + DNS hijack check |
| History        | Every stored scan, plus a diff view against the currently-loaded scan |
| Log            | Live scan progress + debug output                                     |

An **intruder alert banner** appears at the top whenever a new MAC is detected between scans.

## Install (Kali / Ubuntu / Debian)

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip nmap network-manager bluez avahi-daemon

# optional, for reverse DNS + raw-socket scanning without sudo:
sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$(which python3)")"

git clone <your repo url> iotguard
cd iotguard
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
# GUI
python3 main.py

# GUI pre-toggled into demo mode (safe, no network access)
python3 main.py --demo

# Terminal demo — also writes demo.html / demo.pdf to ~/IoTGuard-reports/
python3 main.py --cli-demo
```

If you get a Qt platform plugin error, install the Qt XCB dependency:

```bash
sudo apt install -y libxcb-cursor0
```

## Permissions

A few features need elevated privileges. Nothing in the main scan path
*requires* root, but you lose fidelity without it:

| Feature                              | Works without root?                  |
| ------------------------------------ | ------------------------------------ |
| WiFi scan via `nmcli`                | Yes                                  |
| mDNS / SSDP discovery                | Yes                                  |
| Active ARP sweep via scapy           | Needs `CAP_NET_RAW` or `sudo`        |
| Passive ARP via `/proc/net/arp`      | Yes (but only sees hosts you've talked to) |
| `nmap -sV` service detection         | Yes, but `sudo` unlocks more probes  |
| BLE scan via `bleak`                 | Yes on most distros                  |
| Classic Bluetooth via `bluetoothctl` | Yes                                  |

The recommended setup is the `setcap` line above — it gives Python the
right capabilities without running the GUI as root.

## Lab Mode safety

Lab Mode performs **active** checks: it attempts to log in to discovered
services using a small list of well-known default credentials (admin/admin,
root/root, etc.). This is intentionally noisy and can trip intrusion-detection
or lock out accounts. IoTGuard will not enable Lab Mode without an explicit
consent dialog each session.

> Only run Lab Mode against devices you own or have written authorization to
> test.

## Shodan setup (optional)

The Network Health tab's internet-exposure check uses Shodan. To enable it:

1. Sign up for a free account at [account.shodan.io](https://account.shodan.io/)
2. Copy your API key from the dashboard
3. Open IoTGuard → Settings → Integrations → paste key → OK
4. On the Network Health tab, click **Run Shodan exposure check**

Without a key, the panel shows an onboarding message explaining how to get one. All other features work without Shodan.

## Project layout

```
iotguard/
├── main.py                       # entry point
├── requirements.txt
├── iotguard/
│   ├── core/
│   │   ├── models.py             # dataclasses + enums (with Fing fields)
│   │   ├── risk_scoring.py       # CVSS 3.1 calculator + IoT presets
│   │   ├── owasp_mapping.py      # OWASP IoT Top 10 catalog
│   │   ├── database.py           # SQLite scan history + diff
│   │   └── device_store.py       # per-MAC persistent metadata
│   ├── intel/
│   │   ├── oui_lookup.py         # MAC → vendor + randomized-MAC detection
│   │   ├── cve_lookup.py         # NVD 2.0 API client w/ cache
│   │   ├── shodan_client.py      # Shodan host API w/ cache
│   │   ├── network_health.py     # public IP / ISP / DNS / latency
│   │   └── dns_hijack.py         # raw-UDP DNS integrity check
│   ├── scanners/
│   │   ├── wifi_scanner.py       # nmcli-based WiFi scan
│   │   ├── network_scanner.py    # ARP + mDNS + SSDP discovery
│   │   ├── bluetooth_scanner.py  # BLE + classic + adapter detection
│   │   ├── port_scanner.py       # nmap + socket fallback + findings
│   │   ├── cred_tester.py        # Lab-mode active cred testing
│   │   ├── device_actions.py     # ping / traceroute / WoL
│   │   └── demo_scanner.py       # deterministic simulated scan
│   ├── reporting/
│   │   ├── html_report.py        # single-file HTML report
│   │   └── pdf_report.py         # ReportLab PDF report
│   ├── gui/
│   │   ├── main_window.py        # main window + tabs + intruder alert
│   │   ├── scan_worker.py        # QThread orchestrator
│   │   ├── widgets/
│   │   │   ├── charts.py         # matplotlib dashboard
│   │   │   ├── device_icons.py   # SVG icon factory
│   │   │   ├── device_cards.py   # Fing-style card grid
│   │   │   ├── network_health.py # network-health tab
│   │   │   └── history_view.py   # history list + diff panel
│   │   └── dialogs/
│   │       ├── settings.py       # scan opts + UI + integrations
│   │       ├── consent.py        # Lab Mode consent gate
│   │       └── device_detail.py  # detail + rename/notes + actions
│   └── resources/
│       └── data/default_creds.json
└── tests/
```

## Data storage

IoTGuard stores:

* `~/.iotguard/config.json` — settings + UI prefs + Shodan API key
* `~/.iotguard/history.db` — scan history (SQLite)
* `~/.iotguard/devices.db` — per-MAC metadata (custom names, notes, first-seen)
* `~/.iotguard/cve_cache.db` — CVE API cache (14-day TTL)
* `~/.iotguard/shodan_cache.db` — Shodan host cache (6-hour TTL)
* `~/IoTGuard-reports/` — default export folder for PDF/HTML/JSON

Delete the directory to reset everything.

## Team

Muhammad Shahab Qamar — SAP 54604
Asim Khurshid — SAP 53653
BS Cybersecurity 6-1 · Faculty of Computing · Riphah International University
Supervisor: Mr Yawar Abbas

## License

For academic use within Riphah International University. See LICENSE if
adding a redistribution license.
