#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          IoT Security Toolkit  - Ethical Pentest Framework   ║
║          For authorized penetration testing only             ║
╚══════════════════════════════════════════════════════════════╝
"""

import argparse
import sys
import os
import json
import time
from datetime import datetime
from modules.discovery    import DeviceDiscovery
from modules.oui          import OUILookup
from modules.scanner      import PortScanner
from modules.credentials  import CredentialTester
from modules.cve          import CVEMatcher
from modules.reporter     import ReportGenerator
from utils.logger         import Logger
from utils.banner         import print_banner

# ── Colour helpers ─────────────────────────────────────────────
R  = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
B  = "\033[94m"; C = "\033[96m"; W = "\033[97m"; X = "\033[0m"

def confirm_authorization() -> bool:
    """Explicit authorization gate — required before any active scan."""
    print(f"\n{R}{'═'*60}")
    print(f"  ⚠  AUTHORIZATION REQUIRED")
    print(f"{'═'*60}{X}")
    print(f"{Y}  This toolkit performs active network reconnaissance.")
    print(f"  Use ONLY on networks/devices you own or have explicit")
    print(f"  written permission to test.")
    print(f"  Unauthorized use may violate computer crime laws.{X}\n")
    ans = input(f"  Do you have authorization to scan the target? [yes/no]: ").strip().lower()
    return ans == "yes"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="IoT Security Toolkit — Ethical Penetration Testing Framework",
        formatter_class=argparse.RawTextHelpFormatter
    )
    p.add_argument("--mode", choices=["network","proximity","both"], default="network",
                   help="Discovery mode:\n  network   = ARP scan on local LAN\n  proximity = WiFi beacon capture\n  both      = run both modes")
    p.add_argument("--target",  default=None,
                   help="Target network CIDR (e.g. 192.168.1.0/24) or single IP")
    p.add_argument("--interface", default=None,
                   help="Network interface (e.g. eth0, wlan0)")
    p.add_argument("--ports",   default="22,23,80,443,554,1883,5683,8080,8443",
                   help="Comma-separated ports to scan (default: common IoT ports)")
    p.add_argument("--creds",   default="data/default_credentials.json",
                   help="Path to credentials JSON file")
    p.add_argument("--timeout", type=int, default=3,
                   help="Connection timeout in seconds (default: 3)")
    p.add_argument("--threads", type=int, default=20,
                   help="Thread count for scanning (default: 20)")
    p.add_argument("--output",  default="output",
                   help="Output directory for reports")
    p.add_argument("--format",  choices=["html","json","both"], default="both",
                   help="Report output format")
    p.add_argument("--skip-creds",  action="store_true", help="Skip credential testing")
    p.add_argument("--skip-cve",    action="store_true", help="Skip CVE lookup")
    p.add_argument("--dry-run",     action="store_true",
                   help="Show what would be tested without sending any credentials")
    p.add_argument("--scope",       default=None,
                   help="Restrict scanning to IP list file (one IP per line)")
    p.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    return p


def load_scope(path: str) -> list:
    """Load allowed IPs from scope file."""
    if not os.path.exists(path):
        print(f"{R}[!] Scope file not found: {path}{X}")
        sys.exit(1)
    with open(path) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def run(args) -> dict:
    log = Logger(verbose=args.verbose)
    os.makedirs(args.output, exist_ok=True)

    scope_ips = None
    if args.scope:
        scope_ips = load_scope(args.scope)
        log.info(f"Scope restricted to {len(scope_ips)} IP(s)")

    # ── 1. Device Discovery ────────────────────────────────────
    log.section("Phase 1 — Device Discovery")
    discovery = DeviceDiscovery(interface=args.interface, timeout=args.timeout, log=log)

    raw_devices = []
    if args.mode in ("network", "both"):
        target = args.target or discovery.detect_local_network()
        log.info(f"ARP scanning: {target}")
        raw_devices += discovery.arp_scan(target)
    if args.mode in ("proximity", "both"):
        log.info("Starting WiFi beacon capture (Ctrl+C to stop)…")
        raw_devices += discovery.proximity_scan(interface=args.interface)

    if scope_ips:
        raw_devices = [d for d in raw_devices if d["ip"] in scope_ips]

    if not raw_devices:
        log.warn("No devices discovered. Exiting.")
        return {}

    log.success(f"Discovered {len(raw_devices)} device(s)")

    # ── Build central device model ─────────────────────────────
    devices = {}
    for d in raw_devices:
        devices[d["ip"]] = {
            "ip":           d["ip"],
            "mac":          d.get("mac", "unknown"),
            "hostname":     d.get("hostname", ""),
            "vendor":       "",
            "device_class": "",
            "open_ports":   {},
            "services":     {},
            "credentials":  [],
            "cves":         [],
            "risk_score":   0,
            "scan_time":    datetime.now().isoformat(),
        }

    # ── 2. OUI Manufacturer Lookup ────────────────────────────
    log.section("Phase 2 — OUI Manufacturer Identification")
    oui = OUILookup(db_path="data/oui_database.json", log=log)
    for ip, dev in devices.items():
        vendor, dev_class = oui.lookup(dev["mac"])
        dev["vendor"]       = vendor
        dev["device_class"] = dev_class
        log.info(f"  {ip} ({dev['mac']}) → {vendor} [{dev_class}]")

    # ── 3. Port & Service Scan ────────────────────────────────
    log.section("Phase 3 — Port & Service Scanning")
    ports = [int(p) for p in args.ports.split(",")]
    scanner = PortScanner(timeout=args.timeout, threads=args.threads, log=log)
    for ip, dev in devices.items():
        results = scanner.scan(ip, ports)
        dev["open_ports"] = results["open_ports"]
        dev["services"]   = results["services"]
        log.info(f"  {ip} — {len(dev['open_ports'])} open port(s): {list(dev['open_ports'].keys())}")

    # ── 4. Default Credential Testing ─────────────────────────
    if not args.skip_creds:
        log.section("Phase 4 — Default Credential Testing")
        if args.dry_run:
            log.warn("DRY RUN — credential tests will be listed but NOT executed")
        tester = CredentialTester(
            creds_path=args.creds,
            timeout=args.timeout,
            dry_run=args.dry_run,
            log=log
        )
        for ip, dev in devices.items():
            findings = tester.test(ip, dev["open_ports"], dev["services"])
            dev["credentials"] = findings
            if findings:
                log.warn(f"  {ip} — {len(findings)} default credential(s) found!")
    else:
        log.info("Credential testing skipped (--skip-creds)")

    # ── 5. CVE Matching ───────────────────────────────────────
    if not args.skip_cve:
        log.section("Phase 5 — CVE Vulnerability Matching")
        cve = CVEMatcher(cache_dir="data/cve_cache", log=log)
        for ip, dev in devices.items():
            vulns = cve.match(dev["vendor"], dev["device_class"], dev["services"])
            dev["cves"] = vulns
            if vulns:
                log.warn(f"  {ip} — {len(vulns)} CVE(s) matched")
    else:
        log.info("CVE matching skipped (--skip-cve)")

    # ── Risk Scoring ──────────────────────────────────────────
    for ip, dev in devices.items():
        score = 0
        score += len(dev["open_ports"]) * 5
        score += len(dev["credentials"]) * 30
        critical = sum(1 for c in dev["cves"] if c.get("severity","").upper() == "CRITICAL")
        high     = sum(1 for c in dev["cves"] if c.get("severity","").upper() == "HIGH")
        score += critical * 25 + high * 15
        if 23 in dev["open_ports"]:  score += 20   # Telnet penalty
        dev["risk_score"] = min(score, 100)

    # ── 6. Report Generation ──────────────────────────────────
    log.section("Phase 6 — Report Generation")
    reporter = ReportGenerator(output_dir=args.output, log=log)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if args.format in ("html", "both"):
        html_path = reporter.html(devices, timestamp)
        log.success(f"HTML report → {html_path}")
    if args.format in ("json", "both"):
        json_path = reporter.json_export(devices, timestamp)
        log.success(f"JSON export → {json_path}")

    # ── Summary ───────────────────────────────────────────────
    log.section("Scan Summary")
    total_vulns = sum(len(d["cves"]) for d in devices.values())
    total_creds = sum(len(d["credentials"]) for d in devices.values())
    critical_devs = [ip for ip, d in devices.items() if d["risk_score"] >= 70]
    print(f"  Devices scanned  : {G}{len(devices)}{X}")
    print(f"  Default creds    : {R if total_creds else G}{total_creds}{X}")
    print(f"  CVEs matched     : {R if total_vulns else G}{total_vulns}{X}")
    print(f"  Critical devices : {R if critical_devs else G}{len(critical_devs)}{X}")

    return devices


def main():
    print_banner()
    parser = build_parser()
    args   = parser.parse_args()

    if not confirm_authorization():
        print(f"\n{R}[!] Authorization not confirmed. Aborting.{X}\n")
        sys.exit(0)

    try:
        run(args)
    except KeyboardInterrupt:
        print(f"\n{Y}[!] Scan interrupted by user.{X}")
    except PermissionError:
        print(f"\n{R}[!] Permission denied. Try running with sudo for raw socket access.{X}")
        sys.exit(1)


if __name__ == "__main__":
    main()
