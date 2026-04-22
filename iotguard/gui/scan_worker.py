"""
Background scan orchestrator — improved with multi-technique discovery.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

from PyQt6.QtCore import QThread, pyqtSignal

from ..core.models import ScanResult, Device, DiscoverySource
from ..scanners.network_scanner import (
    nmap_host_sweep, arp_discover, icmp_sweep, netbios_scan,
    mdns_discover, ssdp_discover, passive_sniff,
    merge_devices, detect_local_subnet,
)
from ..scanners.wifi_scanner import WifiScanner
from ..scanners.bluetooth_scanner import bluetooth_proximity_scan
from ..scanners.port_scanner import scan_devices as port_scan_devices
from ..scanners.cred_tester import test_device_credentials
from ..scanners.demo_scanner import build_demo_scan
from ..intel.cve_lookup import CVELookup
from ..intel.oui_lookup import lookup_vendor

log = logging.getLogger(__name__)


@dataclass
class ScanOptions:
    interface: str = ""
    subnet: str = ""
    scan_wifi: bool = True
    scan_network: bool = True
    scan_bluetooth: bool = True
    scan_ports: bool = True
    enrich_cves: bool = True
    lab_mode: bool = False
    demo_mode: bool = False
    port_parallelism: int = 8
    port_timeout: float = 1.0
    mdns_duration: float = 4.0
    ssdp_duration: float = 3.0
    ble_duration: float = 6.0
    include_classic_bt: bool = True
    # New options
    use_nmap_sweep: bool = True       # nmap -sn host discovery
    deep_port_scan: bool = True       # -sS -sV -O vs -sT
    run_vuln_scripts: bool = True     # --script=vuln,auth
    passive_sniff: bool = True        # passive wire sniffer
    passive_duration: float = 5.0    # seconds of passive sniff


class ScanWorker(QThread):
    progress = pyqtSignal(int, str)
    log      = pyqtSignal(str)
    finished_scan = pyqtSignal(object)
    failed   = pyqtSignal(str)

    def __init__(self, options: ScanOptions, parent=None):
        super().__init__(parent)
        self.options = options
        self._cancel = False

    def cancel(self) -> None:
        self._cancel = True

    def run(self) -> None:
        try:
            self._run_inner()
        except Exception as e:
            log.exception("Scan worker failed")
            self.failed.emit(f"{type(e).__name__}: {e}")

    def _run_inner(self) -> None:
        opts = self.options

        if opts.demo_mode:
            self._emit(2, "Building simulated scan…", also_log=True)
            scan = build_demo_scan(interface=opts.interface or "wlan0",
                                   subnet=opts.subnet or "192.168.50.0/24")
            for pct, stage in [(25, "Simulating WiFi scan"),
                               (50, "Simulating device discovery"),
                               (75, "Simulating vulnerability checks"),
                               (95, "Compiling demo report")]:
                if self._cancel:
                    break
                self._emit(pct, stage)
                self.msleep(250)
            self._emit(100, "Demo scan complete", also_log=True)
            scan.finished_at = datetime.now(timezone.utc).isoformat()
            self.finished_scan.emit(scan)
            return

        # Determine interface + subnet
        iface = opts.interface
        subnet = opts.subnet
        if not iface or not subnet:
            det_iface, det_subnet = detect_local_subnet(iface)
            iface = iface or det_iface
            subnet = subnet or det_subnet

        scan = ScanResult(interface=iface, subnet=subnet,
                          lab_mode=opts.lab_mode, demo_mode=False)
        self.log.emit(f"Starting scan on {iface} ({subnet})  "
                      f"lab={opts.lab_mode} nmap={opts.use_nmap_sweep} "
                      f"vuln_scripts={opts.run_vuln_scripts}")

        # Stage budget: 8 possible stages, each gets ~11%
        progress = 2

        # ── 1. WiFi ─────────────────────────────────────────────────────────
        if opts.scan_wifi and not self._cancel:
            self._emit(progress, "Scanning WiFi networks (nmcli)…")
            wifi = WifiScanner(interface=iface).scan()
            scan.wifi_networks = wifi
            self.log.emit(f"  WiFi: {len(wifi)} networks")
            progress += 8; self._emit(progress, "WiFi scan done", also_log=True)

        # ── 2a. nmap host sweep ──────────────────────────────────────────────
        all_device_lists = []
        if opts.scan_network and opts.use_nmap_sweep and not self._cancel:
            self._emit(progress, f"nmap host sweep on {subnet}…")
            nmap_devices = nmap_host_sweep(subnet)
            all_device_lists.append(nmap_devices)
            self.log.emit(f"  nmap sweep: {len(nmap_devices)} hosts")

        # ── 2b. ARP sweep ────────────────────────────────────────────────────
        if opts.scan_network and not self._cancel:
            self._emit(progress + 2, "ARP sweep…")
            arp_devices = arp_discover(subnet)
            all_device_lists.append(arp_devices)
            self.log.emit(f"  ARP: {len(arp_devices)} devices")

        # ── 2c. ICMP sweep ───────────────────────────────────────────────────
        if opts.scan_network and not self._cancel:
            self._emit(progress + 3, "ICMP ping sweep…")
            icmp_devices = icmp_sweep(subnet)
            all_device_lists.append(icmp_devices)
            self.log.emit(f"  ICMP: {len(icmp_devices)} hosts")

        # ── 2d. NetBIOS scan ─────────────────────────────────────────────────
        if opts.scan_network and not self._cancel:
            self._emit(progress + 4, "NetBIOS/NBT-NS scan…")
            nb_devices = netbios_scan(subnet)
            all_device_lists.append(nb_devices)
            self.log.emit(f"  NetBIOS: {len(nb_devices)} devices")

        # ── 2e. mDNS ─────────────────────────────────────────────────────────
        if opts.scan_network and not self._cancel:
            self._emit(progress + 5, "mDNS / Bonjour discovery…")
            mdns_devices = mdns_discover(opts.mdns_duration)
            all_device_lists.append(mdns_devices)
            self.log.emit(f"  mDNS: {len(mdns_devices)} records")

        # ── 2f. SSDP ─────────────────────────────────────────────────────────
        if opts.scan_network and not self._cancel:
            self._emit(progress + 6, "SSDP / UPnP discovery…")
            ssdp_devices = ssdp_discover(opts.ssdp_duration)
            all_device_lists.append(ssdp_devices)
            self.log.emit(f"  SSDP: {len(ssdp_devices)} responders")

        # ── 2g. Passive sniff ────────────────────────────────────────────────
        if opts.scan_network and opts.passive_sniff and not self._cancel:
            self._emit(progress + 7, f"Passive wire sniff ({opts.passive_duration:.0f}s)…")
            sniff_devices = passive_sniff(opts.passive_duration, iface)
            all_device_lists.append(sniff_devices)
            self.log.emit(f"  Passive sniff: {len(sniff_devices)} hosts")

        if opts.scan_network:
            progress += 15; self._emit(progress, "Device discovery done", also_log=True)

        # ── 3. Bluetooth ─────────────────────────────────────────────────────
        ble_devices: list[Device] = []
        if opts.scan_bluetooth and not self._cancel:
            from ..scanners.bluetooth_scanner import has_bluetooth_adapter
            available, reason = has_bluetooth_adapter()
            if not available:
                self.log.emit(f"  Bluetooth: skipped ({reason})")
            else:
                self._emit(progress, f"Bluetooth/BLE scan ({opts.ble_duration:.0f}s)…")
                ble_devices = bluetooth_proximity_scan(
                    ble_duration=opts.ble_duration,
                    classic_duration=opts.ble_duration,
                    include_classic=opts.include_classic_bt,
                )
                self.log.emit(f"  Bluetooth: {len(ble_devices)} peripherals")
            progress += 8; self._emit(progress, "Bluetooth done", also_log=True)

        all_device_lists.append(ble_devices)

        # Merge all sources
        scan.devices = merge_devices(*all_device_lists)
        total_found = len(scan.devices)
        self.log.emit(f"  Merged: {total_found} unique devices across all sources")

        # ── 4. Port scan ──────────────────────────────────────────────────────
        routable = [d for d in scan.devices if d.ip]
        if opts.scan_ports and routable and not self._cancel:
            self._emit(progress, f"Port scanning {len(routable)} devices…")

            def _pcb(done, total, host):
                if self._cancel: return
                pct = progress + int((done / max(total, 1)) * 20)
                self._emit(min(pct, progress + 20),
                           f"Port scan {done}/{total}: {host}")

            port_scan_devices(
                routable,
                parallelism=opts.port_parallelism,
                timeout=opts.port_timeout,
                deep_scan=opts.deep_port_scan,
                run_vuln_scripts=opts.run_vuln_scripts,
                progress_cb=_pcb,
            )
            progress += 22; self._emit(progress, "Port scan done", also_log=True)

        # ── 5. Lab mode cred testing ──────────────────────────────────────────
        if opts.lab_mode and routable and not self._cancel:
            self._emit(progress, "Lab Mode: testing default credentials…")
            for i, d in enumerate(routable, 1):
                if self._cancel: break
                test_device_credentials(d, enabled=True)
                if i % 2 == 0:
                    self._emit(progress, f"Cred test {i}/{len(routable)}: {d.ip}")
            progress += 10; self._emit(progress, "Credential tests done", also_log=True)

        # ── 6. CVE enrichment ─────────────────────────────────────────────────
        if opts.enrich_cves and not self._cancel:
            self._emit(progress, "Enriching with CVE data (NVD)…")
            self._enrich_cves(scan.devices)
            progress += 8; self._emit(progress, "CVE enrichment done", also_log=True)

        scan.finished_at = datetime.now(timezone.utc).isoformat()
        total_findings = sum(len(d.findings) for d in scan.devices)
        self.log.emit(f"Scan complete: {total_found} devices, {total_findings} findings")
        self._emit(100, "Scan complete", also_log=True)
        self.finished_scan.emit(scan)

    def _emit(self, pct: int, stage: str, also_log: bool = False) -> None:
        self.progress.emit(max(0, min(100, pct)), stage)
        if also_log:
            self.log.emit(f"[{pct:3d}%] {stage}")

    def _enrich_cves(self, devices: Iterable[Device]) -> None:
        cve = CVELookup()
        try:
            for d in devices:
                if self._cancel:
                    break
                keywords = set()
                if d.vendor:
                    keywords.add(d.vendor.split()[0].lower())
                for op in d.open_ports:
                    if op.product:
                        kw = f"{op.product} {op.version}".strip().lower()
                        if kw:
                            keywords.add(kw)
                for kw in list(keywords)[:4]:
                    matches = cve.query(kw, max_results=3)
                    if not matches:
                        continue
                    top = matches[0]
                    cve_id = top.get("id", "")
                    cve_score = float(top.get("score", 0.0))
                    if d.findings:
                        target_f = max(d.findings, key=lambda f: f.risk.order)
                        if cve_id and cve_id not in target_f.cve_ids:
                            target_f.cve_ids.append(cve_id)
                    self.log.emit(f"  CVE: {d.display_name} ← {cve_id} ({cve_score})")
        finally:
            cve.close()
