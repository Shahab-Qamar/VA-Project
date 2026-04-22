"""
SQLite scan history store for IoTGuard.

Every scan is serialized as JSON and keyed by scan_id. Lightweight denormalized
columns (subnet, started_at, device_count, finding_count, worst_risk) give us
fast list queries without having to parse the blob every time.

The diff helper compares two scans by (mac) or (ip) and reports:
    new_devices       - seen in 'current' but not 'previous'
    removed_devices   - seen in 'previous' but not 'current'
    changed_devices   - same key, but open ports / findings changed
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Optional

from .models import Device, ScanResult, RiskLevel, DeviceType, DiscoverySource, OpenPort, Finding, WifiNetwork, EncryptionType


DEFAULT_DB_PATH = Path.home() / ".iotguard" / "history.db"


# -- schema ------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id        TEXT PRIMARY KEY,
    started_at     TEXT NOT NULL,
    finished_at    TEXT,
    interface      TEXT,
    subnet         TEXT,
    lab_mode       INTEGER DEFAULT 0,
    demo_mode      INTEGER DEFAULT 0,
    device_count   INTEGER DEFAULT 0,
    wifi_count     INTEGER DEFAULT 0,
    finding_count  INTEGER DEFAULT 0,
    worst_risk     TEXT,
    payload        TEXT NOT NULL          -- full ScanResult as JSON
);

CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_subnet  ON scans(subnet);
"""


class HistoryDB:
    def __init__(self, path: Path | str | None = None):
        self.path = Path(path) if path else DEFAULT_DB_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # -- persistence ---------------------------------------------------------

    def save(self, scan: ScanResult) -> None:
        summary = scan.summary()
        worst = "Info"
        for level in ("Critical", "High", "Medium", "Low", "Info"):
            if summary["risk_counts"].get(level, 0) > 0:
                worst = level
                break
        self._conn.execute(
            """INSERT OR REPLACE INTO scans
               (scan_id, started_at, finished_at, interface, subnet,
                lab_mode, demo_mode, device_count, wifi_count, finding_count,
                worst_risk, payload)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (scan.scan_id, scan.started_at, scan.finished_at,
             scan.interface, scan.subnet,
             1 if scan.lab_mode else 0, 1 if scan.demo_mode else 0,
             summary["device_count"], summary["wifi_count"],
             summary["total_findings"], worst,
             scan.to_json()),
        )
        self._conn.commit()

    def delete(self, scan_id: str) -> None:
        self._conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        self._conn.commit()

    def list_scans(self, limit: int = 100) -> list[dict]:
        cur = self._conn.execute(
            """SELECT scan_id, started_at, finished_at, interface, subnet,
                      lab_mode, demo_mode, device_count, wifi_count,
                      finding_count, worst_risk
               FROM scans ORDER BY started_at DESC LIMIT ?""",
            (limit,),
        )
        return [dict(r) for r in cur.fetchall()]

    def load(self, scan_id: str) -> Optional[ScanResult]:
        cur = self._conn.execute(
            "SELECT payload FROM scans WHERE scan_id = ?", (scan_id,)
        )
        row = cur.fetchone()
        if not row:
            return None
        return _scan_from_dict(json.loads(row["payload"]))

    def latest(self, subnet: str | None = None) -> Optional[ScanResult]:
        if subnet:
            cur = self._conn.execute(
                "SELECT payload FROM scans WHERE subnet = ? "
                "ORDER BY started_at DESC LIMIT 1",
                (subnet,),
            )
        else:
            cur = self._conn.execute(
                "SELECT payload FROM scans ORDER BY started_at DESC LIMIT 1"
            )
        row = cur.fetchone()
        if not row:
            return None
        return _scan_from_dict(json.loads(row["payload"]))

    def close(self) -> None:
        self._conn.close()


# -- diff helper -------------------------------------------------------------

def diff_scans(previous: ScanResult, current: ScanResult) -> dict:
    """Compute a device/finding-level diff between two scans."""
    def key(d: Device) -> str:
        return (d.mac or d.ip or d.display_name).lower()

    prev_map = {key(d): d for d in previous.devices}
    curr_map = {key(d): d for d in current.devices}

    new_keys     = set(curr_map) - set(prev_map)
    removed_keys = set(prev_map) - set(curr_map)
    common_keys  = set(prev_map) & set(curr_map)

    changed = []
    for k in common_keys:
        p, c = prev_map[k], curr_map[k]
        p_ports = {(pp.port, pp.protocol) for pp in p.open_ports}
        c_ports = {(pp.port, pp.protocol) for pp in c.open_ports}
        p_finds = {f.title for f in p.findings}
        c_finds = {f.title for f in c.findings}
        if p_ports != c_ports or p_finds != c_finds:
            changed.append({
                "device": c.display_name,
                "ip": c.ip,
                "mac": c.mac,
                "new_ports":      sorted(c_ports - p_ports),
                "closed_ports":   sorted(p_ports - c_ports),
                "new_findings":   sorted(c_finds - p_finds),
                "resolved_findings": sorted(p_finds - c_finds),
            })

    return {
        "previous_scan_id": previous.scan_id,
        "current_scan_id":  current.scan_id,
        "new_devices":     [curr_map[k].display_name for k in new_keys],
        "removed_devices": [prev_map[k].display_name for k in removed_keys],
        "changed_devices": changed,
    }


# -- deserialization ---------------------------------------------------------
# ScanResult.to_dict() is lossy for enums; rebuild explicitly.

def _scan_from_dict(d: dict) -> ScanResult:
    scan = ScanResult(
        scan_id=d.get("scan_id", ""),
        started_at=d.get("started_at", ""),
        finished_at=d.get("finished_at", ""),
        interface=d.get("interface", ""),
        subnet=d.get("subnet", ""),
        lab_mode=d.get("lab_mode", False),
        demo_mode=d.get("demo_mode", False),
    )
    for wd in d.get("wifi_networks", []):
        w = WifiNetwork(
            ssid=wd.get("ssid", ""),
            bssid=wd.get("bssid", ""),
            channel=wd.get("channel", 0),
            frequency_mhz=wd.get("frequency_mhz", 0),
            signal_dbm=wd.get("signal_dbm", -100),
            encryption=EncryptionType(wd.get("encryption", "Unknown")),
            hidden=wd.get("hidden", False),
            rogue_suspected=wd.get("rogue_suspected", False),
            wps_enabled=wd.get("wps_enabled", False),
        )
        for fd in wd.get("findings", []):
            w.findings.append(_finding_from_dict(fd))
        scan.wifi_networks.append(w)

    for dd in d.get("devices", []):
        dev = Device(
            ip=dd.get("ip", ""),
            mac=dd.get("mac", ""),
            hostname=dd.get("hostname", ""),
            vendor=dd.get("vendor", ""),
            device_type=DeviceType(dd.get("device_type", "Unknown")),
            os_guess=dd.get("os_guess", ""),
            discovery_sources=[DiscoverySource(s) for s in dd.get("discovery_sources", [])],
            mdns_services=dd.get("mdns_services", []),
            upnp_model=dd.get("upnp_model", ""),
            upnp_manufacturer=dd.get("upnp_manufacturer", ""),
            ble_name=dd.get("ble_name", ""),
            ble_rssi=dd.get("ble_rssi", 0),
            last_seen=dd.get("last_seen", ""),
            services_banner=dd.get("services_banner", {}),
        )
        for pd in dd.get("open_ports", []):
            dev.open_ports.append(OpenPort(
                port=pd.get("port", 0),
                protocol=pd.get("protocol", "tcp"),
                service=pd.get("service", ""),
                product=pd.get("product", ""),
                version=pd.get("version", ""),
                banner=pd.get("banner", ""),
                state=pd.get("state", "open"),
            ))
        for fd in dd.get("findings", []):
            dev.findings.append(_finding_from_dict(fd))
        scan.devices.append(dev)
    return scan


def _finding_from_dict(fd: dict) -> Finding:
    return Finding(
        id=fd.get("id", ""),
        title=fd.get("title", ""),
        description=fd.get("description", ""),
        risk=RiskLevel(fd.get("risk", "Info")),
        cvss_score=fd.get("cvss_score", 0.0),
        cvss_vector=fd.get("cvss_vector", ""),
        cve_ids=fd.get("cve_ids", []),
        owasp_iot=fd.get("owasp_iot"),
        remediation=fd.get("remediation", ""),
        evidence=fd.get("evidence", ""),
        target=fd.get("target", ""),
    )
