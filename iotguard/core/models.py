"""
Core data models for IoTGuard.

All scanner and reporting modules exchange these dataclasses. Keeping them
here (and keeping them pure Python with no Qt / SQL imports) lets the GUI,
DB, and report layers all depend on the same shapes without circular imports.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Optional
import json
import uuid


# -- enums -------------------------------------------------------------------

class RiskLevel(str, Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    @property
    def color(self) -> str:
        return {
            "Info": "#6b7280",
            "Low": "#10b981",
            "Medium": "#f59e0b",
            "High": "#ef4444",
            "Critical": "#991b1b",
        }[self.value]

    @property
    def order(self) -> int:
        return ["Info", "Low", "Medium", "High", "Critical"].index(self.value)


class DeviceType(str, Enum):
    ROUTER = "Router / Gateway"
    CAMERA = "IP Camera"
    SMART_TV = "Smart TV"
    SMART_SPEAKER = "Smart Speaker"
    SMART_BULB = "Smart Bulb"
    SMART_PLUG = "Smart Plug"
    THERMOSTAT = "Thermostat"
    PRINTER = "Printer"
    NAS = "NAS / Storage"
    PHONE = "Phone / Tablet"
    COMPUTER = "Computer"
    WEARABLE = "Wearable"
    BLE_PERIPHERAL = "BLE Peripheral"
    IOT_GENERIC = "Generic IoT"
    UNKNOWN = "Unknown"


class EncryptionType(str, Enum):
    OPEN = "Open"
    WEP = "WEP"
    WPA = "WPA"
    WPA2 = "WPA2"
    WPA2_WPA3 = "WPA2/WPA3"
    WPA3 = "WPA3"
    UNKNOWN = "Unknown"

    @property
    def is_weak(self) -> bool:
        return self in (EncryptionType.OPEN, EncryptionType.WEP, EncryptionType.WPA)


class DiscoverySource(str, Enum):
    ARP = "ARP"
    MDNS = "mDNS"
    SSDP = "SSDP/UPnP"
    BLE = "BLE"
    BLUETOOTH = "Bluetooth"
    WIFI_BEACON = "WiFi Beacon"
    NMAP = "Nmap"
    DEMO = "Demo"


# -- core records -------------------------------------------------------------

@dataclass
class OpenPort:
    port: int
    protocol: str = "tcp"                   # tcp / udp
    service: str = ""                       # e.g. http, telnet
    product: str = ""                       # e.g. "OpenSSH"
    version: str = ""
    banner: str = ""
    state: str = "open"


@dataclass
class Finding:
    """A single security finding tied to a device or network."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str = ""
    description: str = ""
    risk: RiskLevel = RiskLevel.INFO
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cve_ids: list[str] = field(default_factory=list)
    owasp_iot: Optional[str] = None         # e.g. "I1 - Weak Passwords"
    remediation: str = ""
    evidence: str = ""                      # banner, credential used, etc.
    target: str = ""                        # IP / MAC / SSID

    def to_dict(self) -> dict:
        d = asdict(self)
        d["risk"] = self.risk.value
        return d


@dataclass
class WifiNetwork:
    ssid: str
    bssid: str = ""
    channel: int = 0
    frequency_mhz: int = 0
    signal_dbm: int = -100
    encryption: EncryptionType = EncryptionType.UNKNOWN
    hidden: bool = False
    rogue_suspected: bool = False
    wps_enabled: bool = False
    findings: list[Finding] = field(default_factory=list)

    @property
    def signal_quality(self) -> str:
        if self.signal_dbm >= -50: return "Excellent"
        if self.signal_dbm >= -60: return "Good"
        if self.signal_dbm >= -70: return "Fair"
        return "Weak"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["encryption"] = self.encryption.value
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


@dataclass
class Device:
    ip: str = ""
    mac: str = ""
    hostname: str = ""
    vendor: str = ""                        # from OUI lookup
    device_type: DeviceType = DeviceType.UNKNOWN
    os_guess: str = ""
    discovery_sources: list[DiscoverySource] = field(default_factory=list)
    open_ports: list[OpenPort] = field(default_factory=list)
    services_banner: dict[str, str] = field(default_factory=dict)
    mdns_services: list[str] = field(default_factory=list)
    upnp_model: str = ""
    upnp_manufacturer: str = ""
    ble_name: str = ""
    ble_rssi: int = 0
    last_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    findings: list[Finding] = field(default_factory=list)
    # Fing-style additions
    custom_name: str = ""                   # user-assigned label (persisted)
    notes: str = ""                         # free-form notes (persisted)
    first_seen: str = ""                    # earliest time seen (persisted)
    online: bool = True                     # present in most recent scan
    is_gateway: bool = False

    @property
    def display_name(self) -> str:
        return (self.custom_name or self.hostname or self.ble_name
                or self.upnp_model or self.ip or self.mac or "unknown")

    @property
    def highest_risk(self) -> RiskLevel:
        if not self.findings:
            return RiskLevel.INFO
        return max(self.findings, key=lambda f: f.risk.order).risk

    @property
    def risk_score(self) -> float:
        """Worst CVSS among findings."""
        if not self.findings:
            return 0.0
        return max(f.cvss_score for f in self.findings)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["device_type"] = self.device_type.value
        d["discovery_sources"] = [s.value for s in self.discovery_sources]
        d["open_ports"] = [asdict(p) for p in self.open_ports]
        d["findings"] = [f.to_dict() for f in self.findings]
        d["highest_risk"] = self.highest_risk.value
        d["risk_score"] = self.risk_score
        return d


@dataclass
class ScanResult:
    """Top-level container for a single scan run."""
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    finished_at: str = ""
    interface: str = ""
    subnet: str = ""
    lab_mode: bool = False
    demo_mode: bool = False
    devices: list[Device] = field(default_factory=list)
    wifi_networks: list[WifiNetwork] = field(default_factory=list)

    def summary(self) -> dict:
        counts = {r.value: 0 for r in RiskLevel}
        for d in self.devices:
            counts[d.highest_risk.value] += 1
        for w in self.wifi_networks:
            if w.findings:
                worst = max(w.findings, key=lambda f: f.risk.order).risk
                counts[worst.value] += 1
        return {
            "device_count": len(self.devices),
            "wifi_count": len(self.wifi_networks),
            "risk_counts": counts,
            "total_findings": sum(len(d.findings) for d in self.devices)
                              + sum(len(w.findings) for w in self.wifi_networks),
        }

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "interface": self.interface,
            "subnet": self.subnet,
            "lab_mode": self.lab_mode,
            "demo_mode": self.demo_mode,
            "devices": [d.to_dict() for d in self.devices],
            "wifi_networks": [w.to_dict() for w in self.wifi_networks],
            "summary": self.summary(),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)
