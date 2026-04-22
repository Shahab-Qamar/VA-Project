"""
Demo / simulated scan mode.

Returns a deterministic, realistic-looking ScanResult containing a mix of
device types at each risk level, so you can demo the GUI and reports
without needing actual lab gear powered on.

Toggled via Settings → "Demo mode (simulated devices)".
"""

from __future__ import annotations

import random
from datetime import datetime, timezone

from ..core.models import (
    Device, DeviceType, DiscoverySource, Finding, OpenPort,
    RiskLevel, ScanResult, WifiNetwork, EncryptionType,
)
from ..core.owasp_mapping import get_owasp
from ..core.risk_scoring import score_preset


def _finding(preset: str, title: str, description: str,
             remediation: str, target: str, evidence: str = "",
             cve_ids: list[str] | None = None) -> Finding:
    score, vector, risk = score_preset(preset)
    return Finding(
        title=title, description=description,
        remediation=remediation,
        risk=risk, cvss_score=score, cvss_vector=vector,
        owasp_iot=get_owasp(preset),
        target=target, evidence=evidence,
        cve_ids=cve_ids or [],
    )


def build_demo_scan(interface: str = "wlan0",
                    subnet: str = "192.168.50.0/24",
                    seed: int = 42) -> ScanResult:
    """Return a fully-populated simulated ScanResult."""
    rng = random.Random(seed)
    scan = ScanResult(
        interface=interface, subnet=subnet,
        lab_mode=True, demo_mode=True,
    )

    # -- WiFi networks -------------------------------------------------------
    nets = [
        WifiNetwork(ssid="HomeNet_5G", bssid="AC:84:C6:11:22:33", channel=36,
                    frequency_mhz=5180, signal_dbm=-48,
                    encryption=EncryptionType.WPA3),
        WifiNetwork(ssid="OfficeGuest", bssid="EC:08:6B:44:55:66", channel=6,
                    frequency_mhz=2437, signal_dbm=-62,
                    encryption=EncryptionType.OPEN),
        WifiNetwork(ssid="CafeWiFi",    bssid="F0:F6:1C:AA:BB:CC", channel=11,
                    frequency_mhz=2462, signal_dbm=-71,
                    encryption=EncryptionType.WEP),
        WifiNetwork(ssid="",            bssid="50:C7:BF:77:88:99", channel=1,
                    frequency_mhz=2412, signal_dbm=-78,
                    encryption=EncryptionType.WPA2, hidden=True),
        WifiNetwork(ssid="HomeNet_5G",  bssid="00:11:22:33:44:55", channel=1,
                    frequency_mhz=2412, signal_dbm=-80,
                    encryption=EncryptionType.OPEN, rogue_suspected=True),
    ]

    for n in nets:
        if n.encryption == EncryptionType.OPEN and not n.rogue_suspected:
            n.findings.append(_finding("open_wifi",
                f"Open WiFi network: {n.ssid or '<hidden>'}",
                "Network transmits traffic in cleartext.",
                "Enable WPA2 (AES) or WPA3.",
                n.ssid))
        if n.encryption == EncryptionType.WEP:
            n.findings.append(_finding("wep_wifi",
                f"WEP encryption: {n.ssid}",
                "WEP is cryptographically broken.",
                "Upgrade to WPA2 or WPA3.",
                n.ssid))
        if n.hidden:
            n.findings.append(_finding("hidden_ssid",
                "Hidden SSID",
                "Hidden SSIDs cause clients to leak probe requests.",
                "Broadcast the SSID normally.",
                n.bssid))
        if n.rogue_suspected:
            n.findings.append(_finding("rogue_ap",
                f"Possible rogue AP for {n.ssid}",
                "Same SSID advertised with different security settings.",
                "Investigate the weaker-encryption BSSID.",
                n.bssid))
    scan.wifi_networks = nets

    # -- Devices -------------------------------------------------------------
    devices: list[Device] = []

    # 1. Hikvision camera with telnet + default creds → Critical
    cam = Device(
        ip="192.168.50.20", mac="BC:DD:C2:4A:5B:6C",
        hostname="camera-lobby.local", vendor="Hangzhou Hikvision (Cameras)",
        device_type=DeviceType.CAMERA,
        os_guess="Embedded Linux 3.x",
        discovery_sources=[DiscoverySource.ARP, DiscoverySource.MDNS,
                           DiscoverySource.NMAP],
        mdns_services=["_rtsp._tcp", "_http._tcp"],
        open_ports=[
            OpenPort(23,  "tcp", "telnet",  "BusyBox telnetd",  "1.20", "BusyBox v1.20.1 login:"),
            OpenPort(80,  "tcp", "http",    "Hikvision embedded http", "", "Realm=\"DS-2CD2032-I\""),
            OpenPort(554, "tcp", "rtsp",    "Hikvision RTSP server", "", ""),
        ],
    )
    cam.findings += [
        _finding("telnet_open",
                 "Telnet service exposed on port 23",
                 "Cleartext management service exposed on network. Mirai-family malware targets this.",
                 "Disable Telnet; block port 23 at the firewall.",
                 f"{cam.ip}:23", evidence="BusyBox v1.20.1 login:"),
        _finding("default_credentials",
                 "Default Telnet credentials accepted",
                 "Telnet accepted admin:12345, the Hikvision factory default.",
                 "Change admin password immediately; disable Telnet.",
                 f"{cam.ip}:23", evidence="admin:*****"),
        _finding("http_admin_exposed",
                 "Device admin interface exposed on port 80",
                 "Hikvision web management interface reachable without TLS.",
                 "Restrict admin access to management VLAN, enable HTTPS.",
                 f"{cam.ip}:80"),
        _finding("cleartext_protocol",
                 "RTSP video stream exposed on port 554",
                 "Live video feed reachable; ensure authentication is enforced.",
                 "Require RTSP authentication, restrict source IPs.",
                 f"{cam.ip}:554"),
        _finding("known_cve_high",
                 "Known unauthenticated RCE (CVE-2021-36260)",
                 "Hikvision firmware pre-2021 is vulnerable to an unauthenticated "
                 "command-injection in the web interface.",
                 "Apply the latest firmware from the vendor immediately.",
                 f"{cam.ip}:80",
                 cve_ids=["CVE-2021-36260"]),
    ]
    devices.append(cam)

    # 2. TP-Link router with WPS + UPnP exposed → High
    router = Device(
        ip="192.168.50.1", mac="F0:F6:1C:AA:BB:CC",
        hostname="tplink-router.local", vendor="TP-Link Technologies",
        device_type=DeviceType.ROUTER,
        os_guess="Linux (OpenWrt)",
        discovery_sources=[DiscoverySource.ARP, DiscoverySource.SSDP,
                           DiscoverySource.NMAP],
        upnp_model="TP-Link/1.0 UPnP/1.0 TL-WR841N",
        open_ports=[
            OpenPort(80,   "tcp", "http",  "TP-Link httpd", "", "Authentication realm=\"TP-LINK\""),
            OpenPort(443,  "tcp", "https", "TP-Link httpd", "", "TLSv1.0"),
            OpenPort(1900, "udp", "upnp",  "TP-Link UPnP",  "", ""),
            OpenPort(53,   "tcp", "domain", "dnsmasq", "2.55", "dnsmasq-2.55"),
        ],
    )
    router.findings += [
        _finding("http_admin_exposed",
                 "Router admin interface exposed on port 80",
                 "Admin panel reachable over cleartext HTTP.",
                 "Enforce HTTPS; restrict admin access to LAN.",
                 f"{router.ip}:80"),
        _finding("upnp_exposed",
                 "UPnP / SSDP service exposed",
                 "UPnP can be abused for port-forward injection (CallStranger).",
                 "Disable UPnP or restrict to LAN.",
                 f"{router.ip}:1900"),
        _finding("weak_tls_cipher",
                 "Outdated TLSv1.0 on admin interface",
                 "Router admin panel negotiates TLSv1.0, deprecated since 2020.",
                 "Update router firmware; prefer TLSv1.2+.",
                 f"{router.ip}:443"),
        _finding("outdated_firmware",
                 "Possibly outdated service (dnsmasq 2.55, 2011)",
                 "dnsmasq 2.55 predates CVE-2017-14491/2/3/4/5/6 fixes.",
                 "Update router firmware.",
                 f"{router.ip}:53",
                 evidence="dnsmasq-2.55",
                 cve_ids=["CVE-2017-14491"]),
    ]
    devices.append(router)

    # 3. Shelly smart plug — low risk, correctly configured
    plug = Device(
        ip="192.168.50.42", mac="B4:E6:2D:12:34:56",
        hostname="shelly-kitchen.local", vendor="Shelly (Allterco Robotics)",
        device_type=DeviceType.SMART_PLUG,
        discovery_sources=[DiscoverySource.MDNS, DiscoverySource.ARP],
        mdns_services=["_http._tcp", "_shelly._tcp"],
        open_ports=[OpenPort(80, "tcp", "http", "mongoose", "6.18", "Server: Mongoose/6.18")],
    )
    devices.append(plug)

    # 4. Raspberry Pi with SSH — informational
    pi = Device(
        ip="192.168.50.30", mac="B8:27:EB:11:22:44",
        hostname="rpi-mqtt.local", vendor="Raspberry Pi Foundation",
        device_type=DeviceType.COMPUTER,
        os_guess="Debian 12 (Raspberry Pi OS)",
        discovery_sources=[DiscoverySource.ARP, DiscoverySource.MDNS],
        mdns_services=["_ssh._tcp", "_workstation._tcp"],
        open_ports=[
            OpenPort(22, "tcp", "ssh",  "OpenSSH", "9.2p1", "OpenSSH_9.2p1 Debian-2+deb12u3"),
            OpenPort(1883, "tcp", "mqtt", "Mosquitto", "2.0.11", "Mosquitto 2.0.11"),
        ],
    )
    devices.append(pi)

    # 5. Google Home BLE peripheral — proximity only
    google_home = Device(
        mac="F4:F5:D8:AA:BB:CC", ble_name="Google Home Mini",
        ble_rssi=-62, vendor="Google", device_type=DeviceType.SMART_SPEAKER,
        discovery_sources=[DiscoverySource.BLE],
    )
    devices.append(google_home)

    # 6. Xiaomi band — BLE wearable
    band = Device(
        mac="A4:DA:22:01:02:03", ble_name="Mi Smart Band 7",
        ble_rssi=-74, vendor="Xiaomi Communications", device_type=DeviceType.WEARABLE,
        discovery_sources=[DiscoverySource.BLE],
    )
    devices.append(band)

    # 7. Old Asus NAS with anonymous FTP — Medium
    nas = Device(
        ip="192.168.50.60", mac="90:C4:DD:AA:BB:CC",
        hostname="asustor-nas.local", vendor="Asustor (NAS)",
        device_type=DeviceType.NAS,
        discovery_sources=[DiscoverySource.ARP, DiscoverySource.MDNS],
        mdns_services=["_smb._tcp", "_afpovertcp._tcp"],
        open_ports=[
            OpenPort(21,  "tcp", "ftp",  "vsftpd", "2.3.4", "vsftpd 2.3.4 anonymous OK"),
            OpenPort(445, "tcp", "microsoft-ds", "Samba smbd", "4.7.6", ""),
        ],
    )
    nas.findings += [
        _finding("ftp_anonymous",
                 "Anonymous FTP login permitted",
                 "FTP accepts anonymous logins, exposing shared files.",
                 "Disable anonymous FTP; prefer SFTP.",
                 f"{nas.ip}:21", evidence="vsftpd 2.3.4 anonymous OK"),
        _finding("smb_open",
                 "SMB file sharing exposed on port 445",
                 "Samba reachable from network; lateral-movement risk.",
                 "Restrict SMB to LAN, patch firmware.",
                 f"{nas.ip}:445"),
    ]
    devices.append(nas)

    scan.devices = devices
    scan.finished_at = datetime.now(timezone.utc).isoformat()
    return scan
