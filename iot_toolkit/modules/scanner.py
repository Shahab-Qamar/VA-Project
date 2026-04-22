"""
Module 3 — Port & Service Scanner
Scans common IoT ports, grabs banners, detects service versions.
"""

import socket
import ssl
import threading
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

# ── Well-known IoT port metadata ──────────────────────────────
IOT_PORT_META = {
    21:   {"service": "FTP",          "risk": "medium",   "note": "File transfer — check anon login"},
    22:   {"service": "SSH",          "risk": "low",      "note": "Secure shell"},
    23:   {"service": "Telnet",       "risk": "critical", "note": "Cleartext — highly insecure"},
    25:   {"service": "SMTP",         "risk": "medium",   "note": "Mail relay"},
    53:   {"service": "DNS",          "risk": "low",      "note": "Domain name service"},
    80:   {"service": "HTTP",         "risk": "medium",   "note": "Web management panel"},
    443:  {"service": "HTTPS",        "risk": "low",      "note": "Encrypted web panel"},
    554:  {"service": "RTSP",         "risk": "high",     "note": "Live video stream"},
    1883: {"service": "MQTT",         "risk": "high",     "note": "IoT messaging — check auth"},
    1900: {"service": "UPnP/SSDP",   "risk": "high",     "note": "Universal Plug and Play"},
    2323: {"service": "Telnet-alt",   "risk": "critical", "note": "Alt Telnet — IoT default"},
    3702: {"service": "WS-Discovery", "risk": "medium",   "note": "ONVIF camera discovery"},
    4840: {"service": "OPC-UA",       "risk": "high",     "note": "Industrial protocol"},
    5683: {"service": "CoAP",         "risk": "high",     "note": "Constrained IoT protocol"},
    6668: {"service": "IRC",          "risk": "high",     "note": "Often used by botnets"},
    7547: {"service": "TR-069",       "risk": "critical", "note": "ISP remote management"},
    8080: {"service": "HTTP-alt",     "risk": "medium",   "note": "Alt web panel"},
    8443: {"service": "HTTPS-alt",    "risk": "low",      "note": "Alt HTTPS panel"},
    8883: {"service": "MQTT-TLS",     "risk": "low",      "note": "Encrypted MQTT"},
    9200: {"service": "Elasticsearch","risk": "critical", "note": "Unauthenticated DB exposure"},
    37777:{"service": "Dahua-DVR",    "risk": "high",     "note": "Dahua proprietary protocol"},
    34567:{"service": "HiSilicon-DVR","risk": "high",     "note": "Generic DVR protocol"},
    49152:{"service": "UPnP-IGD",     "risk": "high",     "note": "Router UPnP IGD"},
}

# ── Banner probes sent to elicit service identification ───────
BANNER_PROBES = {
    80:   b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    554:  b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n",
    1883: b"\x10\x14\x00\x04MQTT\x04\x00\x00\x3c\x00\x08iot-scan",
    21:   b"",
    22:   b"",
    23:   b"",
}


class PortScanner:
    def __init__(self, timeout: int = 3, threads: int = 20, log=None):
        self.timeout = timeout
        self.threads = threads
        self.log     = log

    def scan(self, ip: str, ports: List[int]) -> Dict:
        """Scan ports and grab banners. Returns enriched results."""
        open_ports = {}
        services   = {}

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._probe_port, ip, port): port
                       for port in ports}
            for future in as_completed(futures):
                port   = futures[future]
                result = future.result()
                if result:
                    open_ports[port] = result
                    meta = IOT_PORT_META.get(port, {})
                    services[port] = {
                        "name":    meta.get("service", result.get("service", "unknown")),
                        "risk":    meta.get("risk", "unknown"),
                        "note":    meta.get("note", ""),
                        "banner":  result.get("banner", ""),
                        "version": result.get("version", ""),
                    }
        return {"open_ports": open_ports, "services": services}

    def _probe_port(self, ip: str, port: int) -> Dict:
        """Try to connect and grab banner. Returns dict or None."""
        # Try plain TCP
        result = self._tcp_connect(ip, port)
        if result is None and port in (443, 8443):
            result = self._tls_connect(ip, port)
        return result

    def _tcp_connect(self, ip: str, port: int) -> Dict:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((ip, port))

            banner = ""
            probe  = BANNER_PROBES.get(port)
            if probe:
                if probe:
                    s.sendall(probe)
                try:
                    s.settimeout(2)
                    banner = s.recv(1024).decode("utf-8", errors="replace").strip()
                except Exception:
                    pass
            else:
                # Wait briefly for spontaneous banner
                try:
                    s.settimeout(1.5)
                    banner = s.recv(512).decode("utf-8", errors="replace").strip()
                except Exception:
                    pass
            s.close()

            version = self._extract_version(banner, port)
            return {
                "state":   "open",
                "banner":  banner[:300],
                "version": version,
                "service": IOT_PORT_META.get(port, {}).get("service", ""),
            }
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    def _tls_connect(self, ip: str, port: int) -> Dict:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=self.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=ip) as s:
                    probe = BANNER_PROBES.get(port, b"HEAD / HTTP/1.0\r\n\r\n")
                    if probe:
                        s.sendall(probe)
                    try:
                        banner = s.recv(512).decode("utf-8", errors="replace").strip()
                    except Exception:
                        banner = ""
                    cert   = s.getpeercert(binary_form=False) or {}
                    return {
                        "state":   "open",
                        "banner":  banner[:300],
                        "version": self._extract_version(banner, port),
                        "service": IOT_PORT_META.get(port, {}).get("service", ""),
                        "tls":     True,
                        "cert_cn": self._cert_cn(cert),
                    }
        except Exception:
            return None

    def _extract_version(self, banner: str, port: int) -> str:
        """Extract service/version string from banner."""
        if not banner:
            return ""
        patterns = [
            r"Server:\s*(.+)",
            r"SSH-\d+\.\d+-(\S+)",
            r"220\s+(\S.+?)[\r\n]",
            r"OpenSSH[_\s]([\d.p]+)",
            r"Apache/([\d.]+)",
            r"nginx/([\d.]+)",
            r"lighttpd/([\d.]+)",
            r"GoAhead/([\d.]+)",
            r"(Hikvision[^\r\n]+)",
            r"(Dahua[^\r\n]+)",
        ]
        for pat in patterns:
            m = re.search(pat, banner, re.IGNORECASE)
            if m:
                return m.group(1).strip()[:80]
        return ""

    def _cert_cn(self, cert: dict) -> str:
        subject = cert.get("subject", [])
        for pair in subject:
            for k, v in pair:
                if k == "commonName":
                    return v
        return ""
