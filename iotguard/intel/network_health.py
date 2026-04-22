"""
Network health information collection.

All calls are cheap and bounded by short timeouts; this runs on the GUI
thread in practice but through a single background refresh so we don't
stall the UI.

External dependencies:
  * ip-api.com (free, no key, rate-limited to 45 req/min) — public IP + ISP
  * Local OS: `ip route`, `resolvectl`, or /etc/resolv.conf for gateway/DNS
  * ICMP-free latency: TCP connect to 1.1.1.1:53 and 8.8.8.8:53
"""

from __future__ import annotations

import json
import logging
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path


log = logging.getLogger(__name__)


@dataclass
class NetworkHealth:
    public_ip: str = ""
    isp: str = ""
    org: str = ""
    country: str = ""
    city: str = ""
    region: str = ""
    as_name: str = ""
    gateway_ip: str = ""
    local_ip: str = ""
    dns_servers: list[str] = field(default_factory=list)
    cloudflare_latency_ms: float = 0.0
    google_latency_ms: float = 0.0
    fetched_at: str = ""
    error: str = ""

    @property
    def internet_ok(self) -> bool:
        return self.cloudflare_latency_ms > 0 or self.google_latency_ms > 0


# ---------------------------------------------------------------------------
# Individual probes
# ---------------------------------------------------------------------------

def _tcp_latency(host: str, port: int = 53, timeout: float = 2.0) -> float:
    """Return connect latency in ms, or 0.0 on failure."""
    start = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return (time.time() - start) * 1000.0
    except OSError:
        return 0.0


def _local_ip() -> str:
    """Trick to discover the local outbound IP without sending anything."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("1.1.1.1", 80))
        return s.getsockname()[0]
    except OSError:
        return ""
    finally:
        s.close()


def _gateway_ip() -> str:
    try:
        out = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True, text=True, timeout=3,
        )
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out.stdout)
        return m.group(1) if m else ""
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


def _dns_servers() -> list[str]:
    """Prefer systemd-resolved, fall back to /etc/resolv.conf."""
    servers: list[str] = []
    try:
        out = subprocess.run(
            ["resolvectl", "status"],
            capture_output=True, text=True, timeout=3,
        )
        for line in out.stdout.splitlines():
            m = re.search(r"(?:Current DNS Server|DNS Servers?):\s+(\S+)", line)
            if m and m.group(1) not in servers:
                servers.append(m.group(1))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    if not servers:
        try:
            for line in Path("/etc/resolv.conf").read_text().splitlines():
                m = re.match(r"\s*nameserver\s+(\S+)", line)
                if m and m.group(1) not in servers:
                    servers.append(m.group(1))
        except (FileNotFoundError, OSError):
            pass
    return servers[:4]


def _public_ip_and_isp(timeout: float = 4.0) -> dict:
    """Query ip-api.com for public IP + ISP. Returns empty dict on failure."""
    url = ("http://ip-api.com/json/?fields="
           "status,message,country,regionName,city,isp,org,as,query")
    req = urllib.request.Request(url, headers={
        "User-Agent": "IoTGuard/1.0 (+lab use)",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError,
            TimeoutError, OSError, json.JSONDecodeError) as e:
        log.info("ip-api.com lookup failed: %s", e)
        return {}

    if data.get("status") != "success":
        return {}
    return data


# ---------------------------------------------------------------------------
# Composite
# ---------------------------------------------------------------------------

def collect_network_health(use_ip_api: bool = True) -> NetworkHealth:
    h = NetworkHealth()
    h.fetched_at = time.strftime("%Y-%m-%d %H:%M:%S")

    h.local_ip = _local_ip()
    h.gateway_ip = _gateway_ip()
    h.dns_servers = _dns_servers()

    h.cloudflare_latency_ms = _tcp_latency("1.1.1.1")
    h.google_latency_ms     = _tcp_latency("8.8.8.8")

    if use_ip_api and h.internet_ok:
        data = _public_ip_and_isp()
        if data:
            h.public_ip = data.get("query", "")
            h.isp       = data.get("isp", "")
            h.org       = data.get("org", "")
            h.country   = data.get("country", "")
            h.region    = data.get("regionName", "")
            h.city      = data.get("city", "")
            h.as_name   = data.get("as", "")
    elif not h.internet_ok:
        h.error = "No internet connectivity (DNS probes failed)"

    return h
