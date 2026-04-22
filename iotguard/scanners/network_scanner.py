"""
Same-subnet device discovery — multi-technique approach.

Pipeline (all run sequentially, results merged by MAC then IP):
  1. nmap -sn sweep  — ICMP + TCP SYN/ACK probes, bypasses most firewalls
  2. ARP sweep        — scapy Ethernet broadcast, most reliable on same segment
  3. /proc/net/arp    — passive fallback when scapy has no raw-socket permission
  4. ICMP sweep       — scapy ping flood, finds hosts that answer ICMP but not ARP
  5. NetBIOS UDP 137  — reveals Windows / Samba / NAS by name query
  6. mDNS / DNS-SD    — Bonjour, Chromecast, HomeKit, Apple devices
  7. SSDP / UPnP      — routers, smart-TVs, hubs
  8. Passive sniffer  — catches devices talking on wire but blocking all probes
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path
from typing import Iterable

from ..core.models import Device, DeviceType, DiscoverySource
from ..intel.oui_lookup import lookup_vendor, classify_by_vendor, classify_by_hostname

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# 1. nmap host-discovery sweep
# ─────────────────────────────────────────────────────────────────────────────

def nmap_host_sweep(subnet: str, timeout: int = 120) -> list[Device]:
    """
    nmap -sn with ICMP + TCP SYN/ACK + UDP probes.

    Without root: nmap silently drops ICMP/-PE/-PP probes but still fires
    TCP SYN (-PS) connect probes, so we still discover most hosts.
    With root / CAP_NET_RAW: all probes work.

    timeout is the subprocess wall-clock timeout (default 120 s).
    --host-timeout 20s caps per-host time so a filtered /24 won't hang.
    """
    import shutil
    if not shutil.which("nmap"):
        log.info("nmap not found; skipping nmap host sweep")
        return []
    try:
        cmd = [
            "nmap", "-sn",
            "-PE", "-PP",                             # ICMP echo + timestamp
            "-PS21,22,23,80,443,445,8080,8443",       # TCP SYN to common ports
            "-PA80,443,3389",                         # TCP ACK (bypasses stateful FW)
            "-PU53,67,161",                           # UDP ping
            "--max-retries", "1",                     # don't retry filtered hosts
            "--host-timeout", "20s",                  # per-host cap
            "-T4",
            "-oX", "-",                               # XML to stdout
            subnet,
        ]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        devices = _parse_nmap_xml_hosts(result.stdout)
        log.info("nmap sweep → %d hosts on %s", len(devices), subnet)
        return devices
    except subprocess.TimeoutExpired:
        log.warning("nmap host sweep timed out after %ds", timeout)
    except Exception as exc:
        log.warning("nmap host sweep failed: %s", exc)
    return []


def _parse_nmap_xml_hosts(xml: str) -> list[Device]:
    """Parse nmap -oX output and return one Device per live host."""
    import xml.etree.ElementTree as ET
    devices: list[Device] = []
    if not xml.strip():
        return devices
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return devices

    for host in root.findall(".//host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip = mac = hostname = vendor = ""
        for addr in host.findall("address"):
            atype = addr.get("addrtype", "")
            if atype == "ipv4":
                ip = addr.get("addr", "")
            elif atype == "mac":
                mac = addr.get("addr", "").upper()
                vendor = addr.get("vendor", "")

        for hn in host.findall(".//hostname"):
            if hn.get("type") in ("PTR", "user"):
                hostname = hn.get("name", "")
                break

        if not ip and not mac:
            continue

        devices.append(Device(
            ip=ip, mac=mac, hostname=hostname, vendor=vendor,
            discovery_sources=[DiscoverySource.NMAP],
        ))
    return devices


# ─────────────────────────────────────────────────────────────────────────────
# 2. ARP sweep (scapy)
# ─────────────────────────────────────────────────────────────────────────────

def arp_discover(subnet: str, timeout: float = 3.0) -> list[Device]:
    """
    Ethernet broadcast ARP sweep — the gold standard for same-segment discovery.
    Needs CAP_NET_RAW or root; falls back to /proc/net/arp otherwise.
    """
    try:
        from scapy.all import ARP, Ether, srp  # type: ignore
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            timeout=timeout, verbose=False, retry=1,
        )
        devices = [
            Device(
                ip=rcv.psrc,
                mac=rcv.hwsrc.upper(),
                discovery_sources=[DiscoverySource.ARP],
            )
            for _, rcv in ans
        ]
        if devices:
            log.info("ARP sweep → %d devices", len(devices))
            return devices
    except PermissionError:
        log.info("ARP sweep needs CAP_NET_RAW; using /proc/net/arp fallback")
    except Exception as exc:
        log.info("ARP sweep failed (%s); using /proc/net/arp fallback", exc)
    return _arp_from_proc()


def _arp_from_proc() -> list[Device]:
    """Read the kernel ARP table — zero-privilege, but only sees hosts
    the local machine has already talked to."""
    p = Path("/proc/net/arp")
    if not p.exists():
        return []
    devices = []
    for line in p.read_text().splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        ip, _, flags, mac, _, _ = parts[:6]
        # flags == "0x0" means incomplete entry; skip broadcast/null MACs
        if flags == "0x0" or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            continue
        devices.append(Device(
            ip=ip, mac=mac.upper(),
            discovery_sources=[DiscoverySource.ARP],
        ))
    return devices


# ─────────────────────────────────────────────────────────────────────────────
# 3. ICMP ping sweep (scapy)
# ─────────────────────────────────────────────────────────────────────────────

def icmp_sweep(subnet: str, timeout: float = 3.0) -> list[Device]:
    """
    Send ICMP echo to every host in the subnet and collect replies.
    Finds hosts that respond to ping but ignore ARP (uncommon but real).
    Skipped for subnets larger than /23 (> 512 hosts) to avoid flooding.
    """
    try:
        from scapy.all import IP, ICMP, sr  # type: ignore
        network = ipaddress.ip_network(subnet, strict=False)
        if network.num_addresses > 512:
            log.debug("ICMP sweep skipped: subnet %s too large", subnet)
            return []
        hosts = [str(h) for h in network.hosts()]
        pkts = [IP(dst=h) / ICMP() for h in hosts]
        # inter=0.001 gives ~1ms between packets — fast but not flooding
        ans, _ = sr(pkts, timeout=timeout, verbose=False, retry=0, inter=0.001)
        devices = [
            Device(
                ip=rcv[IP].src,
                discovery_sources=[DiscoverySource.NMAP],  # closest enum
            )
            for _, rcv in ans
        ]
        log.info("ICMP sweep → %d hosts", len(devices))
        return devices
    except PermissionError:
        log.debug("ICMP sweep needs CAP_NET_RAW; skipped")
    except Exception as exc:
        log.debug("ICMP sweep skipped: %s", exc)
    return []


# ─────────────────────────────────────────────────────────────────────────────
# 4. NetBIOS UDP 137 probe
# ─────────────────────────────────────────────────────────────────────────────

# Valid NBSTAT query for the wildcard name "*" (encoded as "CKAAA...AA")
# Structure: TxID(2) + Flags(2) + QDCount(2) + 3×Zero(6) + EncodedName(34) + Type(2) + Class(2)
_NBNS_QUERY = (
    b"\xab\xcd"          # Transaction ID (arbitrary)
    b"\x00\x00"          # Flags: standard query
    b"\x00\x01"          # QDCount = 1
    b"\x00\x00"          # ANCount = 0
    b"\x00\x00"          # NSCount = 0
    b"\x00\x00"          # ARCount = 0
    b"\x20"              # Name length (32)
    b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # Encoded wildcard "*"
    b"\x00"              # Name terminator
    b"\x00\x21"          # QTYPE = NBSTAT (33)
    b"\x00\x01"          # QCLASS = IN
)


def netbios_scan(subnet: str, timeout: float = 2.0) -> list[Device]:
    """
    Send NBSTAT (UDP 137) query to every host — Windows, Samba, NAS boxes
    respond with their NetBIOS name table, revealing hostname + workgroup.
    Does not need elevated privileges (UDP send/recv is unprivileged).
    """
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        if network.num_addresses > 512:
            log.debug("NetBIOS scan skipped: subnet %s too large", subnet)
            return []
        hosts = [str(h) for h in network.hosts()]
    except ValueError:
        return []

    found: list[Device] = []
    lock = threading.Lock()

    def _probe(ip: str) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(_NBNS_QUERY, (ip, 137))
                data, _ = s.recvfrom(1024)
            hostname = _parse_nbns_response(data)
            with lock:
                found.append(Device(
                    ip=ip,
                    hostname=hostname,
                    discovery_sources=[DiscoverySource.NMAP],
                ))
        except Exception:
            pass  # no response = host is down or not running NetBIOS

    # Fan out — 50 threads at a time with a small stagger to avoid UDP bursts
    threads = [threading.Thread(target=_probe, args=(h,), daemon=True) for h in hosts]
    for i, t in enumerate(threads):
        t.start()
        if i % 50 == 49:
            time.sleep(0.05)
    for t in threads:
        t.join(timeout=timeout + 1.0)

    log.info("NetBIOS → %d devices", len(found))
    return found


def _parse_nbns_response(data: bytes) -> str:
    """Extract the primary workstation name from an NBSTAT response."""
    try:
        # Byte 56 = number of names in the response
        if len(data) < 57:
            return ""
        num_names = data[56]
        offset = 57
        for _ in range(num_names):
            if offset + 18 > len(data):
                break
            raw_name = data[offset:offset + 15]
            name_type = data[offset + 15]
            flags = struct.unpack(">H", data[offset + 16:offset + 18])[0]
            # type 0x00 = workstation name; skip group names (flag bit 0x8000)
            if name_type == 0x00 and not (flags & 0x8000):
                return raw_name.decode("ascii", errors="ignore").strip()
            offset += 18
    except Exception:
        pass
    return ""


# ─────────────────────────────────────────────────────────────────────────────
# 5. mDNS / DNS-SD
# ─────────────────────────────────────────────────────────────────────────────

_MDNS_SERVICE_TYPES = [
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_ipp._tcp.local.",
    "_printer._tcp.local.",
    "_ssh._tcp.local.",
    "_rtsp._tcp.local.",
    "_airplay._tcp.local.",
    "_googlecast._tcp.local.",
    "_hue._tcp.local.",
    "_spotify-connect._tcp.local.",
    "_workstation._tcp.local.",
    "_smb._tcp.local.",
    "_nvstream._tcp.local.",
    "_homekit._tcp.local.",
    "_afpovertcp._tcp.local.",
    "_device-info._tcp.local.",
    "_raop._tcp.local.",
    "_companion-link._tcp.local.",
    "_daap._tcp.local.",
    "_dpap._tcp.local.",
]


def mdns_discover(duration: float = 4.0) -> list[Device]:
    """Browse mDNS service types via zeroconf and collect responding devices."""
    try:
        from zeroconf import Zeroconf, ServiceBrowser, ServiceListener  # type: ignore
    except ImportError:
        log.info("zeroconf not installed; skipping mDNS")
        return []

    collected: dict[str, Device] = {}

    class _Listener(ServiceListener):
        def add_service(self, zc, type_, name):
            try:
                info = zc.get_service_info(type_, name, timeout=1500)
            except Exception:
                return
            if not info:
                return
            addresses = (info.parsed_addresses()
                         if hasattr(info, "parsed_addresses") else [])
            ip = addresses[0] if addresses else ""
            # Strip the service type suffix from the name to get a clean hostname
            host = name.replace(f".{type_}", "")
            key = ip or host
            dev = collected.setdefault(key, Device(
                ip=ip, hostname=host,
                discovery_sources=[DiscoverySource.MDNS],
            ))
            svc = type_.rstrip(".")
            if svc not in dev.mdns_services:
                dev.mdns_services.append(svc)

        def update_service(self, zc, type_, name): pass
        def remove_service(self, zc, type_, name): pass

    zc = Zeroconf()
    try:
        listener = _Listener()
        browsers = [ServiceBrowser(zc, t, listener) for t in _MDNS_SERVICE_TYPES]
        time.sleep(duration)
        for b in browsers:
            b.cancel()
    finally:
        zc.close()
    return list(collected.values())


# ─────────────────────────────────────────────────────────────────────────────
# 6. SSDP / UPnP
# ─────────────────────────────────────────────────────────────────────────────

_SSDP_ADDR = "239.255.255.250"
_SSDP_PORT = 1900

_SSDP_SEARCH_TARGETS = [
    "ssdp:all",
    "upnp:rootdevice",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
]

_SSDP_TMPL = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {_SSDP_ADDR}:{_SSDP_PORT}\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: {st}\r\n\r\n"
)


def ssdp_discover(timeout: float = 4.0) -> list[Device]:
    """Send SSDP M-SEARCH multicasts and collect UPnP device responses."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
        sock.settimeout(0.5)
    except OSError as exc:
        log.warning("SSDP socket creation failed: %s", exc)
        return []

    # Send all search target types to maximise response coverage
    for st in _SSDP_SEARCH_TARGETS:
        try:
            sock.sendto(
                _SSDP_TMPL.format(st=st).encode("ascii"),
                (_SSDP_ADDR, _SSDP_PORT),
            )
        except OSError:
            pass

    end = time.time() + timeout
    seen: dict[str, Device] = {}

    while time.time() < end:
        try:
            data, (ip, _) = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            break

        # Parse HTTP-style headers: split each line on first colon
        headers: dict[str, str] = {}
        for line in data.decode("utf-8", errors="ignore").splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()

        dev = seen.setdefault(ip, Device(
            ip=ip, discovery_sources=[DiscoverySource.SSDP],
        ))
        server = headers.get("server", "")
        location = headers.get("location", "")
        if server and not dev.upnp_model:
            dev.upnp_model = server[:120]
        if location:
            dev.services_banner["upnp_location"] = location
            # Best-effort: fetch the description XML for model/manufacturer
            _try_fetch_upnp_description(dev, location)

    sock.close()
    log.info("SSDP → %d responders", len(seen))
    return list(seen.values())


def _try_fetch_upnp_description(dev: Device, location: str) -> None:
    """Fetch UPnP device description XML and extract model/manufacturer."""
    import urllib.request
    import xml.etree.ElementTree as ET
    try:
        req = urllib.request.Request(
            location, headers={"User-Agent": "IoTGuard/1.0"}
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            xml_text = resp.read(8192).decode("utf-8", errors="ignore")
        root = ET.fromstring(xml_text)
        device_el = root.find(".//{*}device")
        if device_el is None:
            return
        def _t(tag: str) -> str:
            el = device_el.find(f"{{*}}{tag}")
            return el.text.strip() if el is not None and el.text else ""
        model = _t("modelName") or _t("friendlyName")
        mfr   = _t("manufacturer")
        if model and not dev.upnp_model:
            dev.upnp_model = model[:120]
        if mfr and not dev.upnp_manufacturer:
            dev.upnp_manufacturer = mfr[:80]
    except Exception:
        pass  # network errors, XML parse failures — silently skip


# ─────────────────────────────────────────────────────────────────────────────
# 7. Passive wire sniffer (scapy)
# ─────────────────────────────────────────────────────────────────────────────

def passive_sniff(duration: float = 5.0, iface: str | None = None) -> list[Device]:
    """
    Passively capture ARP + IP traffic for `duration` seconds.
    Reveals devices that actively communicate but ignore all active probes
    (e.g. some printers, IoT sensors, certain managed switches).
    Needs CAP_NET_RAW; silently skipped without it.
    """
    try:
        from scapy.all import sniff, ARP, IP, Ether  # type: ignore
    except ImportError:
        return []

    seen: dict[str, Device] = {}

    def _on_packet(pkt) -> None:
        ip_addr = mac_addr = ""
        try:
            if ARP in pkt:
                ip_addr  = pkt[ARP].psrc
                mac_addr = pkt[ARP].hwsrc.upper()
            elif IP in pkt and Ether in pkt:
                ip_addr  = pkt[IP].src
                mac_addr = pkt[Ether].src.upper()
        except Exception:
            return
        # Filter out broadcast, multicast, link-local, and unset addresses
        if not ip_addr:
            return
        try:
            parsed = ipaddress.ip_address(ip_addr)
        except ValueError:
            return
        if parsed.is_multicast or parsed.is_loopback or parsed.is_unspecified:
            return
        # Also skip broadcast MACs
        if mac_addr in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00", ""):
            return
        key = mac_addr or ip_addr
        if key not in seen:
            seen[key] = Device(
                ip=ip_addr, mac=mac_addr,
                discovery_sources=[DiscoverySource.ARP],
            )

    try:
        kwargs: dict = {"timeout": duration, "store": False, "prn": _on_packet}
        if iface:
            kwargs["iface"] = iface
        sniff(**kwargs)
        log.info("Passive sniff → %d unique hosts in %.1fs", len(seen), duration)
    except PermissionError:
        log.debug("Passive sniff requires CAP_NET_RAW; skipped")
    except Exception as exc:
        log.debug("Passive sniff failed: %s", exc)

    return list(seen.values())


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def detect_local_subnet(interface: str | None = None) -> tuple[str, str]:
    """Return (interface_name, cidr_string) for the default-route interface."""
    try:
        out = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True, text=True, timeout=3,
        )
        m = re.search(r"default via \S+ dev (\S+)", out.stdout)
        if m:
            iface = m.group(1)
            out2 = subprocess.run(
                ["ip", "-4", "-o", "addr", "show", "dev", iface],
                capture_output=True, text=True, timeout=3,
            )
            m2 = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", out2.stdout)
            if m2:
                net = ipaddress.ip_network(m2.group(1), strict=False)
                return iface, str(net)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return (interface or "eth0"), "192.168.1.0/24"


def resolve_hostname(ip: str, timeout: float = 0.5) -> str:
    """Reverse-DNS lookup with a short timeout; returns "" on failure."""
    saved = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""
    finally:
        socket.setdefaulttimeout(saved)


def merge_devices(*sources: Iterable[Device]) -> list[Device]:
    """
    Fold Device records from multiple discovery sources into one canonical list.

    Merge key priority:
      1. MAC address (uppercase, lower-cased for lookup)
      2. IP address (if MAC is absent, e.g. BLE or mDNS-only devices)
      3. hostname   (last resort for Bluetooth-only records)

    When two records share a key, missing fields from the newer record are
    filled into the existing one; discovery sources are union-merged.
    """
    merged: dict[str, Device] = {}

    def _key(d: Device) -> str:
        return (d.mac or d.ip or d.hostname).lower()

    for src in sources:
        for d in src:
            k = _key(d)
            if not k:
                continue
            if k not in merged:
                merged[k] = d
                continue
            ex = merged[k]
            # Fill blanks
            if d.ip  and not ex.ip:   ex.ip  = d.ip
            if d.mac and not ex.mac:  ex.mac = d.mac
            if d.hostname and not ex.hostname:  ex.hostname = d.hostname
            if d.vendor   and not ex.vendor:    ex.vendor   = d.vendor
            if d.upnp_model        and not ex.upnp_model:        ex.upnp_model        = d.upnp_model
            if d.upnp_manufacturer and not ex.upnp_manufacturer: ex.upnp_manufacturer = d.upnp_manufacturer
            # Union-merge list fields
            ex.mdns_services = list({*ex.mdns_services, *d.mdns_services})
            for s in d.discovery_sources:
                if s not in ex.discovery_sources:
                    ex.discovery_sources.append(s)
            ex.services_banner.update(d.services_banner)

    # Enrich every merged device
    gateway_ip = _detect_gateway_ip()
    for dev in merged.values():
        # OUI vendor lookup
        if dev.mac and not dev.vendor:
            dev.vendor = lookup_vendor(dev.mac)
        # Reverse DNS
        if dev.ip and not dev.hostname:
            dev.hostname = resolve_hostname(dev.ip)
        # Device-type heuristic
        if dev.device_type == DeviceType.UNKNOWN:
            guess = classify_by_vendor(dev.vendor) or classify_by_hostname(dev.hostname)
            if guess:
                try:
                    dev.device_type = DeviceType(guess)
                except ValueError:
                    pass
        # Gateway override
        if dev.ip and gateway_ip and dev.ip == gateway_ip:
            dev.device_type = DeviceType.ROUTER
            dev.is_gateway  = True

    # Sort by IP address numerically; BLE-only (no IP) go to the end
    def _sort_key(d: Device):
        if d.ip:
            try:
                return tuple(int(x) for x in d.ip.split("."))
            except ValueError:
                pass
        return (999, 999, 999, 999)

    return sorted(merged.values(), key=_sort_key)


def _detect_gateway_ip() -> str:
    """Return the default-route gateway IPv4, or empty string on failure."""
    try:
        out = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True, text=True, timeout=3,
        )
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out.stdout)
        return m.group(1) if m else ""
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""
