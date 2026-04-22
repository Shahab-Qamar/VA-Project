"""
Best-effort DNS hijack / poisoning detection.

Compares the A-record answers from the router's DNS server against a known-
good upstream (Cloudflare 1.1.1.1) for a handful of high-signal domains.
Mismatch on any of them is a red flag — compromised routers commonly
redirect banking / ad / update domains to attacker-controlled hosts.

We intentionally do NOT use a full resolver library; raw UDP DNS over sockets
keeps the dependency surface zero.
"""

from __future__ import annotations

import logging
import socket
import struct
import random

log = logging.getLogger(__name__)


CHECK_DOMAINS = [
    "www.google.com",
    "www.cloudflare.com",
    "www.microsoft.com",
    "accounts.google.com",
    "update.microsoft.com",
]
REFERENCE_DNS = "1.1.1.1"


def _encode_qname(name: str) -> bytes:
    parts = name.strip(".").split(".")
    return b"".join(bytes([len(p)]) + p.encode("ascii") for p in parts) + b"\x00"


def _dns_query_a(server: str, name: str, timeout: float = 2.5) -> list[str]:
    """Send a single A-record DNS query, return list of answer IPs."""
    tx_id = random.randint(1, 0xFFFE)
    flags = 0x0100           # standard recursive
    header = struct.pack("!HHHHHH", tx_id, flags, 1, 0, 0, 0)
    question = _encode_qname(name) + struct.pack("!HH", 1, 1)   # QTYPE=A, QCLASS=IN
    pkt = header + question

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(pkt, (server, 53))
        data, _ = sock.recvfrom(2048)
    except (OSError, socket.timeout):
        return []
    finally:
        sock.close()

    if len(data) < 12:
        return []
    ancount = struct.unpack("!H", data[6:8])[0]
    if ancount == 0:
        return []

    # Skip question section
    idx = 12
    while idx < len(data) and data[idx] != 0:
        idx += data[idx] + 1
    idx += 1 + 4   # null + QTYPE + QCLASS

    results: list[str] = []
    for _ in range(ancount):
        # Name field: either pointer (2 bytes) or labels. Skip it.
        if idx >= len(data):
            break
        if data[idx] & 0xC0:
            idx += 2
        else:
            while idx < len(data) and data[idx] != 0:
                idx += data[idx] + 1
            idx += 1
        if idx + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[idx:idx + 10])
        idx += 10
        if rtype == 1 and rdlen == 4:
            ip = ".".join(str(b) for b in data[idx:idx + 4])
            results.append(ip)
        idx += rdlen
    return results


def check_dns_hijack(router_dns: str, domains: list[str] | None = None,
                     reference: str = REFERENCE_DNS) -> dict:
    """Return a dict summarizing any mismatches."""
    domains = domains or CHECK_DOMAINS
    report = {
        "router_dns": router_dns,
        "reference_dns": reference,
        "checked": [],
        "mismatches": [],
        "unreachable_router": False,
        "unreachable_reference": False,
    }

    if not router_dns:
        report["unreachable_router"] = True
        return report

    for d in domains:
        ref_ips    = set(_dns_query_a(reference,  d))
        router_ips = set(_dns_query_a(router_dns, d))

        entry = {
            "domain": d,
            "router_ips": sorted(router_ips),
            "reference_ips": sorted(ref_ips),
            "match": bool(ref_ips and router_ips and (ref_ips & router_ips)),
        }
        report["checked"].append(entry)

        if not ref_ips:
            report["unreachable_reference"] = True
        if not router_ips:
            continue
        if not entry["match"]:
            report["mismatches"].append(entry)

    return report
