"""
Active default-credential tester — the "Lab Mode" component.

IMPORTANT — SAFETY RAILS
------------------------
This module only runs when Lab Mode is explicitly enabled by the user AND
the user has accepted the consent dialog in the GUI. The GUI enforces both.
Still, we defensively require `enabled=True` on every call and cap attempts
per host to avoid accidental lockouts.

What we test (and nothing more):
  * HTTP/HTTPS login forms and HTTP Basic auth on common admin ports
  * FTP authentication
  * Telnet authentication
  * SSH authentication (with a very small wordlist)

Tested targets come exclusively from scan results — we never accept a
user-entered hostname here.
"""

from __future__ import annotations

import base64
import json
import logging
import socket
import ssl
from pathlib import Path
from typing import Optional

from ..core.models import Device, Finding, OpenPort
from ..core.owasp_mapping import get_owasp
from ..core.risk_scoring import score_preset

log = logging.getLogger(__name__)


MAX_ATTEMPTS_PER_SERVICE = 6
SOCKET_TIMEOUT = 3.0


# ---------------------------------------------------------------------------
# Credential list
# ---------------------------------------------------------------------------

def _load_creds() -> dict:
    path = Path(__file__).parent.parent / "resources" / "data" / "default_creds.json"
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError) as e:
        log.warning("default_creds.json unavailable: %s", e)
        return {"generic": [], "by_vendor": {}}


def _creds_for(vendor: str, creds_db: dict) -> list[tuple[str, str]]:
    v = (vendor or "").lower()
    pairs: list[tuple[str, str]] = []
    for vendor_key, vendor_pairs in creds_db.get("by_vendor", {}).items():
        if vendor_key in v:
            pairs.extend((u, p) for u, p in vendor_pairs)
    pairs.extend((u, p) for u, p in creds_db.get("generic", []))
    # Dedupe while preserving order, cap for safety.
    seen = set()
    out: list[tuple[str, str]] = []
    for up in pairs:
        if up not in seen:
            seen.add(up); out.append(up)
    return out[:MAX_ATTEMPTS_PER_SERVICE]


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

def test_device_credentials(device: Device, enabled: bool = False,
                            verify_ssl: bool = False) -> None:
    """Attach a Finding on the device if default creds succeed. No-op unless
    `enabled=True`. Uses at most MAX_ATTEMPTS_PER_SERVICE credentials per
    service."""
    if not enabled or not device.ip:
        return

    creds_db = _load_creds()
    creds = _creds_for(device.vendor, creds_db)
    if not creds:
        return

    for op in list(device.open_ports):
        svc = (op.service or "").lower()
        try:
            if svc == "ftp" or op.port == 21:
                _try_ftp(device, op, creds)
            elif svc == "telnet" or op.port in (23, 2323):
                _try_telnet(device, op, creds)
            elif svc == "ssh" or op.port == 22:
                _try_ssh(device, op, creds)
            elif svc in ("http", "http-alt", "http-proxy") or op.port in (
                80, 81, 8000, 8008, 8080, 8081):
                _try_http_basic(device, op, creds, tls=False)
            elif svc in ("https", "https-alt") or op.port in (443, 8443, 9443):
                _try_http_basic(device, op, creds, tls=True,
                                verify_ssl=verify_ssl)
        except Exception as e:
            log.debug("cred test error %s:%d  %s", device.ip, op.port, e)


# ---------------------------------------------------------------------------
# Per-service testers
# ---------------------------------------------------------------------------

def _try_ftp(device: Device, op: OpenPort, creds) -> None:
    from ftplib import FTP, error_perm
    for user, pwd in creds:
        try:
            ftp = FTP()
            ftp.connect(device.ip, op.port, timeout=SOCKET_TIMEOUT)
            ftp.login(user, pwd)
            ftp.quit()
        except (error_perm, OSError, EOFError):
            continue
        _record_success(device, op, "FTP", user, pwd)
        return


def _try_telnet(device: Device, op: OpenPort, creds) -> None:
    """Very light-weight Telnet auth test using raw sockets. We avoid
    telnetlib (deprecated in 3.11, removed in 3.13)."""
    for user, pwd in creds:
        try:
            with socket.create_connection((device.ip, op.port),
                                          timeout=SOCKET_TIMEOUT) as s:
                s.settimeout(SOCKET_TIMEOUT)
                # read any banner / login: prompt
                try:
                    s.recv(512)
                except socket.timeout:
                    pass
                s.sendall((user + "\r\n").encode())
                try:
                    s.recv(512)
                except socket.timeout:
                    pass
                s.sendall((pwd + "\r\n").encode())
                try:
                    resp = s.recv(1024).decode("utf-8", errors="ignore").lower()
                except socket.timeout:
                    continue
                if any(tok in resp for tok in ("$", "#", ">", "welcome",
                                               "last login")) and \
                   not any(bad in resp for bad in ("incorrect", "fail",
                                                    "invalid", "denied")):
                    _record_success(device, op, "Telnet", user, pwd)
                    return
        except OSError:
            continue


def _try_ssh(device: Device, op: OpenPort, creds) -> None:
    try:
        import paramiko                                  # type: ignore
    except ImportError:
        return
    paramiko_logger = logging.getLogger("paramiko")
    paramiko_logger.setLevel(logging.CRITICAL)
    for user, pwd in creds:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                device.ip, port=op.port,
                username=user, password=pwd,
                timeout=SOCKET_TIMEOUT, allow_agent=False, look_for_keys=False,
                banner_timeout=SOCKET_TIMEOUT, auth_timeout=SOCKET_TIMEOUT,
            )
            client.close()
        except Exception:
            continue
        _record_success(device, op, "SSH", user, pwd)
        return


def _try_http_basic(device: Device, op: OpenPort, creds,
                    tls: bool = False, verify_ssl: bool = False) -> None:
    """Probe common admin paths with HTTP Basic. Only flags on 200/302 after
    previously seeing 401."""
    import urllib.request
    import urllib.error

    scheme = "https" if tls else "http"
    paths = ["/", "/login", "/admin", "/cgi-bin/luci", "/setup.cgi"]

    ctx = None
    if tls:
        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

    # First, confirm the endpoint actually requires auth.
    requires_auth = False
    for path in paths:
        url = f"{scheme}://{device.ip}:{op.port}{path}"
        req = urllib.request.Request(url)
        try:
            urllib.request.urlopen(req, timeout=SOCKET_TIMEOUT, context=ctx)
        except urllib.error.HTTPError as e:
            if e.code == 401:
                requires_auth = True
                break
        except (urllib.error.URLError, OSError, ssl.SSLError):
            continue
    if not requires_auth:
        return

    for user, pwd in creds:
        token = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        for path in paths:
            url = f"{scheme}://{device.ip}:{op.port}{path}"
            req = urllib.request.Request(url, headers={"Authorization": f"Basic {token}"})
            try:
                resp = urllib.request.urlopen(req, timeout=SOCKET_TIMEOUT, context=ctx)
                if 200 <= resp.status < 400:
                    _record_success(device, op, "HTTP", user, pwd)
                    return
            except urllib.error.HTTPError as e:
                if 200 <= e.code < 400:
                    _record_success(device, op, "HTTP", user, pwd)
                    return
                continue
            except (urllib.error.URLError, OSError, ssl.SSLError):
                continue


# ---------------------------------------------------------------------------
# Finding helper
# ---------------------------------------------------------------------------

def _record_success(device: Device, op: OpenPort, protocol: str,
                    user: str, pwd: str) -> None:
    score, vector, risk = score_preset("default_credentials")
    device.findings.append(Finding(
        title=f"Default {protocol} credentials accepted",
        description=(f"The {protocol} service on port {op.port} accepted the "
                     f"credential pair '{user}:{pwd or '<empty>'}'. This gives "
                     f"an attacker full control of the device and is the "
                     f"primary vector used by IoT-targeting malware such as Mirai."),
        remediation=("Immediately change to a strong, unique password on every "
                     "account. Disable unused services. Where possible, enable "
                     "certificate-based or MFA authentication."),
        risk=risk,
        cvss_score=score,
        cvss_vector=vector,
        owasp_iot=get_owasp("default_credentials"),
        target=f"{device.ip}:{op.port}",
        evidence=f"{user}:{'*' * max(len(pwd), 1)}",     # mask password
    ))
