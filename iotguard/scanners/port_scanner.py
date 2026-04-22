"""
Port + service scanning with deep nmap NSE integration and exploit mapping.

Scan modes
----------
Fast (default without deep_scan):
    nmap -sT -sV -T4 --version-intensity 3 -Pn --open
    Falls back to pure-socket scan if nmap is absent.

Deep (deep_scan=True, needs root/CAP_NET_RAW):
    nmap -sS -sV -O -T4 --version-intensity 7 -Pn --open

Vuln scripts (run_vuln_scripts=True, slow but thorough):
    Appends --script=default,banner,http-server-header,ftp-anon,
                     ssh-auth-methods,http-auth-finder,snmp-info,
                     smb-security-mode
    When ALSO deep_scan=True, also adds:
                     vuln,auth,smb-vuln-*,ssl-*
"""

from __future__ import annotations

import logging
import re
import shutil
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable

from ..core.models import Device, Finding, OpenPort, RiskLevel
from ..core.owasp_mapping import get_owasp
from ..core.risk_scoring import score_preset, CVSSMetrics, calculate_base_score, score_to_risk

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Port list
# ─────────────────────────────────────────────────────────────────────────────

IOT_PORTS = [
    # Management
    21, 22, 23, 80, 81, 88, 443, 445, 8080, 8081, 8443, 8888, 9090,
    # IoT protocols
    1883, 8883,          # MQTT / MQTTS
    5683, 5684,          # CoAP
    502, 503,            # Modbus TCP
    # Camera / AV
    554, 8554, 7070, 8008, 8009,
    9000, 9001, 34567, 34599, 37777,   # DVR/NVR/Dahua
    # Printers
    9100, 515, 631,
    # File sharing / NAS
    2049, 111, 873, 548,
    # Windows / SMB / RDP
    135, 139, 445, 3389, 5985, 5986,
    # Database
    3306, 5432, 6379, 27017,
    # Remote access
    5900, 5901, 4899,    # VNC / RAdmin
    # Discovery / UPnP
    1900, 5353, 5357,
    # ISP backdoor
    7547,                # TR-069 / CWMP
    # Misc
    25, 53, 110, 143, 993, 995, 587,
    2323,                # Alt Telnet (Mirai)
    49152, 49153,
]


# ─────────────────────────────────────────────────────────────────────────────
# Known public exploit database
# ─────────────────────────────────────────────────────────────────────────────

KNOWN_EXPLOITS: dict[str, list[dict]] = {
    "telnet": [
        {"id": "CVE-2016-6563", "name": "Mirai Telnet default creds RCE",
         "type": "RCE", "public": True},
    ],
    "ftp": [
        {"id": "CVE-2010-1938", "name": "ProFTPD 1.3.x off-by-one RCE",
         "type": "RCE", "public": True},
    ],
    "http": [
        {"id": "CVE-2017-8225", "name": "GoAhead web server auth bypass",
         "type": "Auth Bypass", "public": True},
    ],
    "rtsp": [
        {"id": "CVE-2018-10661", "name": "Hikvision auth bypass via /Security/users/",
         "type": "Auth Bypass", "public": True},
    ],
    "snmp": [
        {"id": "CVE-2017-6736", "name": "Cisco IOS SNMP RCE",
         "type": "RCE", "public": True},
    ],
    "upnp": [
        {"id": "CVE-2020-12695", "name": "CallStranger UPnP SSRF/DDoS",
         "type": "SSRF", "public": True},
        {"id": "CVE-2013-0229",  "name": "MiniUPnPd buffer overflow",
         "type": "RCE", "public": True},
    ],
    "microsoft-ds": [
        {"id": "CVE-2017-0144", "name": "EternalBlue MS17-010",
         "type": "RCE", "public": True,
         "metasploit": "exploit/windows/smb/ms17_010_eternalblue"},
        {"id": "CVE-2020-0796", "name": "SMBGhost SMBv3 compression RCE",
         "type": "RCE", "public": True},
    ],
    "netbios-ssn": [
        {"id": "CVE-2017-0144", "name": "EternalBlue MS17-010",
         "type": "RCE", "public": True},
    ],
    "vnc": [
        {"id": "CVE-2006-2369", "name": "RealVNC authentication bypass",
         "type": "Auth Bypass", "public": True},
    ],
    "ssh": [
        {"id": "CVE-2018-10933", "name": "libssh server-side auth bypass",
         "type": "Auth Bypass", "public": True},
    ],
    "mysql": [
        {"id": "CVE-2012-2122", "name": "MySQL authentication bypass",
         "type": "Auth Bypass", "public": True},
    ],
    "redis": [
        {"id": "CVE-2022-0543", "name": "Redis Lua sandbox escape RCE",
         "type": "RCE", "public": True},
    ],
    "ms-wbt-server": [
        {"id": "CVE-2019-0708", "name": "BlueKeep RDP pre-auth RCE",
         "type": "RCE", "public": True,
         "metasploit": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce"},
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# NSE script name → (preset_name, display_title)
# ─────────────────────────────────────────────────────────────────────────────

_NSE_MAP: dict[str, tuple[str | None, str]] = {
    "ftp-anon":               ("ftp_anonymous",      "Anonymous FTP Login Permitted"),
    "http-default-accounts":  ("default_credentials","HTTP Default Credentials Found"),
    "snmp-brute":             ("weak_credentials",   "SNMP Weak Community String"),
    "ftp-brute":              ("weak_credentials",   "FTP Weak/Default Credentials"),
    "telnet-brute":           ("weak_credentials",   "Telnet Weak/Default Credentials"),
    "ssh-brute":              ("weak_credentials",   "SSH Weak Credentials"),
    "smb-vuln-ms17-010":      ("known_cve_high",     "EternalBlue MS17-010 (CVE-2017-0144)"),
    "smb-vuln-ms08-067":      ("known_cve_high",     "MS08-067 NetAPI RCE"),
    "smb-vuln-ms10-054":      ("known_cve_high",     "MS10-054 SMB RCE"),
    "smb-vuln-ms10-061":      ("known_cve_high",     "MS10-061 Print Spooler RCE"),
    "http-shellshock":        ("known_cve_high",     "Shellshock (CVE-2014-6271)"),
    "ssl-heartbleed":         ("known_cve_high",     "Heartbleed (CVE-2014-0160)"),
    "ssl-poodle":             ("known_cve_high",     "POODLE SSLv3 (CVE-2014-3566)"),
    "sslv2":                  ("weak_tls_cipher",    "SSLv2 Supported (insecure)"),
    "rdp-vuln-ms12-020":      ("known_cve_high",     "MS12-020 RDP DoS/RCE"),
    "realvnc-auth-bypass":    ("no_authentication",  "VNC Authentication Bypass"),
    "vnc-info":               ("no_authentication",  "VNC No Authentication"),
    "http-auth-finder":       ("http_admin_exposed", "HTTP Authentication Required"),
    "smb-security-mode":      ("smb_open",           "SMB Security Mode Assessment"),
    "ssh-auth-methods":       (None,                 "SSH Auth Methods Exposed"),
    "http-server-header":     (None,                 "HTTP Server Header"),
    "snmp-info":              ("snmp_public",        "SNMP Information Disclosure"),
}

_NSE_REMEDIATIONS: dict[str, str] = {
    "smb-vuln-ms17-010": "Apply MS17-010 patch immediately. Block port 445 at perimeter.",
    "ssl-heartbleed":    "Update OpenSSL ≥ 1.0.1g. Revoke and reissue all certificates.",
    "http-shellshock":   "Update bash. Disable CGI or sanitise env vars passed to scripts.",
    "ftp-anon":          "Disable anonymous FTP. Require authentication or use SFTP.",
    "http-default-accounts": "Change all default credentials immediately.",
    "rdp-vuln-ms12-020": "Apply MS12-020. Restrict RDP access to VPN/jump-host only.",
    "ssl-poodle":        "Disable SSLv3. Enforce TLS 1.2+.",
    "realvnc-auth-bypass": "Update VNC server. Require strong password authentication.",
}


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def scan_device(
    device: Device,
    ports: Iterable[int] | None = None,
    timeout: float = 1.0,
    deep_scan: bool = False,
    run_vuln_scripts: bool = False,
) -> None:
    """Port-scan a single device and attach findings in-place."""
    if not device.ip:
        return

    if shutil.which("nmap"):
        ok = _nmap_scan(device, ports, deep_scan=deep_scan,
                        run_vuln_scripts=run_vuln_scripts)
        if ok:
            _apply_service_findings(device)
            _apply_exploit_findings(device)
            return

    # nmap not available — pure-socket fallback
    _fallback_scan(device, list(ports or IOT_PORTS), timeout=timeout)
    _apply_service_findings(device)
    _apply_exploit_findings(device)


def scan_devices(
    devices: list[Device],
    ports: Iterable[int] | None = None,
    parallelism: int = 8,
    timeout: float = 1.0,
    deep_scan: bool = False,
    run_vuln_scripts: bool = False,
    progress_cb=None,
) -> None:
    """Parallel port scan across a list of devices."""
    total = len(devices)
    done  = 0
    with ThreadPoolExecutor(max_workers=parallelism) as ex:
        futures = {
            ex.submit(scan_device, d, ports, timeout, deep_scan, run_vuln_scripts): d
            for d in devices
        }
        for fut in as_completed(futures):
            done += 1
            if progress_cb:
                try:
                    progress_cb(done, total,
                                futures[fut].ip or futures[fut].display_name)
                except Exception:
                    pass


# ─────────────────────────────────────────────────────────────────────────────
# nmap scan path
# ─────────────────────────────────────────────────────────────────────────────

def _nmap_scan(device: Device, ports, deep_scan: bool,
               run_vuln_scripts: bool) -> bool:
    try:
        import nmap  # type: ignore
    except ImportError:
        log.info("python-nmap not installed; falling back to socket scan")
        return False

    port_arg = ",".join(str(p) for p in (ports or IOT_PORTS))

    if deep_scan:
        # SYN scan + version + OS (needs root/CAP_NET_RAW)
        nmap_args = "-sS -sV -O -T4 --version-intensity 7 -Pn --open"
    else:
        # TCP connect scan — works without root
        nmap_args = "-sT -sV -T4 --version-intensity 3 -Pn --open"

    if run_vuln_scripts:
        if deep_scan:
            # Full vuln suite when we have privileges
            nmap_args += (
                " --script=default,banner,http-server-header,"
                "ftp-anon,ssh-auth-methods,http-auth-finder,"
                "snmp-info,smb-security-mode,"
                "smb-vuln-ms17-010,smb-vuln-ms08-067,"
                "ssl-heartbleed,ssl-poodle,sslv2,"
                "realvnc-auth-bypass,vnc-info"
            )
        else:
            # Faster subset — safe scripts + targeted vuln checks
            nmap_args += (
                " --script=default,banner,http-server-header,"
                "ftp-anon,ssh-auth-methods,http-auth-finder,"
                "snmp-info,smb-security-mode"
            )

    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=device.ip, ports=port_arg, arguments=nmap_args,
                timeout=120)
    except Exception as exc:
        log.info("nmap scan failed for %s: %s", device.ip, exc)
        return False

    if device.ip not in nm.all_hosts():
        # Ran OK but host was down/filtered — nothing to parse
        return True

    host = nm[device.ip]

    # OS detection — guard against empty osmatch list
    osmatch_list = host.get("osmatch", [])
    if osmatch_list:
        best = osmatch_list[0]
        device.os_guess = (
            f"{best.get('name', '')} ({best.get('accuracy', '')}%)"
        )

    # Open ports
    for proto in host.all_protocols():
        for port in sorted(host[proto].keys()):
            info = host[proto][port]
            if info.get("state") not in ("open", "open|filtered"):
                continue
            banner = _compose_banner(info)
            op = OpenPort(
                port=int(port),
                protocol=proto,
                service=info.get("name", ""),
                product=info.get("product", ""),
                version=info.get("version", ""),
                banner=banner,
                state=info.get("state", "open"),
            )
            device.open_ports.append(op)
            if banner:
                device.services_banner[f"{proto}/{port}"] = banner

            # Per-port NSE scripts
            if run_vuln_scripts and info.get("script"):
                _parse_nse_scripts(device, info["script"],
                                   target=f"{device.ip}:{port}")

    # Host-level NSE scripts (python-nmap stores these as a list under 'hostscript')
    if run_vuln_scripts:
        hostscripts = nm[device.ip].get("hostscript", [])
        for hs in hostscripts:
            script_id = hs.get("id", "")
            output    = hs.get("output", "")
            if script_id and output:
                _parse_nse_scripts(device, {script_id: output},
                                   target=device.ip)

    return True


def _compose_banner(info: dict) -> str:
    parts = [str(info[k]) for k in ("product", "version", "extrainfo")
             if info.get(k)]
    return " ".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# NSE script output → Finding objects
# ─────────────────────────────────────────────────────────────────────────────

def _parse_nse_scripts(device: Device, scripts: dict[str, str],
                       target: str = "") -> None:
    target = target or device.ip
    existing_titles = {f.title for f in device.findings}

    for script_name, output in scripts.items():
        if not output:
            continue
        output_lower = output.lower()

        # Skip clean results
        if any(x in output_lower for x in
               ("not vulnerable", "check failed", " false", "disabled")):
            continue

        preset_name, title = _NSE_MAP.get(
            script_name,
            (None, script_name.replace("-", " ").title()),
        )

        # Skip purely informational scripts with no security implication
        if preset_name is None and script_name in ("http-server-header",
                                                    "ssh-auth-methods"):
            continue

        if title in existing_titles:
            continue

        cve_ids = re.findall(r"CVE-\d{4}-\d+", output, re.IGNORECASE)
        has_exploit = any(x in output_lower for x in
                          ("exploit", "metasploit", "msfmodule",
                           "exploitdb", "edb-id"))

        if preset_name:
            score, vector, risk = score_preset(preset_name)
            if has_exploit and risk.order < RiskLevel.HIGH.order:
                risk  = RiskLevel.HIGH
                score = max(score, 7.5)
                vector = ""
        else:
            m = re.search(r"CVSS[:\s]+(\d+\.?\d*)", output, re.IGNORECASE)
            score  = float(m.group(1)) if m else 5.0
            vector = ""
            risk   = score_to_risk(score)

        desc = _clean_nse_output(output)
        remed = _NSE_REMEDIATIONS.get(
            script_name,
            "Review the finding and apply the relevant vendor patches.",
        )

        device.findings.append(Finding(
            title=title,
            description=desc or f"NSE script '{script_name}' flagged a finding.",
            risk=risk,
            cvss_score=score,
            cvss_vector=vector,
            cve_ids=cve_ids,
            owasp_iot=get_owasp(preset_name) if preset_name else None,
            target=target,
            evidence=output[:400],
            remediation=remed,
        ))
        existing_titles.add(title)


def _clean_nse_output(output: str) -> str:
    """Return a short, clean summary from raw NSE output."""
    lines = [l.strip() for l in output.splitlines()
             if l.strip() and len(l.strip()) > 10]
    return " | ".join(lines[:3])[:300]


# ─────────────────────────────────────────────────────────────────────────────
# Pure-socket fallback scanner
# ─────────────────────────────────────────────────────────────────────────────

def _fallback_scan(device: Device, ports: list[int],
                   timeout: float = 1.0) -> None:
    for port in ports:
        if _tcp_open(device.ip, port, timeout):
            service, banner = _probe_banner(device.ip, port, timeout)
            device.open_ports.append(OpenPort(
                port=port, protocol="tcp",
                service=service, banner=banner, state="open",
            ))
            if banner:
                device.services_banner[f"tcp/{port}"] = banner


def _tcp_open(ip: str, port: int, timeout: float) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        s.close()


def _probe_banner(ip: str, port: int, timeout: float) -> tuple[str, str]:
    """Connect and grab a service banner with service-specific probes."""
    service = _guess_service(port)

    # TLS ports — use SSL directly
    if port in (443, 8443, 9443, 993, 995):
        return service, _tls_banner(ip, port, timeout)

    try:
        s = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return service, ""

    banner = ""
    try:
        s.settimeout(timeout)
        # HTTP: send a GET request to trigger the response headers
        if port in (80, 8080, 81, 8000, 8008, 8081, 8888, 9090):
            s.sendall(
                f"GET / HTTP/1.0\r\nHost: {ip}\r\n"
                f"User-Agent: IoTGuard/1.0\r\n\r\n".encode()
            )
        # Other services typically send a banner on connect — just receive
        raw = s.recv(512)
        banner = raw.decode("utf-8", errors="ignore").strip()
    except OSError:
        pass
    finally:
        s.close()

    return service, banner[:300]


def _tls_banner(ip: str, port: int, timeout: float) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as tls:
                version = tls.version() or ""
                cipher  = tls.cipher()
                cipher_name = cipher[0] if cipher else ""
                # Flag deprecated protocols explicitly
                if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                    return f"WEAK: {version} {cipher_name}"
                return f"{version} {cipher_name}"
    except ssl.SSLError as exc:
        return f"SSL Error: {exc}"
    except OSError:
        return ""


def _guess_service(port: int) -> str:
    return {
        21: "ftp",    22: "ssh",      23: "telnet",   25: "smtp",
        53: "dns",    80: "http",     81: "http",    110: "pop3",
        111: "rpcbind", 135: "msrpc", 137: "netbios-ns",
        139: "netbios-ssn", 143: "imap", 161: "snmp",
        443: "https", 445: "microsoft-ds", 502: "modbus",
        515: "printer", 554: "rtsp", 587: "smtp",
        631: "ipp",   873: "rsync", 993: "imaps", 995: "pop3s",
        1883: "mqtt", 1900: "upnp", 2049: "nfs",
        2323: "telnet", 3306: "mysql", 3389: "ms-wbt-server",
        5432: "postgresql", 5683: "coap", 5900: "vnc",
        5985: "winrm", 6379: "redis", 7547: "tr-069",
        8080: "http", 8443: "https", 8883: "mqtts",
        8554: "rtsp", 9100: "printer", 27017: "mongodb",
        34567: "dvr-web", 37777: "dahua",
    }.get(port, "")


# ─────────────────────────────────────────────────────────────────────────────
# Finding generation from open ports
# ─────────────────────────────────────────────────────────────────────────────

def _apply_service_findings(device: Device) -> None:  # noqa: C901 (complexity OK)
    """Iterate open ports and create risk Findings for dangerous services."""
    existing_titles = {f.title for f in device.findings}

    def _add(title, desc, remed, preset, port, banner="", cves=None):
        if title in existing_titles:
            return
        score, vector, risk = score_preset(preset)
        device.findings.append(Finding(
            title=title, description=desc, remediation=remed,
            risk=risk, cvss_score=score, cvss_vector=vector,
            owasp_iot=get_owasp(preset),
            target=f"{device.ip}:{port}",
            evidence=banner[:300],
            cve_ids=cves or [],
        ))
        existing_titles.add(title)

    def _add_custom(title, desc, remed, metrics, port, banner="", cves=None,
                    owasp_preset=None):
        if title in existing_titles:
            return
        score = calculate_base_score(metrics)
        risk  = score_to_risk(score)
        device.findings.append(Finding(
            title=title, description=desc, remediation=remed,
            risk=risk, cvss_score=score, cvss_vector=metrics.vector(),
            owasp_iot=get_owasp(owasp_preset) if owasp_preset else None,
            target=f"{device.ip}:{port}",
            evidence=banner[:300],
            cve_ids=cves or [],
        ))
        existing_titles.add(title)

    for op in device.open_ports:
        svc  = (op.service or _guess_service(op.port) or "").lower()
        port = op.port
        bnr  = (op.banner or "").lower()

        # ── Telnet (inc. Mirai's alt port 2323) ─────────────────────────────
        if svc in ("telnet",) or port in (23, 2323):
            _add(
                f"Telnet exposed on port {port}",
                "Telnet transmits credentials and session data in cleartext. "
                "Port 2323 is actively scanned by Mirai-variant botnets for "
                "default-credential exploitation.",
                "Disable Telnet. Use SSH. Block ports 23 and 2323 at the firewall.",
                "telnet_open", port, op.banner or "",
            )

        # ── FTP ──────────────────────────────────────────────────────────────
        elif svc == "ftp" or port == 21:
            if "anonymous" in bnr or "230 " in bnr or "login successful" in bnr:
                _add(
                    "Anonymous FTP login permitted",
                    "The FTP service accepts unauthenticated (anonymous) logins, "
                    "potentially exposing all stored files.",
                    "Disable anonymous FTP. Require authentication. Switch to SFTP/FTPS.",
                    "ftp_anonymous", port, op.banner or "",
                )
            else:
                _add(
                    f"FTP service exposed (port {port})",
                    "FTP transmits credentials and file contents in cleartext. "
                    "Frequently targeted for default-credential brute-force.",
                    "Switch to SFTP (port 22). Restrict access by IP. Disable FTP if unused.",
                    "ftp_open", port, op.banner or "",
                )

        # ── SNMP ─────────────────────────────────────────────────────────────
        elif svc == "snmp" or port == 161:
            _add(
                "SNMP service exposed",
                "Default SNMP v1/v2c community strings ('public', 'private') allow "
                "full device enumeration and configuration changes. SNMPv1/v2c are "
                "cleartext and unauthenticated.",
                "Use SNMPv3 with authentication and encryption. Change community strings. "
                "Restrict by ACL. Disable if not required.",
                "snmp_public", port, op.banner or "",
            )

        # ── SMB / NetBIOS ────────────────────────────────────────────────────
        elif svc in ("microsoft-ds", "netbios-ssn") or port in (139, 445):
            _add(
                f"SMB/NetBIOS exposed (port {port})",
                "SMB is the primary lateral-movement vector for ransomware. "
                "EternalBlue (MS17-010) exploits unpatched SMBv1. "
                "SMBGhost (CVE-2020-0796) affects SMBv3.",
                "Apply MS17-010/MS20-0796 patches. Disable SMBv1. "
                "Block ports 139/445 at the network perimeter.",
                "smb_open", port, op.banner or "",
                cves=["CVE-2017-0144", "CVE-2020-0796"],
            )

        # ── UPnP ─────────────────────────────────────────────────────────────
        elif svc in ("upnp", "ssdp") or port == 1900:
            _add(
                "UPnP/SSDP service exposed",
                "UPnP allows arbitrary port-forwarding injection (CallStranger "
                "CVE-2020-12695). Exposed UPnP is abused by malware for NAT "
                "traversal and amplification attacks.",
                "Disable UPnP in the router admin panel. Restrict to LAN only.",
                "upnp_exposed", port, op.banner or "",
                cves=["CVE-2020-12695"],
            )

        # ── MQTT (plaintext) ─────────────────────────────────────────────────
        elif svc == "mqtt" or port == 1883:
            _add_custom(
                f"MQTT broker exposed without TLS (port {port})",
                "An MQTT broker is accessible without authentication or encryption. "
                "An attacker can subscribe to all topics (intercepting sensor data) "
                "or publish malicious commands to actuators.",
                "Enable MQTT authentication. Use port 8883 (MQTTS/TLS). "
                "Restrict access by VLAN or firewall rule.",
                CVSSMetrics("N", "L", "N", "N", "U", "H", "H", "L"),
                port, op.banner or "", owasp_preset="telnet_open",
            )

        # ── RTSP ─────────────────────────────────────────────────────────────
        elif svc == "rtsp" or port in (554, 8554):
            _add(
                f"RTSP video stream exposed (port {port})",
                "RTSP camera streams frequently have no authentication or use "
                "default credentials. Live video is accessible to any network host. "
                "CVE-2018-10661 (Hikvision) allows unauthenticated access.",
                "Enable RTSP authentication. Restrict camera access to a VLAN. "
                "Use RTSPS (over TLS) where supported.",
                "cleartext_protocol", port, op.banner or "",
                cves=["CVE-2018-10661"],
            )

        # ── DVR / NVR web interfaces ─────────────────────────────────────────
        elif port in (34567, 34599, 37777):
            _add_custom(
                f"DVR/NVR management interface exposed (port {port})",
                "Dahua / generic DVR management ports are frequently targeted. "
                "CVE-2021-33044/33045 allow unauthenticated login on Dahua devices.",
                "Apply firmware updates. Change default credentials. "
                "Restrict management access to LAN only.",
                CVSSMetrics("N", "L", "N", "N", "U", "H", "H", "H"),
                port, op.banner or "",
                cves=["CVE-2021-33044", "CVE-2021-33045"],
                owasp_preset="http_admin_exposed",
            )

        # ── HTTP admin panels ────────────────────────────────────────────────
        elif svc in ("http", "http-proxy", "http-alt") or port in (
            80, 81, 8080, 8081, 8000, 8008, 8888, 9090
        ):
            admin_keywords = (
                "router", "admin", "login", "dvr", "camera", "realm=",
                "authorization", "dahua", "hikvision", "netgear", "linksys",
                "asus", "tp-link", "d-link", "mikrotik", "ubiquiti",
                "management", "configure", "dashboard",
            )
            if any(kw in bnr for kw in admin_keywords):
                _add(
                    f"Device admin interface exposed (port {port})",
                    "A web-based device management interface is reachable on the network. "
                    "IoT admin panels commonly ship with default credentials and "
                    "unauthenticated API endpoints.",
                    "Restrict admin access to LAN or management VLAN. "
                    "Change default credentials. Enable HTTPS.",
                    "http_admin_exposed", port, op.banner or "",
                )

        # ── VNC ──────────────────────────────────────────────────────────────
        elif svc == "vnc" or port in (5900, 5901):
            _add_custom(
                f"VNC remote desktop exposed (port {port})",
                "VNC provides full graphical remote access. Many IoT/embedded devices "
                "run VNC with no password or a trivially guessable default. "
                "CVE-2006-2369 (RealVNC) allows authentication bypass.",
                "Disable VNC if not required. Set a strong password. "
                "Restrict access by IP. Tunnel through SSH.",
                CVSSMetrics("N", "L", "N", "N", "U", "H", "H", "H"),
                port, op.banner or "",
                cves=["CVE-2006-2369"],
                owasp_preset="no_authentication",
            )

        # ── RDP ──────────────────────────────────────────────────────────────
        elif svc == "ms-wbt-server" or port == 3389:
            _add_custom(
                "RDP remote desktop exposed",
                "Remote Desktop Protocol is exposed to the network. "
                "BlueKeep (CVE-2019-0708) is a wormable pre-auth RCE. "
                "RDP brute-force is the leading ransomware entry vector.",
                "Restrict RDP to VPN/jump-host only. Apply all Windows patches. "
                "Enable Network Level Authentication (NLA).",
                CVSSMetrics("N", "L", "N", "N", "U", "H", "H", "H"),
                port, op.banner or "",
                cves=["CVE-2019-0708"],
                owasp_preset="telnet_open",
            )

        # ── Redis ────────────────────────────────────────────────────────────
        elif svc == "redis" or port == 6379:
            _add_custom(
                "Redis database exposed without authentication",
                "An unauthenticated Redis instance allows arbitrary data access, "
                "modification, and — by writing cron jobs or SSH keys — "
                "full remote code execution on the host.",
                "Bind Redis to 127.0.0.1 only. Set 'requirepass'. Use Redis ACLs. "
                "Block port 6379 at the firewall.",
                CVSSMetrics("N", "L", "N", "N", "U", "H", "H", "H"),
                port, op.banner or "",
                owasp_preset="no_authentication",
            )

        # ── TR-069 / CWMP ────────────────────────────────────────────────────
        elif port == 7547:
            _add_custom(
                "TR-069/CWMP management port exposed (port 7547)",
                "TR-069 is an ISP remote management protocol. Port 7547 was exploited "
                "in the 2016 Mirai Switcher campaign (CVE-2014-9222/9223) to take over "
                "Zyxel and Eir routers. Exposure suggests the device is ISP-managed.",
                "Contact your ISP. Apply router firmware updates immediately. "
                "Block port 7547 at the network edge if possible.",
                CVSSMetrics("N", "L", "N", "N", "U", "H", "H", "H"),
                port, op.banner or "",
                cves=["CVE-2014-9222", "CVE-2014-9223"],
                owasp_preset="http_admin_exposed",
            )

        # ── Modbus (ICS/SCADA) ────────────────────────────────────────────────
        elif svc == "modbus" or port == 502:
            _add_custom(
                "Modbus ICS/SCADA protocol exposed",
                "Modbus TCP has zero authentication. Any host can read sensor values "
                "and write coil/register values to control physical hardware directly.",
                "Isolate Modbus devices on a dedicated OT/ICS VLAN. "
                "Deploy a Modbus firewall/proxy that enforces function-code allow-lists.",
                CVSSMetrics("A", "L", "N", "N", "U", "H", "H", "H"),
                port, op.banner or "",
                owasp_preset="no_authentication",
            )

        # ── Weak/deprecated TLS ───────────────────────────────────────────────
        if "weak:" in (op.banner or "").lower():
            _add(
                f"Weak/deprecated TLS on port {port}",
                f"Service is using a deprecated protocol: {op.banner}. "
                "Vulnerable to POODLE, BEAST, DROWN and cipher-downgrade attacks.",
                "Disable SSLv2/3 and TLS 1.0/1.1. Enforce TLS 1.2+ with "
                "AEAD cipher suites (AES-GCM, ChaCha20-Poly1305).",
                "weak_tls_cipher", port, op.banner or "",
            )

    # Outdated firmware hint (year in banner)
    for op in device.open_ports:
        for year in range(2005, 2020):
            if str(year) in (op.banner or "") + (op.version or ""):
                title = f"Possibly outdated firmware/software ({year})"
                if title not in existing_titles:
                    score, vec, risk = score_preset("outdated_firmware")
                    device.findings.append(Finding(
                        title=title,
                        description=(
                            f"Service banner references {year}, indicating "
                            "potentially unpatched firmware or software."
                        ),
                        remediation="Check the vendor portal for firmware updates "
                                    "and apply the latest release.",
                        risk=risk, cvss_score=score, cvss_vector=vec,
                        owasp_iot=get_owasp("outdated_firmware"),
                        target=f"{device.ip}:{op.port}",
                        evidence=f"{op.product} {op.version} {op.banner}".strip(),
                    ))
                    existing_titles.add(title)
                break


def _apply_exploit_findings(device: Device) -> None:
    """
    For each open port, check if the running service has a known public exploit.
    Only adds an exploit finding if the service was actually found open
    (avoids adding exploit findings for services not confirmed running).
    """
    existing_titles = {f.title for f in device.findings}
    open_service_names = {
        (op.service or _guess_service(op.port) or "").lower()
        for op in device.open_ports
    }

    for svc_name, exploits in KNOWN_EXPLOITS.items():
        if svc_name.lower() not in open_service_names:
            continue
        for exploit in exploits:
            title = f"Known public exploit: {exploit['name']}"
            if title in existing_titles:
                continue
            exploit_type = exploit.get("type", "")
            risk = (RiskLevel.CRITICAL
                    if exploit_type == "RCE"
                    else RiskLevel.HIGH)
            m = CVSSMetrics("N", "L", "N", "N", "U", "H", "H", "H")
            score = calculate_base_score(m)
            msf = exploit.get("metasploit", "")
            remed = ("Apply vendor patches immediately. "
                     f"{'Metasploit module: ' + msf + '. ' if msf else ''}"
                     "Disable or firewall the service if a patch is unavailable.")
            device.findings.append(Finding(
                title=title,
                description=(
                    f"A public exploit for {exploit['id']} ({exploit_type}) "
                    f"targets {svc_name} on this device. "
                    "This can be executed without prior authentication."
                ),
                remediation=remed,
                risk=risk,
                cvss_score=score,
                cvss_vector=m.vector(),
                cve_ids=[exploit["id"]],
                owasp_iot=get_owasp("known_cve_high"),
                target=device.ip,
                evidence=f"Service: {svc_name} | Exploit: {exploit['id']}",
            ))
            existing_titles.add(title)
