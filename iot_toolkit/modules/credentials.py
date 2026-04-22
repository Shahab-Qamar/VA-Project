"""
Module 4 — Default Credential Tester
Tests SSH, Telnet, and HTTP web panels for default credentials.
⚠  For authorized penetration testing only.
"""

import socket
import time
import json
import os
import re
import base64
import urllib.request
import urllib.parse
import urllib.error
from typing import List, Dict


class CredentialTester:
    def __init__(self, creds_path: str = "data/default_credentials.json",
                 timeout: int = 3, dry_run: bool = False, log=None):
        self.timeout   = timeout
        self.dry_run   = dry_run
        self.log       = log
        self.creds     = self._load_creds(creds_path)
        self._rate_delay = 0.3  # seconds between attempts (avoid lockouts)

    # ── Credential loader ──────────────────────────────────────

    def _load_creds(self, path: str) -> List[Dict]:
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
        # Built-in common IoT default credentials
        return [
            {"user": "admin",     "pass": "admin"},
            {"user": "admin",     "pass": ""},
            {"user": "admin",     "pass": "1234"},
            {"user": "admin",     "pass": "12345"},
            {"user": "admin",     "pass": "password"},
            {"user": "admin",     "pass": "admin123"},
            {"user": "admin",     "pass": "888888"},
            {"user": "root",      "pass": "root"},
            {"user": "root",      "pass": ""},
            {"user": "root",      "pass": "toor"},
            {"user": "root",      "pass": "12345"},
            {"user": "root",      "pass": "vizxv"},        # Mirai default
            {"user": "root",      "pass": "xc3511"},       # Hikvision
            {"user": "root",      "pass": "jvbzd"},        # DVR default
            {"user": "root",      "pass": "anko"},         # set-top box
            {"user": "root",      "pass": "hi3518"},       # HiSilicon camera
            {"user": "root",      "pass": "7ujMko0admin"},
            {"user": "guest",     "pass": "guest"},
            {"user": "user",      "pass": "user"},
            {"user": "support",   "pass": "support"},
            {"user": "service",   "pass": "service"},
            {"user": "ubnt",      "pass": "ubnt"},         # Ubiquiti
            {"user": "pi",        "pass": "raspberry"},    # Raspberry Pi
            {"user": "Admin",     "pass": "Admin"},
            {"user": "supervisor","pass": "supervisor"},
        ]

    # ── Main dispatch ──────────────────────────────────────────

    def test(self, ip: str, open_ports: dict, services: dict) -> List[Dict]:
        """Test applicable protocols based on open ports."""
        findings = []

        if 23 in open_ports:
            findings += self._test_telnet(ip, 23)
        if 2323 in open_ports:
            findings += self._test_telnet(ip, 2323)
        if 22 in open_ports:
            findings += self._test_ssh(ip, 22)
        for port in (80, 8080, 8443, 443):
            if port in open_ports:
                findings += self._test_http(ip, port)

        return findings

    # ── Telnet ─────────────────────────────────────────────────

    def _test_telnet(self, ip: str, port: int) -> List[Dict]:
        findings = []
        self.log and self.log.info(f"    Telnet {ip}:{port}")

        for cred in self.creds:
            u, p = cred["user"], cred["pass"]
            if self.dry_run:
                self.log and self.log.info(f"      [DRY-RUN] would test {u}:{p}")
                continue
            try:
                result = self._telnet_auth(ip, port, u, p)
                if result:
                    findings.append({"protocol": "telnet", "port": port,
                                     "user": u, "pass": p, "status": "success"})
                    self.log and self.log.warn(f"      [!] MATCH telnet {u}:{p}")
                    break  # Stop after first match
            except Exception:
                pass
            time.sleep(self._rate_delay)
        return findings

    def _telnet_auth(self, ip: str, port: int, user: str, password: str) -> bool:
        """Low-level Telnet login via raw socket."""
        try:
            s = socket.socket()
            s.settimeout(self.timeout)
            s.connect((ip, port))
            time.sleep(0.5)

            # Strip Telnet IAC negotiations
            def read_until(prompt: bytes, timeout: float = 3.0) -> bytes:
                s.settimeout(timeout)
                buf = b""
                end = time.time() + timeout
                while time.time() < end:
                    try:
                        chunk = s.recv(128)
                        if not chunk:
                            break
                        # Strip IAC sequences
                        cleaned = b""
                        i = 0
                        while i < len(chunk):
                            if chunk[i] == 0xff and i + 2 < len(chunk):
                                i += 3
                            else:
                                cleaned += bytes([chunk[i]])
                                i += 1
                        buf += cleaned
                        if prompt.lower() in buf.lower():
                            return buf
                    except socket.timeout:
                        break
                return buf

            # Wait for login prompt
            banner = read_until(b"login:")
            if not banner:
                return False

            s.send(user.encode() + b"\r\n")
            time.sleep(0.3)
            s.send(password.encode() + b"\r\n")
            time.sleep(0.5)

            response = read_until(b"$", timeout=2)
            success_indicators = [b"#", b"$", b"~", b"last login", b"welcome"]
            return any(ind in response.lower() for ind in success_indicators)
        except Exception:
            return False
        finally:
            try:
                s.close()
            except Exception:
                pass

    # ── SSH ────────────────────────────────────────────────────

    def _test_ssh(self, ip: str, port: int) -> List[Dict]:
        findings = []
        self.log and self.log.info(f"    SSH {ip}:{port}")

        # Try paramiko if available; else note it
        try:
            import paramiko
        except ImportError:
            self.log and self.log.warn("      paramiko not installed — SSH testing skipped")
            self.log and self.log.warn("      Install with: pip install paramiko")
            return []

        for cred in self.creds:
            u, p = cred["user"], cred["pass"]
            if self.dry_run:
                self.log and self.log.info(f"      [DRY-RUN] would test SSH {u}:{p}")
                continue
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(ip, port=port, username=u, password=p,
                               timeout=self.timeout, allow_agent=False,
                               look_for_keys=False)
                client.close()
                findings.append({"protocol": "ssh", "port": port,
                                 "user": u, "pass": p, "status": "success"})
                self.log and self.log.warn(f"      [!] MATCH ssh {u}:{p}")
                break
            except paramiko.AuthenticationException:
                pass
            except Exception:
                break
            time.sleep(self._rate_delay)
        return findings

    # ── HTTP Web Panel ─────────────────────────────────────────

    def _test_http(self, ip: str, port: int) -> List[Dict]:
        findings = []
        scheme   = "https" if port in (443, 8443) else "http"
        base_url = f"{scheme}://{ip}:{port}"
        self.log and self.log.info(f"    HTTP {base_url}")

        # 1. HTTP Basic Auth
        findings += self._test_http_basic(base_url)
        # 2. Form-based login detection
        if not findings:
            findings += self._test_http_form(base_url)

        return findings

    def _test_http_basic(self, base_url: str) -> List[Dict]:
        findings = []
        for cred in self.creds:
            u, p = cred["user"], cred["pass"]
            if self.dry_run:
                self.log and self.log.info(f"      [DRY-RUN] HTTP Basic {u}:{p}")
                continue
            try:
                token = base64.b64encode(f"{u}:{p}".encode()).decode()
                req   = urllib.request.Request(
                    base_url,
                    headers={"Authorization": f"Basic {token}",
                             "User-Agent": "IoT-SecurityScanner/1.0"}
                )
                ctx = self._ssl_ctx()
                resp = urllib.request.urlopen(req, timeout=self.timeout, context=ctx)
                if resp.status in (200, 301, 302):
                    findings.append({"protocol": "http-basic", "port": 0,
                                     "user": u, "pass": p, "status": "success",
                                     "url": base_url})
                    self.log and self.log.warn(f"      [!] MATCH HTTP Basic {u}:{p}")
                    break
            except urllib.error.HTTPError as e:
                if e.code != 401:
                    break  # Not a Basic Auth protected URL
            except Exception:
                break
            time.sleep(self._rate_delay)
        return findings

    def _test_http_form(self, base_url: str) -> List[Dict]:
        """Detect and attempt common form-based login pages."""
        COMMON_LOGIN_PATHS = [
            "/login", "/admin/login", "/web/login", "/cgi-bin/login.cgi",
            "/webman/login.cgi", "/admin", "/manager/html",
        ]
        findings = []
        for path in COMMON_LOGIN_PATHS:
            url = base_url + path
            try:
                req  = urllib.request.Request(
                    url, headers={"User-Agent": "IoT-SecurityScanner/1.0"})
                ctx  = self._ssl_ctx()
                resp = urllib.request.urlopen(req, timeout=self.timeout, context=ctx)
                html = resp.read(4096).decode("utf-8", errors="replace")
                # Check for form with username/password fields
                if re.search(r'<input[^>]+(?:name=["\'](?:user|username|login)["\'])',
                             html, re.IGNORECASE):
                    if self.dry_run:
                        self.log and self.log.info(
                            f"      [DRY-RUN] Form login found at {path}")
                        return []
                    # Found a form — try first 5 creds
                    for cred in self.creds[:5]:
                        r = self._submit_form(base_url + path, html,
                                              cred["user"], cred["pass"])
                        if r:
                            findings.append({"protocol": "http-form", "port": 0,
                                             "user": cred["user"], "pass": cred["pass"],
                                             "status": "success", "url": base_url + path})
                            self.log and self.log.warn(
                                f"      [!] MATCH form {cred['user']}:{cred['pass']}")
                            return findings
                        time.sleep(self._rate_delay)
                    break
            except Exception:
                continue
        return findings

    def _submit_form(self, url: str, html: str, user: str, password: str) -> bool:
        """Submit a detected login form."""
        # Extract field names
        user_field = "username"
        pass_field = "password"
        m = re.search(r'<input[^>]+name=["\']([^"\']*(?:user|login)[^"\']*)["\']',
                      html, re.IGNORECASE)
        if m:
            user_field = m.group(1)
        m = re.search(r'<input[^>]+name=["\']([^"\']*(?:pass|pwd)[^"\']*)["\']',
                      html, re.IGNORECASE)
        if m:
            pass_field = m.group(1)

        data = urllib.parse.urlencode({user_field: user, pass_field: password}).encode()
        try:
            req  = urllib.request.Request(
                url, data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded",
                         "User-Agent": "IoT-SecurityScanner/1.0"})
            ctx  = self._ssl_ctx()
            resp = urllib.request.urlopen(req, timeout=self.timeout, context=ctx)
            body = resp.read(2048).decode("utf-8", errors="replace")
            # Heuristic: if response has no "invalid" / "error" and contains
            # typical logged-in indicators, treat as success
            fail_kw   = ["invalid", "incorrect", "failed", "error", "denied",
                         "unauthorized", "wrong"]
            success_kw = ["logout", "dashboard", "welcome", "settings", "admin panel"]
            body_lower = body.lower()
            has_fail    = any(kw in body_lower for kw in fail_kw)
            has_success = any(kw in body_lower for kw in success_kw)
            return has_success and not has_fail
        except Exception:
            return False

    def _ssl_ctx(self):
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        return ctx
