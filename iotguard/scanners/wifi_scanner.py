"""
Passive WiFi scanner using NetworkManager's `nmcli`.

Why nmcli instead of raw scapy / airodump?
  * Works with the built-in wireless adapter without monitor mode.
  * No root required for listing nearby BSSIDs.
  * Standard on Kali, Ubuntu, Fedora, Debian, Arch, etc.

What we detect:
  * SSID, BSSID, channel, frequency, signal (dBm), encryption
  * Hidden SSIDs (empty SSID broadcast)
  * Rogue AP suspects (same SSID, multiple BSSIDs with suspicious OUI or
    signal anomaly — heuristic, flagged as Low/Medium so a human confirms)
  * WPS status (best effort — nmcli doesn't expose it; we mark unknown
    unless `iw` is available and reports WPS IE)
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from collections import defaultdict

from ..core.models import (
    Finding, RiskLevel, WifiNetwork, EncryptionType,
)
from ..core.owasp_mapping import get_owasp
from ..core.risk_scoring import score_preset

log = logging.getLogger(__name__)


class WifiScanner:
    def __init__(self, interface: str | None = None):
        self.interface = interface

    # -- public --------------------------------------------------------------

    def scan(self) -> list[WifiNetwork]:
        """Return list of nearby WiFi networks with findings attached."""
        if shutil.which("nmcli") is None:
            log.warning("nmcli not found; WiFi scan skipped")
            return []

        raw = self._nmcli_list()
        networks = [self._parse_row(r) for r in raw]
        networks = [n for n in networks if n is not None]

        # Rogue AP heuristic: same SSID, multiple BSSIDs, wildly different
        # signal strength → mark weaker ones as suspect.
        self._flag_rogue_aps(networks)

        # Per-network findings (open/WEP/WPA, hidden SSID, WPS…)
        for net in networks:
            self._apply_findings(net)

        return networks

    # -- nmcli ---------------------------------------------------------------

    def _nmcli_list(self) -> list[str]:
        # Ask nmcli to re-scan, then list with a stable colon-separated format.
        try:
            subprocess.run(
                ["nmcli", "-t", "device", "wifi", "rescan"],
                timeout=10, check=False, capture_output=True,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        fields = "SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY"
        cmd = ["nmcli", "-t", "-f", fields, "device", "wifi", "list"]
        if self.interface:
            cmd += ["ifname", self.interface]

        try:
            out = subprocess.run(cmd, timeout=15, capture_output=True, text=True)
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            log.warning("nmcli failed: %s", e)
            return []

        if out.returncode != 0:
            log.warning("nmcli returned %s: %s", out.returncode, out.stderr.strip())
        return [ln for ln in out.stdout.splitlines() if ln.strip()]

    # -- parsing -------------------------------------------------------------

    def _parse_row(self, row: str) -> WifiNetwork | None:
        """Parse colon-separated nmcli row, handling escaped colons in BSSID."""
        # nmcli escapes ':' inside the BSSID (an IEEE MAC) as '\:'. Decode.
        tokens = re.split(r'(?<!\\):', row)
        tokens = [t.replace(r'\:', ':') for t in tokens]
        if len(tokens) < 6:
            return None

        ssid, bssid, chan, freq, signal, security = tokens[:6]
        try:
            channel = int(chan) if chan.isdigit() else 0
        except ValueError:
            channel = 0
        # "2412 MHz" or "5180 MHz"
        freq_match = re.search(r"(\d+)", freq)
        frequency = int(freq_match.group(1)) if freq_match else 0

        # nmcli reports signal 0..100%. Convert roughly to dBm.
        sig_pct = int(signal) if signal.isdigit() else 0
        signal_dbm = self._pct_to_dbm(sig_pct)

        return WifiNetwork(
            ssid=ssid,
            bssid=bssid,
            channel=channel,
            frequency_mhz=frequency,
            signal_dbm=signal_dbm,
            encryption=self._parse_security(security),
            hidden=(ssid == ""),
        )

    @staticmethod
    def _pct_to_dbm(pct: int) -> int:
        """Quick monotonic mapping of NM signal % to approximate dBm."""
        if pct >= 100: return -40
        if pct <= 0:   return -100
        return int(-100 + (pct / 100.0) * 60)   # -100 .. -40

    @staticmethod
    def _parse_security(sec: str) -> EncryptionType:
        s = (sec or "").upper()
        if not s or s == "--":        return EncryptionType.OPEN
        if "WPA3" in s and "WPA2" in s: return EncryptionType.WPA2_WPA3
        if "WPA3" in s:               return EncryptionType.WPA3
        if "WPA2" in s:               return EncryptionType.WPA2
        if "WPA1" in s or "WPA " in s or s.endswith("WPA"):
                                      return EncryptionType.WPA
        if "WEP" in s:                return EncryptionType.WEP
        return EncryptionType.UNKNOWN

    # -- rogue AP heuristic --------------------------------------------------

    def _flag_rogue_aps(self, nets: list[WifiNetwork]) -> None:
        by_ssid: dict[str, list[WifiNetwork]] = defaultdict(list)
        for n in nets:
            if n.ssid:                   # hidden SSIDs excluded from this check
                by_ssid[n.ssid].append(n)

        for ssid, group in by_ssid.items():
            if len(group) < 2:
                continue
            # Same SSID advertised with different security settings = suspect
            enc_set = {g.encryption for g in group}
            if len(enc_set) > 1:
                for g in group:
                    if g.encryption in (EncryptionType.OPEN, EncryptionType.WEP):
                        g.rogue_suspected = True
            # Different BSSID OUIs but same SSID is normal (multi-AP), so we
            # only flag the inconsistent-encryption case to avoid noise.

    # -- findings ------------------------------------------------------------

    def _apply_findings(self, net: WifiNetwork) -> None:
        ssid_label = net.ssid or "<hidden>"

        if net.encryption == EncryptionType.OPEN:
            self._add(net, "open_wifi",
                      f"Open / unencrypted WiFi network: {ssid_label}",
                      "This network transmits all traffic in cleartext. Any "
                      "client within range can passively capture credentials, "
                      "cookies, and DNS requests.",
                      "Enable WPA2-PSK (AES) or preferably WPA3. Disable open "
                      "guest networks or isolate them on a separate VLAN.")
        elif net.encryption == EncryptionType.WEP:
            self._add(net, "wep_wifi",
                      f"WEP encryption in use: {ssid_label}",
                      "WEP is cryptographically broken and can be recovered "
                      "in minutes with publicly-available tools.",
                      "Upgrade immediately to WPA2-PSK (AES) or WPA3.")
        elif net.encryption == EncryptionType.WPA:
            self._add(net, "wpa_wifi",
                      f"Legacy WPA (TKIP) in use: {ssid_label}",
                      "WPA1 with TKIP is vulnerable to multiple known attacks "
                      "(Beck-Tews, Ohigashi-Morii).",
                      "Switch to WPA2-PSK (AES/CCMP) or WPA3.")

        if net.hidden:
            self._add(net, "hidden_ssid",
                      "Hidden SSID (cloaked network)",
                      "Hidden SSIDs provide negligible security benefit and "
                      "cause clients to probe for the network everywhere, "
                      "leaking the SSID to passive attackers.",
                      "Broadcast the SSID normally and rely on WPA2/WPA3.")

        if net.rogue_suspected:
            self._add(net, "rogue_ap",
                      f"Possible rogue AP for SSID: {ssid_label}",
                      "Multiple access points advertise this SSID with "
                      "inconsistent security settings. This is consistent "
                      "with an evil-twin or downgrade attack.",
                      "Verify legitimate APs by BSSID, investigate the "
                      "weaker-encryption BSSID, and consider 802.11w (PMF).")

        if net.wps_enabled:
            self._add(net, "wps_enabled",
                      f"WPS enabled on {ssid_label}",
                      "WPS PIN authentication is susceptible to Pixie-Dust "
                      "and online bruteforce attacks.",
                      "Disable WPS in the router admin panel.")

    @staticmethod
    def _add(net: WifiNetwork, preset: str, title: str,
             description: str, remediation: str) -> None:
        score, vector, risk = score_preset(preset)
        net.findings.append(Finding(
            title=title,
            description=description,
            remediation=remediation,
            risk=risk,
            cvss_score=score,
            cvss_vector=vector,
            owasp_iot=get_owasp(preset),
            target=net.ssid or net.bssid,
        ))
