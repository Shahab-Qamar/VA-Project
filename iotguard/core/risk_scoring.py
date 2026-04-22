"""
CVSS 3.1 base score calculator + risk rating helper.

Implements the official CVSS v3.1 specification for base metrics
(spec: FIRST.org). We stick to base metrics since temporal and
environmental inputs are rarely available during a scan.

This mirrors the approach used in WebRecon Pro so reports across
your tools stay consistent.
"""

from __future__ import annotations

from dataclasses import dataclass
from .models import RiskLevel


# -- metric weights (CVSS 3.1 spec) ------------------------------------------

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}     # Attack Vector
AC = {"L": 0.77, "H": 0.44}                            # Attack Complexity
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED   = {"N": 0.85, "L": 0.68, "H": 0.50}
UI = {"N": 0.85, "R": 0.62}                            # User Interaction
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}                 # C/I/A impact


@dataclass
class CVSSMetrics:
    AV: str = "N"       # Network / Adjacent / Local / Physical
    AC: str = "L"       # Low / High
    PR: str = "N"       # None / Low / High
    UI: str = "N"       # None / Required
    S:  str = "U"       # Unchanged / Changed
    C:  str = "N"       # None / Low / High
    I:  str = "N"
    A:  str = "N"

    def vector(self) -> str:
        return (f"CVSS:3.1/AV:{self.AV}/AC:{self.AC}/PR:{self.PR}/UI:{self.UI}"
                f"/S:{self.S}/C:{self.C}/I:{self.I}/A:{self.A}")


def _round_up(x: float) -> float:
    """CVSS roundup: one decimal place, rounding up at 0.01 granularity."""
    int_input = int(x * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000
    return (int((int_input // 10_000) + 1)) / 10


def calculate_base_score(m: CVSSMetrics) -> float:
    """Return CVSS 3.1 base score 0.0 – 10.0."""
    pr_map = PR_CHANGED if m.S == "C" else PR_UNCHANGED
    av = AV[m.AV]; ac = AC[m.AC]; pr = pr_map[m.PR]; ui = UI[m.UI]
    c = CIA[m.C]; i = CIA[m.I]; a = CIA[m.A]

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if m.S == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    if m.S == "U":
        base = min(impact + exploitability, 10)
    else:
        base = min(1.08 * (impact + exploitability), 10)
    return _round_up(base)


def score_to_risk(score: float) -> RiskLevel:
    """Map a numeric CVSS score to a RiskLevel bucket (CVSS 3.1 severity)."""
    if score == 0.0:   return RiskLevel.INFO
    if score < 4.0:    return RiskLevel.LOW
    if score < 7.0:    return RiskLevel.MEDIUM
    if score < 9.0:    return RiskLevel.HIGH
    return RiskLevel.CRITICAL


# -- convenience presets for common IoT findings -----------------------------

PRESETS: dict[str, CVSSMetrics] = {
    # Authentication weaknesses
    "default_credentials":   CVSSMetrics("N", "L", "N", "N", "U", "H", "H", "H"),  # 9.8 Critical
    "no_authentication":     CVSSMetrics("N", "L", "N", "N", "U", "H", "H", "L"),  # 9.4
    "weak_credentials":      CVSSMetrics("N", "L", "N", "N", "U", "H", "H", "L"),  # 9.4

    # Cleartext / exposed services
    "telnet_open":           CVSSMetrics("N", "L", "N", "N", "U", "H", "H", "L"),  # 9.4
    "ftp_anonymous":         CVSSMetrics("N", "L", "N", "N", "U", "L", "L", "N"),  # 6.5
    "ftp_open":              CVSSMetrics("N", "L", "L", "N", "U", "L", "L", "N"),  # 5.4
    "http_admin_exposed":    CVSSMetrics("N", "L", "N", "N", "U", "L", "L", "N"),  # 6.5
    "upnp_exposed":          CVSSMetrics("N", "L", "N", "N", "U", "L", "L", "L"),  # 7.3
    "snmp_public":           CVSSMetrics("N", "L", "N", "N", "U", "L", "L", "N"),  # 6.5
    "smb_open":              CVSSMetrics("A", "L", "L", "N", "U", "L", "L", "L"),  # 6.3

    # WiFi
    "open_wifi":             CVSSMetrics("A", "L", "N", "N", "U", "H", "H", "L"),  # 8.3
    "wep_wifi":              CVSSMetrics("A", "L", "N", "N", "U", "H", "H", "L"),  # 8.3
    "wpa_wifi":              CVSSMetrics("A", "H", "N", "N", "U", "L", "L", "N"),  # 4.6
    "wps_enabled":           CVSSMetrics("A", "L", "N", "N", "U", "L", "L", "L"),  # 6.3
    "hidden_ssid":           CVSSMetrics("A", "L", "N", "N", "U", "N", "N", "N"),  # 0 Info
    "rogue_ap":              CVSSMetrics("A", "L", "N", "R", "C", "H", "H", "N"),  # 8.1

    # TLS
    "self_signed_cert":      CVSSMetrics("N", "H", "N", "R", "U", "L", "L", "N"),  # 4.2
    "expired_cert":          CVSSMetrics("N", "H", "N", "R", "U", "L", "L", "N"),  # 4.2
    "weak_tls_cipher":       CVSSMetrics("N", "H", "N", "N", "U", "L", "L", "N"),  # 5.9

    # Firmware / CVE
    "outdated_firmware":     CVSSMetrics("N", "L", "N", "N", "U", "L", "L", "L"),  # 7.3
    "known_cve_high":        CVSSMetrics("N", "L", "N", "N", "U", "H", "H", "H"),  # 9.8
}


def score_preset(name: str) -> tuple[float, str, RiskLevel]:
    """Return (score, vector, risk) for a named preset. Unknown → 0/Info."""
    m = PRESETS.get(name)
    if not m:
        return 0.0, "", RiskLevel.INFO
    s = calculate_base_score(m)
    return s, m.vector(), score_to_risk(s)


if __name__ == "__main__":   # quick sanity check
    for name in PRESETS:
        s, v, r = score_preset(name)
        print(f"{name:28s} {s:4.1f} {r.value:10s} {v}")
