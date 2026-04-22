"""
OWASP IoT Top 10 (2018) category definitions and finding → category mapping.

Each scanner module tags its findings with a preset key (e.g. "telnet_open",
"default_credentials") and this module resolves that key to the matching
OWASP IoT Top 10 category for the report.

Reference: https://owasp.org/www-project-internet-of-things/
"""

from __future__ import annotations


# -- category catalogue ------------------------------------------------------

OWASP_IOT_TOP_10 = {
    "I1": {
        "title": "Weak, Guessable, or Hardcoded Passwords",
        "description": "Use of easily bruteforced, publicly available, or "
                       "unchangeable credentials, including backdoors in "
                       "firmware or client software.",
    },
    "I2": {
        "title": "Insecure Network Services",
        "description": "Unneeded or insecure network services running on the "
                       "device itself, especially those exposed to the "
                       "internet, that compromise C/I/A.",
    },
    "I3": {
        "title": "Insecure Ecosystem Interfaces",
        "description": "Insecure web, backend API, cloud, or mobile interfaces "
                       "in the ecosystem outside of the device.",
    },
    "I4": {
        "title": "Lack of Secure Update Mechanism",
        "description": "Lack of ability to securely update the device, "
                       "including firmware validation, secure delivery, and "
                       "anti-rollback mechanisms.",
    },
    "I5": {
        "title": "Use of Insecure or Outdated Components",
        "description": "Use of deprecated or insecure software components / "
                       "libraries that could allow the device to be compromised.",
    },
    "I6": {
        "title": "Insufficient Privacy Protection",
        "description": "User's personal information stored on the device or "
                       "in the ecosystem is used insecurely, improperly, or "
                       "without permission.",
    },
    "I7": {
        "title": "Insecure Data Transfer and Storage",
        "description": "Lack of encryption or access control of sensitive "
                       "data anywhere in the ecosystem, including at rest, "
                       "in transit, or during processing.",
    },
    "I8": {
        "title": "Lack of Device Management",
        "description": "Lack of security support on devices deployed in "
                       "production, including asset management, update "
                       "management, and response capabilities.",
    },
    "I9": {
        "title": "Insecure Default Settings",
        "description": "Devices or systems shipped with insecure default "
                       "settings or lack the ability to make the system more "
                       "secure by restricting operators from modifying "
                       "configurations.",
    },
    "I10": {
        "title": "Lack of Physical Hardening",
        "description": "Lack of physical hardening measures allowing attackers "
                       "to gain sensitive information that can help in a "
                       "future remote attack or take local control.",
    },
}


# -- finding preset -> OWASP category ----------------------------------------

PRESET_TO_OWASP = {
    "default_credentials":   "I1",
    "weak_credentials":      "I1",
    "no_authentication":     "I1",

    "telnet_open":           "I2",
    "ftp_open":              "I2",
    "ftp_anonymous":         "I2",
    "http_admin_exposed":    "I2",
    "upnp_exposed":          "I2",
    "snmp_public":           "I2",
    "smb_open":              "I2",
    "open_wifi":             "I2",
    "wep_wifi":              "I2",
    "wpa_wifi":              "I2",
    "wps_enabled":           "I9",
    "hidden_ssid":           "I9",
    "rogue_ap":              "I3",

    "self_signed_cert":      "I7",
    "expired_cert":          "I7",
    "weak_tls_cipher":       "I7",
    "cleartext_protocol":    "I7",

    "outdated_firmware":     "I4",
    "known_cve_high":        "I5",
    "unsupported_device":    "I8",
}


def get_owasp(preset: str) -> str | None:
    """Return formatted 'I2 - Insecure Network Services' or None."""
    cat = PRESET_TO_OWASP.get(preset)
    if not cat:
        return None
    return f"{cat} - {OWASP_IOT_TOP_10[cat]['title']}"


def get_category_info(code: str) -> dict | None:
    return OWASP_IOT_TOP_10.get(code)
