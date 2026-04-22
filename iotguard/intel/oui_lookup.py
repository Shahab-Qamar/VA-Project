"""
MAC OUI (vendor) lookup.

Primary path: the `mac-vendor-lookup` Python package (async + offline).
Fallback path: a bundled small offline map of the most common IoT vendors
so the app is useful even before the IEEE list is fetched.

Call sequence:
    lookup_vendor("AA:BB:CC:DD:EE:FF") -> "Apple, Inc."
"""

from __future__ import annotations

import logging
import re
from functools import lru_cache

log = logging.getLogger(__name__)


# -- small built-in map for common IoT OUIs (first 6 hex chars, uppercase) ---
# Curated from publicly-registered IEEE prefixes. Used when the offline DB
# hasn't been populated yet.

_BUILTIN = {
    "B827EB": "Raspberry Pi Foundation",
    "DCA632": "Raspberry Pi Foundation",
    "E45F01": "Raspberry Pi Trading",
    "28CDC1": "Raspberry Pi Trading",
    "D83ADD": "Raspberry Pi Trading",

    "FCFBFB": "Cisco Systems",
    "00000C": "Cisco Systems",
    "001D70": "Cisco Systems",

    "F0F61C": "TP-Link Technologies",
    "50C7BF": "TP-Link Technologies",
    "C46E1F": "TP-Link Technologies",
    "98DA C4": "TP-Link Technologies",
    "AC84C6": "TP-Link Technologies",

    "D4CA6D": "D-Link International",
    "B8A386": "D-Link International",

    "EC086B": "Netgear",
    "204E7F": "Netgear",
    "C40415": "Netgear",

    "A4E975": "Asus",
    "F832E4": "Asustek Computer",
    "D017C2": "Asustek Computer",

    "38F9D3": "Apple, Inc.",
    "F0B479": "Apple, Inc.",
    "AC3C0B": "Apple, Inc.",
    "DC2B61": "Apple, Inc.",
    "00CDFE": "Apple, Inc.",

    "001788": "Philips Lighting (Hue)",
    "00178A": "Philips Lighting (Hue)",
    "ECB5FA": "Philips Lighting (Hue)",

    "44650D": "Amazon Technologies (Echo/FireTV)",
    "FCA183": "Amazon Technologies",
    "6C56976": "Amazon Technologies",

    "18B430": "Nest Labs",
    "64166D": "Nest Labs",

    "5CCF7F": "Espressif (ESP8266/ESP32)",
    "240AC4": "Espressif",
    "3C6105": "Espressif",
    "98F4AB": "Espressif",
    "EC64C9": "Espressif",

    "DC4F22": "Wireless-Tag Technology (Tuya)",
    "10521C": "Tuya Smart Inc",
    "D82C5E": "Tuya Smart Inc",

    "E0B94D": "Google",
    "6C968C": "Google (Home/Chromecast)",
    "F4F5D8": "Google",
    "F8B4E2": "Google Home",

    "A4DA22": "Xiaomi Communications",
    "F48B32": "Xiaomi Communications",
    "64CC2E": "Xiaomi Communications",

    "3C71BF": "Ring LLC",
    "A0D0DC": "Ring",

    "001132": "Synology",
    "90C4DD": "Asustor (NAS)",

    "BCDDC2": "Hangzhou Hikvision (Cameras)",
    "44194E": "Hangzhou Hikvision",
    "C0516F": "Hangzhou Hikvision",

    "4CEDFB": "Dahua Technology (Cameras)",
    "A0BD1D": "Dahua Technology",

    "F0E35A": "Samsung Electronics",
    "F4F5E8": "Samsung Electronics",
    "5C0A5B": "Samsung Electronics",

    "F8C1B6": "Sonos",
    "000E58": "Sonos",

    "B4E62D": "Shelly (Allterco Robotics)",
    "84CCA8": "Shelly (Allterco Robotics)",
}


def _normalize(mac: str) -> str:
    """Strip separators, upper, return first 6 hex chars."""
    if not mac:
        return ""
    hx = re.sub(r"[^0-9a-fA-F]", "", mac).upper()
    return hx[:6]


@lru_cache(maxsize=4096)
def lookup_vendor(mac: str) -> str:
    """Return best-effort vendor string; empty string if unknown.
    Returns the literal 'Randomized / Private' for locally-administered MACs
    (modern phones/laptops rotate these per-network for privacy)."""
    prefix = _normalize(mac)
    if not prefix:
        return ""

    # Detect locally-administered / randomized MAC.
    # Second hex digit of the first octet, bit 0x02 set => locally administered.
    try:
        first_octet = int(prefix[:2], 16)
        if first_octet & 0x02:
            return "Randomized / Private"
    except ValueError:
        pass

    # fast path: built-in curated map
    if prefix in _BUILTIN:
        return _BUILTIN[prefix]

    # optional richer path: mac_vendor_lookup offline DB
    try:
        from mac_vendor_lookup import MacLookup, VendorNotFoundError  # type: ignore
        try:
            return MacLookup().lookup(mac)
        except VendorNotFoundError:
            return ""
        except Exception as e:
            log.debug("mac_vendor_lookup failed for %s: %s", mac, e)
            return ""
    except ImportError:
        return ""


def classify_by_vendor(vendor: str) -> str | None:
    """Heuristic: map vendor string to a DeviceType value name."""
    if not vendor:
        return None
    v = vendor.lower()
    if "randomized" in v or "private" in v:      return "Phone / Tablet"
    if "raspberry" in v:                         return "Computer"
    if "cisco" in v or "tp-link" in v or "d-link" in v \
       or "netgear" in v or "asus" in v \
       or "huawei" in v or "mikrotik" in v \
       or "zte" in v or "ubiquiti" in v:         return "Router / Gateway"
    if "philips lighting" in v or "hue" in v:    return "Smart Bulb"
    if "tuya" in v or "shelly" in v:             return "Smart Plug"
    if "amazon" in v or "google home" in v \
       or "sonos" in v:                          return "Smart Speaker"
    if "nest" in v or "ring" in v:               return "IP Camera"
    if "hikvision" in v or "dahua" in v:         return "IP Camera"
    if "synology" in v or "asustor" in v:        return "NAS / Storage"
    if "apple" in v or "samsung" in v \
       or "xiaomi" in v or "oneplus" in v:       return "Phone / Tablet"
    if "micro-star" in v or "dell" in v \
       or "lenovo" in v or "hp inc" in v \
       or "hewlett" in v or "intel corporate" in v \
       or "liteon" in v or "asustek" in v:       return "Computer"
    if "espressif" in v:                         return "Generic IoT"
    return None


def classify_by_hostname(hostname: str) -> str | None:
    """Second-chance classification when MAC is randomized but hostname
    leaks device type (e.g. 'Samsung-Galaxy-S22.local', 'iPhone.lan')."""
    if not hostname:
        return None
    h = hostname.lower()
    if any(k in h for k in ("iphone", "ipad", "android", "galaxy",
                             "oneplus", "pixel", "redmi", "mi-phone")):
        return "Phone / Tablet"
    if any(k in h for k in ("macbook", "laptop", "desktop", "pc",
                             "thinkpad", "latitude", "inspiron")):
        return "Computer"
    if "watch" in h or "band" in h or "fit" in h:
        return "Wearable"
    if "tv" in h or "roku" in h or "chromecast" in h or "firestick" in h:
        return "Smart TV"
    if "printer" in h or "hp-" in h or "canon" in h or "brother" in h:
        return "Printer"
    if "cam" in h or "doorbell" in h:
        return "IP Camera"
    if "echo" in h or "alexa" in h or "google-home" in h or "nest-audio" in h:
        return "Smart Speaker"
    if "router" in h or "gateway" in h or "modem" in h or "ap-" in h:
        return "Router / Gateway"
    return None
