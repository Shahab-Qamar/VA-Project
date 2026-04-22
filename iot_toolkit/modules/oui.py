"""
Module 2 — OUI Manufacturer Identification
Matches MAC prefix to vendor and classifies device type.
"""

import json
import os
import re
import urllib.request
from typing import Tuple


# ── Device classification keywords ────────────────────────────
DEVICE_CLASSES = {
    "Camera 🎥": [
        "hikvision", "dahua", "axis", "amcrest", "reolink", "foscam",
        "hanwha", "vivotek", "avigilon", "bosch security", "pelco",
        "uniview", "tiandy", "kedacom", "wisenet",
    ],
    "Router / AP 📡": [
        "tp-link", "asus", "netgear", "linksys", "ubiquiti", "mikrotik",
        "cisco", "zyxel", "dlink", "d-link", "huawei", "belkin",
        "buffalo", "synology", "qnap", "aruba",
    ],
    "Smart Home 🏠": [
        "xiaomi", "philips", "amazon", "google", "nest", "ring",
        "ecobee", "lutron", "wemo", "lifx", "tuya", "shelly",
        "sonoff", "belkin", "samsung smartthings", "eve systems",
    ],
    "NAS / Storage 💾": [
        "western digital", "seagate", "synology", "qnap",
    ],
    "Smart TV / Media 📺": [
        "samsung", "lg electronics", "sony", "tcl", "hisense",
        "vizio", "roku", "nvidia",
    ],
    "Printer 🖨": [
        "brother", "hp inc", "hewlett-packard", "canon", "epson",
        "lexmark", "xerox", "ricoh",
    ],
    "Industrial IoT ⚙": [
        "siemens", "honeywell", "schneider", "rockwell", "advantech",
        "moxa", "wago", "beckhoff",
    ],
    "Unknown Device ❓": [],
}


class OUILookup:
    def __init__(self, db_path: str = "data/oui_database.json", log=None):
        self.log     = log
        self.db_path = db_path
        self.db      = self._load_db()

    # ── Database loading ───────────────────────────────────────

    def _load_db(self) -> dict:
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path) as f:
                    return json.load(f)
            except json.JSONDecodeError:
                pass

        self.log and self.log.info("OUI database not found — using built-in sample")
        return self._builtin_oui()

    def _builtin_oui(self) -> dict:
        """Compact built-in OUI table for common IoT vendors."""
        return {
            "00:00:5e": "IANA",
            "00:01:c7": "Cisco Systems",
            "00:04:4b": "NVIDIA",
            "00:05:69": "VMware",
            "00:09:17": "D-Link",
            "00:0c:29": "VMware",
            "00:0e:35": "Intel",
            "00:17:88": "Philips Lighting",
            "00:18:ae": "D-Link",
            "00:1b:21": "Intel",
            "00:1c:b3": "Apple",
            "00:1d:0f": "ASUS",
            "00:1d:7e": "Cisco-Linksys",
            "00:1e:58": "D-Link",
            "00:21:27": "Hikvision",
            "00:23:54": "Hikvision",
            "00:24:be": "Hikvision",
            "00:26:e9": "Huawei",
            "00:50:56": "VMware",
            "00:50:c2": "DAHUA",
            "14:cf:92": "TP-Link",
            "18:a6:f7": "TP-Link",
            "1c:3b:e4": "Ubiquiti",
            "24:a4:3c": "Ubiquiti",
            "28:6c:07": "Xiaomi",
            "2c:56:dc": "Xiaomi",
            "34:ce:00": "Xiaomi",
            "38:26:2a": "Hikvision",
            "40:31:3c": "Hikvision",
            "44:d9:e7": "TP-Link",
            "50:c7:bf": "TP-Link",
            "54:a7:03": "Xiaomi",
            "58:ef:68": "Dahua",
            "5c:e9:1e": "Dahua",
            "60:38:e0": "Reolink",
            "6c:40:08": "Philips Hue (Signify)",
            "70:70:0d": "Samsung",
            "74:da:38": "ASUS",
            "78:45:61": "Amazon",
            "7c:01:91": "Amazon",
            "80:35:c1": "Amazon",
            "84:d6:d0": "TP-Link",
            "88:c3:97": "MikroTik",
            "8c:ec:7b": "Axis Communications",
            "9c:a5:25": "Apple",
            "a0:40:a0": "Samsung",
            "ac:84:c9": "ASUS",
            "b0:7f:b9": "TP-Link",
            "b4:fb:e4": "Ubiquiti",
            "c0:4a:00": "Cisco",
            "c8:3a:35": "Tenda",
            "cc:32:e5": "Samsung",
            "d4:6e:5c": "Synology",
            "d8:97:ba": "TP-Link",
            "dc:ef:09": "Shenzhen Dajiang (DJI)",
            "e0:cb:4e": "Xiaomi",
            "e4:fa:c4": "Netgear",
            "ec:08:6b": "TP-Link",
            "f0:18:98": "Hikvision",
            "f4:31:c3": "Ring (Amazon)",
            "fc:77:74": "Xiaomi",
        }

    # ── Lookup ─────────────────────────────────────────────────

    def lookup(self, mac: str) -> Tuple[str, str]:
        """
        Return (vendor_name, device_class) for a given MAC address.
        """
        if not mac or mac.lower() in ("unknown", "ff:ff:ff:ff:ff:ff"):
            return ("Unknown", "Unknown Device ❓")

        # Normalise to lowercase colon notation
        mac_clean = mac.lower().replace("-", ":").replace(".", ":")

        # Try /24, /20, /28 prefixes
        for prefix_len in (3, 2):
            parts  = mac_clean.split(":")
            prefix = ":".join(parts[:prefix_len])
            vendor = self.db.get(prefix, "")
            if vendor:
                return (vendor, self._classify(vendor))

        return ("Unknown", "Unknown Device ❓")

    def _classify(self, vendor: str) -> str:
        """Map vendor string to device class."""
        v = vendor.lower()
        for class_name, keywords in DEVICE_CLASSES.items():
            if any(kw in v for kw in keywords):
                return class_name
        return "Unknown Device ❓"

    # ── Optional: download full IEEE OUI database ──────────────

    def download_oui_db(self, save_path: str = None) -> bool:
        """
        Download and parse the full IEEE OUI registry.
        Saves as JSON to self.db_path (or save_path).
        Takes ~30 seconds — run once at setup.
        """
        url  = "https://standards-oui.ieee.org/oui/oui.txt"
        path = save_path or self.db_path
        os.makedirs(os.path.dirname(path), exist_ok=True)

        try:
            self.log and self.log.info("Downloading IEEE OUI database…")
            with urllib.request.urlopen(url, timeout=30) as resp:
                content = resp.read().decode("utf-8", errors="replace")

            db = {}
            pattern = re.compile(r"([0-9A-F]{6})\s+\(base 16\)\s+(.+)")
            for m in pattern.finditer(content):
                raw    = m.group(1)
                vendor = m.group(2).strip()
                prefix = ":".join(raw[i:i+2].lower() for i in range(0, 6, 2))
                db[prefix] = vendor

            with open(path, "w") as f:
                json.dump(db, f, indent=2)

            self.db = db
            self.log and self.log.success(f"OUI database saved ({len(db)} entries) → {path}")
            return True

        except Exception as e:
            self.log and self.log.warn(f"OUI download failed: {e}")
            return False
