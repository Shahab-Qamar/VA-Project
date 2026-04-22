"""
Persistent per-device metadata keyed by MAC address.

Fing-like: when a user renames a device ("Dad's phone") or adds notes, that
label sticks across scans. This store is separate from the scan history DB
because the lifecycle is different — metadata is one row per MAC, scans are
one row per scan run.

Schema:
    mac           primary key, uppercase
    custom_name   user label
    notes         free-form text
    first_seen    earliest timestamp we ever saw this MAC
    last_seen     updated every scan
    device_type   user-confirmed type (overrides auto-classification)
    pinned        1 if user flagged as trusted/known
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


DEFAULT_PATH = Path.home() / ".iotguard" / "devices.db"


_SCHEMA = """
CREATE TABLE IF NOT EXISTS device_metadata (
    mac          TEXT PRIMARY KEY,
    custom_name  TEXT DEFAULT '',
    notes        TEXT DEFAULT '',
    first_seen   TEXT DEFAULT '',
    last_seen    TEXT DEFAULT '',
    device_type  TEXT DEFAULT '',
    pinned       INTEGER DEFAULT 0
);
"""


class DeviceMetadataStore:
    def __init__(self, path: Path | str | None = None):
        self.path = Path(path) if path else DEFAULT_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # -- read ----------------------------------------------------------------

    def get(self, mac: str) -> dict:
        if not mac:
            return {}
        key = mac.upper()
        row = self._conn.execute(
            "SELECT mac, custom_name, notes, first_seen, last_seen, "
            "device_type, pinned FROM device_metadata WHERE mac = ?",
            (key,),
        ).fetchone()
        return dict(row) if row else {}

    def all_macs(self) -> list[str]:
        cur = self._conn.execute("SELECT mac FROM device_metadata")
        return [r["mac"] for r in cur.fetchall()]

    # -- write ---------------------------------------------------------------

    def upsert_seen(self, mac: str) -> None:
        """Bump last_seen and set first_seen if missing."""
        if not mac:
            return
        key = mac.upper()
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._conn.execute(
            """INSERT INTO device_metadata (mac, first_seen, last_seen)
               VALUES (?, ?, ?)
               ON CONFLICT(mac) DO UPDATE SET last_seen = excluded.last_seen""",
            (key, now, now),
        )
        self._conn.commit()

    def set_custom_name(self, mac: str, name: str) -> None:
        if not mac:
            return
        self._ensure_row(mac)
        self._conn.execute(
            "UPDATE device_metadata SET custom_name = ? WHERE mac = ?",
            (name, mac.upper()),
        )
        self._conn.commit()

    def set_notes(self, mac: str, notes: str) -> None:
        if not mac:
            return
        self._ensure_row(mac)
        self._conn.execute(
            "UPDATE device_metadata SET notes = ? WHERE mac = ?",
            (notes, mac.upper()),
        )
        self._conn.commit()

    def set_pinned(self, mac: str, pinned: bool) -> None:
        if not mac:
            return
        self._ensure_row(mac)
        self._conn.execute(
            "UPDATE device_metadata SET pinned = ? WHERE mac = ?",
            (1 if pinned else 0, mac.upper()),
        )
        self._conn.commit()

    def set_device_type(self, mac: str, device_type: str) -> None:
        if not mac:
            return
        self._ensure_row(mac)
        self._conn.execute(
            "UPDATE device_metadata SET device_type = ? WHERE mac = ?",
            (device_type, mac.upper()),
        )
        self._conn.commit()

    def _ensure_row(self, mac: str) -> None:
        key = mac.upper()
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._conn.execute(
            """INSERT INTO device_metadata (mac, first_seen, last_seen)
               VALUES (?, ?, ?)
               ON CONFLICT(mac) DO NOTHING""",
            (key, now, now),
        )
        self._conn.commit()

    # -- bulk helper used by scan pipeline -----------------------------------

    def apply_to_devices(self, devices) -> None:
        """Merge stored metadata into a list of Device objects in-place and
        bump last_seen for each MAC present."""
        from .models import DeviceType
        for dev in devices:
            if not dev.mac:
                continue
            self.upsert_seen(dev.mac)
            meta = self.get(dev.mac)
            if not meta:
                continue
            if meta.get("custom_name"):
                dev.custom_name = meta["custom_name"]
            if meta.get("notes"):
                dev.notes = meta["notes"]
            if meta.get("first_seen"):
                dev.first_seen = meta["first_seen"]
            if meta.get("device_type"):
                try:
                    dev.device_type = DeviceType(meta["device_type"])
                except (ValueError, KeyError):
                    pass
