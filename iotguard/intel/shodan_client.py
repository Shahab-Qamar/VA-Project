"""
Shodan API client for internet-facing exposure checks.

Used by the Network Health panel to look up the user's public IP and show
whether their router has any externally-visible open ports / services —
the #1 risk vector for home networks.

Free tier allows `/shodan/host/{ip}` with a key. We cache results for 6
hours to stay well under rate limits.

API docs: https://developer.shodan.io/api
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


CACHE_PATH = Path.home() / ".iotguard" / "shodan_cache.db"
CACHE_TTL = 6 * 3600          # 6 hours


_SCHEMA = """
CREATE TABLE IF NOT EXISTS shodan_cache (
    ip          TEXT PRIMARY KEY,
    fetched_at  INTEGER NOT NULL,
    payload     TEXT NOT NULL
);
"""


class ShodanClient:
    def __init__(self, api_key: str = "",
                 cache_path: Path | str | None = None,
                 timeout: int = 8):
        self.api_key = (api_key or "").strip()
        self.timeout = timeout
        self.cache_path = Path(cache_path) if cache_path else CACHE_PATH
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.cache_path), check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # -- public --------------------------------------------------------------

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def host_info(self, ip: str) -> Optional[dict]:
        """Return simplified Shodan host info, or None on failure / no key."""
        if not self.configured or not ip:
            return None

        cached = self._read_cache(ip)
        if cached is not None:
            return cached

        fresh = self._fetch(ip)
        if fresh is not None:
            self._write_cache(ip, fresh)
        return fresh

    # -- cache ---------------------------------------------------------------

    def _read_cache(self, ip: str) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT fetched_at, payload FROM shodan_cache WHERE ip = ?",
            (ip,),
        ).fetchone()
        if not row:
            return None
        fetched_at, payload = row
        if (time.time() - fetched_at) > CACHE_TTL:
            return None
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            return None

    def _write_cache(self, ip: str, payload: dict) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO shodan_cache (ip, fetched_at, payload) "
            "VALUES (?, ?, ?)",
            (ip, int(time.time()), json.dumps(payload)),
        )
        self._conn.commit()

    # -- network -------------------------------------------------------------

    def _fetch(self, ip: str) -> Optional[dict]:
        url = (f"https://api.shodan.io/shodan/host/{urllib.parse.quote(ip)}"
               f"?key={urllib.parse.quote(self.api_key)}&minify=true")
        req = urllib.request.Request(url, headers={
            "User-Agent": "IoTGuard/1.0",
        })
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                # "No information available for that IP" — not an error.
                return {"ip": ip, "ports": [], "hostnames": [],
                        "vulns": [], "not_indexed": True}
            log.info("Shodan HTTP %s for %s", e.code, ip)
            return None
        except (urllib.error.URLError, TimeoutError, OSError,
                json.JSONDecodeError) as e:
            log.info("Shodan fetch failed for %s: %s", ip, e)
            return None

        return self._simplify(data)

    @staticmethod
    def _simplify(data: dict) -> dict:
        return {
            "ip":         data.get("ip_str", ""),
            "isp":        data.get("isp", ""),
            "org":        data.get("org", ""),
            "country":    data.get("country_name", ""),
            "city":       data.get("city", ""),
            "os":         data.get("os", "") or "",
            "ports":      sorted(data.get("ports", [])),
            "hostnames":  data.get("hostnames", []),
            "vulns":      list(data.get("vulns", []))[:20],
            "last_update":data.get("last_update", ""),
            "tags":       data.get("tags", []),
            "not_indexed": False,
        }
