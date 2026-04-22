"""
CVE lookup against the NVD 2.0 REST API with a local SQLite cache.

NVD API docs: https://nvd.nist.gov/developers/vulnerabilities

Design notes:
  * We call the NVD API by keyword (vendor + product + optional version).
    This is less precise than a CPE lookup but doesn't require the caller
    to already know the CPE URI.
  * Results are cached keyed on the query string, because NVD imposes a
    public rate limit of 5 req / 30s (50 with an API key).
  * Network failures degrade gracefully: return cached data if we have it,
    or an empty list otherwise. The GUI stays responsive either way.

Typical usage (sync, from a worker thread):
    lookup = CVELookup()
    matches = lookup.query("dlink dir-825", max_results=5)
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Optional

import urllib.request
import urllib.parse
import urllib.error

log = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_PATH = Path.home() / ".iotguard" / "cve_cache.db"
CACHE_TTL_SECONDS = 14 * 24 * 3600      # 14 days


_SCHEMA = """
CREATE TABLE IF NOT EXISTS cve_cache (
    query       TEXT PRIMARY KEY,
    fetched_at  INTEGER NOT NULL,
    payload     TEXT NOT NULL
);
"""


class CVELookup:
    def __init__(self, api_key: str | None = None,
                 cache_path: Path | str | None = None,
                 timeout: int = 8):
        self.api_key = api_key
        self.timeout = timeout
        self.cache_path = Path(cache_path) if cache_path else CACHE_PATH
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.cache_path), check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # -- public API ----------------------------------------------------------

    def query(self, keyword: str, max_results: int = 5) -> list[dict]:
        """Return a list of simplified CVE dicts matching the keyword."""
        keyword = (keyword or "").strip().lower()
        if not keyword:
            return []

        cached = self._read_cache(keyword)
        if cached is not None:
            return cached[:max_results]

        fresh = self._fetch_from_nvd(keyword, max_results)
        if fresh is not None:
            self._write_cache(keyword, fresh)
            return fresh[:max_results]

        # Network failure and no cache — return empty rather than crashing.
        return []

    def close(self) -> None:
        self._conn.close()

    # -- cache internals -----------------------------------------------------

    def _read_cache(self, key: str) -> Optional[list[dict]]:
        row = self._conn.execute(
            "SELECT fetched_at, payload FROM cve_cache WHERE query = ?",
            (key,)
        ).fetchone()
        if not row:
            return None
        fetched_at, payload = row
        if (time.time() - fetched_at) > CACHE_TTL_SECONDS:
            return None
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            return None

    def _write_cache(self, key: str, payload: list[dict]) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO cve_cache (query, fetched_at, payload) "
            "VALUES (?, ?, ?)",
            (key, int(time.time()), json.dumps(payload))
        )
        self._conn.commit()

    # -- network -------------------------------------------------------------

    def _fetch_from_nvd(self, keyword: str, max_results: int) -> Optional[list[dict]]:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(max_results * 2, 20),
        }
        url = f"{NVD_URL}?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(url, headers={
            "User-Agent": "IoTGuard/1.0 (+security research; lab use)",
        })
        if self.api_key:
            req.add_header("apiKey", self.api_key)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
            log.info("NVD fetch failed for '%s': %s", keyword, e)
            return None
        except json.JSONDecodeError as e:
            log.info("NVD returned invalid JSON: %s", e)
            return None

        return [self._simplify(v) for v in data.get("vulnerabilities", [])]

    @staticmethod
    def _simplify(entry: dict) -> dict:
        """Keep only the fields we actually render."""
        cve = entry.get("cve", {})
        descs = cve.get("descriptions", [])
        desc_en = next((d["value"] for d in descs if d.get("lang") == "en"), "")

        metrics = cve.get("metrics", {})
        score = 0.0
        severity = ""
        vector = ""
        for mkey in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if mkey in metrics and metrics[mkey]:
                m = metrics[mkey][0].get("cvssData", {})
                score = m.get("baseScore", 0.0)
                severity = m.get("baseSeverity", "") or metrics[mkey][0].get("baseSeverity", "")
                vector = m.get("vectorString", "")
                break

        return {
            "id":          cve.get("id", ""),
            "description": desc_en[:500],
            "score":       score,
            "severity":    severity,
            "vector":      vector,
            "published":   cve.get("published", "")[:10],
        }
