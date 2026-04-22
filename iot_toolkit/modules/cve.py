"""
Module 5 — CVE Vulnerability Matcher
Queries the NVD API and caches results locally.
"""

import json
import os
import re
import time
import hashlib
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timedelta
from typing import List, Dict


# ── Severity colour map ───────────────────────────────────────
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}


class CVEMatcher:
    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, cache_dir: str = "data/cve_cache",
                 cache_ttl_hours: int = 24, log=None):
        self.cache_dir = cache_dir
        self.ttl       = timedelta(hours=cache_ttl_hours)
        self.log       = log
        os.makedirs(cache_dir, exist_ok=True)

    # ── Main match ─────────────────────────────────────────────

    def match(self, vendor: str, device_class: str, services: dict) -> List[Dict]:
        """Return list of CVEs matched against vendor + service versions."""
        cves = []

        # 1. Vendor-level CVEs
        if vendor and vendor.lower() not in ("unknown", ""):
            cves += self._query(vendor)

        # 2. Service / version CVEs (banner-based)
        for port, svc in services.items():
            version = svc.get("version", "")
            name    = svc.get("name", "")
            if version:
                cves += self._query_version(name, version)

        # Deduplicate by CVE ID, keep highest severity
        seen   = {}
        for c in cves:
            cid = c.get("id", "")
            if cid not in seen or (
                SEVERITY_ORDER.get(c.get("severity",""), 0) >
                SEVERITY_ORDER.get(seen[cid].get("severity",""), 0)
            ):
                seen[cid] = c

        return sorted(seen.values(),
                      key=lambda x: SEVERITY_ORDER.get(x.get("severity",""), 0),
                      reverse=True)

    # ── NVD API query ──────────────────────────────────────────

    def _query(self, keyword: str, max_results: int = 10) -> List[Dict]:
        """Query NVD by keyword with local cache."""
        cache_key = hashlib.md5(keyword.lower().encode()).hexdigest()
        cached    = self._cache_get(cache_key)
        if cached is not None:
            return cached

        params = urllib.parse.urlencode({
            "keywordSearch": keyword,
            "resultsPerPage": max_results,
        })
        url = f"{self.NVD_API}?{params}"

        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "IoT-SecurityScanner/1.0"})
            self.log and self.log.info(f"    NVD query: {keyword[:40]}")
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            results = self._parse_nvd(data)
            self._cache_set(cache_key, results)
            time.sleep(0.6)  # NVD rate limit: ~100 req/min without API key
            return results
        except urllib.error.HTTPError as e:
            if e.code == 403:
                self.log and self.log.warn("NVD rate-limited. Using cached data only.")
            return []
        except Exception as e:
            self.log and self.log.warn(f"NVD query failed ({keyword}): {e}")
            return self._offline_fallback(keyword)

    def _query_version(self, service: str, version: str) -> List[Dict]:
        """Query NVD with service+version string."""
        # Clean up version string for search
        search = f"{service} {version}".strip()
        # Remove trailing non-version characters
        search = re.sub(r"[^\w\s._-]", "", search)[:80]
        if len(search) < 4:
            return []
        return self._query(search, max_results=5)

    # ── Parser ─────────────────────────────────────────────────

    def _parse_nvd(self, data: dict) -> List[Dict]:
        results = []
        for vuln in data.get("vulnerabilities", []):
            cve_data = vuln.get("cve", {})
            cve_id   = cve_data.get("id", "")
            if not cve_id:
                continue

            # Description
            desc = ""
            for d in cve_data.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            # CVSS severity
            severity = "UNKNOWN"
            score    = None
            metrics  = cve_data.get("metrics", {})
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(metric_key, [])
                if metric_list:
                    cvss     = metric_list[0].get("cvssData", {})
                    score    = cvss.get("baseScore")
                    severity = cvss.get("baseSeverity", "UNKNOWN")
                    if not severity and score:
                        severity = self._score_to_severity(score)
                    break

            # References (look for exploit-db link)
            refs      = cve_data.get("references", [])
            exploit   = next((r["url"] for r in refs
                              if "exploit-db" in r.get("url","").lower()), "")

            published = cve_data.get("published", "")[:10]

            results.append({
                "id":          cve_id,
                "severity":    severity.upper(),
                "score":       score,
                "description": desc[:300],
                "published":   published,
                "exploit_url": exploit,
                "references":  [r["url"] for r in refs[:3]],
            })
        return results

    def _score_to_severity(self, score: float) -> str:
        if score >= 9.0:  return "CRITICAL"
        if score >= 7.0:  return "HIGH"
        if score >= 4.0:  return "MEDIUM"
        return "LOW"

    # ── Offline fallback CVE database ─────────────────────────

    def _offline_fallback(self, keyword: str) -> List[Dict]:
        """Static known CVEs for common IoT vendors when NVD is unreachable."""
        KNOWN = {
            "hikvision": [
                {"id": "CVE-2021-36260", "severity": "CRITICAL", "score": 9.8,
                 "description": "Unauthenticated RCE via web server in Hikvision cameras.",
                 "published": "2021-09-19",
                 "exploit_url": "https://www.exploit-db.com/exploits/50441",
                 "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-36260"]},
                {"id": "CVE-2017-7921",  "severity": "CRITICAL", "score": 10.0,
                 "description": "Authentication bypass in Hikvision cameras.",
                 "published": "2017-05-06", "exploit_url": "", "references": []},
            ],
            "dahua": [
                {"id": "CVE-2021-33044", "severity": "CRITICAL", "score": 9.8,
                 "description": "Authentication bypass in Dahua devices.",
                 "published": "2021-09-26", "exploit_url": "", "references": []},
            ],
            "tp-link": [
                {"id": "CVE-2023-1389",  "severity": "HIGH",     "score": 8.8,
                 "description": "Command injection in TP-Link Archer AX21.",
                 "published": "2023-03-15",
                 "exploit_url": "https://www.exploit-db.com/exploits/51462",
                 "references": []},
            ],
            "netgear": [
                {"id": "CVE-2021-45732", "severity": "HIGH",     "score": 8.8,
                 "description": "Buffer overflow in NETGEAR router management.",
                 "published": "2021-12-26", "exploit_url": "", "references": []},
            ],
            "dlink": [
                {"id": "CVE-2019-16920", "severity": "CRITICAL", "score": 9.8,
                 "description": "Unauthenticated RCE in D-Link routers.",
                 "published": "2019-09-27",
                 "exploit_url": "https://www.exploit-db.com/exploits/47538",
                 "references": []},
            ],
            "axis": [
                {"id": "CVE-2018-10660", "severity": "CRITICAL", "score": 9.8,
                 "description": "Shell command injection in Axis cameras.",
                 "published": "2018-09-24", "exploit_url": "", "references": []},
            ],
            "philips": [
                {"id": "CVE-2020-6007",  "severity": "HIGH",     "score": 7.9,
                 "description": "Philips Hue bridge Zigbee buffer overflow.",
                 "published": "2020-02-11", "exploit_url": "", "references": []},
            ],
            "ubiquiti": [
                {"id": "CVE-2021-22909", "severity": "HIGH",     "score": 7.2,
                 "description": "Command injection in Ubiquiti EdgeRouters.",
                 "published": "2021-05-19", "exploit_url": "", "references": []},
            ],
            "telnet": [
                {"id": "CVE-1999-0529",  "severity": "HIGH",     "score": 7.5,
                 "description": "Telnet transmits credentials in cleartext.",
                 "published": "1999-01-01", "exploit_url": "", "references": []},
            ],
            "mqtt": [
                {"id": "CVE-2020-13849", "severity": "HIGH",     "score": 7.5,
                 "description": "MQTT broker allows unauthenticated connections.",
                 "published": "2020-06-08", "exploit_url": "", "references": []},
            ],
        }
        kl = keyword.lower()
        for key, cves in KNOWN.items():
            if key in kl:
                return cves
        return []

    # ── Cache helpers ──────────────────────────────────────────

    def _cache_path(self, key: str) -> str:
        return os.path.join(self.cache_dir, f"{key}.json")

    def _cache_get(self, key: str):
        path = self._cache_path(key)
        if not os.path.exists(path):
            return None
        try:
            with open(path) as f:
                entry = json.load(f)
            cached_at = datetime.fromisoformat(entry["cached_at"])
            if datetime.now() - cached_at < self.ttl:
                return entry["data"]
        except Exception:
            pass
        return None

    def _cache_set(self, key: str, data: list):
        path = self._cache_path(key)
        try:
            with open(path, "w") as f:
                json.dump({"cached_at": datetime.now().isoformat(), "data": data}, f)
        except Exception:
            pass
