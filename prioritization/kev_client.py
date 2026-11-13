"""Phase 2 -- CISA KEV client.

The Known Exploited Vulnerabilities (KEV) catalog lists CVEs that CISA has
confirmed are actively exploited in the wild. KEV membership is the single
strongest "fix this now" signal available, so it gets a large weight in the
priority score.

Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
No auth required. It's a single large JSON document, so we download it once
and cache it on disk (it changes a few times a week at most).
"""

from __future__ import annotations

import json
import time
import urllib.request
from pathlib import Path
from typing import Callable, Optional

KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
DEFAULT_CACHE = Path(__file__).resolve().parent.parent / "data" / "kev_cache.json"
CACHE_TTL_SECONDS = 24 * 3600  # refresh at most once a day.

# Injectable fetcher: (url) -> raw bytes. Swapped in tests.
Fetcher = Callable[[str], bytes]


def _http_fetch(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "devsecops-chain/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


class KEVClient:
    def __init__(
        self,
        cache_path: Optional[Path] = None,
        fetcher: Optional[Fetcher] = None,
        ttl: int = CACHE_TTL_SECONDS,
    ):
        self.cache_path = Path(cache_path) if cache_path else DEFAULT_CACHE
        self.fetcher = fetcher or _http_fetch
        self.ttl = ttl
        self._entries: Optional[dict[str, dict]] = None
        self._loaded_from: Optional[str] = None

    def _extract_entries(self, payload: dict) -> dict[str, dict]:
        """Map CVE ID -> the KEV metadata most useful for risk decisions."""
        entries: dict[str, dict] = {}
        for v in payload.get("vulnerabilities", []):
            if not isinstance(v, dict) or not v.get("cveID"):
                continue
            entries[v["cveID"]] = {
                "ransomware": str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
                "due_date": v.get("dueDate"),
                "date_added": v.get("dateAdded"),
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "name": v.get("vulnerabilityName"),
            }
        return entries

    def _load(self, force: bool = False) -> dict[str, dict]:
        if self._entries is not None and not force:
            return self._entries

        cache_valid = False
        if self.cache_path.exists():
            age = time.time() - self.cache_path.stat().st_mtime
            cache_valid = age < self.ttl
            try:
                payload = json.loads(self.cache_path.read_text(encoding="utf-8"))
                self._entries = self._extract_entries(payload)
                self._loaded_from = "cache"
            except (json.JSONDecodeError, OSError):
                self._entries = None

        # Fresh cache is authoritative; skip the network round-trip.
        if self._entries is not None and cache_valid:
            return self._entries

        # Cache missing or stale: attempt a fresh download.
        try:
            raw = self.fetcher(KEV_FEED_URL)
            payload = json.loads(raw.decode("utf-8"))
            self._entries = self._extract_entries(payload)
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_bytes(raw)
            self._loaded_from = "network"
        except Exception:
            # Offline: fall back to whatever cache we already loaded (may be None).
            if self._entries is None:
                self._entries = {}
                self._loaded_from = "empty"

        return self._entries

    def is_listed(self, cve_id: str) -> bool:
        return cve_id in self._load()

    def entry(self, cve_id: str) -> Optional[dict]:
        """KEV metadata for a CVE, or None if it isn't listed."""
        return self._load().get(cve_id)

    def known_ransomware(self, cve_id: str) -> bool:
        e = self.entry(cve_id)
        return bool(e and e.get("ransomware"))

    def due_date(self, cve_id: str) -> Optional[str]:
        e = self.entry(cve_id)
        return e.get("due_date") if e else None

    def listed_ids(self) -> set[str]:
        return set(self._load())

    @property
    def source(self) -> Optional[str]:
        """Where the current KEV set came from: 'cache', 'network', or 'empty'."""
        self._load()
        return self._loaded_from
