"""Phase 2 -- EPSS client.

EPSS (Exploit Prediction Scoring System) estimates the probability that a
vulnerability will be exploited in the wild in the next 30 days (0.0-1.0).
This is a far better exploitation signal than CVSS severity alone.

API: https://api.first.org/data/v1/epss?cve=CVE-2023-XXXX,CVE-...
No auth required. Supports batch queries (comma-separated CVE IDs).

Results are cached on disk so repeated runs don't hammer the API and so the
pipeline degrades gracefully offline.
"""

from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable, Optional

EPSS_API = "https://api.first.org/data/v1/epss"
DEFAULT_CACHE = Path(__file__).resolve().parent.parent / "data" / "epss_cache.json"
CACHE_TTL_SECONDS = 7 * 24 * 3600  # EPSS updates daily; a week is plenty.

# Injectable HTTP fetcher: (url) -> parsed JSON dict. Swapped in tests.
Fetcher = Callable[[str], dict]


def _http_fetch(url: str, timeout: int = 30) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "devsecops-chain/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


class EPSSClient:
    def __init__(
        self,
        cache_path: Optional[Path] = None,
        fetcher: Optional[Fetcher] = None,
        ttl: int = CACHE_TTL_SECONDS,
    ):
        self.cache_path = Path(cache_path) if cache_path else DEFAULT_CACHE
        self.fetcher = fetcher or _http_fetch
        self.ttl = ttl
        self._cache: dict[str, dict] = self._load_cache()

    def _load_cache(self) -> dict[str, dict]:
        if self.cache_path.exists():
            try:
                return json.loads(self.cache_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _save_cache(self) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(
            json.dumps(self._cache, indent=2), encoding="utf-8"
        )

    def _is_fresh(self, entry: dict) -> bool:
        return (time.time() - entry.get("fetched_at", 0)) < self.ttl

    def _query_api(self, cve_ids: list[str]) -> dict[str, float]:
        """Fetch EPSS scores for the given CVE IDs in one batched request."""
        url = f"{EPSS_API}?{urllib.parse.urlencode({'cve': ','.join(cve_ids)})}"
        try:
            payload = self.fetcher(url)
        except Exception:
            # Network failure: caller falls back to cache/None.
            return {}
        scores: dict[str, float] = {}
        for row in payload.get("data", []):
            cve = row.get("cve")
            epss = row.get("epss")
            if cve and epss is not None:
                try:
                    scores[cve] = float(epss)
                except (TypeError, ValueError):
                    continue
        return scores

    def scores(self, cve_ids: list[str]) -> dict[str, Optional[float]]:
        """Return EPSS score (or None) for each CVE ID, using cache when fresh."""
        result: dict[str, Optional[float]] = {}
        to_fetch: list[str] = []

        for cve in cve_ids:
            entry = self._cache.get(cve)
            if entry and self._is_fresh(entry):
                result[cve] = entry.get("epss")
            else:
                to_fetch.append(cve)

        if to_fetch:
            fetched = self._query_api(to_fetch)
            now = time.time()
            for cve in to_fetch:
                if cve in fetched:
                    self._cache[cve] = {"epss": fetched[cve], "fetched_at": now}
                    result[cve] = fetched[cve]
                else:
                    # Keep stale cache value if we have one, else None.
                    stale = self._cache.get(cve)
                    result[cve] = stale.get("epss") if stale else None
            self._save_cache()

        return result

    def score(self, cve_id: str) -> Optional[float]:
        return self.scores([cve_id]).get(cve_id)
