"""Phase 3 -- CVE context retrieval.

Fetches the official CVE description and metadata from the NVD API 2.0 so the
explanation engine has authoritative grounding instead of relying on the LLM's
parametric memory (which hallucinates CVE details).

API: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-XXXX-YYYY
No auth required (a key raises rate limits but isn't needed for a class project).

Results are cached on disk; NVD data for a given CVE is effectively static.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_CACHE = Path(__file__).resolve().parent.parent / "data" / "nvd_cache.json"

Fetcher = Callable[[str], dict]


def _http_fetch(url: str, timeout: int = 30) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "devsecops-chain/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


@dataclass
class CVEContext:
    cve_id: str
    description: Optional[str] = None
    published: Optional[str] = None
    cvss_v3: Optional[float] = None
    cwe_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "published": self.published,
            "cvss_v3": self.cvss_v3,
            "cwe_ids": self.cwe_ids,
            "references": self.references,
        }


def _english_description(descriptions: list[dict]) -> Optional[str]:
    for entry in descriptions or []:
        if entry.get("lang") == "en":
            return entry.get("value")
    # Fall back to the first description regardless of language.
    if descriptions:
        return descriptions[0].get("value")
    return None


def _extract_cwe(weaknesses: list[dict]) -> list[str]:
    cwes: list[str] = []
    for w in weaknesses or []:
        for desc in w.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-") and val not in cwes:
                cwes.append(val)
    return cwes


def _extract_cvss_v3(metrics: dict) -> Optional[float]:
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key)
        if entries:
            score = entries[0].get("cvssData", {}).get("baseScore")
            if isinstance(score, (int, float)):
                return float(score)
    return None


def parse_nvd_response(cve_id: str, payload: dict) -> Optional[CVEContext]:
    """Turn one NVD API response into a CVEContext, or None if not found."""
    vulns = payload.get("vulnerabilities") or []
    if not vulns:
        return None
    cve = vulns[0].get("cve", {})
    metrics = cve.get("metrics", {})
    refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]
    return CVEContext(
        cve_id=cve.get("id", cve_id),
        description=_english_description(cve.get("descriptions", [])),
        published=cve.get("published"),
        cvss_v3=_extract_cvss_v3(metrics),
        cwe_ids=_extract_cwe(cve.get("weaknesses", [])),
        references=refs[:5],
    )


class NVDClient:
    def __init__(
        self,
        cache_path: Optional[Path] = None,
        fetcher: Optional[Fetcher] = None,
        api_key: Optional[str] = None,
    ):
        self.cache_path = Path(cache_path) if cache_path else DEFAULT_CACHE
        self.fetcher = fetcher or _http_fetch
        self.api_key = api_key
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
        self.cache_path.write_text(json.dumps(self._cache, indent=2), encoding="utf-8")

    def context(self, cve_id: str) -> Optional[CVEContext]:
        if cve_id in self._cache:
            return CVEContext(**self._cache[cve_id])

        url = f"{NVD_API}?{urllib.parse.urlencode({'cveId': cve_id})}"
        try:
            payload = self.fetcher(url)
        except Exception:
            return None

        ctx = parse_nvd_response(cve_id, payload)
        if ctx:
            self._cache[cve_id] = ctx.to_dict()
            self._save_cache()
        return ctx

    def contexts(self, cve_ids: list[str]) -> dict[str, Optional[CVEContext]]:
        return {cve: self.context(cve) for cve in cve_ids}
