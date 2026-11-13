"""Shared data shapes consumed and produced by every pipeline stage.

Stages stay decoupled: the scanner emits Finding objects, prioritization
enriches and re-ranks them, reachability filters them, and the explanation
engine annotates them -- all by mutating/copying this one structure.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Finding:
    """A single vulnerability finding flowing through the pipeline.

    Fields are grouped by the stage that populates them:
      - scanner:         cve_id, package, version, cvss, severity, fixed_version, target
      - prioritization:  epss, kev_listed, priority_score
      - reachability:    reachable
      - explanation:     explanation, suggested_fix, confidence
    """

    # --- identity (set by the scanner) ---
    cve_id: str
    package: str
    version: str
    severity: str = ""            # Trivy severity: CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN
    cvss: Optional[float] = None  # CVSS v3 base score, 0.0-10.0
    fixed_version: Optional[str] = None
    target: Optional[str] = None  # scanned artifact, e.g. "requirements.txt"
    title: Optional[str] = None

    # --- prioritization (Phase 2) ---
    epss: Optional[float] = None       # exploit probability, 0.0-1.0
    kev_listed: bool = False           # present in CISA Known Exploited Vulnerabilities
    known_ransomware: bool = False     # CISA: known use in ransomware campaigns
    kev_due_date: Optional[str] = None # CISA-mandated remediation deadline (YYYY-MM-DD)
    priority_score: Optional[float] = None

    # --- reachability / exposure (Phase 5) ---
    reachable: Optional[bool] = None
    exposure: Optional[str] = None     # none | unlinked | local | cli | network
    exploit_path: list[str] = field(default_factory=list)  # entrypoint -> ... -> sink

    # --- explanation (Phase 3) ---
    explanation: Optional[str] = None
    suggested_fix: Optional[str] = None
    confidence: Optional[str] = None   # high / medium / low
    grounded: Optional[bool] = None    # LLM claims all traceable to evidence?

    # Free-form bag for extra per-CVE context (e.g. NVD description).
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        kwargs = {k: v for k, v in data.items() if k in known}
        return cls(**kwargs)
