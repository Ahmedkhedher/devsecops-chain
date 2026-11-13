"""Phase 2 -- Risk-based prioritization.

Combines three signals into a single priority_score and re-ranks findings so
that genuinely risky issues surface first:

  priority_score = (CVSS * w_cvss) + (EPSS * 100 * w_epss)
                   + (kev_bonus if KEV) + (ransomware_bonus if ransomware)

Rationale: CVSS measures worst-case impact but not likelihood; EPSS estimates
real-world exploitation probability; KEV membership means it's already being
exploited. A KEV-listed medium-severity CVE should outrank a non-exploited
critical one -- the default weights are tuned so that holds (see tests).

The weights are a starting point, not gospel. Tune them against real output
during Phase 6 evaluation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from common.finding import Finding

# Default weights (see module docstring). CVSS and EPSS each contribute up to
# 40 points (EPSS is 0-1, scaled by 100); KEV adds a flat bonus.
DEFAULT_W_CVSS = 0.4
DEFAULT_W_EPSS = 0.4
DEFAULT_KEV_BONUS = 20.0
# Extra weight when CISA confirms the CVE is used in ransomware campaigns.
DEFAULT_RANSOMWARE_BONUS = 10.0

# Used when a finding has no EPSS score (e.g. very new or un-scored CVE).
# Neutral-low: don't inflate, don't fully zero-out the CVSS contribution.
EPSS_FALLBACK = 0.0


@dataclass
class ScorerConfig:
    w_cvss: float = DEFAULT_W_CVSS
    w_epss: float = DEFAULT_W_EPSS
    kev_bonus: float = DEFAULT_KEV_BONUS
    ransomware_bonus: float = DEFAULT_RANSOMWARE_BONUS
    epss_fallback: float = EPSS_FALLBACK


def compute_priority_score(
    cvss: Optional[float],
    epss: Optional[float],
    kev_listed: bool,
    config: Optional[ScorerConfig] = None,
    known_ransomware: bool = False,
) -> float:
    cfg = config or ScorerConfig()
    cvss_val = cvss if cvss is not None else 0.0
    epss_val = epss if epss is not None else cfg.epss_fallback
    score = (
        cvss_val * cfg.w_cvss
        + epss_val * 100.0 * cfg.w_epss
        + (cfg.kev_bonus if kev_listed else 0.0)
        + (cfg.ransomware_bonus if known_ransomware else 0.0)
    )
    return round(score, 2)


def score_finding(f: Finding, config: Optional[ScorerConfig] = None) -> Finding:
    """Populate f.priority_score in place from its cvss/epss/kev fields."""
    f.priority_score = compute_priority_score(
        f.cvss,
        f.epss,
        f.kev_listed,
        config,
        known_ransomware=f.known_ransomware,
    )
    return f


def rank(findings: list[Finding], config: Optional[ScorerConfig] = None) -> list[Finding]:
    """Score every finding and return a new list sorted by priority (desc).

    Ties break on CVSS then CVE ID for stable, deterministic output.
    """
    scored = [score_finding(f, config) for f in findings]
    scored.sort(
        key=lambda f: (
            -(f.priority_score or 0.0),
            -(f.cvss or 0.0),
            f.cve_id,
        )
    )
    return scored
