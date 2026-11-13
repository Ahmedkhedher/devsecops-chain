"""Phase 2 orchestration: enrich findings with EPSS + KEV, then rank.

This is the glue the CI pipeline calls: hand it the scanner's Finding list,
get back the same findings annotated with epss/kev_listed/priority_score and
re-sorted by real-world risk.
"""

from __future__ import annotations

from typing import Optional

from common.finding import Finding
from prioritization.epss_client import EPSSClient
from prioritization.kev_client import KEVClient
from prioritization.scorer import ScorerConfig, rank


def prioritize(
    findings: list[Finding],
    epss_client: Optional[EPSSClient] = None,
    kev_client: Optional[KEVClient] = None,
    config: Optional[ScorerConfig] = None,
) -> list[Finding]:
    """Annotate findings with EPSS + KEV signals and return them re-ranked."""
    if not findings:
        return []

    epss_client = epss_client or EPSSClient()
    kev_client = kev_client or KEVClient()

    cve_ids = [f.cve_id for f in findings]
    scores = epss_client.scores(cve_ids)

    for f in findings:
        f.epss = scores.get(f.cve_id)
        f.kev_listed = kev_client.is_listed(f.cve_id)
        f.known_ransomware = kev_client.known_ransomware(f.cve_id)
        f.kev_due_date = kev_client.due_date(f.cve_id)

    return rank(findings, config)
