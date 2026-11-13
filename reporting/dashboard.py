"""Build a portable decision lab without servers, CDNs, or network requests."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

from common.finding import Finding


def _weight(finding: Finding) -> float:
    value = finding.priority_score
    if value is None:
        return 0.0
    return float(value) if math.isfinite(value) and value >= 0 else 0.0


def build_report(findings: list[Finding]) -> dict:
    """Group fixes by artifact/package/version; never guess version ordering.

    Each action is a review task, not a verified install command. Different CVEs
    can specify incompatible release branches, so preserve all fix requirements.
    Scores are heuristic points, not probabilities or expected monetary losses.
    """
    rows = []
    groups = {}
    for index, finding in enumerate(findings):
        row = finding.to_dict()
        row["weight"] = _weight(finding)
        row["id"] = index
        key = (finding.target or "", finding.package, finding.version)
        group = groups.setdefault(key, {
            "id": hashlib.sha256(json.dumps(key).encode()).hexdigest()[:20],
            "target": key[0], "package": key[1], "version": key[2],
            "finding_ids": [], "fixable_ids": [], "requirements": set(),
            "weight": 0.0,
        })
        row["action_id"] = group["id"]
        group["finding_ids"].append(index)
        if finding.fixed_version and finding.fixed_version.strip():
            group["fixable_ids"].append(index)
            group["requirements"].add(finding.fixed_version.strip())
            group["weight"] += row["weight"]
        rows.append(row)
    actions = []
    for group in groups.values():
        group["requirements"] = sorted(group["requirements"])
        group["weight"] = round(group["weight"], 4)
        actions.append(group)
    actions.sort(key=lambda a: (-a["weight"], a["package"], a["target"], a["version"]))
    return {
        "schema_version": 1,
        "findings": rows,
        "actions": actions,
        "total_weight": round(sum(r["weight"] for r in rows), 4),
        "unscored": sum(f.priority_score is None for f in findings),
    }


def render_dashboard(findings: list[Finding]) -> str:
    """Embed JSON safely even when scanner-controlled strings contain HTML."""
    payload = json.dumps(build_report(findings), ensure_ascii=True)
    payload = payload.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    template = Path(__file__).with_name("dashboard.html").read_text(encoding="utf-8")
    return template.replace("__REPORT_DATA__", payload)