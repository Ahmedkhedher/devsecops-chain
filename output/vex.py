"""Phase 2 (advanced) -- OpenVEX output.

VEX (Vulnerability Exploitability eXchange) is the machine-readable answer to
"are we actually affected?". Instead of forcing downstream consumers to
re-derive our reachability and exposure conclusions, we publish them as an
OpenVEX 0.2.0 document:

  * package present but never imported          -> not_affected / vulnerable_code_not_present
  * called only off any entrypoint path          -> not_affected / vulnerable_code_not_in_execute_path
  * reachable from a route/CLI/main              -> affected (+ action_statement)
  * analysis inconclusive                        -> under_investigation

This lets a customer's scanner suppress findings with a standards-based
justification instead of a hand-written ignore list.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import quote

from common.finding import Finding

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
TOOLING = "devsecops-chain/0.2.0"
_ID_NAMESPACE = uuid.UUID("6f2f8f9e-6d5a-4b55-9d8f-2a8f1a8d2f10")


def purl_for(finding: Finding) -> str:
    """PyPI package URL. The scanner currently targets Python projects."""
    return f"pkg:pypi/{quote(finding.package.lower())}@{quote(finding.version)}"


def _status_for(f: Finding) -> tuple[str, Optional[str], Optional[str]]:
    """Return (status, justification, status_notes) for a finding."""
    if f.exposure == "none":
        return ("not_affected", "vulnerable_code_not_present",
                "Not imported anywhere in the scanned source tree.")
    if f.exposure == "unlinked":
        return ("not_affected", "vulnerable_code_not_in_execute_path",
                "Called only from code that no web, CLI, or main entrypoint reaches.")
    if f.exposure in ("local", "cli", "network"):
        return ("affected", None, None)
    if f.reachable is False:
        return ("not_affected", "vulnerable_code_not_in_execute_path",
                "Reachability analysis found the package is not used.")
    return ("under_investigation", None,
            "Reachability/exposure data unavailable for this finding.")


def _impact_statement(f: Finding, status: str) -> Optional[str]:
    if status == "affected":
        if f.exploit_path:
            return "Reachable from a " + f.exposure + " entrypoint: " + " -> ".join(f.exploit_path)
        return f"Reachable from a {f.exposure} entrypoint."
    return None


def build_vex(
    findings: list[Finding],
    author: str = "devsecops-chain",
    timestamp: Optional[str] = None,
    tooling: str = TOOLING,
) -> dict:
    """Build an OpenVEX 0.2.0 document from pipeline findings."""
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    statements = []
    seen: set[tuple[str, str]] = set()
    for f in sorted(findings, key=lambda x: (-(x.priority_score or 0.0), x.cve_id)):
        purl = purl_for(f)
        key = (f.cve_id, purl)
        if key in seen:
            continue
        seen.add(key)

        status, justification, notes = _status_for(f)
        stmt: dict = {
            "vulnerability": {"name": f.cve_id},
            "products": [{"@id": purl}],
            "status": status,
        }
        if justification:
            stmt["justification"] = justification
        if notes:
            stmt["status_notes"] = notes

        impact = _impact_statement(f, status)
        if impact:
            stmt["impact_statement"] = impact
        if status == "affected":
            if f.fixed_version:
                stmt["action_statement"] = (
                    f"Upgrade {f.package} to {f.fixed_version} or later."
                )
            else:
                stmt["action_statement"] = (
                    "No fixed version is published; apply mitigations or replace the dependency."
                )
        statements.append(stmt)

    digest = uuid.uuid5(
        _ID_NAMESPACE,
        json.dumps(statements, sort_keys=True),
    )
    return {
        "@context": OPENVEX_CONTEXT,
        "@id": f"urn:uuid:{digest}",
        "author": author,
        "timestamp": timestamp,
        "version": 1,
        "tooling": tooling,
        "statements": statements,
    }


def render_vex(findings: list[Finding], **kwargs) -> str:
    return json.dumps(build_vex(findings, **kwargs), indent=2, sort_keys=False)


def write_vex(path: str | Path, findings: list[Finding], **kwargs) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_vex(findings, **kwargs), encoding="utf-8")
    return destination
