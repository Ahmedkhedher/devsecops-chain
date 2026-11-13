"""Phase 6 (advanced) -- Policy-as-code gate with expiring waivers.

A vulnerability scanner that only prints a table doesn't change a merge
decision. This module turns findings into a deterministic pass/fail gate:

  * declarative JSON rules over severity/exposure/KEV/EPSS/CISA due dates
  * every rule can be `fail` or `warn`, and optionally non-waivable
  * waivers require an owner, a reason, and an expiry date -- there is no
    such thing as a permanent exception
  * expired waivers are reported as policy hygiene violations instead of
    silently suppressing risk

Exit-code semantics live in `evaluate_gate`: `passed` is False when any
non-waived `fail` violation exists.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Optional

from common.finding import Finding

SEVERITY_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
ACTIONS = {"fail", "warn"}
CONDITIONS = {
    "severity", "exposure", "kev_listed", "known_ransomware", "reachable",
    "has_fix", "overdue", "priority_gte", "cvss_gte", "epss_gte", "cve",
    "package",
}


class PolicyError(ValueError):
    """The policy file is missing, malformed, or ambiguous."""


@dataclass
class Rule:
    id: str
    when: dict
    action: str = "fail"
    description: str = ""
    waivable: bool = True


@dataclass
class Waiver:
    id: str
    cve: str
    expires: date
    reason: str
    owner: str
    package: Optional[str] = None
    ticket: Optional[str] = None


@dataclass
class Policy:
    name: str
    rules: list[Rule] = field(default_factory=list)
    waivers: list[Waiver] = field(default_factory=list)
    raw_waivers: list[dict] = field(default_factory=list)
    fail_on_severity: Optional[str] = None
    max_priority_score: Optional[float] = None
    fail_on_ransomware: bool = False
    fail_on_overdue: bool = False
    require_fix_for_affected: bool = False


@dataclass
class Violation:
    cve: str
    package: str
    rule_id: str
    action: str
    reason: str
    waivable: bool = True

    def to_dict(self) -> dict:
        return {
            "cve": self.cve, "package": self.package, "rule": self.rule_id,
            "action": self.action, "reason": self.reason,
            "waivable": self.waivable,
        }


@dataclass
class WaiverUse:
    waiver_id: str
    cve: str
    package: str
    expires: str
    reason: str

    def to_dict(self) -> dict:
        return {
            "waiver": self.waiver_id, "cve": self.cve, "package": self.package,
            "expires": self.expires, "reason": self.reason,
        }


@dataclass
class GateReport:
    policy_name: str
    passed: bool
    evaluated: int
    violations: list[Violation] = field(default_factory=list)
    warnings: list[Violation] = field(default_factory=list)
    waived: list[WaiverUse] = field(default_factory=list)
    expired_waivers: list[dict] = field(default_factory=list)
    stale_waivers: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "policy": self.policy_name,
            "passed": self.passed,
            "evaluated": self.evaluated,
            "violations": [v.to_dict() for v in self.violations],
            "warnings": [w.to_dict() for w in self.warnings],
            "waived": [w.to_dict() for w in self.waived],
            "expired_waivers": self.expired_waivers,
            "stale_waivers": self.stale_waivers,
        }

    def render_text(self) -> str:
        head = "PASS" if self.passed else "FAIL"
        lines = [
            f"Policy gate: {head}  ({self.policy_name}, "
            f"{self.evaluated} finding(s), {len(self.violations)} violation(s), "
            f"{len(self.waived)} waiver(s))"
        ]
        for v in self.violations:
            lines.append(f"  VIOLATION [{v.rule_id}] {v.cve} ({v.package}): {v.reason}")
        for w in self.warnings:
            lines.append(f"  WARNING   [{w.rule_id}] {w.cve} ({w.package}): {w.reason}")
        for w in self.waived:
            lines.append(
                f"  WAIVED    {w.cve} ({w.package}) by {w.waiver_id} "
                f"until {w.expires}: {w.reason}"
            )
        for e in self.expired_waivers:
            lines.append(
                f"  EXPIRED   waiver {e['waiver']} for {e['cve']} "
                f"expired {e['expires']}"
            )
        for s in self.stale_waivers:
            lines.append(f"  STALE     waiver {s['waiver']} for {s['cve']} matches no finding")
        return "\n".join(lines)

    def render_markdown(self, limit: int = 10) -> str:
        head = "PASS" if self.passed else "FAIL"
        lines = [f"### Policy gate: {head} — `{self.policy_name}`"]
        if self.violations:
            lines += [
                "",
                "| Rule | CVE | Package | Reason |",
                "|------|-----|---------|--------|",
            ]
            for v in self.violations[:limit]:
                lines.append(
                    f"| `{v.rule_id}` | {v.cve} | `{v.package}` | {v.reason} |"
                )
            if len(self.violations) > limit:
                lines.append(f"\n_…and {len(self.violations) - limit} more violation(s)._")
        if self.waived:
            joined = ", ".join(f"{w.cve} (`{w.waiver_id}`)" for w in self.waived)
            lines += ["", f"Waived: {joined}"]
        if self.expired_waivers:
            joined = ", ".join(f"{e['waiver']} ({e['cve']})" for e in self.expired_waivers)
            lines += ["", f"**Expired waivers:** {joined}"]
        return "\n".join(lines)


def _parse_date(value: Any, field_name: str) -> date:
    try:
        return date.fromisoformat(str(value))
    except (TypeError, ValueError):
        raise PolicyError(f"{field_name} must be an ISO date (YYYY-MM-DD), got {value!r}")


def load_policy(path: str | Path) -> Policy:
    """Load and validate a policy file. Typos fail loudly, not silently."""
    path = Path(path)
    if not path.exists():
        raise PolicyError(f"policy file not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PolicyError(f"invalid JSON in {path}: {exc}")
    if not isinstance(data, dict):
        raise PolicyError("policy root must be a JSON object")
    if data.get("version") != 1:
        raise PolicyError("policy version must be 1")

    defaults = data.get("defaults", {})
    if not isinstance(defaults, dict):
        raise PolicyError("defaults must be an object")
    known_defaults = {
        "fail_on_severity", "max_priority_score", "fail_on_ransomware",
        "fail_on_overdue", "require_fix_for_affected",
    }
    unknown = set(defaults) - known_defaults
    if unknown:
        raise PolicyError(f"unknown default(s): {', '.join(sorted(unknown))}")
    severity = defaults.get("fail_on_severity")
    if severity is not None and str(severity).upper() not in SEVERITY_RANK:
        raise PolicyError(f"unknown severity: {severity!r}")

    rules: list[Rule] = []
    for i, raw in enumerate(data.get("rules", [])):
        if not isinstance(raw, dict):
            raise PolicyError(f"rule #{i} must be an object")
        rule_id = raw.get("id")
        if not rule_id:
            raise PolicyError(f"rule #{i} has no id")
        action = raw.get("action", "fail")
        if action not in ACTIONS:
            raise PolicyError(f"rule {rule_id}: action must be one of {sorted(ACTIONS)}")
        when = raw.get("when", {})
        if not isinstance(when, dict) or not when:
            raise PolicyError(f"rule {rule_id}: 'when' must be a non-empty object")
        bad = set(when) - CONDITIONS
        if bad:
            raise PolicyError(f"rule {rule_id}: unknown condition(s): {', '.join(sorted(bad))}")
        rules.append(Rule(
            id=rule_id, when=when, action=action,
            description=raw.get("description", ""),
            waivable=bool(raw.get("waivable", True)),
        ))

    waivers: list[Waiver] = []
    for i, raw in enumerate(data.get("waivers", [])):
        if not isinstance(raw, dict):
            raise PolicyError(f"waiver #{i} must be an object")
        wid = raw.get("id")
        cve = raw.get("cve")
        if not wid or not cve:
            raise PolicyError(f"waiver #{i} needs both id and cve")
        for required in ("expires", "reason", "owner"):
            if not raw.get(required):
                raise PolicyError(
                    f"waiver {wid}: '{required}' is required -- exemptions must expire "
                    "and have an accountable owner"
                )
        waivers.append(Waiver(
            id=str(wid), cve=str(cve),
            expires=_parse_date(raw["expires"], f"waiver {wid} expires"),
            reason=str(raw["reason"]), owner=str(raw["owner"]),
            package=raw.get("package"),
            ticket=raw.get("ticket"),
        ))

    return Policy(
        name=data.get("name", path.stem),
        rules=rules, waivers=waivers, raw_waivers=data.get("waivers", []),
        fail_on_severity=str(severity).upper() if severity else None,
        max_priority_score=defaults.get("max_priority_score"),
        fail_on_ransomware=bool(defaults.get("fail_on_ransomware", False)),
        fail_on_overdue=bool(defaults.get("fail_on_overdue", False)),
        require_fix_for_affected=bool(defaults.get("require_fix_for_affected", False)),
    )


def _is_overdue(f: Finding, today: date) -> bool:
    if not f.kev_due_date:
        return False
    try:
        return date.fromisoformat(f.kev_due_date) < today
    except ValueError:
        return False


def _matches(when: dict, f: Finding, today: date) -> bool:
    for key, expected in when.items():
        if key == "severity":
            if SEVERITY_RANK.get((f.severity or "UNKNOWN").upper(), 0) < SEVERITY_RANK[
                str(expected).upper()
            ]:
                return False
        elif key == "exposure":
            allowed = expected if isinstance(expected, list) else [expected]
            if f.exposure not in allowed:
                return False
        elif key in ("cve", "package"):
            allowed = expected if isinstance(expected, list) else [expected]
            if getattr(f, key) not in allowed:
                return False
        elif key == "kev_listed":
            if bool(f.kev_listed) != bool(expected):
                return False
        elif key == "known_ransomware":
            if bool(f.known_ransomware) != bool(expected):
                return False
        elif key == "reachable":
            if f.reachable is not expected:
                return False
        elif key == "has_fix":
            if bool(f.fixed_version) != bool(expected):
                return False
        elif key == "overdue":
            if _is_overdue(f, today) != bool(expected):
                return False
        elif key == "priority_gte":
            if f.priority_score is None or f.priority_score < float(expected):
                return False
        elif key == "cvss_gte":
            if f.cvss is None or f.cvss < float(expected):
                return False
        elif key == "epss_gte":
            if f.epss is None or f.epss < float(expected):
                return False
    return True


def _waiver_matches(w: Waiver, f: Finding) -> bool:
    if w.cve != f.cve_id:
        return False
    if w.package and w.package != f.package:
        return False
    return True


def _default_violations(policy: Policy, f: Finding, today: date) -> list[Violation]:
    out: list[Violation] = []
    if policy.fail_on_severity:
        threshold = SEVERITY_RANK[policy.fail_on_severity]
        if SEVERITY_RANK.get((f.severity or "UNKNOWN").upper(), 0) >= threshold:
            out.append(Violation(
                cve=f.cve_id, package=f.package, rule_id="default:severity",
                action="fail",
                reason=f"severity {f.severity} meets or exceeds {policy.fail_on_severity}",
            ))
    if policy.max_priority_score is not None and f.priority_score is not None:
        if f.priority_score >= float(policy.max_priority_score):
            out.append(Violation(
                cve=f.cve_id, package=f.package, rule_id="default:priority",
                action="fail",
                reason=f"priority {f.priority_score} >= {policy.max_priority_score}",
            ))
    if policy.fail_on_ransomware and f.known_ransomware:
        out.append(Violation(
            cve=f.cve_id, package=f.package, rule_id="default:ransomware",
            action="fail", reason="CISA reports known ransomware campaign use",
        ))
    if policy.fail_on_overdue and _is_overdue(f, today):
        out.append(Violation(
            cve=f.cve_id, package=f.package, rule_id="default:overdue",
            action="fail",
            reason=f"CISA remediation deadline {f.kev_due_date} has passed",
        ))
    if policy.require_fix_for_affected:
        if f.exposure in ("local", "cli", "network") and not f.fixed_version:
            out.append(Violation(
                cve=f.cve_id, package=f.package, rule_id="default:fix-required",
                action="fail",
                reason=f"exposed ({f.exposure}) with no published fixed version",
            ))
    return out


def evaluate_gate(
    findings: list[Finding],
    policy: Policy,
    today: Optional[date] = None,
) -> GateReport:
    """Evaluate every finding against the policy, applying valid waivers."""
    today = today or date.today()
    report = GateReport(policy_name=policy.name, passed=True,
                        evaluated=len(findings))

    matched_waivers: set[str] = set()
    expired_reported: set[str] = set()
    for f in findings:
        raw = _default_violations(policy, f, today)
        for rule in policy.rules:
            if _matches(rule.when, f, today):
                raw.append(Violation(
                    cve=f.cve_id, package=f.package, rule_id=rule.id,
                    action=rule.action,
                    reason=rule.description or f"matched rule {rule.id}",
                    waivable=rule.waivable,
                ))

        for v in raw:
            if v.action == "warn":
                report.warnings.append(v)
                continue
            waiver = None
            if v.waivable:
                for w in policy.waivers:
                    if _waiver_matches(w, f):
                        matched_waivers.add(w.id)
                        if w.expires < today:
                            if w.id not in expired_reported:
                                expired_reported.add(w.id)
                                report.expired_waivers.append({
                                    "waiver": w.id, "cve": w.cve,
                                    "expires": w.expires.isoformat(),
                                    "owner": w.owner,
                                })
                            continue
                        waiver = w
                        break
            if waiver is not None:
                if not any(x.waiver_id == waiver.id and x.cve == f.cve_id
                           for x in report.waived):
                    report.waived.append(WaiverUse(
                        waiver_id=waiver.id, cve=f.cve_id, package=f.package,
                        expires=waiver.expires.isoformat(), reason=waiver.reason,
                    ))
            else:
                report.violations.append(v)

    for w in policy.waivers:
        if w.expires < today:
            if w.id not in expired_reported:
                report.expired_waivers.append({
                    "waiver": w.id, "cve": w.cve,
                    "expires": w.expires.isoformat(), "owner": w.owner,
                })
        elif w.id not in matched_waivers:
            report.stale_waivers.append({
                "waiver": w.id, "cve": w.cve,
                "expires": w.expires.isoformat(),
            })

    report.passed = not report.violations
    return report
