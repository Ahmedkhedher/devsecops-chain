"""Phase 3b -- LLM groundedness / hallucination audit.

An explanation that reads well is not necessarily true. This module compares
what the LLM wrote against the evidence the pipeline actually retrieved (NVD
description, CVSS, EPSS, KEV flags, fixed version, reachability) and flags:

  conflict      the explanation contradicts a fact we know
                (wrong CVE, wrong CVSS, claims active exploitation when not KEV)
  unsupported   a specificity not present in the evidence
                (claims SQL injection when NVD describes a DoS)
  unverifiable  the claim type cannot be checked because evidence is missing

`grounded` is False when any conflict or unsupported claim exists. Missing NVD
data alone lowers the score but does not condemn the explanation -- offline
runs should not be marked as hallucinations.

This is intentionally rule-based: every verdict is explainable and testable,
which is what an evaluation chapter needs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from common.finding import Finding

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
VERSION_RE = re.compile(r"\b\d+\.\d+(?:\.\d+)?\b")
ISO_DATE_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
SCORE_RE = re.compile(r"\b(\d{1,2}(?:\.\d+)?)\b")
PERCENT_RE = re.compile(r"\b(\d{1,3}(?:\.\d+)?)\s*%")
SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")

EXPLOITATION_PHRASES = [
    r"\bknown\s+(?:to\s+be\s+)?exploited\b",
    r"\bactively\s+exploited\b",
    r"\bexploited\s+in\s+the\s+wild\b",
    r"\bin\s+the\s+CISA\s+KEV\b",
    r"\blisted\s+in\s+(?:the\s+)?KEV\b",
]
NEGATION_RE = re.compile(r"\b(not|no|never|without|unknown|unclear)\b")

VULN_CLASSES: dict[str, list[str]] = {
    "remote code execution": [
        r"remote code execution", r"\bRCE\b", r"arbitrary code execution",
        r"execute arbitrary code", r"code execution",
    ],
    "command injection": [r"command injection", r"shell injection"],
    "SQL injection": [r"SQL injection", r"\bSQLi\b"],
    "cross-site scripting": [r"cross-site scripting", r"\bXSS\b"],
    "denial of service": [r"denial of service", r"\bDoS\b", r"denial-of-service"],
    "path traversal": [r"path traversal", r"directory traversal"],
    "server-side request forgery": [r"server-side request forgery", r"\bSSRF\b"],
    "deserialization": [r"deserializ", r"deserialis"],
    "authentication bypass": [r"authentication bypass", r"auth(?:entication)? bypass"],
    "information disclosure": [
        r"information disclosure", r"information leak", r"expose(?:s|d)? information",
        r"leak(?:s|ed)? (?:data|information|credentials)",
    ],
    "open redirect": [r"open redirect"],
    "privilege escalation": [r"privilege escalation"],
}

USED_CLAIMS = [
    r"\bis (?:imported|used|reachable)\b",
    r"\bused in (?:this|the) codebase\b",
    r"\breachable from\b",
]
UNUSED_CLAIMS = [
    r"\b(?:not|never)\s+(?:imported|used|reachable)\b",
    r"\bunused\b",
    r"\bnot present in (?:this|the) codebase\b",
]
FIX_WORDS = re.compile(r"\b(upgrade|fixed|fix|patch(?:ed)?|version)\b", re.IGNORECASE)


@dataclass
class GroundingIssue:
    kind: str       # conflict | unsupported | unverifiable
    claim: str
    detail: str

    def to_dict(self) -> dict:
        return {"kind": self.kind, "claim": self.claim, "detail": self.detail}


@dataclass
class GroundingResult:
    grounded: bool
    score: float
    checked: int
    issues: list[GroundingIssue] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "grounded": self.grounded,
            "score": round(self.score, 3),
            "checked_claims": self.checked,
            "issues": [i.to_dict() for i in self.issues],
            "evidence": self.evidence,
        }


def _negated(sentence: str, start: int) -> bool:
    window = sentence[max(0, start - 32):start]
    return bool(NEGATION_RE.search(window))


def _version_matches(token: str, known: Optional[str]) -> bool:
    if not known:
        return False
    if token == known:
        return True
    return token.startswith(known + ".") or known.startswith(token + ".")


def _evidence_text(f: Finding) -> tuple[str, list[str]]:
    parts: list[str] = []
    used: list[str] = []
    desc = f.extra.get("nvd_description")
    if isinstance(desc, str) and desc.strip():
        parts.append(desc)
        used.append("nvd_description")
    if f.title:
        parts.append(f.title)
        used.append("scanner_title")
    if isinstance(f.extra.get("cwe_ids"), list) and f.extra["cwe_ids"]:
        used.append("cwe")
    return " ".join(parts).lower(), used


def audit_explanation(f: Finding, text: Optional[str] = None) -> GroundingResult:
    """Check an explanation against the finding's retrieved evidence."""
    text = (text if text is not None else f.explanation) or ""
    evidence_text, evidence_used = _evidence_text(f)
    issues: list[GroundingIssue] = []
    checked = 0

    for raw in SENTENCE_SPLIT.split(" ".join(text.split())):
        sentence = raw.strip()
        if not sentence:
            continue
        low = sentence.lower()
        checks = 0

        # 1. CVE identifiers must refer to this finding.
        for cve in CVE_RE.findall(sentence):
            checks += 1
            if cve.upper() != f.cve_id.upper():
                issues.append(GroundingIssue(
                    "conflict", sentence,
                    f"mentions {cve} but this finding is {f.cve_id}",
                ))

        # 2. Active-exploitation claims require KEV membership.
        for pattern in EXPLOITATION_PHRASES:
            for m in re.finditer(pattern, low):
                checks += 1
                if not f.kev_listed and not _negated(low, m.start()):
                    issues.append(GroundingIssue(
                        "conflict", sentence,
                        "claims active exploitation but CVE is not in CISA KEV",
                    ))

        # 3. Ransomware claims require CISA's ransomware flag.
        for m in re.finditer(r"\bransomware\b", low):
            checks += 1
            if not f.known_ransomware and not _negated(low, m.start()):
                issues.append(GroundingIssue(
                    "conflict", sentence,
                    "claims ransomware use but CISA does not report it for this CVE",
                ))

        # 4. CVSS claims must match the scanner score.
        if "cvss" in low:
            scores = [float(x) for x in SCORE_RE.findall(low)]
            scores = [s for s in scores if 0.0 <= s <= 10.0]
            if scores:
                checks += 1
                if f.cvss is None:
                    issues.append(GroundingIssue(
                        "unverifiable", sentence, "CVSS score is not available for this CVE",
                    ))
                elif not any(abs(s - f.cvss) <= 0.05 for s in scores):
                    issues.append(GroundingIssue(
                        "conflict", sentence,
                        f"claims CVSS {scores[0]} but scanner reports {f.cvss}",
                    ))

        # 5. EPSS claims must match the enrichment value.
        if "epss" in low:
            checks += 1
            pct = PERCENT_RE.search(low)
            values = PERCENT_RE.findall(low)
            if f.epss is None:
                issues.append(GroundingIssue(
                    "unverifiable", sentence, "EPSS score is not available for this CVE",
                ))
            elif values:
                claimed = max(float(v) for v in values)
                if abs(claimed - f.epss * 100.0) > 0.6:
                    issues.append(GroundingIssue(
                        "conflict", sentence,
                        f"claims EPSS {claimed}% but enrichment reports {f.epss * 100:.2f}%",
                    ))
            elif pct is None:
                nums = [float(x) for x in SCORE_RE.findall(low)
                        if "." in x and 0.0 <= float(x) <= 1.0]
                if nums and not any(abs(n - f.epss) <= 0.006 for n in nums):
                    issues.append(GroundingIssue(
                        "conflict", sentence,
                        f"claims EPSS {nums[0]} but enrichment reports {f.epss:.3f}",
                    ))

        # 6. Fix/version claims must agree with the known versions.
        if FIX_WORDS.search(low):
            versions = VERSION_RE.findall(sentence)
            for token in versions:
                checks += 1
                if not (_version_matches(token, f.fixed_version)
                        or _version_matches(token, f.version)):
                    if f.fixed_version:
                        issues.append(GroundingIssue(
                            "unsupported", sentence,
                            f"mentions version {token}; known fixed version is {f.fixed_version}",
                        ))
                    else:
                        issues.append(GroundingIssue(
                            "unverifiable", sentence,
                            f"mentions version {token} but no fixed version is published",
                        ))
            if "upgrade" in low and "no " not in low and not versions and not f.fixed_version:
                checks += 1
                issues.append(GroundingIssue(
                    "unsupported", sentence,
                    "recommends an upgrade but no fixed version exists",
                ))

        # 7. KEV due-date claims must match the catalog.
        if f.kev_due_date and ("due date" in low or "deadline" in low):
            dates = ISO_DATE_RE.findall(sentence)
            for token in dates:
                checks += 1
                if token != f.kev_due_date:
                    issues.append(GroundingIssue(
                        "conflict", sentence,
                        f"claims deadline {token} but CISA lists {f.kev_due_date}",
                    ))

        # 8. Vulnerability-class claims must appear in the evidence.
        for label, patterns in VULN_CLASSES.items():
            if not any(re.search(p, low, re.IGNORECASE) for p in patterns):
                continue
            checks += 1
            if not evidence_text:
                issues.append(GroundingIssue(
                    "unverifiable", sentence,
                    f"claims {label} but no NVD description is available to verify it",
                ))
            elif not any(re.search(p, evidence_text, re.IGNORECASE) for p in patterns):
                issues.append(GroundingIssue(
                    "unsupported", sentence,
                    f"claims {label} but the retrieved evidence does not mention it",
                ))

        # 9. Reachability claims must match the analysis.
        for pattern in USED_CLAIMS:
            for m in re.finditer(pattern, low):
                checks += 1
                if f.reachable is False and not _negated(low, m.start()):
                    issues.append(GroundingIssue(
                        "conflict", sentence,
                        "claims the dependency is used but reachability found it unused",
                    ))
                elif f.reachable is None:
                    issues.append(GroundingIssue(
                        "unverifiable", sentence,
                        "claims usage but reachability analysis did not run",
                    ))
        for pattern in UNUSED_CLAIMS:
            for m in re.finditer(pattern, low):
                checks += 1
                if f.reachable is True and not _negated(low, m.start()):
                    issues.append(GroundingIssue(
                        "conflict", sentence,
                        "claims the dependency is unused but it is imported",
                    ))
                elif f.reachable is None:
                    issues.append(GroundingIssue(
                        "unverifiable", sentence,
                        "claims non-usage but reachability analysis did not run",
                    ))

        if checks:
            checked += 1
        # Supported sentences need no bookkeeping beyond the check count.

    weights = {"conflict": 1.0, "unsupported": 0.6, "unverifiable": 0.15}
    penalty = sum(weights[i.kind] for i in issues)
    score = max(0.0, 1.0 - penalty / max(1, checked)) if checked else 1.0
    grounded = not any(i.kind in ("conflict", "unsupported") for i in issues)
    return GroundingResult(
        grounded=grounded,
        score=score,
        checked=checked,
        issues=issues,
        evidence=evidence_used,
    )


def apply_grounding(findings: list[Finding]) -> list[Finding]:
    """Audit every explained finding and attach `grounded` + grounding details."""
    for f in findings:
        if not f.explanation:
            continue
        if f.explanation.startswith("(explanation unavailable"):
            f.grounded = None
            continue
        result = audit_explanation(f)
        f.grounded = result.grounded
        f.extra["grounding"] = result.to_dict()
    return findings


def hallucination_rate(findings: list[Finding]) -> Optional[float]:
    """Fraction of audited explanations that contain a conflict/unsupported claim."""
    audited = [f for f in findings if f.grounded is not None]
    if not audited:
        return None
    return sum(1 for f in audited if not f.grounded) / len(audited)
