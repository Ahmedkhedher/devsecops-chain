"""Remediation autopilot: the smallest set of version bumps that clears the most risk.

Findings are grouped per (manifest, package), a single target version is chosen
per package, and a unified diff is produced so the plan can be reviewed and
applied as one patch rather than 40 disconnected CVEs. Everything here is pure
and offline: it reads manifests and never touches the network.
"""

from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from common.finding import Finding

MAX_MANIFEST_BYTES = 200_000
_SKIPPED_DIRS = {
    "node_modules", ".venv", "venv", "env", "site-packages", ".git",
    "__pycache__", "dist", "build", ".tox", ".mypy_cache",
}

_REQ_LINE = re.compile(
    r"^(?P<prefix>\s*)(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?P<extras>\[[^\]]*\])?\s*"
    r"(?P<op>==|>=|<=|~=|!=|>|<)\s*(?P<version>[A-Za-z0-9_.!+*-]+)"
    r"(?P<suffix>.*)$"
)
_NPM_RANGES = ("~", "^", ">=", "=", "v")


def normalize_package(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def version_key(raw: Optional[str]) -> tuple[int, ...]:
    """Order version strings without third-party deps (numeric core only)."""
    core = re.split(r"[-+]|[A-Za-z]", (raw or "").strip().lstrip("vV"), maxsplit=1)[0]
    parts = [int(chunk) for chunk in re.findall(r"\d+", core)][:4]
    return tuple(parts + [0] * (4 - len(parts)))


def _risk(f: Finding) -> float:
    return float(f.priority_score if f.priority_score is not None else (f.cvss or 0.0))


def _strip_npm_range(spec: object) -> str:
    return str(spec).strip().lstrip("".join(_NPM_RANGES)).strip()


@dataclass
class UpgradeStep:
    package: str
    manifest: str
    ecosystem: str
    current_version: str
    target_version: str
    cleared_cves: list[str] = field(default_factory=list)
    risk_cleared: float = 0.0
    kev_cleared: int = 0
    ransomware_cleared: int = 0
    command: str = ""

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "manifest": self.manifest,
            "ecosystem": self.ecosystem,
            "from": self.current_version,
            "to": self.target_version,
            "cleared_cves": self.cleared_cves,
            "cves_cleared": len(self.cleared_cves),
            "risk_cleared": round(self.risk_cleared, 2),
            "kev_cleared": self.kev_cleared,
            "ransomware_cleared": self.ransomware_cleared,
            "command": self.command,
        }


@dataclass
class RemediationPlan:
    steps: list[UpgradeStep] = field(default_factory=list)
    manual: list[dict] = field(default_factory=list)
    risk_before: float = 0.0
    risk_after: float = 0.0
    cves_total: int = 0
    patch: str = ""

    @property
    def cves_cleared(self) -> int:
        return sum(len(step.cleared_cves) for step in self.steps)

    @property
    def reduction_pct(self) -> float:
        if self.risk_before <= 0:
            return 0.0
        return round(100.0 * (self.risk_before - self.risk_after) / self.risk_before, 1)

    def to_dict(self) -> dict:
        return {
            "steps": [step.to_dict() for step in self.steps],
            "manual": self.manual,
            "summary": {
                "cves_total": self.cves_total,
                "cves_cleared": self.cves_cleared,
                "risk_before": round(self.risk_before, 2),
                "risk_after": round(self.risk_after, 2),
                "reduction_pct": self.reduction_pct,
                "upgrades": len(self.steps),
                "needs_review": len(self.manual),
            },
        }


# --- manifest discovery ----------------------------------------------------

def _walk(root: Path, pattern: re.Pattern) -> list[Path]:
    found: list[Path] = []
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            children = list(current.iterdir())
        except OSError:
            continue
        for child in children:
            if child.is_dir():
                if child.name not in _SKIPPED_DIRS and child != root:
                    stack.append(child)
            elif pattern.fullmatch(child.name):
                found.append(child)
    return sorted(found)


def find_manifests(root: Path) -> list[tuple[Path, str]]:
    """Editable dependency manifests under `root` as (path, ecosystem)."""
    if not root.is_dir():
        return []
    python = [(path, "python")
              for path in _walk(root, re.compile(r"requirements[^/]*\.txt"))]
    node: list[tuple[Path, str]] = []
    for path in _walk(root, re.compile(r"package\.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and (
            isinstance(data.get("dependencies"), dict)
            or isinstance(data.get("devDependencies"), dict)
        ):
            node.append((path, "node"))
    return python + node


def _requirements_pins(text: str) -> dict[str, list[int]]:
    """Normalized package name -> line indexes carrying a version pin."""
    pins: dict[str, list[int]] = {}
    for index, line in enumerate(text.splitlines()):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-")):
            continue
        match = _REQ_LINE.match(line)
        if match:
            pins.setdefault(normalize_package(match.group("name")), []).append(index)
    return pins


# --- rewriting -------------------------------------------------------------

def _patch_requirements(text: str, pins: dict[str, list[int]],
                        wanted: dict[str, str]) -> str:
    lines = text.splitlines(keepends=True)
    for name, indexes in pins.items():
        target = wanted.get(name)
        if not target:
            continue
        for index in indexes:
            original = lines[index].rstrip("\r\n")
            match = _REQ_LINE.match(original)
            if not match or version_key(match.group("version")) >= version_key(target):
                continue
            rebuilt = (
                original[: match.start("version")]
                + target
                + original[match.end("version"):]
            )
            lines[index] = rebuilt + ("\n" if lines[index].endswith("\n") else "")
    return "".join(lines)


def _patch_package_json(text: str, wanted: dict[str, str]) -> str:
    try:
        data = json.loads(text)
    except ValueError:
        return text
    if not isinstance(data, dict):
        return text
    for section in ("dependencies", "devDependencies"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, spec in list(block.items()):
            target = wanted.get(normalize_package(name))
            current = _strip_npm_range(spec)
            if not target or version_key(current) >= version_key(target):
                continue
            prefix = next((p for p in _NPM_RANGES if str(spec).startswith(p)), "")
            block[name] = f"{prefix}{target}" if prefix else target
    return json.dumps(data, indent=2) + ("\n" if text.endswith("\n") else "")


def _diff(original: str, updated: str, rel: str) -> str:
    return "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            updated.splitlines(keepends=True),
            fromfile=rel,
            tofile=rel,
        )
    )


# --- planning --------------------------------------------------------------

def build_plan(findings: list[Finding], root: Path) -> RemediationPlan:
    """Group findings into per-manifest upgrade steps plus a unified patch."""
    plan = RemediationPlan(
        risk_before=sum(_risk(f) for f in findings),
        cves_total=len(findings),
    )

    python_manifests: list[tuple[Path, str, str, dict[str, list[int]]]] = []
    node_manifests: list[tuple[Path, str, str, dict]] = []
    for path, ecosystem in find_manifests(root):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if len(text) > MAX_MANIFEST_BYTES:
            continue
        rel = path.relative_to(root).as_posix()
        if ecosystem == "python":
            python_manifests.append((path, rel, text, _requirements_pins(text)))
        else:
            try:
                node_manifests.append((path, rel, text, json.loads(text)))
            except ValueError:
                continue

    def pins_for(package: str) -> list[tuple[str, str, str]]:
        """(manifest rel path, ecosystem, pinned version) for one package."""
        key = normalize_package(package)
        hits: list[tuple[str, str, str]] = []
        for _path, rel, text, pins in python_manifests:
            indexes = pins.get(key)
            if not indexes:
                continue
            match = _REQ_LINE.match(text.splitlines()[indexes[0]].rstrip("\r\n"))
            if match:
                hits.append((rel, "python", match.group("version")))
        for _path, rel, _text, data in node_manifests:
            for section in ("dependencies", "devDependencies"):
                block = data.get(section)
                if not isinstance(block, dict):
                    continue
                for name, spec in block.items():
                    if normalize_package(name) == key:
                        hits.append((rel, "node", _strip_npm_range(spec)))
        return hits

    groups: dict[tuple[str, str, str], tuple[str, list[Finding]]] = {}
    for finding in findings:
        hits = pins_for(finding.package)
        if not finding.fixed_version:
            plan.manual.append({
                "cve_id": finding.cve_id,
                "package": finding.package,
                "version": finding.version,
                "severity": finding.severity,
                "reason": "no upstream fix published -- mitigate, accept with an "
                          "expiring waiver, or drop the dependency",
            })
            continue
        if not hits:
            plan.manual.append({
                "cve_id": finding.cve_id,
                "package": finding.package,
                "version": finding.version,
                "severity": finding.severity,
                "reason": "not pinned in an editable manifest (transitive or "
                          "lockfile-only) -- upgrade its parent or regenerate the lock",
            })
            continue
        for rel, ecosystem, pinned in hits:
            entry = groups.setdefault(
                (rel, ecosystem, normalize_package(finding.package)), (pinned, [])
            )
            entry[1].append(finding)

    changes: dict[str, dict[str, str]] = {}
    cleared_risk = 0.0
    for (rel, ecosystem, key), (pinned, group) in sorted(groups.items()):
        candidates = [f.fixed_version for f in group
                      if version_key(f.fixed_version) > version_key(pinned)]
        if not candidates:
            plan.manual.append({
                "cve_id": ", ".join(sorted(f.cve_id for f in group)),
                "package": group[0].package,
                "version": pinned,
                "severity": group[0].severity,
                "reason": "published fix is not newer than the pinned version -- "
                          "verify the advisory and consider dropping the dependency",
            })
            continue
        to_version = max(candidates, key=version_key)
        resolved = [f for f in group
                    if version_key(f.fixed_version) <= version_key(to_version)]
        package = group[0].package
        step = UpgradeStep(
            package=package,
            manifest=rel,
            ecosystem=ecosystem,
            current_version=pinned,
            target_version=to_version,
            cleared_cves=sorted({f.cve_id for f in resolved}),
            risk_cleared=round(sum(_risk(f) for f in resolved), 2),
            kev_cleared=sum(1 for f in resolved if f.kev_listed),
            ransomware_cleared=sum(1 for f in resolved if f.known_ransomware),
            command=(
                f'pip install --upgrade "{package}=={to_version}"'
                if ecosystem == "python"
                else f"npm install {package}@{to_version}"
            ),
        )
        plan.steps.append(step)
        cleared_risk += step.risk_cleared
        changes.setdefault(rel, {})[key] = to_version

    plan.risk_after = max(0.0, round(plan.risk_before - cleared_risk, 2))
    plan.steps.sort(key=lambda step: (-step.risk_cleared, step.package))

    patches: list[str] = []
    for _path, rel, text, pins in python_manifests:
        wanted = changes.get(rel)
        if not wanted:
            continue
        updated = _patch_requirements(text, pins, wanted)
        if updated != text:
            patches.append(_diff(text, updated, rel))
    for _path, rel, text, _data in node_manifests:
        wanted = changes.get(rel)
        if not wanted:
            continue
        updated = _patch_package_json(text, wanted)
        if updated != text:
            patches.append(_diff(text, updated, rel))
    plan.patch = "".join(patches)
    return plan


def render_markdown(plan: RemediationPlan) -> str:
    """Human-readable plan for the report and PR comment."""
    lines = [
        "## Remediation plan",
        "",
        f"{plan.cves_cleared}/{plan.cves_total} CVEs cleared by {len(plan.steps)} "
        f"upgrade(s) -- priority mass cut {plan.reduction_pct}% "
        f"({plan.risk_before:.2f} -> {plan.risk_after:.2f}).",
        "",
    ]
    if plan.steps:
        lines += ["| Package | From | To | Manifest | CVEs | KEV | Risk |",
                  "|---|---|---|---|---|---|---|"]
        for step in plan.steps:
            lines.append(
                f"| `{step.package}` | {step.current_version} | **{step.target_version}** "
                f"| `{step.manifest}` | {len(step.cleared_cves)} | {step.kev_cleared} "
                f"| {step.risk_cleared:.2f} |"
            )
        lines += ["", "```bash"] + [step.command for step in plan.steps] + ["```", ""]
    if plan.manual:
        lines.append("### Needs a human")
        for item in plan.manual:
            lines.append(
                f"- **{item['cve_id']}** `{item['package']}=={item['version']}` "
                f"({item['severity'] or 'UNKNOWN'}) -- {item['reason']}"
            )
        lines.append("")
    if plan.patch:
        lines += ["### Patch", "```diff", plan.patch.strip("\n"), "```", ""]
    return "\n".join(lines)
