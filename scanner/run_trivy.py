"""Phase 1 -- Detection pipeline.

Wraps Trivy, captures its JSON report, and parses it into standardized
Finding objects. Runs Trivy as a subprocess when available, or parses a
pre-existing JSON report (--from-json) so the parser is testable offline.

Usage:
    py -m scanner.run_trivy ../testproject            # scan a directory
    py -m scanner.run_trivy --from-json report.json   # parse an existing report
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

# Ensure the repo root is importable whether run as a script or a module.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.finding import Finding


class TrivyError(RuntimeError):
    """Raised when Trivy cannot be run or returns a non-parseable report."""


# Trivy's default DB mirror (mirror.gcr.io) is slow or blocked on some
# networks; its own 5-minute DB-download deadline then aborts the scan.
# GHCR is the canonical registry and the safer default here.
DEFAULT_DB_REPOSITORY = "ghcr.io/aquasecurity/trivy-db:2"
DEFAULT_TRIVY_TIMEOUT = "30m"
DEFAULT_PROCESS_TIMEOUT = 1900  # seconds; must exceed the Trivy --timeout


def build_trivy_command(
    target: str,
    trivy_bin: str = "trivy",
    trivy_timeout: str = DEFAULT_TRIVY_TIMEOUT,
) -> list[str]:
    return [
        trivy_bin, "fs",
        "--format", "json",
        "--scanners", "vuln",
        "--timeout", trivy_timeout,
        "--quiet",
        target,
    ]


def resolve_trivy(trivy_bin: str = "trivy") -> Optional[str]:
    """Resolve Trivy even when the current process has a stale PATH.

    Winget installs its shims into %LOCALAPPDATA%\\Microsoft\\WinGet\\Links
    and updates the user PATH, but long-running shells and apps keep their
    original environment; look there directly as a fallback.
    """
    if os.path.dirname(trivy_bin):
        return trivy_bin if os.path.isfile(trivy_bin) else None
    found = shutil.which(trivy_bin)
    if found:
        return found
    if sys.platform == "win32" and Path(trivy_bin).stem.lower() == "trivy":
        local = os.environ.get("LOCALAPPDATA")
        if local:
            shim = Path(local) / "Microsoft" / "WinGet" / "Links" / "trivy.exe"
            if shim.is_file():
                return str(shim)
    return None


def trivy_env(db_repository: Optional[str] = None) -> dict[str, str]:
    env = os.environ.copy()
    if db_repository:
        env["TRIVY_DB_REPOSITORY"] = db_repository
    elif not env.get("TRIVY_DB_REPOSITORY"):
        env["TRIVY_DB_REPOSITORY"] = DEFAULT_DB_REPOSITORY
    return env


def run_trivy(
    target: str,
    trivy_bin: str = "trivy",
    timeout: int = DEFAULT_PROCESS_TIMEOUT,
    trivy_timeout: str = DEFAULT_TRIVY_TIMEOUT,
    db_repository: Optional[str] = None,
) -> dict:
    """Invoke Trivy against `target` and return the parsed JSON report.

    Uses `trivy fs` (filesystem/SCA scan) which covers dependency manifests
    like requirements.txt, package-lock.json, go.sum, etc.
    """
    resolved = resolve_trivy(trivy_bin)
    if resolved is None:
        raise TrivyError(
            f"Trivy executable '{trivy_bin}' not found. Install it from "
            f"https://trivy.dev or pass --from-json to parse an existing report."
        )
    cmd = build_trivy_command(target, resolved, trivy_timeout)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=trivy_env(db_repository),
        )
    except FileNotFoundError as exc:
        raise TrivyError(
            f"Trivy executable '{trivy_bin}' not found. Install it from "
            f"https://trivy.dev or pass --from-json to parse an existing report."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise TrivyError(f"Trivy timed out after {timeout}s scanning {target}") from exc

    if proc.returncode not in (0, 1):
        # Trivy exits 1 when vulnerabilities are found (with --exit-code), else 0.
        raise TrivyError(
            f"Trivy failed (exit {proc.returncode}): {proc.stderr.strip()[:500]}"
        )
    if not proc.stdout.strip():
        raise TrivyError(f"Trivy produced no output for {target}: {proc.stderr.strip()[:500]}")

    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise TrivyError(f"Could not parse Trivy JSON output: {exc}") from exc


def _extract_cvss(vuln: dict) -> Optional[float]:
    """Pull the highest available CVSS v3 score from a Trivy vuln entry."""
    cvss_block = vuln.get("CVSS") or {}
    best: Optional[float] = None
    for _source, entry in cvss_block.items():
        if not isinstance(entry, dict):
            continue
        score = entry.get("V3Score") or entry.get("V2Score")
        if isinstance(score, (int, float)):
            best = score if best is None else max(best, float(score))
    # Fall back to a top-level score if present.
    if best is None:
        score = vuln.get("CVSSScore")
        if isinstance(score, (int, float)):
            best = float(score)
    return best


def parse_report(report: dict) -> list[Finding]:
    """Convert a Trivy JSON report into a list of Finding objects."""
    findings: list[Finding] = []
    artifact = report.get("ArtifactName")

    for result in report.get("Results") or []:
        target = result.get("Target") or artifact
        for vuln in result.get("Vulnerabilities") or []:
            fixed = vuln.get("FixedVersion") or None
            findings.append(
                Finding(
                    cve_id=vuln.get("VulnerabilityID", "UNKNOWN"),
                    package=vuln.get("PkgName", "unknown"),
                    version=vuln.get("InstalledVersion", ""),
                    severity=(vuln.get("Severity") or "").upper(),
                    cvss=_extract_cvss(vuln),
                    fixed_version=fixed,
                    target=target,
                    title=vuln.get("Title") or None,
                )
            )
    return findings


def scan(target: str, trivy_bin: str = "trivy",
         timeout: int = DEFAULT_PROCESS_TIMEOUT) -> list[Finding]:
    """Run Trivy on `target` and return parsed findings."""
    return parse_report(run_trivy(target, trivy_bin=trivy_bin, timeout=timeout))


def scan_or_load(target: Optional[str], from_json: Optional[str],
                 trivy_bin: str = "trivy") -> list[Finding]:
    if from_json:
        report = json.loads(Path(from_json).read_text(encoding="utf-8"))
        return parse_report(report)
    if not target:
        raise TrivyError("Provide either a scan target or --from-json <report.json>.")
    return scan(target, trivy_bin=trivy_bin)


def _format_finding(f: Finding) -> str:
    cvss = f"{f.cvss:.1f}" if f.cvss is not None else "n/a"
    fix = f" -> {f.fixed_version}" if f.fixed_version else ""
    return (
        f"[{f.severity or 'UNKNOWN':8}] {f.cve_id}  "
        f"{f.package}=={f.version}{fix}  (CVSS {cvss})  in {f.target}"
    )


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run Trivy and emit Finding objects.")
    parser.add_argument("target", nargs="?", help="path/image to scan")
    parser.add_argument("--from-json", help="parse an existing Trivy JSON report instead of scanning")
    parser.add_argument("--trivy-bin", default="trivy", help="Trivy executable name/path")
    parser.add_argument("--json-out", help="write findings as JSON to this path")
    args = parser.parse_args(argv)

    try:
        findings = scan_or_load(args.target, args.from_json, trivy_bin=args.trivy_bin)
    except TrivyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # Phase 1 checkpoint: a clean list of Finding objects, sorted by CVSS.
    findings.sort(key=lambda f: (f.cvss is None, -(f.cvss or 0)))
    for f in findings:
        print(_format_finding(f))
    print(f"\n{len(findings)} finding(s).")

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps([f.to_dict() for f in findings], indent=2),
            encoding="utf-8",
        )
        print(f"wrote {args.json_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
