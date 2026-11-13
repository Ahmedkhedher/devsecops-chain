"""Pipeline orchestrator -- chains every stage into one runnable flow.

    scan -> prioritize (EPSS+KEV) -> reachability -> exposure -> explain -> output

This is the single entry point the CI workflow calls. Every stage is optional
and independently injectable, so the pipeline runs fully offline (fixture scan,
stub LLM, no network enrichment) for demos and tests, or live in CI.

Reachability feeds back into ranking: a finding whose package is never imported
gets its priority_score penalized, so real used-dependency risk floats to the
top and dead-dependency noise sinks. This is the false-positive reduction the
project is built to demonstrate.

Usage:
    py -m pipeline testproject --code-root testproject
    py -m pipeline --from-json tests/fixtures/trivy_report.json --code-root testproject --offline
    py -m pipeline testproject --json-out data/findings.json --top 10
    py -m pipeline --from-json report.json --offline --policy .security/policy.json --history
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from common.finding import Finding
from scanner.run_trivy import scan, scan_or_load, TrivyError
from prioritization.enrich import prioritize
from prioritization.epss_client import EPSSClient
from prioritization.kev_client import KEVClient
from prioritization.scorer import ScorerConfig
from reachability.ast_checker import apply_reachability
from reachability.exposure import apply_exposure
from explanation.explainer import (
    Explainer, StubLLM, OllamaLLM, OpenAICompatLLM,
    DEFAULT_OLLAMA_MODEL, ollama_host,
)
from explanation.cve_context import NVDClient

# Multiplicative penalty applied to priority_score when a package is present
# but never used. Kept < 1 so unreachable findings sink below reachable ones of
# similar raw risk, without being fully zeroed (SCA can miss dynamic imports).
UNREACHABLE_PENALTY = 0.5


@dataclass
class PipelineOptions:
    offline: bool = False          # no network: skip EPSS/KEV/NVD fetches
    do_prioritize: bool = True
    do_reachability: bool = True
    do_exposure: bool = True       # call-graph entrypoint tracing (needs code_root)
    do_explain: bool = True
    llm: str = "stub"              # stub | ollama | openai; independent of offline
    ollama_model: str = DEFAULT_OLLAMA_MODEL
    top: Optional[int] = None      # limit output to top-N findings
    code_root: Optional[Path] = None
    package_symbols: Optional[dict] = None


def _make_llm(opts: PipelineOptions):
    if opts.llm == "stub":
        return StubLLM()
    if opts.llm == "ollama":
        return OllamaLLM(model=opts.ollama_model, host=ollama_host())
    if opts.llm == "openai":
        return OpenAICompatLLM(
            model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
            base_url=os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
            api_key=os.environ.get("OPENAI_API_KEY", ""),
        )
    raise ValueError(f"unknown llm backend: {opts.llm}")


def _apply_reachability_penalty(findings: list[Finding]) -> None:
    """Demote findings whose package is present but never used."""
    for f in findings:
        if f.reachable is False and f.priority_score is not None:
            f.priority_score = round(f.priority_score * UNREACHABLE_PENALTY, 2)


def run_pipeline(
    findings: list[Finding],
    opts: Optional[PipelineOptions] = None,
    progress: Optional[Callable[[str], None]] = None,
) -> list[Finding]:
    """Run enrichment stages over an already-scanned list of findings.

    `progress` (optional) is called with a human-readable message before each
    stage, so a front-end can show what's happening. It's invoked on the
    caller's thread -- the GUI marshals it back to the UI thread.
    """
    opts = opts or PipelineOptions()

    def _stage(msg: str) -> None:
        if progress is not None:
            progress(msg)

    # --- Phase 2: prioritization ---
    if opts.do_prioritize:
        _stage("Prioritizing (EPSS + KEV)" if not opts.offline else "Ranking by severity")
        if opts.offline:
            # No network: rank on CVSS alone (EPSS/KEV left unset).
            from prioritization.scorer import rank
            findings = rank(findings, ScorerConfig())
        else:
            findings = prioritize(
                findings,
                epss_client=EPSSClient(),
                kev_client=KEVClient(),
            )

    # --- Phase 5: reachability ---
    if opts.do_reachability and opts.code_root:
        _stage("Checking reachability (scanning source)")
        apply_reachability(
            findings, opts.code_root,
            package_symbols=opts.package_symbols,
        )
        _apply_reachability_penalty(findings)
        # Re-sort after the penalty so demoted findings drop down.
        findings.sort(key=lambda f: (-(f.priority_score or 0.0), -(f.cvss or 0.0), f.cve_id))

        if opts.do_exposure:
            _stage("Tracing exploit paths (call graph)")
            apply_exposure(
                findings, opts.code_root,
                package_symbols=opts.package_symbols,
            )

    # --- Phase 3: explanation ---
    if opts.do_explain:
        _stage(f"Generating explanations ({len(findings)} findings)")
        nvd = None if opts.offline else NVDClient()
        explainer = Explainer(llm=_make_llm(opts), nvd_client=nvd)
        findings = explainer.explain_all(
            findings,
            progress=lambda index, total: _stage(f"Explaining {index} of {total}"),
        )

    if opts.top:
        findings = findings[: opts.top]

    return findings


def scan_and_run(
    target: Optional[str],
    opts: PipelineOptions,
    from_json: Optional[str] = None,
    trivy_bin: str = "trivy",
    progress: Optional[Callable[[str], None]] = None,
) -> list[Finding]:
    if progress is not None:
        progress("Loading findings" if from_json else "Scanning with Trivy")
    findings = scan_or_load(target, from_json, trivy_bin=trivy_bin)
    if progress is not None:
        progress(f"{len(findings)} raw finding(s) parsed")
    return run_pipeline(findings, opts, progress=progress)


def _render_text(findings: list[Finding]) -> str:
    lines = []
    for i, f in enumerate(findings, 1):
        ps = f"{f.priority_score:.1f}" if f.priority_score is not None else "n/a"
        flags = []
        if f.kev_listed:
            flags.append("KEV")
        if f.known_ransomware:
            flags.append("RANSOMWARE")
        if f.kev_due_date:
            flags.append(f"due {f.kev_due_date}")
        if f.epss is not None:
            flags.append(f"EPSS {f.epss:.2f}")
        if f.reachable is True:
            flags.append("reachable")
        elif f.reachable is False:
            flags.append("UNUSED")
        if f.exposure and f.exposure not in ("none", "unlinked"):
            flags.append(f"exposed:{f.exposure}")
        flag_str = f"  [{' '.join(flags)}]" if flags else ""
        lines.append(
            f"{i}. [{f.severity or '?'}] {f.cve_id}  {f.package}=={f.version}"
            f"  priority={ps}{flag_str}"
        )
        if f.fixed_version:
            lines.append(f"     fix: upgrade to {f.fixed_version}")
        if f.explanation:
            exp = f.explanation.replace("\n", " ")
            lines.append(f"     {exp[:200]}")
            if f.confidence:
                lines.append(f"     (confidence: {f.confidence})")
            if f.grounded is False:
                lines.append("     (grounding check: explanation contains unsupported claims)")
    return "\n".join(lines)


def _render_markdown(findings: list[Finding], limit: int = 10) -> str:
    """PR-comment style output used by the CI stage."""
    if not findings:
        return "No vulnerabilities found. :white_check_mark:"
    lines = [
        f"## :shield: Security scan — {len(findings)} finding(s)",
        "",
        "| # | Severity | CVE | Package | Priority | Signals | Fix |",
        "|---|----------|-----|---------|----------|---------|-----|",
    ]
    for i, f in enumerate(findings[:limit], 1):
        ps = f"{f.priority_score:.1f}" if f.priority_score is not None else "—"
        sig = []
        if f.kev_listed:
            sig.append("KEV")
        if f.known_ransomware:
            sig.append("ransomware")
        if f.kev_due_date:
            sig.append(f"due {f.kev_due_date}")
        if f.epss is not None:
            sig.append(f"EPSS {f.epss:.2f}")
        if f.reachable is False:
            sig.append("unused")
        elif f.reachable is True:
            sig.append("reachable")
        if f.exposure and f.exposure not in ("none", "unlinked"):
            sig.append(f"{f.exposure}-exposed")
        fix = f"`{f.fixed_version}`" if f.fixed_version else "—"
        lines.append(
            f"| {i} | {f.severity or '?'} | {f.cve_id} | "
            f"`{f.package}=={f.version}` | {ps} | {' '.join(sig) or '—'} | {fix} |"
        )
    if len(findings) > limit:
        lines.append(f"\n_…and {len(findings) - limit} more._")
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Run the full DevSecOps pipeline.")
    p.add_argument("target", nargs="?", help="path/image to scan with Trivy")
    p.add_argument("--from-json", help="parse an existing Trivy JSON report")
    p.add_argument("--code-root", help="source root for reachability analysis")
    p.add_argument("--offline", action="store_true",
                   help="no network: CVSS-only ranking, no EPSS/KEV/NVD")
    p.add_argument("--llm", default="stub", choices=["stub", "ollama", "openai"])
    p.add_argument("--ollama-model", default=DEFAULT_OLLAMA_MODEL)
    p.add_argument("--top", type=int, help="limit to top-N findings")
    p.add_argument("--trivy-bin", default="trivy")
    p.add_argument("--json-out", help="write findings JSON here")
    p.add_argument("--markdown-out", help="write PR-comment markdown here")
    p.add_argument("--vex-out", help="write an OpenVEX 0.2.0 document here")
    p.add_argument("--remediation-out",
                   help="write the upgrade plan (markdown) here")
    p.add_argument("--patch-out",
                   help="write the manifest patch (unified diff) here")
    p.add_argument("--policy", help="JSON policy file; exit 1 when the gate fails")
    p.add_argument("--policy-out", help="write the policy gate report as JSON here")
    p.add_argument("--policy-markdown-out",
                   help="write the policy gate report as markdown here")
    p.add_argument("--no-policy-fail", action="store_true",
                   help="report policy results but always exit 0")
    p.add_argument("--history", nargs="?", const=str(ROOT / "data" / "history.db"),
                   help="record this run in SQLite and print the delta "
                        "(default: data/history.db)")
    p.add_argument("--delta-markdown-out", help="write the history delta as markdown here")
    p.add_argument("--html-out", help="write an interactive offline Security Decision Lab")
    p.add_argument("--no-prioritize", action="store_true")
    p.add_argument("--no-reachability", action="store_true")
    p.add_argument("--no-exposure", action="store_true",
                   help="skip call-graph exploit-path tracing")
    p.add_argument("--no-explain", action="store_true")
    args = p.parse_args(argv)

    opts = PipelineOptions(
        offline=args.offline,
        do_prioritize=not args.no_prioritize,
        do_reachability=not args.no_reachability,
        do_exposure=not args.no_exposure,
        do_explain=not args.no_explain,
        llm=args.llm,
        ollama_model=args.ollama_model,
        top=args.top,
        code_root=Path(args.code_root) if args.code_root else None,
    )
    # Analyze every finding; --top only trims what gets printed/exported.
    # Policy gates and history deltas must see the full result set.
    opts.top = None

    try:
        all_findings = scan_and_run(args.target, opts, from_json=args.from_json,
                                    trivy_bin=args.trivy_bin)
    except TrivyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    findings = all_findings[: args.top] if args.top else all_findings

    print(_render_text(findings))
    print(f"\n{len(findings)} finding(s).")

    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(
            json.dumps([f.to_dict() for f in findings], indent=2), encoding="utf-8"
        )
        print(f"wrote {args.json_out}")

    if args.markdown_out:
        Path(args.markdown_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.markdown_out).write_text(
            _render_markdown(findings, limit=args.top or 10), encoding="utf-8"
        )
        print(f"wrote {args.markdown_out}")

    if args.vex_out:
        from output.vex import write_vex
        destination = write_vex(args.vex_out, findings)
        print(f"wrote {destination}")

    if args.remediation_out or args.patch_out:
        from remediation.planner import build_plan, render_markdown

        root = opts.code_root or (Path(args.target) if args.target else ROOT)
        plan = build_plan(all_findings, root)
        print(
            f"\nRemediation: {plan.cves_cleared}/{plan.cves_total} CVE(s) cleared by "
            f"{len(plan.steps)} upgrade(s), priority mass down {plan.reduction_pct}%, "
            f"{len(plan.manual)} finding(s) need a human."
        )
        if args.remediation_out:
            Path(args.remediation_out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.remediation_out).write_text(
                render_markdown(plan), encoding="utf-8"
            )
            print(f"wrote {args.remediation_out}")
        if args.patch_out:
            Path(args.patch_out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.patch_out).write_text(plan.patch, encoding="utf-8")
            print(f"wrote {args.patch_out}")

    if args.html_out:
        from reporting.dashboard import render_dashboard
        destination = Path(args.html_out)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(render_dashboard(findings), encoding="utf-8")
        print(f"wrote {args.html_out}")

    exit_code = 0
    if args.policy:
        from policy.gate import PolicyError, evaluate_gate, load_policy
        try:
            policy = load_policy(args.policy)
        except PolicyError as exc:
            print(f"policy error: {exc}", file=sys.stderr)
            return 2
        report = evaluate_gate(all_findings, policy)
        print("\n" + report.render_text())
        if args.policy_out:
            Path(args.policy_out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.policy_out).write_text(
                json.dumps(report.to_dict(), indent=2), encoding="utf-8"
            )
            print(f"wrote {args.policy_out}")
        if args.policy_markdown_out:
            Path(args.policy_markdown_out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.policy_markdown_out).write_text(
                report.render_markdown(), encoding="utf-8"
            )
            print(f"wrote {args.policy_markdown_out}")
        if not report.passed and not args.no_policy_fail:
            exit_code = 1

    if args.history:
        from history.store import HistoryStore
        with HistoryStore(args.history) as store:
            delta = store.record_and_diff(
                all_findings,
                target=args.target or args.from_json,
                mode="offline" if args.offline else "live",
            )
        print("\n" + delta.render_text())
        if args.delta_markdown_out:
            Path(args.delta_markdown_out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.delta_markdown_out).write_text(
                delta.render_markdown(), encoding="utf-8"
            )
            print(f"wrote {args.delta_markdown_out}")

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
