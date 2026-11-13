"""Phase 6 -- Evaluation harness.

Turns "I built a thing" into "here's proof it works." Runs the full pipeline
against labeled benchmark cases and reports:

  - detection recall:  did the scanner catch the known-vulnerable CVEs?
  - precision:         of what we reported, how much is real (vs. noise)?
  - false-positive reduction: how many low-relevance findings did
    prioritization + reachability correctly demote below the reporting cutoff?
  - rank quality:      do genuinely risky findings (KEV / reachable) surface at
    the top of the list?

A benchmark case = a Trivy JSON report + a code root (for reachability) +
ground truth (the CVEs that are truly present/relevant, and which are noise).
Cases run fully offline against fixtures, so evaluation is reproducible in CI
and doesn't depend on live network APIs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from common.finding import Finding
from scanner.run_trivy import parse_report
from pipeline import PipelineOptions, run_pipeline


@dataclass
class GroundTruth:
    """Labeled expectations for one benchmark case."""
    # CVEs that are genuinely present and should be detected.
    true_cves: set[str] = field(default_factory=set)
    # CVEs that are present but low-relevance (e.g. unused dependency) and
    # should be demoted below the reporting cutoff -- the false positives we
    # expect reachability/prioritization to suppress.
    noise_cves: set[str] = field(default_factory=set)
    # CVEs that MUST appear in the top-N of the ranked output.
    must_rank_top: set[str] = field(default_factory=set)


@dataclass
class BenchmarkCase:
    name: str
    report_path: Path
    code_root: Optional[Path]
    ground_truth: GroundTruth


@dataclass
class CaseResult:
    name: str
    detected: int                 # findings emitted by the pipeline
    true_positives: int           # true_cves we actually reported
    recall: float                 # true_positives / |true_cves|
    precision: float              # true_positives / detected (0 if none detected)
    noise_demoted: int            # noise_cves correctly pushed below the cutoff
    noise_total: int
    false_positive_reduction: float  # noise_demoted / noise_total
    top_rank_ok: bool             # all must_rank_top present in top-N
    explanations_checked: int = 0
    ungrounded_explanations: int = 0
    hallucination_rate: float = 0.0  # ungrounded / checked explanations
    reported_cves: list[str] = field(default_factory=list)
    top_cves: list[str] = field(default_factory=list)


@dataclass
class EvalReport:
    cases: list[CaseResult] = field(default_factory=list)

    @property
    def mean_recall(self) -> float:
        return _mean([c.recall for c in self.cases])

    @property
    def mean_precision(self) -> float:
        return _mean([c.precision for c in self.cases])

    @property
    def mean_fp_reduction(self) -> float:
        return _mean([c.false_positive_reduction for c in self.cases])

    @property
    def mean_hallucination_rate(self) -> float:
        return _mean([c.hallucination_rate for c in self.cases])

    def to_dict(self) -> dict:
        return {
            "summary": {
                "cases": len(self.cases),
                "mean_recall": round(self.mean_recall, 3),
                "mean_precision": round(self.mean_precision, 3),
                "mean_false_positive_reduction": round(self.mean_fp_reduction, 3),
                "mean_hallucination_rate": round(self.mean_hallucination_rate, 3),
            },
            "cases_detail": [
                {
                    "name": c.name,
                    "detected": c.detected,
                    "true_positives": c.true_positives,
                    "recall": round(c.recall, 3),
                    "precision": round(c.precision, 3),
                    "noise_demoted": c.noise_demoted,
                    "noise_total": c.noise_total,
                    "false_positive_reduction": round(c.false_positive_reduction, 3),
                    "top_rank_ok": c.top_rank_ok,
                    "explanations_checked": c.explanations_checked,
                    "ungrounded_explanations": c.ungrounded_explanations,
                    "hallucination_rate": round(c.hallucination_rate, 3),
                    "top_cves": c.top_cves,
                }
                for c in self.cases
            ],
        }

    def render_text(self) -> str:
        lines = ["=== Evaluation report ==="]
        for c in self.cases:
            lines.append(
                f"\n[{c.name}]\n"
                f"  recall={c.recall:.2f}  precision={c.precision:.2f}  "
                f"fp_reduction={c.false_positive_reduction:.2f}  top_rank_ok={c.top_rank_ok}\n"
                f"  true_positives={c.true_positives}  noise_demoted={c.noise_demoted}/{c.noise_total}\n"
                f"  hallucination_rate={c.hallucination_rate:.2f} "
                f"({c.ungrounded_explanations}/{c.explanations_checked} audited)\n"
                f"  top: {', '.join(c.top_cves) or '(none)'}"
            )
        lines.append(
            f"\n--- aggregate ---\n"
            f"  mean recall:              {self.mean_recall:.3f}\n"
            f"  mean precision:           {self.mean_precision:.3f}\n"
            f"  mean FP reduction:        {self.mean_fp_reduction:.3f}\n"
            f"  mean hallucination rate:  {self.mean_hallucination_rate:.3f}"
        )
        return "\n".join(lines)


def _mean(xs: list[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def _ratio(num: int, den: int) -> float:
    return (num / den) if den else 0.0


def evaluate_case(
    case: BenchmarkCase,
    opts: Optional[PipelineOptions] = None,
    top_n: int = 5,
) -> CaseResult:
    """Run the pipeline on one case and score it against ground truth."""
    opts = opts or PipelineOptions(offline=True, do_explain=True)
    # Force the code root / top from the case unless the caller overrode them.
    opts = PipelineOptions(**{**opts.__dict__, "code_root": case.code_root, "top": None})

    report = json.loads(Path(case.report_path).read_text(encoding="utf-8"))
    findings = parse_report(report)
    ranked = run_pipeline(findings, opts)

    reported = [f.cve_id for f in ranked]
    top = reported[:top_n]
    gt = case.ground_truth

    true_positives = len(gt.true_cves & set(reported))
    detected = len(reported)

    # Noise CVEs that did NOT make the top-N cutoff were successfully demoted.
    noise_in_top = gt.noise_cves & set(top)
    noise_demoted = len(gt.noise_cves) - len(noise_in_top)

    top_rank_ok = gt.must_rank_top.issubset(set(top)) if gt.must_rank_top else True

    audited = [f for f in ranked if f.grounded is not None]
    ungrounded = [f for f in audited if f.grounded is False]

    return CaseResult(
        name=case.name,
        detected=detected,
        true_positives=true_positives,
        recall=_ratio(true_positives, len(gt.true_cves)),
        precision=_ratio(true_positives, detected),
        noise_demoted=noise_demoted,
        noise_total=len(gt.noise_cves),
        false_positive_reduction=_ratio(noise_demoted, len(gt.noise_cves)),
        top_rank_ok=top_rank_ok,
        explanations_checked=len(audited),
        ungrounded_explanations=len(ungrounded),
        hallucination_rate=_ratio(len(ungrounded), len(audited)),
        reported_cves=reported,
        top_cves=top,
    )


def run_benchmark(
    cases: list[BenchmarkCase],
    opts: Optional[PipelineOptions] = None,
    top_n: int = 5,
) -> EvalReport:
    return EvalReport(cases=[evaluate_case(c, opts, top_n) for c in cases])


# --- Built-in sample suite (offline, fixture-based) ------------------------

def sample_cases(root: Optional[Path] = None) -> list[BenchmarkCase]:
    """A ready-made benchmark using the repo's own fixtures + seed project.

    Uses the shipped Trivy fixture. Ground truth reflects the seed project:
      - pyyaml and requests ARE imported in testproject/app.py  -> true & top
      - pip, urllib3, werkzeug are NOT imported                  -> noise
    """
    root = Path(root) if root else Path(__file__).resolve().parent.parent
    fixture = root / "tests" / "fixtures" / "trivy_report.json"
    code_root = root / "testproject"
    return [
        BenchmarkCase(
            name="seed-testproject",
            report_path=fixture,
            code_root=code_root,
            ground_truth=GroundTruth(
                true_cves={"CVE-2020-14343", "CVE-2023-32681", "CVE-2018-20225",
                           "CVE-2021-33503", "CVE-2023-25577"},
                noise_cves={"CVE-2018-20225", "CVE-2021-33503", "CVE-2023-25577"},
                must_rank_top={"CVE-2020-14343", "CVE-2023-32681"},
            ),
        )
    ]


def main(argv: Optional[list[str]] = None) -> int:
    import argparse

    p = argparse.ArgumentParser(description="Run the evaluation benchmark.")
    p.add_argument("--top", type=int, default=5, help="reporting cutoff for top-N")
    p.add_argument("--json-out", help="write the eval report as JSON here")
    args = p.parse_args(argv)

    report = run_benchmark(sample_cases(), top_n=args.top)
    print(report.render_text())

    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(
            json.dumps(report.to_dict(), indent=2), encoding="utf-8"
        )
        print(f"\nwrote {args.json_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
