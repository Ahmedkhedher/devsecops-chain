"""Tests for Phase 6: evaluation harness."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from eval.benchmark import (
    GroundTruth, BenchmarkCase, evaluate_case, run_benchmark,
    sample_cases, _ratio, _mean,
)
from pipeline import PipelineOptions

FIXTURE = ROOT / "tests" / "fixtures" / "trivy_report.json"
CODE_ROOT = ROOT / "testproject"


class TestHelpers(unittest.TestCase):
    def test_ratio_zero_denominator(self):
        self.assertEqual(_ratio(3, 0), 0.0)

    def test_ratio_normal(self):
        self.assertAlmostEqual(_ratio(1, 4), 0.25)

    def test_mean_empty(self):
        self.assertEqual(_mean([]), 0.0)

    def test_mean(self):
        self.assertAlmostEqual(_mean([1.0, 2.0, 3.0]), 2.0)


class TestEvaluateCase(unittest.TestCase):
    def _case(self, gt):
        return BenchmarkCase(
            name="t", report_path=FIXTURE, code_root=CODE_ROOT, ground_truth=gt,
        )

    def test_full_recall_when_all_present(self):
        gt = GroundTruth(true_cves={
            "CVE-2020-14343", "CVE-2023-32681", "CVE-2018-20225",
            "CVE-2021-33503", "CVE-2023-25577",
        })
        res = evaluate_case(self._case(gt), top_n=5)
        self.assertAlmostEqual(res.recall, 1.0)
        self.assertEqual(res.true_positives, 5)
        self.assertEqual(res.detected, 5)

    def test_partial_recall(self):
        gt = GroundTruth(true_cves={"CVE-2020-14343", "CVE-DOES-NOT-EXIST"})
        res = evaluate_case(self._case(gt), top_n=5)
        self.assertAlmostEqual(res.recall, 0.5)
        self.assertEqual(res.true_positives, 1)

    def test_precision(self):
        # Only 2 of the 5 detected are labeled true -> precision 0.4
        gt = GroundTruth(true_cves={"CVE-2020-14343", "CVE-2023-32681"})
        res = evaluate_case(self._case(gt), top_n=5)
        self.assertAlmostEqual(res.precision, 2 / 5)

    def test_noise_demoted_by_reachability(self):
        """Unused deps (pip/urllib3/werkzeug) should fall out of the top-2."""
        gt = GroundTruth(
            true_cves={"CVE-2020-14343", "CVE-2023-32681"},
            noise_cves={"CVE-2018-20225", "CVE-2021-33503", "CVE-2023-25577"},
        )
        res = evaluate_case(self._case(gt), top_n=2)
        # The two reachable CVEs occupy the top; all 3 noise items demoted.
        self.assertEqual(res.noise_demoted, 3)
        self.assertAlmostEqual(res.false_positive_reduction, 1.0)
        self.assertEqual(set(res.top_cves), {"CVE-2020-14343", "CVE-2023-32681"})

    def test_top_rank_ok_flag(self):
        gt = GroundTruth(must_rank_top={"CVE-2020-14343"})
        res = evaluate_case(self._case(gt), top_n=3)
        self.assertTrue(res.top_rank_ok)

    def test_top_rank_fails_when_missing(self):
        gt = GroundTruth(must_rank_top={"CVE-NOT-REAL"})
        res = evaluate_case(self._case(gt), top_n=3)
        self.assertFalse(res.top_rank_ok)

    def test_no_reachability_keeps_noise_in_top(self):
        """Sanity: without reachability, a CRITICAL unused dep stays on top."""
        gt = GroundTruth(
            true_cves={"CVE-2020-14343"},
            noise_cves={"CVE-2018-20225"},  # pip, CRITICAL cvss 9.8, unused
        )
        opts = PipelineOptions(offline=True, do_explain=False, do_reachability=False)
        res = evaluate_case(self._case(gt), opts=opts, top_n=2)
        # With reachability off, pip's high CVSS keeps it in the top -> not demoted.
        self.assertIn("CVE-2018-20225", res.top_cves)
        self.assertEqual(res.noise_demoted, 0)

    def test_hallucination_rate_field(self):
        gt = GroundTruth(true_cves={"CVE-2020-14343"})
        opts = PipelineOptions(offline=True, do_explain=True)
        res = evaluate_case(self._case(gt), opts=opts, top_n=5)
        self.assertEqual(res.explanations_checked, 5)
        self.assertEqual(res.ungrounded_explanations, 0)
        self.assertEqual(res.hallucination_rate, 0.0)


class TestRunBenchmark(unittest.TestCase):
    def test_aggregate_report(self):
        cases = sample_cases()
        report = run_benchmark(cases, top_n=5)
        self.assertEqual(len(report.cases), 1)
        self.assertAlmostEqual(report.mean_recall, 1.0)
        d = report.to_dict()
        self.assertIn("summary", d)
        self.assertEqual(d["summary"]["cases"], 1)
        # The default benchmark audits every explanation, not just rankings.
        self.assertEqual(report.cases[0].explanations_checked, 5)

    def test_render_text(self):
        report = run_benchmark(sample_cases(), top_n=5)
        txt = report.render_text()
        self.assertIn("Evaluation report", txt)
        self.assertIn("seed-testproject", txt)
        self.assertIn("mean recall", txt)

    def test_sample_case_fp_reduction_is_high(self):
        """The headline result: reachability suppresses unused-dependency noise."""
        report = run_benchmark(sample_cases(), top_n=2)
        self.assertGreaterEqual(report.mean_fp_reduction, 0.9)


if __name__ == "__main__":
    unittest.main()
