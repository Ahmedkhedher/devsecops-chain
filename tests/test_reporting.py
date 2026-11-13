"""Tests for the offline Security Decision Lab (report builder + HTML shell)."""

import json
import math
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from common.finding import Finding
from pipeline import main
from reporting.dashboard import build_report, render_dashboard

FIXTURE = ROOT / "tests" / "fixtures" / "trivy_report.json"


def _extract_payload(html: str) -> dict:
    match = re.search(
        r'<script type="application/json" id="report-data">(.*?)</script>',
        html, re.S,
    )
    assert match, "embedded report payload not found"
    return json.loads(match.group(1))


class TestBuildReport(unittest.TestCase):
    def test_groups_by_artifact_package_version(self):
        findings = [
            Finding(cve_id="CVE-1", package="django", version="1.11",
                    target="requirements.txt", cvss=9.8, priority_score=3.9),
            Finding(cve_id="CVE-2", package="django", version="1.11",
                    target="requirements.txt", cvss=7.5, priority_score=3.0,
                    fixed_version="2.0"),
            Finding(cve_id="CVE-3", package="django", version="1.11",
                    target="other-requirements.txt", cvss=5.0, priority_score=2.0,
                    fixed_version="2.0"),
        ]
        report = build_report(findings)
        self.assertEqual(len(report["actions"]), 2)
        # Only fixable findings contribute to an action's projected weight;
        # the unscored-fix finding still counts toward the total backlog.
        by_target = {a["target"]: a for a in report["actions"]}
        self.assertEqual(by_target["requirements.txt"]["weight"], 3.0)
        self.assertEqual(by_target["other-requirements.txt"]["weight"], 2.0)
        self.assertEqual(by_target["requirements.txt"]["fixable_ids"], [1])
        self.assertEqual(sorted(by_target["requirements.txt"]["finding_ids"]), [0, 1])
        self.assertAlmostEqual(report["total_weight"], 8.9)

    def test_conflicting_fix_requirements_are_all_preserved(self):
        findings = [
            Finding(cve_id="CVE-1", package="lib", version="1.0",
                    priority_score=3.0, fixed_version="1.2"),
            Finding(cve_id="CVE-2", package="lib", version="1.0",
                    priority_score=2.0, fixed_version="1.5"),
        ]
        action = build_report(findings)["actions"][0]
        # Never guess a single "best" version: both requirements are review input.
        self.assertEqual(action["requirements"], ["1.2", "1.5"])

    def test_unscored_and_nonfinite_scores_never_inflate_totals(self):
        findings = [
            Finding(cve_id="CVE-1", package="a", version="1", priority_score=None),
            Finding(cve_id="CVE-2", package="b", version="1",
                    priority_score=float("nan"), fixed_version="2"),
            Finding(cve_id="CVE-3", package="c", version="1",
                    priority_score=-4.0, fixed_version="2"),
        ]
        report = build_report(findings)
        self.assertEqual(report["unscored"], 1)
        self.assertEqual(report["total_weight"], 0.0)
        self.assertTrue(all(
            not math.isnan(f["weight"]) and f["weight"] >= 0
            for f in report["findings"]
        ))

    def test_actions_sorted_by_projected_weight(self):
        findings = [
            Finding(cve_id="CVE-LOW", package="small", version="1",
                    priority_score=1.0, fixed_version="2"),
            Finding(cve_id="CVE-HIGH", package="big", version="1",
                    priority_score=9.0, fixed_version="2"),
        ]
        report = build_report(findings)
        self.assertEqual([a["package"] for a in report["actions"]], ["big", "small"])


class TestRenderDashboard(unittest.TestCase):
    def test_embedded_payload_round_trips(self):
        findings = [Finding(cve_id="CVE-1", package="requests", version="2.6.0",
                            cvss=6.1, priority_score=2.4, fixed_version="2.31.0",
                            reachable=True)]
        html = render_dashboard(findings)
        self.assertEqual(_extract_payload(html), build_report(findings))
        self.assertNotIn("__REPORT_DATA__", html)

    def test_scanner_controlled_text_cannot_break_out_of_script(self):
        hostile = "</script><img src=x onerror=alert(1)>"
        html = render_dashboard([
            Finding(cve_id=hostile, package=hostile, version="1",
                    target=hostile, priority_score=1.0),
        ])
        # The raw payload is escaped so it stays JSON data, never live markup.
        self.assertNotIn(hostile, html)
        self.assertIn("\\u003c/script\\u003e", html)
        # Exactly one data block plus one executable block, both closed.
        self.assertEqual(html.count('type="application/json"'), 1)
        self.assertEqual(html.count("<script>"), 1)

    def test_report_declares_offline_csp_and_no_remote_assets(self):
        html = render_dashboard([])
        self.assertIn('connect-src \'none\'', html)
        self.assertNotIn("http://", html)
        self.assertNotIn("https://", html)
        self.assertNotIn("src=\"//", html)

    def test_empty_report_still_renders(self):
        html = render_dashboard([])
        payload = _extract_payload(html)
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["actions"], [])
        self.assertIn("No findings to inspect", html)


class TestHtmlOutFlag(unittest.TestCase):
    def test_cli_writes_dashboard(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "lab.html"
            code = main([
                "--from-json", str(FIXTURE), "--offline", "--no-explain",
                "--html-out", str(out),
            ])
            self.assertEqual(code, 0)
            self.assertTrue(out.exists())
            payload = _extract_payload(out.read_text(encoding="utf-8"))
            self.assertGreater(len(payload["findings"]), 0)
            self.assertGreater(len(payload["actions"]), 0)


if __name__ == "__main__":
    unittest.main()