"""Headless tests for the GUI's non-window logic.

Creating a real Tk window needs a display, so these cover the pure pieces the
window delegates to: toggle->PipelineOptions mapping, detail rendering, and
formatters. They also confirm the module imports without opening a window.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from common.finding import Finding
from gui.app import (
    COLUMNS, _num, _yes_no, fmt_elapsed, make_options, render_detail,
    render_plan_text, render_readiness_text, wrap,
)
from remediation.planner import RemediationPlan, UpgradeStep


class TestFmtElapsed(unittest.TestCase):
    def test_seconds_under_minute(self):
        self.assertEqual(fmt_elapsed(7), "0:07")

    def test_minutes_seconds(self):
        self.assertEqual(fmt_elapsed(65), "1:05")

    def test_hours(self):
        self.assertEqual(fmt_elapsed(3725), "1:02:05")

    def test_negative_clamped(self):
        self.assertEqual(fmt_elapsed(-5), "0:00")


class TestMakeOptions(unittest.TestCase):
    def test_offline_when_no_enrichment_keeps_chosen_llm(self):
        opts = make_options(Path("/x"), online=False, reach=True, llm="ollama", top=5)
        self.assertTrue(opts.offline)
        self.assertEqual(opts.llm, "ollama")

    def test_online_keeps_chosen_llm(self):
        opts = make_options(Path("/x"), online=True, reach=True, llm="ollama", top=5)
        self.assertFalse(opts.offline)
        self.assertEqual(opts.llm, "ollama")

    def test_reachability_sets_code_root(self):
        opts = make_options(Path("/x"), online=False, reach=True, llm="stub", top=0)
        self.assertTrue(opts.do_reachability)
        self.assertEqual(opts.code_root, Path("/x"))

    def test_no_reachability_clears_code_root(self):
        opts = make_options(Path("/x"), online=False, reach=False, llm="stub", top=0)
        self.assertFalse(opts.do_reachability)
        self.assertIsNone(opts.code_root)

    def test_top_zero_is_none(self):
        self.assertIsNone(make_options(Path("/x"), False, False, "stub", 0).top)
        self.assertEqual(make_options(Path("/x"), False, False, "stub", 12).top, 12)


class TestFormatters(unittest.TestCase):
    def test_num_none(self):
        self.assertEqual(_num(None), "—")

    def test_num_float(self):
        self.assertEqual(_num(2.345), "2.35")

    def test_num_int(self):
        self.assertEqual(_num(5), "5")

    def test_yes_no(self):
        self.assertEqual(_yes_no(True), "yes")
        self.assertEqual(_yes_no(False), "no")
        self.assertEqual(_yes_no(None), "—")


class TestRenderDetail(unittest.TestCase):
    def test_contains_all_key_fields(self):
        f = Finding(
            cve_id="CVE-2020-14343", package="pyyaml", version="5.1",
            severity="CRITICAL", cvss=9.8, epss=0.91, kev_listed=True,
            reachable=True, priority_score=52.3, fixed_version="5.4",
            exposure="network",
            exploit_path=["app.py:handler", "requests.get()"],
            explanation="PyYAML allows arbitrary code execution via unsafe load.",
            suggested_fix="Upgrade pyyaml to 5.4 or later.", confidence="high",
        )
        text = render_detail(f)
        self.assertIn("CVE-2020-14343", text)
        self.assertIn("pyyaml", text)
        self.assertIn("CRITICAL", text)
        self.assertIn("actively exploited", text)
        self.assertIn("Used in code: yes", text)
        self.assertIn("Exposure:     network", text)
        self.assertIn("app.py:handler → requests.get()", text)
        self.assertIn("Upgrade pyyaml", text)
        self.assertIn("Confidence: high", text)

    def test_missing_optional_fields_do_not_crash(self):
        f = Finding(cve_id="CVE-1", package="x", version="1")
        text = render_detail(f)
        self.assertIn("CVE-1", text)
        self.assertIn("Used in code: —", text)


class TestWrap(unittest.TestCase):
    def test_collapses_whitespace(self):
        out = wrap("a  b\n\n  c", width=80)
        self.assertEqual(out, "a b c")

    def test_columns_shape(self):
        # Sanity that the table has the columns the population code writes.
        keys = [c[0] for c in COLUMNS]
        self.assertEqual(
            keys, ["priority", "severity", "cve", "package", "version",
                   "reachable", "exposure", "kev", "epss", "fix"]
        )


class TestPlanAndReadinessText(unittest.TestCase):
    def test_plan_text_lists_commands_manual_and_patch(self):
        plan = RemediationPlan(risk_before=6.0, risk_after=2.0, cves_total=2)
        plan.steps = [UpgradeStep(
            package="pyyaml", manifest="requirements.txt", ecosystem="python",
            current_version="5.1", target_version="5.4", cleared_cves=["CVE-1"],
            risk_cleared=4.0, kev_cleared=1,
            command='pip install --upgrade "pyyaml==5.4"',
        )]
        plan.manual = [{"cve_id": "CVE-2", "package": "pip", "version": "9.0.1",
                        "severity": "CRITICAL", "reason": "no upstream fix"}]
        plan.patch = "-pyyaml==5.1\n+pyyaml==5.4\n"
        text = render_plan_text(plan)
        self.assertIn("1 of 2 CVE(s) cleared by 1 upgrade(s)", text)
        self.assertIn('pip install --upgrade "pyyaml==5.4"', text)
        self.assertIn("Needs a human:", text)
        self.assertIn("Manifest patch:", text)

    def test_readiness_text_shows_status_and_hints(self):
        report = {
            "python": "3.15.0",
            "trivy": {"status": "ok", "detail": "Trivy 0.76.0"},
            "ollama": {"status": "missing", "detail": "not running",
                       "hint": "run 'ollama serve'"},
            "openai": {"status": "missing", "detail": "no API key"},
            "policy": {"status": "ok", "detail": "3 rule(s)"},
            "capabilities": {"demo": True, "live_scan": True,
                             "ollama_explanations": False},
        }
        text = render_readiness_text(report)
        self.assertIn("[OK     ] Trivy scanner", text)
        self.assertIn("run 'ollama serve'", text)
        self.assertIn("ollama explanations: no", text)

    def test_readiness_error_is_readable(self):
        self.assertIn("boom", render_readiness_text({"error": "boom"}))


if __name__ == "__main__":
    unittest.main()
