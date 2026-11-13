"""Tests for the pipeline orchestrator (stage chaining + reachability demotion)."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from common.finding import Finding
from explanation.explainer import OllamaLLM, StubLLM
from pipeline import (
    PipelineOptions, run_pipeline, _apply_reachability_penalty, _make_llm,
    _render_markdown, _render_text, UNREACHABLE_PENALTY,
)

FIXTURE = ROOT / "tests" / "fixtures" / "trivy_report.json"


def _write(root: Path, rel: str, content: str):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


class TestReachabilityPenalty(unittest.TestCase):
    def test_unreachable_is_penalized(self):
        f = Finding(cve_id="CVE-1", package="x", version="1",
                    cvss=9.0, priority_score=3.6, reachable=False)
        _apply_reachability_penalty([f])
        self.assertAlmostEqual(f.priority_score, 3.6 * UNREACHABLE_PENALTY)

    def test_reachable_untouched(self):
        f = Finding(cve_id="CVE-1", package="x", version="1",
                    cvss=9.0, priority_score=3.6, reachable=True)
        _apply_reachability_penalty([f])
        self.assertAlmostEqual(f.priority_score, 3.6)

    def test_none_reachable_untouched(self):
        f = Finding(cve_id="CVE-1", package="x", version="1",
                    cvss=9.0, priority_score=3.6, reachable=None)
        _apply_reachability_penalty([f])
        self.assertAlmostEqual(f.priority_score, 3.6)


class TestRunPipelineOffline(unittest.TestCase):
    def test_offline_ranks_and_demotes_unused(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            # requests is used; django is not.
            _write(root, "app.py", "import requests\nrequests.get('x')\n")
            findings = [
                Finding(cve_id="CVE-DJANGO", package="django", version="1.11",
                        severity="CRITICAL", cvss=9.8),
                Finding(cve_id="CVE-REQ", package="requests", version="2.6.0",
                        severity="MEDIUM", cvss=6.1),
            ]
            opts = PipelineOptions(offline=True, code_root=root, do_explain=False)
            out = run_pipeline(findings, opts)

            by_id = {f.cve_id: f for f in out}
            self.assertTrue(by_id["CVE-REQ"].reachable)
            self.assertFalse(by_id["CVE-DJANGO"].reachable)
            # Despite lower CVSS, the reachable package must outrank the
            # unused critical one after the penalty.
            self.assertEqual(out[0].cve_id, "CVE-REQ")

    def test_offline_explain_populates_stub(self):
        findings = [Finding(cve_id="CVE-1", package="x", version="1",
                            severity="HIGH", cvss=7.0, fixed_version="2.0")]
        out = run_pipeline(findings, PipelineOptions(offline=True))
        self.assertTrue(out[0].explanation)
        self.assertIn("2.0", out[0].suggested_fix)

    def test_top_limits_output(self):
        findings = [Finding(cve_id=f"CVE-{i}", package="x", version="1", cvss=float(i))
                    for i in range(1, 6)]
        out = run_pipeline(findings, PipelineOptions(offline=True, do_explain=False, top=2))
        self.assertEqual(len(out), 2)

    def test_stage_toggles(self):
        findings = [Finding(cve_id="CVE-1", package="x", version="1", cvss=7.0)]
        out = run_pipeline(findings, PipelineOptions(
            offline=True, do_prioritize=False, do_reachability=False, do_explain=False))
        self.assertIsNone(out[0].priority_score)
        self.assertIsNone(out[0].explanation)


class TestRenderers(unittest.TestCase):
    def test_markdown_empty(self):
        self.assertIn("No vulnerabilities", _render_markdown([]))

    def test_markdown_table(self):
        f = Finding(cve_id="CVE-1", package="requests", version="2.6.0",
                    severity="MEDIUM", cvss=6.1, priority_score=2.4,
                    fixed_version="2.31.0", kev_listed=True, reachable=True)
        md = _render_markdown([f])
        self.assertIn("| # | Severity | CVE |", md)
        self.assertIn("CVE-1", md)
        self.assertIn("KEV", md)
        self.assertIn("2.31.0", md)

    def test_markdown_truncates_to_limit(self):
        findings = [Finding(cve_id=f"CVE-{i}", package="x", version="1") for i in range(15)]
        md = _render_markdown(findings, limit=10)
        self.assertIn("5 more", md)

    def test_text_render(self):
        f = Finding(cve_id="CVE-1", package="x", version="1", severity="HIGH",
                    cvss=7.0, priority_score=2.8, fixed_version="2.0",
                    explanation="Some text.", confidence="medium")
        txt = _render_text([f])
        self.assertIn("CVE-1", txt)
        self.assertIn("confidence: medium", txt)


class TestProgressCallback(unittest.TestCase):
    """The GUI relies on run_pipeline emitting stage messages via `progress`."""

    def test_emits_stage_before_each_enabled_stage(self):
        seen = []
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "app.py", "import requests\n")
            findings = [Finding(cve_id="CVE-1", package="requests", version="1", cvss=7.0)]
            opts = PipelineOptions(offline=True, code_root=root)
            run_pipeline(findings, opts, progress=seen.append)
        # Offline still ranks, reachability runs, explanation runs (stub).
        self.assertTrue(any("Ranking" in m for m in seen), seen)
        self.assertTrue(any("reachability" in m.lower() for m in seen), seen)
        self.assertTrue(any("explanation" in m.lower() for m in seen), seen)

    def test_no_stage_for_disabled(self):
        seen = []
        findings = [Finding(cve_id="CVE-1", package="x", version="1", cvss=7.0)]
        opts = PipelineOptions(offline=True, do_prioritize=False,
                               do_reachability=False, do_explain=False)
        run_pipeline(findings, opts, progress=seen.append)
        self.assertEqual(seen, [])

    def test_none_progress_is_safe(self):
        findings = [Finding(cve_id="CVE-1", package="x", version="1", cvss=7.0)]
        out = run_pipeline(findings, PipelineOptions(offline=True), progress=None)
        self.assertEqual(len(out), 1)


class TestLLMSelection(unittest.TestCase):
    def test_offline_does_not_override_an_explicit_ollama_choice(self):
        llm = _make_llm(PipelineOptions(offline=True, llm="ollama"))
        self.assertIsInstance(llm, OllamaLLM)

    def test_offline_defaults_to_the_stub(self):
        llm = _make_llm(PipelineOptions(offline=True))
        self.assertIsInstance(llm, StubLLM)


class TestScanAndRunIntegration(unittest.TestCase):
    def test_fixture_through_pipeline(self):
        import json
        from scanner.run_trivy import parse_report
        report = json.loads(FIXTURE.read_text(encoding="utf-8"))
        findings = parse_report(report)
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "app.py", "import yaml\nimport requests\n")
            out = run_pipeline(findings, PipelineOptions(
                offline=True, code_root=root, do_explain=False))
        # pyyaml (imported as yaml) and requests are reachable -> top of list.
        top_packages = {f.package for f in out[:2]}
        self.assertTrue({"pyyaml", "requests"} & top_packages)


if __name__ == "__main__":
    unittest.main()
