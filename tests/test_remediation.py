"""Tests for the remediation autopilot.

The planner reads manifests from a temp folder and writes a patch, so every
test builds its own tiny project on disk. No network, no installed packages.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from common.finding import Finding
from pipeline import main
from remediation.planner import (
    RemediationPlan, build_plan, find_manifests, normalize_package,
    render_markdown, version_key,
)

FIXTURE = ROOT / "tests" / "fixtures" / "trivy_report.json"


def _finding(cve="CVE-1", package="x", version="1.0", fixed=None, **kw):
    return Finding(cve_id=cve, package=package, version=version,
                   fixed_version=fixed, **kw)


def _write(root: Path, name: str, text: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class TestVersionOrdering(unittest.TestCase):
    def test_numeric_core_orders_correctly(self):
        self.assertGreater(version_key("1.2.10"), version_key("1.2.9"))
        self.assertGreater(version_key("2.31.0"), version_key("2.6.0"))
        self.assertEqual(version_key("1.2"), version_key("1.2.0"))

    def test_prerelease_and_prefix_noise_is_tolerated(self):
        self.assertEqual(version_key("v1.2.3"), version_key("1.2.3"))
        self.assertEqual(version_key("2.0rc1"), (2, 0, 0, 0))
        self.assertEqual(version_key(None), (0, 0, 0, 0))

    def test_package_names_are_pep503_normalized(self):
        self.assertEqual(normalize_package("PyYAML"), "pyyaml")
        self.assertEqual(normalize_package("zope.interface"), "zope-interface")
        self.assertEqual(normalize_package("Django"), "django")


class TestManifestDiscovery(unittest.TestCase):
    def test_finds_editable_manifests_and_skips_vendor_dirs(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "requirements.txt", "requests==2.6.0\n")
            _write(root, "api/requirements-dev.txt", "pytest==7.0.0\n")
            _write(root, "node_modules/left-pad/package.json",
                   json.dumps({"name": "x", "dependencies": {"left-pad": "1.0.0"}}))
            _write(root, "web/package.json",
                   json.dumps({"name": "app", "dependencies": {"lodash": "^4.17.20"}}))
            _write(root, "web/empty/package.json", json.dumps({"name": "no-deps"}))
            found = {path.relative_to(root).as_posix()
                     for path, _kind in find_manifests(root)}
            self.assertEqual(found, {
                "requirements.txt", "api/requirements-dev.txt", "web/package.json",
            })
            self.assertEqual(find_manifests(root / "missing"), [])


class TestBuildPlan(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def _plan(self, findings, requirements="requests==2.6.0\n"):
        _write(self.root, "requirements.txt", requirements)
        return build_plan(findings, self.root)

    def test_groups_several_cves_into_one_upgrade(self):
        plan = self._plan([
            _finding("CVE-1", "requests", "2.6.0", "2.31.0", priority_score=3.0),
            _finding("CVE-2", "requests", "2.6.0", "2.28.1", priority_score=2.0),
            _finding("CVE-3", "requests", "2.6.0", "2.31.0", priority_score=1.0,
                     kev_listed=True, known_ransomware=True),
        ])
        self.assertEqual(len(plan.steps), 1)
        step = plan.steps[0]
        self.assertEqual(step.target_version, "2.31.0")
        self.assertEqual(step.cleared_cves, ["CVE-1", "CVE-2", "CVE-3"])
        self.assertEqual(step.risk_cleared, 6.0)
        self.assertEqual(step.kev_cleared, 1)
        self.assertEqual(step.ransomware_cleared, 1)
        self.assertEqual(step.command, 'pip install --upgrade "requests==2.31.0"')
        self.assertEqual(plan.risk_after, 0.0)
        self.assertEqual(plan.reduction_pct, 100.0)

    def test_patch_preserves_comments_and_extras(self):
        plan = self._plan(
            [_finding("CVE-1", "pyyaml", "5.1", "5.4")],
            requirements="# pinned for tests\nPyYAML[toml]==5.1  # old parser\n",
        )
        self.assertIn("-PyYAML[toml]==5.1", plan.patch)
        self.assertIn("+PyYAML[toml]==5.4", plan.patch)
        self.assertIn("# pinned for tests", plan.patch)
        self.assertIn("# old parser", plan.patch)

    def test_unpinned_package_goes_to_the_manual_list(self):
        plan = self._plan([_finding("CVE-9", "werkzeug", "0.16.0", "2.2.3")])
        self.assertEqual(plan.steps, [])
        self.assertIn("not pinned", plan.manual[0]["reason"])
        self.assertEqual(plan.manual[0]["cve_id"], "CVE-9")

    def test_no_upstream_fix_goes_to_the_manual_list(self):
        plan = self._plan([_finding("CVE-8", "requests", "2.6.0", None,
                                    severity="HIGH")])
        self.assertIn("no upstream fix", plan.manual[0]["reason"])

    def test_fix_not_newer_than_pin_needs_review(self):
        plan = self._plan([_finding("CVE-7", "requests", "2.6.0", "2.5.0")])
        self.assertEqual(plan.steps, [])
        self.assertIn("not newer", plan.manual[0]["reason"])

    def test_steps_sort_by_risk_cleared(self):
        plan = self._plan(
            [
                _finding("CVE-1", "flask", "0.12.2", "2.3.2", priority_score=1.0),
                _finding("CVE-2", "requests", "2.6.0", "2.31.0", priority_score=9.0),
            ],
            requirements="requests==2.6.0\nflask==0.12.2\n",
        )
        self.assertEqual([step.package for step in plan.steps], ["requests", "flask"])

    def test_npm_bump_keeps_the_range_prefix(self):
        _write(self.root, "package.json", json.dumps(
            {"name": "app", "dependencies": {"lodash": "^4.17.20"}}, indent=2))
        plan = build_plan(
            [_finding("CVE-5", "lodash", "4.17.20", "4.17.21")], self.root)
        step = plan.steps[0]
        self.assertEqual(step.ecosystem, "node")
        self.assertEqual(step.command, "npm install lodash@4.17.21")
        self.assertIn('"lodash": "^4.17.21"', plan.patch)

    def test_empty_root_produces_an_empty_plan(self):
        with tempfile.TemporaryDirectory() as d:
            plan = build_plan([_finding()], Path(d))
        self.assertEqual(plan.steps, [])
        self.assertEqual(plan.patch, "")
        self.assertEqual(plan.reduction_pct, 0.0)

    def test_serialization_shape(self):
        plan = self._plan([_finding("CVE-1", "requests", "2.6.0", "2.31.0")])
        payload = plan.to_dict()
        self.assertEqual(payload["summary"]["cves_cleared"], 1)
        self.assertEqual(payload["summary"]["upgrades"], 1)
        self.assertEqual(payload["steps"][0]["to"], "2.31.0")
        self.assertEqual(payload["steps"][0]["from"], "2.6.0")


class TestRenderMarkdown(unittest.TestCase):
    def test_renders_table_commands_and_manual_list(self):
        plan = RemediationPlan(
            risk_before=5.0, risk_after=1.0, cves_total=2,
        )
        from remediation.planner import UpgradeStep

        plan.steps = [UpgradeStep(
            package="requests", manifest="requirements.txt", ecosystem="python",
            current_version="2.6.0", target_version="2.31.0",
            cleared_cves=["CVE-1"], risk_cleared=4.0, kev_cleared=1,
            command='pip install --upgrade "requests==2.31.0"',
        )]
        plan.manual = [{"cve_id": "CVE-2", "package": "pip", "version": "9.0.1",
                        "severity": "CRITICAL", "reason": "no upstream fix"}]
        plan.patch = "--- a\n+++ a\n-x\n+y\n"
        text = render_markdown(plan)
        self.assertIn("## Remediation plan", text)
        self.assertIn("| `requests` | 2.6.0 | **2.31.0**", text)
        self.assertIn('pip install --upgrade "requests==2.31.0"', text)
        self.assertIn("### Needs a human", text)
        self.assertIn("```diff", text)


class TestCLIOutputs(unittest.TestCase):
    def test_cli_writes_plan_and_patch(self):
        with tempfile.TemporaryDirectory() as d:
            plan_path = Path(d) / "plan.md"
            patch_path = Path(d) / "plan.patch"
            code = main([
                "--from-json", str(FIXTURE), "--offline", "--no-explain",
                "--code-root", str(ROOT / "testproject"),
                "--remediation-out", str(plan_path), "--patch-out", str(patch_path),
            ])
            self.assertEqual(code, 0)
            self.assertIn("## Remediation plan",
                          plan_path.read_text(encoding="utf-8"))
            self.assertIn("+pyyaml==5.4",
                          patch_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
