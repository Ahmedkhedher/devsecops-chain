"""Tests for Phase 1: Trivy report parsing into Finding objects."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from common.finding import Finding
from scanner.run_trivy import (
    build_trivy_command, parse_report, resolve_trivy, run_trivy, scan_or_load,
    trivy_env, TrivyError, _extract_cvss, DEFAULT_DB_REPOSITORY,
)

FIXTURE = ROOT / "tests" / "fixtures" / "trivy_report.json"


class TestParseReport(unittest.TestCase):
    def setUp(self):
        self.findings = scan_or_load(None, str(FIXTURE))

    def test_parses_all_vulnerabilities(self):
        self.assertEqual(len(self.findings), 5)

    def test_all_are_finding_objects(self):
        self.assertTrue(all(isinstance(f, Finding) for f in self.findings))

    def test_fields_populated(self):
        by_id = {f.cve_id: f for f in self.findings}
        req = by_id["CVE-2023-32681"]
        self.assertEqual(req.package, "requests")
        self.assertEqual(req.version, "2.6.0")
        self.assertEqual(req.fixed_version, "2.31.0")
        self.assertEqual(req.severity, "MEDIUM")
        self.assertAlmostEqual(req.cvss, 6.1)
        self.assertEqual(req.target, "testproject/requirements.txt")

    def test_severity_normalized_uppercase(self):
        self.assertTrue(all(f.severity == f.severity.upper() for f in self.findings))

    def test_cvss_extraction_prefers_v3(self):
        vuln = {"CVSS": {"nvd": {"V3Score": 7.5, "V2Score": 5.0}}}
        self.assertEqual(_extract_cvss(vuln), 7.5)

    def test_cvss_extraction_none_when_absent(self):
        self.assertIsNone(_extract_cvss({}))

    def test_roundtrip_to_from_dict(self):
        f = self.findings[0]
        restored = Finding.from_dict(f.to_dict())
        self.assertEqual(restored.cve_id, f.cve_id)
        self.assertEqual(restored.package, f.package)


class TestCommandConstruction(unittest.TestCase):
    def test_command_includes_timeout(self):
        cmd = build_trivy_command("/project", trivy_timeout="30m")
        self.assertIn("--timeout", cmd)
        self.assertEqual(cmd[cmd.index("--timeout") + 1], "30m")
        self.assertEqual(cmd[-1], "/project")

    def test_env_defaults_to_ghcr_mirror(self):
        with patch.dict(os.environ, {}, clear=True):
            env = trivy_env()
        self.assertEqual(env["TRIVY_DB_REPOSITORY"], DEFAULT_DB_REPOSITORY)

    def test_env_respects_existing_override(self):
        with patch.dict(os.environ, {"TRIVY_DB_REPOSITORY": "example.com/db:1"},
                        clear=True):
            env = trivy_env()
        self.assertEqual(env["TRIVY_DB_REPOSITORY"], "example.com/db:1")

    def test_env_explicit_argument_wins(self):
        with patch.dict(os.environ, {"TRIVY_DB_REPOSITORY": "example.com/db:1"},
                        clear=True):
            env = trivy_env("other.example/db:2")
        self.assertEqual(env["TRIVY_DB_REPOSITORY"], "other.example/db:2")


class TestTrivyResolution(unittest.TestCase):
    def test_explicit_existing_path_is_used(self):
        self.assertEqual(resolve_trivy(str(FIXTURE)), str(FIXTURE))

    def test_explicit_missing_path_returns_none(self):
        self.assertIsNone(resolve_trivy(str(ROOT / "missing" / "trivy.exe")))

    def test_winget_shim_found_when_path_is_stale(self):
        with tempfile.TemporaryDirectory() as tmp:
            shim = Path(tmp) / "Microsoft" / "WinGet" / "Links" / "trivy.exe"
            shim.parent.mkdir(parents=True)
            shim.write_text("")
            with patch("scanner.run_trivy.shutil.which", return_value=None), \
                 patch("scanner.run_trivy.sys.platform", "win32"), \
                 patch.dict(os.environ, {"LOCALAPPDATA": tmp}):
                self.assertEqual(resolve_trivy("trivy"), str(shim))

    def test_missing_binary_raises_friendly_error(self):
        with self.assertRaises(TrivyError) as ctx:
            run_trivy(".", trivy_bin=str(ROOT / "missing" / "trivy.exe"), timeout=1)
        self.assertIn("not found", str(ctx.exception))


class TestEmptyReport(unittest.TestCase):
    def test_no_results(self):
        self.assertEqual(parse_report({"Results": []}), [])

    def test_results_without_vulnerabilities(self):
        report = {"Results": [{"Target": "x", "Vulnerabilities": None}]}
        self.assertEqual(parse_report(report), [])


if __name__ == "__main__":
    unittest.main()
