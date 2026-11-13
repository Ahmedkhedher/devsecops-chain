"""Tests for the OpenVEX 0.2.0 output stage."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from common.finding import Finding
from output.vex import build_vex, purl_for, render_vex, write_vex, OPENVEX_CONTEXT


def _f(**kw) -> Finding:
    base = dict(cve_id="CVE-2020-14343", package="PyYAML", version="5.1",
                severity="CRITICAL", fixed_version="5.4")
    base.update(kw)
    return Finding(**base)


class TestVexStatus(unittest.TestCase):
    def _statement(self, **kw):
        return build_vex([_f(**kw)], timestamp="2026-01-01T00:00:00Z")["statements"][0]

    def test_unimported_package_is_not_affected(self):
        st = self._statement(exposure="none")
        self.assertEqual(st["status"], "not_affected")
        self.assertEqual(st["justification"], "vulnerable_code_not_present")

    def test_unlinked_package_is_not_in_execute_path(self):
        st = self._statement(exposure="unlinked")
        self.assertEqual(st["status"], "not_affected")
        self.assertEqual(st["justification"], "vulnerable_code_not_in_execute_path")

    def test_network_exposure_is_affected_with_action(self):
        st = self._statement(
            exposure="network",
            exploit_path=["app.py:handler", "requests.get()"],
        )
        self.assertEqual(st["status"], "affected")
        self.assertIn("requests.get()", st["impact_statement"])
        self.assertIn("5.4", st["action_statement"])
        self.assertNotIn("justification", st)

    def test_cli_and_local_are_affected(self):
        for exposure in ("cli", "local"):
            st = self._statement(exposure=exposure, reachable=True)
            self.assertEqual(st["status"], "affected", exposure)

    def test_unreachable_without_exposure_is_not_affected(self):
        st = self._statement(reachable=False)
        self.assertEqual(st["status"], "not_affected")
        self.assertEqual(st["justification"], "vulnerable_code_not_in_execute_path")

    def test_unknown_analysis_is_under_investigation(self):
        st = self._statement()
        self.assertEqual(st["status"], "under_investigation")
        self.assertIn("status_notes", st)

    def test_affected_without_fix_uses_mitigation_action(self):
        st = self._statement(exposure="network", fixed_version=None)
        self.assertIn("No fixed version", st["action_statement"])


class TestVexDocument(unittest.TestCase):
    def test_context_id_and_timestamp(self):
        doc = build_vex([_f(exposure="none")], timestamp="2026-01-01T00:00:00Z")
        self.assertEqual(doc["@context"], OPENVEX_CONTEXT)
        self.assertEqual(doc["timestamp"], "2026-01-01T00:00:00Z")
        self.assertTrue(doc["@id"].startswith("urn:uuid:"))
        self.assertEqual(doc["version"], 1)

    def test_id_is_stable_for_same_findings(self):
        one = build_vex([_f(exposure="none")])["@id"]
        two = build_vex([_f(exposure="none")])["@id"]
        self.assertEqual(one, two)

    def test_id_changes_when_findings_change(self):
        one = build_vex([_f(exposure="none")])["@id"]
        two = build_vex([_f(exposure="network")])["@id"]
        self.assertNotEqual(one, two)

    def test_purl(self):
        self.assertEqual(purl_for(_f()), "pkg:pypi/pyyaml@5.1")

    def test_duplicate_findings_are_merged(self):
        doc = build_vex([_f(exposure="none"), _f(exposure="none")],
                        timestamp="2026-01-01T00:00:00Z")
        self.assertEqual(len(doc["statements"]), 1)

    def test_render_round_trips_as_json(self):
        text = render_vex([_f(exposure="network")], timestamp="2026-01-01T00:00:00Z")
        doc = json.loads(text)
        self.assertEqual(doc["statements"][0]["vulnerability"]["name"],
                         "CVE-2020-14343")

    def test_write_creates_parent_directory(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "nested" / "vex.json"
            written = write_vex(path, [_f(exposure="none")])
            self.assertEqual(written, path)
            self.assertTrue(path.exists())


if __name__ == "__main__":
    unittest.main()
