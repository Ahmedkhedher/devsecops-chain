"""Tests for the policy-as-code gate and expiring waivers."""

import json
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from common.finding import Finding
from policy.gate import (
    PolicyError, evaluate_gate, load_policy,
)


def _policy(data: dict, tmp: Path):
    path = tmp / "policy.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return load_policy(path)


BASE = {
    "version": 1,
    "name": "test-gate",
    "defaults": {},
    "rules": [],
    "waivers": [],
}


class TestPolicyLoading(unittest.TestCase):
    def test_missing_file(self):
        with self.assertRaises(PolicyError):
            load_policy(Path("does-not-exist.json"))

    def test_bad_version(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(PolicyError):
                _policy({**BASE, "version": 2}, Path(d))

    def test_unknown_condition_is_rejected(self):
        data = {**BASE, "rules": [
            {"id": "typo", "when": {"sevrity": "HIGH"}, "action": "fail"},
        ]}
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(PolicyError) as ctx:
                _policy(data, Path(d))
        self.assertIn("sevrity", str(ctx.exception))

    def test_waiver_requires_expiry_reason_owner(self):
        data = {**BASE, "waivers": [{"id": "W1", "cve": "CVE-1"}]}
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(PolicyError) as ctx:
                _policy(data, Path(d))
        self.assertIn("expires", str(ctx.exception))

    def test_valid_policy_loads(self):
        data = {
            **BASE,
            "defaults": {"fail_on_severity": "high"},
            "rules": [{"id": "r", "when": {"kev_listed": True}, "action": "warn"}],
            "waivers": [{
                "id": "W1", "cve": "CVE-1", "expires": "2030-01-01",
                "reason": "not exploitable here", "owner": "sec@example.com",
            }],
        }
        with tempfile.TemporaryDirectory() as d:
            policy = _policy(data, Path(d))
        self.assertEqual(policy.fail_on_severity, "HIGH")
        self.assertEqual(policy.rules[0].action, "warn")
        self.assertEqual(policy.waivers[0].expires, date(2030, 1, 1))


class TestGateEvaluation(unittest.TestCase):
    def test_severity_threshold_fails(self):
        with tempfile.TemporaryDirectory() as d:
            policy = _policy({**BASE, "defaults": {"fail_on_severity": "HIGH"}}, Path(d))
            report = evaluate_gate(
                [Finding(cve_id="CVE-1", package="x", version="1", severity="HIGH")],
                policy,
            )
        self.assertFalse(report.passed)
        self.assertEqual(report.violations[0].rule_id, "default:severity")

    def test_below_threshold_passes(self):
        with tempfile.TemporaryDirectory() as d:
            policy = _policy({**BASE, "defaults": {"fail_on_severity": "HIGH"}}, Path(d))
            report = evaluate_gate(
                [Finding(cve_id="CVE-1", package="x", version="1", severity="MEDIUM")],
                policy,
            )
        self.assertTrue(report.passed)

    def test_compound_rule_requires_all_conditions(self):
        with tempfile.TemporaryDirectory() as d:
            policy = _policy({**BASE, "rules": [{
                "id": "kev-network",
                "when": {"kev_listed": True, "exposure": ["network", "cli"]},
                "action": "fail",
            }]}, Path(d))
            kev_unused = Finding(cve_id="CVE-1", package="x", version="1",
                                 kev_listed=True, exposure="unlinked")
            clean_network = Finding(cve_id="CVE-2", package="y", version="1",
                                     exposure="network")
            kev_network = Finding(cve_id="CVE-3", package="z", version="1",
                                  kev_listed=True, exposure="network")
            report = evaluate_gate([kev_unused, clean_network, kev_network], policy)
        self.assertEqual([v.cve for v in report.violations], ["CVE-3"])

    def test_warn_rules_do_not_fail(self):
        with tempfile.TemporaryDirectory() as d:
            policy = _policy({**BASE, "rules": [{
                "id": "warn-me", "when": {"severity": "LOW"}, "action": "warn",
            }]}, Path(d))
            report = evaluate_gate(
                [Finding(cve_id="CVE-1", package="x", version="1", severity="HIGH")],
                policy,
            )
        self.assertTrue(report.passed)
        self.assertEqual(len(report.warnings), 1)

    def test_valid_waiver_suppresses(self):
        with tempfile.TemporaryDirectory() as d:
            policy = _policy({
                **BASE,
                "rules": [{"id": "r", "when": {"kev_listed": True}, "action": "fail"}],
                "waivers": [{
                    "id": "W1", "cve": "CVE-1", "package": "x",
                    "expires": "2030-01-01", "reason": "mitigated upstream",
                    "owner": "sec@example.com",
                }],
            }, Path(d))
            report = evaluate_gate(
                [Finding(cve_id="CVE-1", package="x", version="1", kev_listed=True)],
                policy, today=date(2026, 10, 20),
            )
        self.assertTrue(report.passed)
        self.assertEqual(report.waived[0].waiver_id, "W1")

    def test_expired_waiver_does_not_suppress_and_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            policy = _policy({
                **BASE,
                "rules": [{"id": "r", "when": {"kev_listed": True}, "action": "fail"}],
                "waivers": [{
                    "id": "W-OLD", "cve": "CVE-1",
                    "expires": "2026-01-01", "reason": "old", "owner": "sec",
                }],
            }, Path(d))
            report = evaluate_gate(
                [Finding(cve_id="CVE-1", package="x", version="1", kev_listed=True)],
                policy, today=date(2026, 10, 20),
            )
        self.assertFalse(report.passed)
        self.assertEqual(len(report.violations), 1)
        self.assertEqual(report.expired_waivers[0]["waiver"], "W-OLD")

    def test_expired_waiver_reported_even_without_matching_findings(self):
        with tempfile.TemporaryDirectory() as d:
            policy = _policy({
                **BASE,
                "waivers": [{
                    "id": "W-OLD", "cve": "CVE-9999-9999",
                    "expires": "2026-01-01", "reason": "old", "owner": "sec",
                }],
            }, Path(d))
            report = evaluate_gate([], policy, today=date(2026, 10, 20))
        self.assertTrue(report.passed)
        self.assertEqual(len(report.expired_waivers), 1)

    def test_non_waivable_rule_ignores_waiver(self):
        with tempfile.TemporaryDirectory() as d:
            policy = _policy({
                **BASE,
                "rules": [{
                    "id": "hard-block", "when": {"kev_listed": True},
                    "action": "fail", "waivable": False,
                }],
                "waivers": [{
                    "id": "W1", "cve": "CVE-1",
                    "expires": "2030-01-01", "reason": "nope", "owner": "sec",
                }],
            }, Path(d))
            report = evaluate_gate(
                [Finding(cve_id="CVE-1", package="x", version="1", kev_listed=True)],
                policy, today=date(2026, 10, 20),
            )
        self.assertFalse(report.passed)
        self.assertEqual(report.violations[0].rule_id, "hard-block")

    def test_package_scoped_waiver_does_not_leak(self):
        with tempfile.TemporaryDirectory() as d:
            policy = _policy({
                **BASE,
                "rules": [{"id": "r", "when": {"kev_listed": True}, "action": "fail"}],
                "waivers": [{
                    "id": "W1", "cve": "CVE-1", "package": "other",
                    "expires": "2030-01-01", "reason": "x", "owner": "sec",
                }],
            }, Path(d))
            report = evaluate_gate(
                [Finding(cve_id="CVE-1", package="x", version="1", kev_listed=True)],
                policy, today=date(2026, 10, 20),
            )
        self.assertFalse(report.passed)

    def test_stale_waiver_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            policy = _policy({
                **BASE,
                "waivers": [{
                    "id": "W1", "cve": "CVE-GONE",
                    "expires": "2030-01-01", "reason": "x", "owner": "sec",
                }],
            }, Path(d))
            report = evaluate_gate([], policy, today=date(2026, 10, 20))
        self.assertEqual(report.stale_waivers[0]["waiver"], "W1")

    def test_overdue_cisa_due_date(self):
        with tempfile.TemporaryDirectory() as d:
            policy = _policy({**BASE, "defaults": {"fail_on_overdue": True}}, Path(d))
            report = evaluate_gate(
                [Finding(cve_id="CVE-1", package="x", version="1",
                         kev_listed=True, kev_due_date="2026-01-01")],
                policy, today=date(2026, 10, 20),
            )
        self.assertFalse(report.passed)
        self.assertEqual(report.violations[0].rule_id, "default:overdue")

    def test_ransomware_default(self):
        with tempfile.TemporaryDirectory() as d:
            policy = _policy({**BASE, "defaults": {"fail_on_ransomware": True}}, Path(d))
            report = evaluate_gate(
                [Finding(cve_id="CVE-1", package="x", version="1",
                         known_ransomware=True)],
                policy,
            )
        self.assertEqual(report.violations[0].rule_id, "default:ransomware")

    def test_require_fix_for_affected(self):
        with tempfile.TemporaryDirectory() as d:
            policy = _policy({
                **BASE, "defaults": {"require_fix_for_affected": True},
            }, Path(d))
            report = evaluate_gate(
                [Finding(cve_id="CVE-1", package="x", version="1",
                         exposure="network")],
                policy,
            )
        self.assertEqual(report.violations[0].rule_id, "default:fix-required")

    def test_priority_threshold(self):
        with tempfile.TemporaryDirectory() as d:
            policy = _policy({
                **BASE, "defaults": {"max_priority_score": 40},
            }, Path(d))
            report = evaluate_gate(
                [Finding(cve_id="CVE-1", package="x", version="1",
                         priority_score=40.1)],
                policy,
            )
        self.assertFalse(report.passed)

    def test_unscored_finding_skips_priority_threshold(self):
        with tempfile.TemporaryDirectory() as d:
            policy = _policy({
                **BASE, "defaults": {"max_priority_score": 40},
            }, Path(d))
            report = evaluate_gate(
                [Finding(cve_id="CVE-1", package="x", version="1")], policy,
            )
        self.assertTrue(report.passed)

    def test_report_rendering(self):
        with tempfile.TemporaryDirectory() as d:
            policy = _policy({**BASE, "defaults": {"fail_on_severity": "HIGH"}}, Path(d))
            report = evaluate_gate(
                [Finding(cve_id="CVE-1", package="x", version="1", severity="CRITICAL")],
                policy,
            )
        text = report.render_text()
        self.assertIn("FAIL", text)
        self.assertIn("default:severity", text)
        self.assertIn("CVE-1", text)
        payload = report.to_dict()
        self.assertFalse(payload["passed"])
        self.assertEqual(payload["violations"][0]["cve"], "CVE-1")
        md = report.render_markdown()
        self.assertIn("Policy gate: FAIL", md)
        self.assertIn("default:severity", md)


class TestSamplePolicy(unittest.TestCase):
    def test_repository_sample_policy_is_valid(self):
        policy = load_policy(ROOT / ".security" / "policy.json")
        self.assertEqual(policy.name, "production-merge-gate")
        self.assertTrue(policy.waivers)


if __name__ == "__main__":
    unittest.main()
