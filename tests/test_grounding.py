"""Tests for the LLM groundedness / hallucination audit."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from common.finding import Finding
from explanation.grounding import (
    apply_grounding, audit_explanation, hallucination_rate,
)
from explanation.explainer import Explainer, StubLLM


def _finding(**kw) -> Finding:
    base = dict(
        cve_id="CVE-2020-14343", package="pyyaml", version="5.1",
        severity="CRITICAL", cvss=9.8, epss=0.42, fixed_version="5.4",
        title="PyYAML arbitrary code execution",
    )
    base.update(kw)
    return Finding(**base)


NVD = "PyYAML 5.1 allows arbitrary code execution via the full_load method."


class TestGroundingConflicts(unittest.TestCase):
    def test_correct_explanation_is_grounded(self):
        f = _finding(extra={"nvd_description": NVD}, reachable=True)
        f.explanation = (
            "PyYAML before 5.4 allows arbitrary code execution. "
            "Upgrade pyyaml to 5.4 or later."
        )
        res = audit_explanation(f)
        self.assertTrue(res.grounded, [i.to_dict() for i in res.issues])
        self.assertEqual(res.score, 1.0)

    def test_wrong_cve_is_a_conflict(self):
        f = _finding()
        f.explanation = "This is CVE-2021-44228, a critical issue."
        res = audit_explanation(f)
        self.assertFalse(res.grounded)
        self.assertEqual(res.issues[0].kind, "conflict")

    def test_exploitation_claim_without_kev_is_a_conflict(self):
        f = _finding()
        f.explanation = "This CVE is actively exploited in the wild."
        res = audit_explanation(f)
        self.assertFalse(res.grounded)
        self.assertIn("CISA KEV", res.issues[0].detail)

    def test_exploitation_claim_with_kev_is_supported(self):
        f = _finding(kev_listed=True)
        f.explanation = "This CVE is actively exploited in the wild."
        res = audit_explanation(f)
        self.assertTrue(res.grounded)

    def test_negated_exploitation_claim_is_not_a_conflict(self):
        f = _finding()
        f.explanation = "This CVE is not known to be exploited in the wild."
        res = audit_explanation(f)
        self.assertTrue(res.grounded)

    def test_ransomware_claim_without_flag_is_a_conflict(self):
        f = _finding()
        f.explanation = "The vulnerability is used in ransomware campaigns."
        res = audit_explanation(f)
        self.assertFalse(res.grounded)
        self.assertIn("ransomware", res.issues[0].detail)

    def test_cvss_mismatch_is_a_conflict(self):
        f = _finding()
        f.explanation = "It has a CVSS score of 7.5."
        res = audit_explanation(f)
        self.assertFalse(res.grounded)
        self.assertIn("9.8", res.issues[0].detail)

    def test_cvss_match_is_supported(self):
        f = _finding()
        f.explanation = "It has a CVSS score of 9.8."
        res = audit_explanation(f)
        self.assertTrue(res.grounded)

    def test_epss_mismatch_is_a_conflict(self):
        f = _finding()
        f.explanation = "EPSS puts exploitation probability at 91%."
        res = audit_explanation(f)
        self.assertFalse(res.grounded)
        self.assertIn("EPSS", res.issues[0].detail)

    def test_wrong_fix_version_is_unsupported(self):
        f = _finding()
        f.explanation = "Upgrade pyyaml to 6.0 to fix this."
        res = audit_explanation(f)
        self.assertFalse(res.grounded)
        self.assertEqual(res.issues[0].kind, "unsupported")

    def test_current_version_mention_is_allowed(self):
        f = _finding()
        f.explanation = "Version 5.1 is vulnerable; upgrade to 5.4."
        res = audit_explanation(f)
        self.assertTrue(res.grounded, [i.to_dict() for i in res.issues])

    def test_reachability_conflict(self):
        f = _finding(reachable=False)
        f.explanation = "The vulnerable package is used in this codebase."
        res = audit_explanation(f)
        self.assertFalse(res.grounded)

    def test_reachability_unverifiable_without_analysis(self):
        f = _finding()
        f.explanation = "The vulnerable package is used in this codebase."
        res = audit_explanation(f)
        # Unverifiable, but not a hallucination.
        self.assertTrue(res.grounded)
        self.assertEqual(res.issues[0].kind, "unverifiable")


class TestGroundingEvidence(unittest.TestCase):
    def test_vuln_class_must_appear_in_nvd(self):
        f = _finding(title="", extra={
            "nvd_description": "A denial of service flaw was found in PyYAML.",
        })
        f.explanation = "This allows remote code execution."
        res = audit_explanation(f)
        self.assertFalse(res.grounded)
        self.assertEqual(res.issues[0].kind, "unsupported")

    def test_vuln_class_supported_by_nvd(self):
        f = _finding(extra={"nvd_description": NVD})
        f.explanation = "This allows arbitrary code execution."
        res = audit_explanation(f)
        self.assertTrue(res.grounded)

    def test_vuln_class_without_nvd_is_unverifiable(self):
        f = _finding(title="")
        f.explanation = "This allows remote code execution."
        res = audit_explanation(f)
        self.assertTrue(res.grounded)
        self.assertEqual(res.issues[0].kind, "unverifiable")
        self.assertEqual(res.evidence, [])

    def test_kev_deadline_mismatch(self):
        f = _finding(kev_listed=True, kev_due_date="2024-06-12")
        f.explanation = "CISA set a due date of 2025-01-01 for remediation."
        res = audit_explanation(f)
        self.assertFalse(res.grounded)
        self.assertIn("2024-06-12", res.issues[0].detail)

    def test_empty_explanation_is_neutral(self):
        f = _finding()
        res = audit_explanation(f, text="")
        self.assertTrue(res.grounded)
        self.assertEqual(res.checked, 0)
        self.assertEqual(res.score, 1.0)


class TestApplyGrounding(unittest.TestCase):
    def test_sets_flags_and_extra(self):
        good = _finding(extra={"nvd_description": NVD})
        good.explanation = "PyYAML allows arbitrary code execution."
        bad = _finding(cve_id="CVE-2020-14343")
        bad.explanation = "This is CVE-1999-0001."
        apply_grounding([good, bad])
        self.assertIs(good.grounded, True)
        self.assertIs(bad.grounded, False)
        self.assertIn("grounding", good.extra)
        self.assertEqual(hallucination_rate([good, bad]), 0.5)

    def test_unexplained_findings_are_skipped(self):
        f = _finding()
        apply_grounding([f])
        self.assertIsNone(f.grounded)
        self.assertIsNone(hallucination_rate([f]))

    def test_failed_explanation_not_audited(self):
        f = _finding()
        f.explanation = "(explanation unavailable: timeout)"
        apply_grounding([f])
        self.assertIsNone(f.grounded)


class TestExplainerIntegration(unittest.TestCase):
    def test_stub_explanation_gets_grounded_flag(self):
        f = _finding()
        out = Explainer(llm=StubLLM()).explain(f)
        self.assertIsNotNone(out.grounded)
        self.assertIn("grounding", out.extra)

    def test_nvd_evidence_is_persisted(self):
        class FakeNVD:
            def context(self, cve_id):
                from explanation.cve_context import CVEContext
                return CVEContext(cve_id=cve_id, description=NVD,
                                  cvss_v3=9.8, cwe_ids=["CWE-502"])
        f = _finding()
        out = Explainer(llm=StubLLM(), nvd_client=FakeNVD()).explain(f)
        self.assertEqual(out.extra["nvd_description"], NVD)
        self.assertEqual(out.extra["nvd_cvss"], 9.8)
        self.assertEqual(out.extra["cwe_ids"], ["CWE-502"])

    def test_hallucinating_llm_is_flagged(self):
        f = _finding()
        llm = StubLLM(response="This is CVE-2021-44228 and it is actively exploited in the wild.")
        out = Explainer(llm=llm).explain(f)
        self.assertIs(out.grounded, False)
        self.assertGreaterEqual(len(out.extra["grounding"]["issues"]), 2)


if __name__ == "__main__":
    unittest.main()
