"""Tests for Phase 3: NVD context parsing + explanation engine."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from common.finding import Finding
from explanation.cve_context import (
    NVDClient, CVEContext, parse_nvd_response,
    _english_description, _extract_cwe, _extract_cvss_v3,
)
from explanation.explainer import (
    DEFAULT_OLLAMA_MODEL, Explainer, LLMUnavailable, StubLLM, build_prompt,
    check_ollama, confidence_for, default_fix,
)


# --- NVD parsing ---

SAMPLE_NVD = {
    "vulnerabilities": [{
        "cve": {
            "id": "CVE-2020-14343",
            "published": "2021-01-19T17:15:00.000",
            "descriptions": [
                {"lang": "es", "value": "descripcion en espanol"},
                {"lang": "en", "value": "A vulnerability in PyYAML allows arbitrary code execution."},
            ],
            "metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}],
            },
            "weaknesses": [
                {"description": [{"value": "CWE-20"}]},
            ],
            "references": [
                {"url": "https://example.com/a"},
                {"url": "https://example.com/b"},
            ],
        }
    }]
}


class TestNVDParsing(unittest.TestCase):
    def test_parses_full_context(self):
        ctx = parse_nvd_response("CVE-2020-14343", SAMPLE_NVD)
        self.assertEqual(ctx.cve_id, "CVE-2020-14343")
        self.assertIn("PyYAML", ctx.description)
        self.assertEqual(ctx.cvss_v3, 9.8)
        self.assertEqual(ctx.cwe_ids, ["CWE-20"])
        self.assertEqual(len(ctx.references), 2)

    def test_prefers_english_description(self):
        self.assertIn("PyYAML", _english_description(SAMPLE_NVD["vulnerabilities"][0]["cve"]["descriptions"]))

    def test_none_when_not_found(self):
        self.assertIsNone(parse_nvd_response("CVE-X", {"vulnerabilities": []}))

    def test_cwe_extraction_dedupes_and_filters(self):
        weaknesses = [{"description": [{"value": "CWE-20"}, {"value": "NVD-CWE-noinfo"}, {"value": "CWE-20"}]}]
        self.assertEqual(_extract_cwe(weaknesses), ["CWE-20"])

    def test_cvss_falls_back_to_v30(self):
        metrics = {"cvssMetricV30": [{"cvssData": {"baseScore": 7.5}}]}
        self.assertEqual(_extract_cvss_v3(metrics), 7.5)

    def test_cvss_none_when_absent(self):
        self.assertIsNone(_extract_cvss_v3({}))


class TestNVDClient(unittest.TestCase):
    def test_uses_fetcher_and_caches(self):
        calls = {"n": 0}

        def fetcher(url):
            calls["n"] += 1
            return SAMPLE_NVD

        with tempfile.TemporaryDirectory() as d:
            cache = Path(d) / "nvd.json"
            c1 = NVDClient(cache_path=cache, fetcher=fetcher)
            ctx = c1.context("CVE-2020-14343")
            self.assertIsNotNone(ctx)
            self.assertEqual(calls["n"], 1)
            # Second client reads from disk cache, no fetch.
            c2 = NVDClient(cache_path=cache, fetcher=fetcher)
            self.assertIsNotNone(c2.context("CVE-2020-14343"))
        self.assertEqual(calls["n"], 1)

    def test_network_failure_returns_none(self):
        def boom(url):
            raise OSError("offline")
        with tempfile.TemporaryDirectory() as d:
            client = NVDClient(cache_path=Path(d) / "n.json", fetcher=boom)
            self.assertIsNone(client.context("CVE-1"))


# --- Prompt + confidence ---

class TestPrompt(unittest.TestCase):
    def test_includes_core_fields(self):
        f = Finding(cve_id="CVE-1", package="requests", version="2.6.0",
                    severity="MEDIUM", cvss=6.1, fixed_version="2.31.0",
                    epss=0.42, kev_listed=False, reachable=True)
        prompt = build_prompt(f)
        self.assertIn("CVE-1", prompt)
        self.assertIn("requests", prompt)
        self.assertIn("2.31.0", prompt)
        self.assertIn("EPSS", prompt)
        self.assertIn("Reachability", prompt)

    def test_includes_nvd_description_when_present(self):
        f = Finding(cve_id="CVE-1", package="x", version="1")
        ctx = CVEContext(cve_id="CVE-1", description="Official NVD text here.")
        self.assertIn("Official NVD text here.", build_prompt(f, ctx))

    def test_kev_flag_shown(self):
        f = Finding(cve_id="CVE-1", package="x", version="1", kev_listed=True)
        self.assertIn("KEV: YES", build_prompt(f))


class TestConfidence(unittest.TestCase):
    def test_low_without_fixed_version(self):
        f = Finding(cve_id="CVE-1", package="x", version="1", fixed_version=None, kev_listed=True)
        self.assertEqual(confidence_for(f), "low")

    def test_high_with_fix_and_kev(self):
        f = Finding(cve_id="CVE-1", package="x", version="1", fixed_version="2.0", kev_listed=True)
        self.assertEqual(confidence_for(f), "high")

    def test_high_with_fix_and_high_epss(self):
        f = Finding(cve_id="CVE-1", package="x", version="1", fixed_version="2.0", epss=0.7)
        self.assertEqual(confidence_for(f), "high")

    def test_medium_otherwise(self):
        f = Finding(cve_id="CVE-1", package="x", version="1", fixed_version="2.0", epss=0.1)
        self.assertEqual(confidence_for(f), "medium")


class _TagsResponse:
    def __init__(self, payload):
        self._body = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class TestOllamaPreflight(unittest.TestCase):
    def test_accepts_an_installed_tag_alias(self):
        payload = {"models": [{"name": "llama3.2:3b"}]}
        with patch("explanation.explainer.urllib.request.urlopen",
                   return_value=_TagsResponse(payload)):
            check_ollama(DEFAULT_OLLAMA_MODEL)

    def test_reports_a_stopped_server_with_a_fix(self):
        with patch("explanation.explainer.urllib.request.urlopen",
                   side_effect=OSError("connection refused")):
            with self.assertRaises(LLMUnavailable) as ctx:
                check_ollama(DEFAULT_OLLAMA_MODEL)
        self.assertIn("ollama serve", str(ctx.exception))

    def test_reports_a_missing_model_and_lists_available(self):
        payload = {"models": [{"name": "qwen2.5vl:3b"}]}
        with patch("explanation.explainer.urllib.request.urlopen",
                   return_value=_TagsResponse(payload)):
            with self.assertRaises(LLMUnavailable) as ctx:
                check_ollama(DEFAULT_OLLAMA_MODEL)
        message = str(ctx.exception)
        self.assertIn("ollama pull", message)
        self.assertIn("qwen2.5vl:3b", message)


class TestExplainer(unittest.TestCase):
    def test_stub_llm_populates_fields(self):
        f = Finding(cve_id="CVE-1", package="requests", version="2.6.0", fixed_version="2.31.0")
        out = Explainer(llm=StubLLM()).explain(f)
        self.assertTrue(out.explanation)
        self.assertIn("2.31.0", out.suggested_fix)
        self.assertEqual(out.confidence, "medium")

    def test_stub_answers_from_prompt_facts_and_audits_clean(self):
        f = Finding(
            cve_id="CVE-2020-14343", package="pyyaml", version="5.1",
            severity="CRITICAL", cvss=9.8, fixed_version="5.4",
            epss=0.42, kev_listed=True, known_ransomware=True,
            kev_due_date="2026-11-01", reachable=False,
        )
        out = Explainer(llm=StubLLM()).explain(f)
        self.assertIn("CVE-2020-14343", out.explanation)
        self.assertIn("Upgrade pyyaml to 5.4", out.explanation)
        self.assertIn("42.0%", out.explanation)
        self.assertIn("CISA KEV", out.explanation)
        self.assertIn("2026-11-01", out.explanation)
        self.assertIn("not imported", out.explanation)
        self.assertTrue(out.grounded)
        self.assertGreaterEqual(out.extra["grounding"]["checked_claims"], 6)
        self.assertEqual(out.extra["grounding"]["issues"], [])

    def test_prompt_is_grounded_and_passed_to_llm(self):
        stub = StubLLM()
        f = Finding(cve_id="CVE-9", package="flask", version="0.12", fixed_version="2.0")
        Explainer(llm=stub).explain(f)
        self.assertIn("CVE-9", stub.last_prompt)
        self.assertIn("flask", stub.last_prompt)

    def test_llm_failure_falls_back(self):
        class Boom:
            def complete(self, prompt):
                raise RuntimeError("inference down")
        f = Finding(cve_id="CVE-1", package="x", version="1", fixed_version="2.0")
        out = Explainer(llm=Boom()).explain(f)
        self.assertIn("explanation unavailable", out.explanation)
        self.assertIsNotNone(out.suggested_fix)  # still gives a fix

    def test_no_fixed_version_fix_message(self):
        f = Finding(cve_id="CVE-1", package="x", version="1", fixed_version=None)
        out = Explainer(llm=StubLLM()).explain(f)
        self.assertIn("No fixed version", out.suggested_fix)

    def test_uses_attached_context(self):
        stub = StubLLM()
        f = Finding(cve_id="CVE-1", package="x", version="1")
        f.extra["cve_context"] = CVEContext(cve_id="CVE-1", description="Attached NVD desc.")
        Explainer(llm=stub).explain(f)
        self.assertIn("Attached NVD desc.", stub.last_prompt)

    def test_explain_all(self):
        findings = [Finding(cve_id=f"CVE-{i}", package="x", version="1") for i in range(3)]
        out = Explainer(llm=StubLLM()).explain_all(findings)
        self.assertEqual(len(out), 3)
        self.assertTrue(all(f.explanation for f in out))


if __name__ == "__main__":
    unittest.main()
