"""Tests for Phase 2: EPSS client, KEV client, scorer, and prioritization."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from common.finding import Finding
from prioritization.epss_client import EPSSClient
from prioritization.kev_client import KEVClient
from prioritization.scorer import compute_priority_score, rank, ScorerConfig
from prioritization.enrich import prioritize


# --- EPSS ---

class TestEPSSClient(unittest.TestCase):
    def _fake_fetcher(self, payload):
        return lambda url: payload

    def test_parses_scores_from_api_shape(self):
        payload = {"data": [
            {"cve": "CVE-2023-32681", "epss": "0.42"},
            {"cve": "CVE-2020-14343", "epss": "0.97"},
        ]}
        with tempfile.TemporaryDirectory() as d:
            client = EPSSClient(cache_path=Path(d) / "c.json",
                                fetcher=self._fake_fetcher(payload))
            scores = client.scores(["CVE-2023-32681", "CVE-2020-14343"])
        self.assertAlmostEqual(scores["CVE-2023-32681"], 0.42)
        self.assertAlmostEqual(scores["CVE-2020-14343"], 0.97)

    def test_cache_hit_avoids_second_fetch(self):
        payload = {"data": [{"cve": "CVE-1", "epss": "0.5"}]}
        calls = {"n": 0}

        def fetcher(url):
            calls["n"] += 1
            return payload

        with tempfile.TemporaryDirectory() as d:
            cache = Path(d) / "c.json"
            c1 = EPSSClient(cache_path=cache, fetcher=fetcher)
            c1.scores(["CVE-1"])
            self.assertEqual(calls["n"], 1)
            # New client, same cache file -> served from cache, no fetch.
            c2 = EPSSClient(cache_path=cache, fetcher=fetcher)
            self.assertAlmostEqual(c2.score("CVE-1"), 0.5)
        self.assertEqual(calls["n"], 1)

    def test_network_failure_returns_none(self):
        def boom(url):
            raise OSError("offline")
        with tempfile.TemporaryDirectory() as d:
            client = EPSSClient(cache_path=Path(d) / "c.json", fetcher=boom)
            self.assertIsNone(client.score("CVE-UNKNOWN"))

    def test_malformed_epss_ignored(self):
        payload = {"data": [{"cve": "CVE-X", "epss": "not-a-number"}]}
        with tempfile.TemporaryDirectory() as d:
            client = EPSSClient(cache_path=Path(d) / "c.json",
                                fetcher=self._fake_fetcher(payload))
            self.assertIsNone(client.score("CVE-X"))


# --- KEV ---

class TestKEVClient(unittest.TestCase):
    def _feed(self, ids):
        return json.dumps(
            {"vulnerabilities": [{"cveID": i} for i in ids]}
        ).encode("utf-8")

    def test_membership_check(self):
        with tempfile.TemporaryDirectory() as d:
            client = KEVClient(cache_path=Path(d) / "k.json",
                               fetcher=lambda url: self._feed(["CVE-2020-14343"]))
            self.assertTrue(client.is_listed("CVE-2020-14343"))
            self.assertFalse(client.is_listed("CVE-9999-0000"))

    def test_caches_to_disk(self):
        with tempfile.TemporaryDirectory() as d:
            cache = Path(d) / "k.json"
            KEVClient(cache_path=cache,
                      fetcher=lambda url: self._feed(["CVE-1"]))._load()
            self.assertTrue(cache.exists())
            # Second client reads from cache without a fetcher.
            c2 = KEVClient(cache_path=cache, fetcher=lambda url: (_ for _ in ()).throw(OSError()))
            self.assertTrue(c2.is_listed("CVE-1"))
            self.assertEqual(c2.source, "cache")

    def test_offline_no_cache_yields_empty(self):
        def boom(url):
            raise OSError("offline")
        with tempfile.TemporaryDirectory() as d:
            client = KEVClient(cache_path=Path(d) / "missing.json", fetcher=boom)
            self.assertFalse(client.is_listed("CVE-1"))
            self.assertEqual(client.listed_ids(), set())

    def test_metadata_ransomware_and_due_date(self):
        feed = json.dumps({"vulnerabilities": [
            {
                "cveID": "CVE-RANSOM",
                "knownRansomwareCampaignUse": "Known",
                "dueDate": "2024-06-12",
                "dateAdded": "2024-06-03",
                "vendorProject": "Acme",
                "product": "Widget",
                "vulnerabilityName": "Acme Widget RCE",
            },
            {"cveID": "CVE-PLAIN", "knownRansomwareCampaignUse": "Unknown"},
        ]}).encode("utf-8")
        with tempfile.TemporaryDirectory() as d:
            client = KEVClient(cache_path=Path(d) / "k.json",
                               fetcher=lambda url: feed)
            self.assertTrue(client.known_ransomware("CVE-RANSOM"))
            self.assertEqual(client.due_date("CVE-RANSOM"), "2024-06-12")
            self.assertEqual(client.entry("CVE-RANSOM")["product"], "Widget")
            self.assertFalse(client.known_ransomware("CVE-PLAIN"))
            self.assertIsNone(client.due_date("CVE-PLAIN"))
            self.assertFalse(client.known_ransomware("CVE-MISSING"))
            self.assertIsNone(client.entry("CVE-MISSING"))


# --- Scorer ---

class TestScorer(unittest.TestCase):
    def test_formula(self):
        # (9.8*0.4) + (0.42*100*0.4) + 0 = 3.92 + 16.8 = 20.72
        self.assertAlmostEqual(
            compute_priority_score(9.8, 0.42, False), 20.72
        )

    def test_kev_bonus_applied(self):
        without = compute_priority_score(5.0, 0.1, False)
        with_kev = compute_priority_score(5.0, 0.1, True)
        self.assertAlmostEqual(with_kev - without, 20.0)

    def test_ransomware_bonus_stacks_on_kev(self):
        kev = compute_priority_score(5.0, 0.1, True)
        ransom = compute_priority_score(5.0, 0.1, True, known_ransomware=True)
        self.assertAlmostEqual(ransom - kev, 10.0)

    def test_ransomware_without_kev_still_bonused(self):
        # Data quality guard: if the feed says ransomware but KEV membership
        # was lost, the extra weight should still apply.
        plain = compute_priority_score(5.0, 0.1, False)
        ransom = compute_priority_score(5.0, 0.1, False, known_ransomware=True)
        self.assertAlmostEqual(ransom - plain, 10.0)

    def test_ransomware_flag_flows_through_rank(self):
        plain = Finding(cve_id="CVE-A", package="a", version="1", cvss=6.0,
                        epss=0.2, kev_listed=True)
        ransom = Finding(cve_id="CVE-B", package="b", version="1", cvss=6.0,
                         epss=0.2, kev_listed=True, known_ransomware=True)
        ranked = rank([plain, ransom])
        self.assertEqual(ranked[0].cve_id, "CVE-B")
        self.assertAlmostEqual(ranked[0].priority_score - ranked[1].priority_score, 10.0)

    def test_missing_epss_uses_fallback(self):
        self.assertAlmostEqual(
            compute_priority_score(9.8, None, False), 9.8 * 0.4
        )

    def test_missing_cvss_treated_as_zero(self):
        self.assertAlmostEqual(compute_priority_score(None, 0.5, False), 20.0)

    def test_custom_config(self):
        cfg = ScorerConfig(w_cvss=1.0, w_epss=0.0, kev_bonus=0.0)
        self.assertAlmostEqual(compute_priority_score(7.0, 0.9, True, cfg), 7.0)

    def test_kev_medium_outranks_nonexploited_critical(self):
        """The Phase 2 checkpoint from the project plan."""
        critical = Finding(cve_id="CVE-CRIT", package="a", version="1",
                           severity="CRITICAL", cvss=9.8, epss=0.02, kev_listed=False)
        kev_medium = Finding(cve_id="CVE-KEV", package="b", version="1",
                             severity="MEDIUM", cvss=5.5, epss=0.10, kev_listed=True)
        ranked = rank([critical, kev_medium])
        self.assertEqual(ranked[0].cve_id, "CVE-KEV")

    def test_rank_is_deterministic_on_ties(self):
        f1 = Finding(cve_id="CVE-B", package="a", version="1", cvss=5.0, epss=0.1)
        f2 = Finding(cve_id="CVE-A", package="b", version="1", cvss=5.0, epss=0.1)
        ranked = rank([f1, f2])
        self.assertEqual([f.cve_id for f in ranked], ["CVE-A", "CVE-B"])

    def test_rank_sets_priority_score(self):
        f = Finding(cve_id="CVE-1", package="a", version="1", cvss=8.0, epss=0.3)
        ranked = rank([f])
        self.assertIsNotNone(ranked[0].priority_score)


# --- Prioritize orchestration ---

class TestPrioritize(unittest.TestCase):
    def test_enriches_and_ranks(self):
        epss_payload = {"data": [
            {"cve": "CVE-LOW", "epss": "0.01"},
            {"cve": "CVE-HIGH", "epss": "0.90"},
        ]}
        kev_feed = json.dumps({"vulnerabilities": [
            {"cveID": "CVE-HIGH", "knownRansomwareCampaignUse": "Known",
             "dueDate": "2024-07-01"},
        ]}).encode("utf-8")

        with tempfile.TemporaryDirectory() as d:
            epss = EPSSClient(cache_path=Path(d) / "e.json",
                              fetcher=lambda url: epss_payload)
            kev = KEVClient(cache_path=Path(d) / "k.json",
                            fetcher=lambda url: kev_feed)
            findings = [
                Finding(cve_id="CVE-LOW", package="a", version="1", cvss=9.0),
                Finding(cve_id="CVE-HIGH", package="b", version="1", cvss=4.0),
            ]
            ranked = prioritize(findings, epss_client=epss, kev_client=kev)

        self.assertEqual(ranked[0].cve_id, "CVE-HIGH")
        self.assertTrue(ranked[0].kev_listed)
        self.assertTrue(ranked[0].known_ransomware)
        self.assertEqual(ranked[0].kev_due_date, "2024-07-01")
        self.assertAlmostEqual(ranked[0].epss, 0.90)
        self.assertIsNotNone(ranked[0].priority_score)
        self.assertFalse(ranked[1].known_ransomware)
        self.assertIsNone(ranked[1].kev_due_date)

    def test_empty_input(self):
        self.assertEqual(prioritize([]), [])


if __name__ == "__main__":
    unittest.main()
