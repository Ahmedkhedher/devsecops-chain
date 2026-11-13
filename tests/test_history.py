"""Tests for SQLite run history and delta reporting."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from common.finding import Finding
from history.store import HistoryStore, fingerprint


def _f(cve="CVE-2020-14343", package="pyyaml", version="5.1",
       priority=3.9, **kw) -> Finding:
    return Finding(cve_id=cve, package=package, version=version,
                   severity=kw.pop("severity", "CRITICAL"),
                   priority_score=priority, **kw)


class TestHistory(unittest.TestCase):
    def test_fingerprint_is_stable(self):
        a = _f(target="requirements.txt")
        b = _f(target="requirements.txt")
        self.assertEqual(fingerprint(a), fingerprint(b))
        self.assertNotEqual(fingerprint(a), fingerprint(_f(version="5.2")))

    def test_baseline_then_persisting(self):
        with tempfile.TemporaryDirectory() as d:
            with HistoryStore(Path(d) / "h.db") as store:
                first = store.record_and_diff([_f()], started_at="2026-10-01T00:00:00Z")
                self.assertFalse(first.has_previous)
                self.assertEqual(len(first.new), 1)

                second = store.record_and_diff([_f()], started_at="2026-10-02T00:00:00Z")
                self.assertTrue(second.has_previous)
                self.assertEqual(len(second.new), 0)
                self.assertEqual(len(second.persisting), 1)
                self.assertEqual(second.previous_run.id, first.current_run.id)

    def test_fixed_finding(self):
        with tempfile.TemporaryDirectory() as d:
            with HistoryStore(Path(d) / "h.db") as store:
                store.record_and_diff(
                    [_f(), _f(cve="CVE-OTHER", package="requests")],
                    started_at="2026-10-01T00:00:00Z",
                )
                report = store.record_and_diff(
                    [_f()], started_at="2026-10-02T00:00:00Z")
        self.assertEqual([e.cve_id for e in report.fixed], ["CVE-OTHER"])
        self.assertEqual(len(report.persisting), 1)
        self.assertEqual(len(report.new), 0)

    def test_new_finding(self):
        with tempfile.TemporaryDirectory() as d:
            with HistoryStore(Path(d) / "h.db") as store:
                store.record_and_diff([_f()], started_at="2026-10-01T00:00:00Z")
                report = store.record_and_diff(
                    [_f(), _f(cve="CVE-NEW", package="urllib3")],
                    started_at="2026-10-02T00:00:00Z",
                )
        self.assertEqual([e.cve_id for e in report.new], ["CVE-NEW"])
        self.assertEqual(len(report.persisting), 1)

    def test_reopened_finding(self):
        with tempfile.TemporaryDirectory() as d:
            with HistoryStore(Path(d) / "h.db") as store:
                store.record_and_diff([_f()], started_at="2026-10-01T00:00:00Z")
                store.record_and_diff([], started_at="2026-10-02T00:00:00Z")
                report = store.record_and_diff([_f()], started_at="2026-10-03T00:00:00Z")
        self.assertEqual([e.cve_id for e in report.reopened], ["CVE-2020-14343"])
        self.assertEqual(report.new, [])

    def test_priority_movement(self):
        with tempfile.TemporaryDirectory() as d:
            with HistoryStore(Path(d) / "h.db") as store:
                store.record_and_diff([_f(priority=3.9)], started_at="2026-10-01T00:00:00Z")
                report = store.record_and_diff(
                    [_f(priority=52.3)], started_at="2026-10-02T00:00:00Z")
        entry = report.persisting[0]
        self.assertEqual(entry.previous_priority, 3.9)
        self.assertAlmostEqual(entry.priority_change, 48.4)

    def test_store_persists_across_connections(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "h.db"
            store = HistoryStore(path)
            store.record([_f()], started_at="2026-10-01T00:00:00Z")
            store.close()
            with HistoryStore(path) as reopened:
                self.assertIsNotNone(reopened.latest_run())

    def test_runs_are_listed_newest_first(self):
        with tempfile.TemporaryDirectory() as d:
            with HistoryStore(Path(d) / "h.db") as store:
                store.record([], started_at="2026-10-01T00:00:00Z")
                store.record([], started_at="2026-10-02T00:00:00Z")
                runs = store.runs()
        self.assertEqual(runs[0].started_at, "2026-10-02T00:00:00Z")
        self.assertEqual(runs[1].started_at, "2026-10-01T00:00:00Z")

    def test_prune_keeps_newest(self):
        with tempfile.TemporaryDirectory() as d:
            with HistoryStore(Path(d) / "h.db") as store:
                for day in range(1, 6):
                    store.record([], started_at=f"2026-10-0{day}T00:00:00Z")
                removed = store.prune(keep=2)
                runs = store.runs()
        self.assertEqual(removed, 3)
        self.assertEqual(len(runs), 2)
        self.assertEqual(runs[0].started_at, "2026-10-05T00:00:00Z")

    def test_unknown_run_raises(self):
        with tempfile.TemporaryDirectory() as d:
            with HistoryStore(Path(d) / "h.db") as store:
                with self.assertRaises(ValueError):
                    store.diff(999)

    def test_render_text_and_markdown(self):
        with tempfile.TemporaryDirectory() as d:
            with HistoryStore(Path(d) / "h.db") as store:
                store.record_and_diff([], started_at="2026-10-01T00:00:00Z")
                report = store.record_and_diff(
                    [_f()], started_at="2026-10-02T00:00:00Z")
        text = report.render_text()
        self.assertIn("+1 new", text)
        self.assertIn("CVE-2020-14343", text)
        md = report.render_markdown()
        self.assertIn("Scan delta", md)
        self.assertIn("**New:**", md)
        payload = report.to_dict()
        self.assertEqual(payload["counts"]["new"], 1)

    def test_baseline_render(self):
        with tempfile.TemporaryDirectory() as d:
            with HistoryStore(Path(d) / "h.db") as store:
                report = store.record_and_diff([_f()], started_at="2026-10-01T00:00:00Z")
        self.assertIn("baseline", report.render_text().lower())
        self.assertIn("baseline", report.render_markdown().lower())


if __name__ == "__main__":
    unittest.main()
