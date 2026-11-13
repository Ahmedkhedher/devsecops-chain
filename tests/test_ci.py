"""Tests for Phase 4: GitHub PR comment posting (request layer is mocked)."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ci import post_pr_comment as ppc


class TestPrFromRef(unittest.TestCase):
    def test_pull_ref(self):
        self.assertEqual(ppc.pr_from_ref("refs/pull/42/merge"), 42)

    def test_branch_ref_is_none(self):
        self.assertIsNone(ppc.pr_from_ref("refs/heads/main"))

    def test_malformed_is_none(self):
        self.assertIsNone(ppc.pr_from_ref("refs/pull/abc/merge"))

    def test_empty(self):
        self.assertIsNone(ppc.pr_from_ref(""))


class TestFindExisting(unittest.TestCase):
    def test_finds_marker(self):
        comments = [
            {"id": 1, "body": "unrelated"},
            {"id": 2, "body": f"{ppc.COMMENT_MARKER}\nold scan"},
        ]
        self.assertEqual(ppc._find_existing(comments)["id"], 2)

    def test_none_when_absent(self):
        self.assertIsNone(ppc._find_existing([{"id": 1, "body": "x"}]))


class TestPostComment(unittest.TestCase):
    def test_creates_new_when_no_existing(self):
        calls = []

        def fake_request(method, url, token, body=None):
            calls.append((method, url, body))
            if method == "GET":
                return []  # no existing comments
            return {"html_url": "https://x/comment/1", "id": 1}

        with mock.patch.object(ppc, "_request", side_effect=fake_request):
            result = ppc.post_comment("o/r", 7, "## scan", "tok")

        methods = [c[0] for c in calls]
        self.assertEqual(methods, ["GET", "POST"])
        self.assertIn("/repos/o/r/issues/7/comments", calls[1][1])
        # Marker is prepended so future runs can find it.
        self.assertIn(ppc.COMMENT_MARKER, calls[1][2]["body"])
        self.assertIn("## scan", calls[1][2]["body"])
        self.assertEqual(result["id"], 1)

    def test_updates_existing_via_patch(self):
        calls = []

        def fake_request(method, url, token, body=None):
            calls.append((method, url, body))
            if method == "GET":
                return [{"id": 99, "body": f"{ppc.COMMENT_MARKER}\nold"}]
            return {"html_url": "https://x/comment/99", "id": 99}

        with mock.patch.object(ppc, "_request", side_effect=fake_request):
            ppc.post_comment("o/r", 7, "## new scan", "tok")

        methods = [c[0] for c in calls]
        self.assertEqual(methods, ["GET", "PATCH"])
        self.assertIn("/issues/comments/99", calls[1][1])
        self.assertIn("## new scan", calls[1][2]["body"])

    def test_custom_api_root(self):
        seen = {}

        def fake_request(method, url, token, body=None):
            seen["url"] = url
            return [] if method == "GET" else {"id": 1}

        with mock.patch.object(ppc, "_request", side_effect=fake_request):
            ppc.post_comment("o/r", 7, "x", "tok", api_root="https://ghe.example/api/v3/")

        self.assertTrue(seen["url"].startswith("https://ghe.example/api/v3/"))


class TestMain(unittest.TestCase):
    def test_missing_args_returns_2(self):
        with tempfile.TemporaryDirectory() as d:
            md = Path(d) / "c.md"
            md.write_text("x", encoding="utf-8")
            with mock.patch.dict("os.environ", {}, clear=True):
                rc = ppc.main(["--markdown", str(md)])
        self.assertEqual(rc, 2)

    def test_happy_path(self):
        with tempfile.TemporaryDirectory() as d:
            md = Path(d) / "c.md"
            md.write_text("## scan", encoding="utf-8")
            with mock.patch.object(ppc, "post_comment", return_value={"html_url": "https://x/1"}) as pc:
                rc = ppc.main([
                    "--markdown", str(md), "--repo", "o/r", "--pr", "5", "--token", "t",
                ])
        self.assertEqual(rc, 0)
        pc.assert_called_once()

    def test_api_error_returns_1(self):
        with tempfile.TemporaryDirectory() as d:
            md = Path(d) / "c.md"
            md.write_text("## scan", encoding="utf-8")
            with mock.patch.object(ppc, "post_comment", side_effect=RuntimeError("boom")):
                rc = ppc.main([
                    "--markdown", str(md), "--repo", "o/r", "--pr", "5", "--token", "t",
                ])
        self.assertEqual(rc, 1)

    def test_pr_detected_from_env_ref(self):
        with tempfile.TemporaryDirectory() as d:
            md = Path(d) / "c.md"
            md.write_text("## scan", encoding="utf-8")
            with mock.patch.dict("os.environ", {"GITHUB_REF": "refs/pull/33/merge"}, clear=False):
                with mock.patch.object(ppc, "post_comment", return_value={"html_url": "u"}) as pc:
                    rc = ppc.main(["--markdown", str(md), "--repo", "o/r", "--token", "t"])
            self.assertEqual(rc, 0)
            self.assertEqual(pc.call_args[0][1], 33)


if __name__ == "__main__":
    unittest.main()
