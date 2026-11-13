"""Headless tests for the local web server.

Every test starts the real ThreadingHTTPServer on an ephemeral port and speaks
HTTP to it, so routing, auth, CSP, the folder API, and the demo scan are
exercised end to end without a browser or network access.
"""

import http.client
import json
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from explanation.explainer import LLMUnavailable
from web.server import APP_ID, AppState, create_server, existing_instance


class _ServerCase(unittest.TestCase):
    use_history = False

    @classmethod
    def setUpClass(cls):
        cls.history_dir = (
            tempfile.TemporaryDirectory() if cls.use_history else None
        )
        history = (
            Path(cls.history_dir.name) / "history.db" if cls.history_dir else None
        )
        cls.state = AppState(idle_timeout=0, history_path=history)
        cls.server = create_server(0, cls.state, idle_timeout=0)
        cls.port = cls.server.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        if cls.history_dir is not None:
            cls.history_dir.cleanup()

    def request(self, method, path, body=None, token=True, headers=None):
        data = None
        sent = dict(headers or {})
        if token:
            sent["X-Scan-Token"] = self.state.token
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            sent["Content-Type"] = "application/json"
        req = urllib.request.Request(
            self.base + path, data=data, headers=sent, method=method
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, dict(exc.headers), exc.read()
            finally:
                exc.close()

    def json_request(self, method, path, body=None, token=True, headers=None):
        status, sent, raw = self.request(method, path, body, token, headers)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except ValueError:
            payload = None
        return status, sent, payload


class TestWebSurface(_ServerCase):
    def test_health_is_public_and_identifies_the_app(self):
        status, _, payload = self.json_request("GET", "/api/health", token=False)
        self.assertEqual(status, 200)
        self.assertEqual(payload["app"], APP_ID)

    def test_api_requires_the_page_token(self):
        status, _, payload = self.json_request("GET", "/api/state", token=False)
        self.assertEqual(status, 401)
        self.assertIn("token", payload["error"])

    def test_api_accepts_the_token(self):
        status, _, payload = self.json_request("GET", "/api/state")
        self.assertEqual(status, 200)
        self.assertIsNone(payload["job"])
        self.assertIn("version", payload)

    def test_non_ascii_token_does_not_crash_the_server(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(
                "GET", "/api/state", headers={"X-Scan-Token": "t\u00f6ken"}
            )
            self.assertEqual(conn.getresponse().status, 401)
        finally:
            conn.close()

    def test_rebinding_host_header_is_rejected(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("GET", "/api/health", headers={"Host": "evil.example"})
            self.assertEqual(conn.getresponse().status, 403)
        finally:
            conn.close()

    def test_index_embeds_token_and_csp(self):
        status, headers, raw = self.request("GET", "/")
        html = raw.decode("utf-8")
        self.assertEqual(status, 200)
        self.assertIn(self.state.token, html)
        self.assertNotIn("__TOKEN__", html)
        self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_static_assets_are_whitelisted(self):
        status, headers, _ = self.request("GET", "/app.js")
        self.assertEqual(status, 200)
        self.assertIn("javascript", headers["Content-Type"])

        status, _, payload = self.json_request("GET", "/../web/server.py")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"], "not found")

    def test_folder_listing_walks_directories(self):
        status, _, payload = self.json_request(
            "GET", f"/api/browse?path={urllib.request.quote(str(ROOT))}"
        )
        self.assertEqual(status, 200)
        names = {entry["name"] for entry in payload["entries"]}
        self.assertTrue({"web", "tests", "scanner"} <= names)
        self.assertEqual(Path(payload["current"]), ROOT.resolve())
        self.assertTrue(payload["roots"])

    def test_folder_listing_rejects_missing_paths(self):
        status, _, payload = self.json_request(
            "GET", "/api/browse?path=" + urllib.request.quote(str(ROOT / "nope"))
        )
        self.assertEqual(status, 400)
        self.assertIn("not a folder", payload["error"])

    def test_scan_rejects_unknown_llm(self):
        status, _, payload = self.json_request(
            "POST", "/api/scan", {"demo": True, "llm": "gpt-from-wishful-thinking"}
        )
        self.assertEqual(status, 400)
        self.assertIn("stub", payload["error"])

    def test_scan_reports_unreachable_ollama_before_starting(self):
        with patch("web.server.check_ollama",
                   side_effect=LLMUnavailable("Ollama is not running at localhost")):
            status, _, payload = self.json_request(
                "POST", "/api/scan", {"demo": True, "llm": "ollama"}
            )
        self.assertEqual(status, 400)
        self.assertIn("Ollama is not running", payload["error"])

    def test_doctor_requires_the_token(self):
        status, _, payload = self.json_request("GET", "/api/doctor", token=False)
        self.assertEqual(status, 401)
        self.assertIn("token", payload["error"])

    def test_doctor_returns_the_environment_report(self):
        canned = {
            "python": "3.15.0",
            "trivy": {"status": "ok", "detail": "Trivy 0.76.0"},
            "ollama": {"status": "ok", "detail": "up", "models": ["llama3.2:latest"]},
            "openai": {"status": "missing", "detail": "no API key"},
            "policy": {"status": "ok", "detail": "3 rule(s)"},
            "capabilities": {"demo": True, "live_scan": True,
                             "ollama_explanations": True, "policy_gate": True},
        }
        with patch("web.server.environment_report", return_value=canned) as report:
            status, _, payload = self.json_request("GET", "/api/doctor")
        self.assertEqual(status, 200)
        self.assertEqual(payload["trivy"]["status"], "ok")
        self.assertTrue(payload["capabilities"]["live_scan"])
        report.assert_called_once()

    def test_scan_rejects_a_malformed_model_name(self):
        with patch("web.server.check_ollama") as check:
            status, _, payload = self.json_request(
                "POST", "/api/scan",
                {"demo": True, "llm": "ollama", "ollama_model": "model; rm -rf /"}
            )
        self.assertEqual(status, 400)
        self.assertIn("invalid Ollama model name", payload["error"])
        check.assert_not_called()

    def test_selected_model_reaches_the_ollama_preflight(self):
        try:
            with patch("web.server.check_ollama") as check, \
                 patch("web.server._run_job", lambda *a, **k: None):
                status, _, _ = self.json_request(
                    "POST", "/api/scan",
                    {"demo": True, "llm": "ollama", "ollama_model": "qwen2.5:3b"}
                )
            self.assertEqual(status, 202)
            self.assertEqual(check.call_args.args[0], "qwen2.5:3b")
        finally:
            with self.state.lock:
                self.state.job.status = "done"

    def test_scan_rejects_missing_folder(self):
        status, _, payload = self.json_request(
            "POST", "/api/scan", {"path": str(ROOT / "does-not-exist")}
        )
        self.assertEqual(status, 400)
        self.assertIn("folder not found", payload["error"])

    def test_body_must_be_json(self):
        req = urllib.request.Request(
            self.base + "/api/scan",
            data=b"not json",
            headers={
                "X-Scan-Token": self.state.token,
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=10)
            self.fail("expected a 400")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 400)
            self.assertIn("must be JSON", exc.read().decode("utf-8"))

    def test_existing_instance_detects_this_server(self):
        self.assertTrue(existing_instance(self.port))


class TestDemoScan(_ServerCase):
    use_history = True

    def _wait_for_completion(self, timeout=45.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status, _, payload = self.json_request("GET", "/api/state")
            self.assertEqual(status, 200)
            job = payload["job"]
            if job and job["status"] != "running":
                return job
            time.sleep(0.05)
        self.fail("demo scan did not finish in time")

    def _run_demo(self):
        if getattr(type(self), "_job", None) is None:
            status, _, payload = self.json_request(
                "POST", "/api/scan", {"demo": True, "policy": True}
            )
            self.assertEqual(status, 202)
            self.assertEqual(payload["mode"], "demo")
            type(self)._job = self._wait_for_completion()
        return type(self)._job

    def test_demo_scan_produces_ranked_findings_and_gate(self):
        job = self._run_demo()
        self.assertEqual(job["status"], "done", job.get("error"))
        self.assertEqual(job["total"], 5)
        self.assertEqual(job["shown"], 5)
        self.assertGreaterEqual(len(job["stages"]), 3)
        self.assertIsNotNone(job["gate"])
        self.assertFalse(job["gate"]["passed"])
        self.assertIn("CVE-2020-14343", {f["cve_id"] for f in job["findings"]})
        self.assertTrue(any(f["exposure"] == "local" for f in job["findings"]))
        scores = [f["priority_score"] for f in job["findings"]]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertIsNotNone(job["delta"])
        self.assertIsNone(job["delta"]["previous_run"])
        self.assertEqual(job["delta"]["counts"]["persisting"], 0)

    def test_demo_wires_reachability_and_explanations(self):
        job = self._run_demo()
        reachable = [f for f in job["findings"] if f["reachable"]]
        self.assertTrue(reachable)
        for finding in reachable[:1]:
            self.assertTrue(finding["explanation"])
            self.assertIn("grounding", finding["extra"])

    def test_json_export(self):
        self._run_demo()
        status, headers, raw = self.request("GET", "/api/export?format=json")
        self.assertEqual(status, 200)
        payload = json.loads(raw.decode("utf-8"))
        self.assertEqual(len(payload), 5)
        self.assertIn("attachment", headers["Content-Disposition"])

    def test_markdown_export(self):
        self._run_demo()
        status, _, raw = self.request("GET", "/api/export?format=markdown")
        self.assertEqual(status, 200)
        self.assertIn("Security scan", raw.decode("utf-8"))

    def test_vex_export(self):
        self._run_demo()
        status, _, raw = self.request("GET", "/api/export?format=vex")
        self.assertEqual(status, 200)
        vex = json.loads(raw.decode("utf-8"))
        self.assertEqual(vex["@context"], "https://openvex.dev/ns/v0.2.0")
        self.assertEqual(len(vex["statements"]), 5)

    def test_policy_export(self):
        self._run_demo()
        status, _, raw = self.request("GET", "/api/export?format=policy")
        self.assertEqual(status, 200)
        report = json.loads(raw.decode("utf-8"))
        self.assertFalse(report["passed"])
        self.assertTrue(report["violations"])

    def test_unknown_export_format(self):
        self._run_demo()
        status, _, payload = self.json_request("GET", "/api/export?format=csv")
        self.assertEqual(status, 400)
        self.assertIn("format", payload["error"])

    def test_demo_job_carries_a_remediation_plan(self):
        plan = self._run_demo()["remediation"]
        self.assertNotIn("error", plan)
        self.assertGreaterEqual(plan["summary"]["cves_cleared"], 3)
        self.assertGreater(plan["summary"]["reduction_pct"], 0.0)
        self.assertTrue(plan["has_patch"])
        for step in plan["steps"]:
            self.assertTrue(step["command"])
            self.assertEqual(step["manifest"], "requirements.txt")

    def test_remediation_export(self):
        self._run_demo()
        status, headers, raw = self.request("GET", "/api/export?format=remediation")
        self.assertEqual(status, 200)
        self.assertIn("remediation-plan.md", headers["Content-Disposition"])
        self.assertIn("## Remediation plan", raw.decode("utf-8"))

    def test_patch_export(self):
        self._run_demo()
        status, _, raw = self.request("GET", "/api/export?format=patch")
        self.assertEqual(status, 200)
        text = raw.decode("utf-8")
        self.assertIn("-pyyaml==5.1", text)
        self.assertIn("+pyyaml==5.4", text)

    def test_second_demo_reports_persisting(self):
        self._run_demo()
        status, _, _ = self.json_request(
            "POST", "/api/scan", {"demo": True, "policy": True}
        )
        self.assertEqual(status, 202)
        job = self._wait_for_completion()
        type(self)._job = job
        delta = job["delta"]
        self.assertIsNotNone(delta["previous_run"])
        self.assertEqual(delta["counts"]["new"], 0)
        self.assertEqual(delta["counts"]["persisting"], 5)

    def test_scan_conflict_while_running(self):
        state = self.state
        with state.lock:
            previous = state.job
        job = state.try_new_job(target="held", mode="demo")
        self.assertIsNotNone(job)
        try:
            status, _, payload = self.json_request(
                "POST", "/api/scan", {"demo": True}
            )
            self.assertEqual(status, 409)
            self.assertIn("already running", payload["error"])
        finally:
            with state.lock:
                job.status = "error"
                state.job = previous


class TestShutdown(unittest.TestCase):
    def test_shutdown_stops_the_server(self):
        state = AppState(idle_timeout=0)
        server = create_server(0, state, idle_timeout=0)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/shutdown",
                data=b"{}",
                headers={
                    "X-Scan-Token": state.token,
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                self.assertEqual(resp.status, 200)
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        finally:
            server.server_close()


if __name__ == "__main__":
    unittest.main()
