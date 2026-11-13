"""Offline tests for the environment readiness checks.

Nothing here touches the network or a real Trivy install: the subprocess and
HTTP edges are patched so the statuses and the aggregated report are exercised
deterministically.
"""

import datetime as dt
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from diagnostics import doctor
from explanation.explainer import LLMUnavailable

TRIVY_VERSION_OUTPUT = """Version: 0.58.1
Vulnerability DB:
  Version: 2
  UpdatedAt: 2026-10-20 06:30:00.000
"""


class TestDBAge(unittest.TestCase):
    def test_age_is_measured_in_hours(self):
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        age = doctor._db_age_hours(f"UpdatedAt: {stamp}")
        self.assertIsNotNone(age)
        self.assertLess(age, 1.0)

    def test_unparseable_timestamp_is_none(self):
        self.assertIsNone(doctor._db_age_hours("UpdatedAt: someday"))
        self.assertIsNone(doctor._db_age_hours(None))


class TestTrivyStatus(unittest.TestCase):
    def test_missing_binary_says_how_to_install(self):
        with patch.object(doctor, "resolve_trivy", return_value=None):
            status = doctor.trivy_status()
        self.assertEqual(status["status"], "missing")
        self.assertIn("winget", status["hint"])

    def test_subprocess_failure_is_reported_not_raised(self):
        with patch.object(doctor, "resolve_trivy", return_value="/usr/bin/trivy"), \
             patch.object(doctor.subprocess, "run",
                          side_effect=subprocess.TimeoutExpired("trivy", 1)):
            status = doctor.trivy_status()
        self.assertEqual(status["status"], "error")
        self.assertIn("could not be queried", status["detail"])

    def test_fresh_db_is_ok(self):
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        output = TRIVY_VERSION_OUTPUT.replace("2026-10-20 06:30:00", stamp)
        proc = type("P", (), {"stdout": output})()
        with patch.object(doctor, "resolve_trivy", return_value="/usr/bin/trivy"), \
             patch.object(doctor.subprocess, "run", return_value=proc):
            status = doctor.trivy_status()
        self.assertEqual(status["status"], "ok")
        self.assertEqual(status["version"], "0.58.1")
        self.assertLess(status["db_age_hours"], 1.0)

    def test_stale_db_warns_with_refresh_command(self):
        stamp = (dt.datetime.now(dt.timezone.utc)
                 - dt.timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
        output = TRIVY_VERSION_OUTPUT.replace("2026-10-20 06:30:00", stamp)
        proc = type("P", (), {"stdout": output})()
        with patch.object(doctor, "resolve_trivy", return_value="/usr/bin/trivy"), \
             patch.object(doctor.subprocess, "run", return_value=proc):
            status = doctor.trivy_status()
        self.assertEqual(status["status"], "warn")
        self.assertIn("download-db-only", status["hint"])

    def test_unreadable_db_state_is_a_warning(self):
        proc = type("P", (), {"stdout": "Version: 0.58.1\n"})()
        with patch.object(doctor, "resolve_trivy", return_value="/usr/bin/trivy"), \
             patch.object(doctor.subprocess, "run", return_value=proc):
            status = doctor.trivy_status()
        self.assertEqual(status["status"], "warn")
        self.assertIn("unknown", status["detail"])


class TestOllamaStatus(unittest.TestCase):
    def test_down_server_is_missing(self):
        with patch.object(doctor, "ollama_models", side_effect=LLMUnavailable("refused")), \
             patch.object(doctor, "ollama_version", side_effect=LLMUnavailable("refused")):
            status = doctor.ollama_status()
        self.assertEqual(status["status"], "missing")
        self.assertIn("ollama serve", status["hint"])

    def test_no_models_warns_with_pull_hint(self):
        with patch.object(doctor, "ollama_models", return_value=[]), \
             patch.object(doctor, "ollama_version", return_value="0.9.0"):
            status = doctor.ollama_status()
        self.assertEqual(status["status"], "warn")
        self.assertIn("ollama pull", status["hint"])

    def test_wanted_model_installed_is_ok(self):
        models = ["llama3.2:latest", "qwen2.5:3b"]
        with patch.object(doctor, "ollama_models", return_value=models), \
             patch.object(doctor, "ollama_version", return_value="0.9.0"), \
             patch.dict(doctor.os.environ, {"OLLAMA_MODEL": "qwen2.5:3b"}):
            status = doctor.ollama_status()
        self.assertEqual(status["status"], "ok")
        self.assertEqual(status["models"], models)

    def test_missing_model_warns_but_lists_alternatives(self):
        with patch.object(doctor, "ollama_models", return_value=["gemma3:4b"]), \
             patch.object(doctor, "ollama_version", return_value="0.9.0"):
            status = doctor.ollama_status()
        self.assertEqual(status["status"], "warn")
        self.assertEqual(status["models"], ["gemma3:4b"])


class TestOpenAIStatus(unittest.TestCase):
    def test_key_is_never_included_in_the_report(self):
        with patch.dict(doctor.os.environ,
                        {"OPENAI_API_KEY": "sk-secret-value", "OPENAI_MODEL": "gpt-4o"},
                        clear=False):
            status = doctor.openai_status()
        self.assertEqual(status["status"], "ok")
        self.assertTrue(status["has_key"])
        self.assertNotIn("sk-secret-value", json.dumps(status))

    def test_unconfigured_is_missing(self):
        env = {k: v for k, v in doctor.os.environ.items()
               if not k.startswith("OPENAI_")}
        with patch.dict(doctor.os.environ, env, clear=True):
            status = doctor.openai_status()
        self.assertEqual(status["status"], "missing")
        self.assertIn("OPENAI_API_KEY", status["hint"])


class TestPolicyStatus(unittest.TestCase):
    def test_project_policy_loads(self):
        status = doctor.policy_status(doctor.DEFAULT_POLICY)
        self.assertIn(status["status"], ("ok", "warn"))
        self.assertIn("rule(s)", status["detail"])

    def test_absent_file_is_missing(self):
        with tempfile.TemporaryDirectory() as d:
            status = doctor.policy_status(Path(d) / "policy.json")
        self.assertEqual(status["status"], "missing")

    def test_broken_policy_is_reported_not_raised(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "policy.json"
            path.write_text("{not json", encoding="utf-8")
            status = doctor.policy_status(path)
        self.assertEqual(status["status"], "error")
        self.assertIn("fail closed", status["hint"])

    def test_expired_waiver_downgrades_to_warn(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "policy.json"
            path.write_text(json.dumps({
                "version": 1,
                "name": "test",
                "rules": [{"id": "crit", "when": {"severity": "CRITICAL"},
                           "action": "fail"}],
                "waivers": [{"id": "w1", "cve": "CVE-1", "reason": "r",
                             "owner": "sec@example.com", "expires": "2020-01-01"}],
            }), encoding="utf-8")
            status = doctor.policy_status(path)
        self.assertEqual(status["status"], "warn")
        self.assertEqual(status["expired_waivers"][0]["id"], "w1")


class TestEnvironmentReport(unittest.TestCase):
    def test_capabilities_follow_the_component_statuses(self):
        fake = {
            "trivy": {"status": "ok", "detail": "Trivy 0.58.1"},
            "ollama": {"status": "missing", "detail": "down", "models": []},
            "openai": {"status": "missing", "detail": "no key"},
            "policy": {"status": "ok", "detail": "3 rule(s)"},
        }
        with patch.object(doctor, "trivy_status", return_value=fake["trivy"]), \
             patch.object(doctor, "ollama_status", return_value=fake["ollama"]), \
             patch.object(doctor, "openai_status", return_value=fake["openai"]), \
             patch.object(doctor, "policy_status", return_value=fake["policy"]):
            report = doctor.environment_report()
        self.assertEqual(report["capabilities"]["live_scan"], True)
        self.assertEqual(report["capabilities"]["ollama_explanations"], False)
        self.assertEqual(report["capabilities"]["policy_gate"], True)
        self.assertTrue(report["capabilities"]["demo"])
        self.assertIn("python", report)


if __name__ == "__main__":
    unittest.main()
