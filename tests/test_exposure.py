"""Tests for Phase 5b: call-graph exploit-path exposure analysis."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from common.finding import Finding
from reachability.exposure import analyze_exposure, apply_exposure


def _write(root: Path, rel: str, content: str):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


WEB_APP = '''
import requests
from flask import Flask

app = Flask(__name__)

@app.route("/proxy")
def proxy():
    return requests.get("http://internal").text

def unused_branch():
    import urllib3
    return urllib3.PoolManager()
'''

CLI_APP = '''
import argparse
import yaml

def run(path):
    with open(path) as fh:
        return yaml.safe_load(fh)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("path")
    args = p.parse_args()
    return run(args.path)

if __name__ == "__main__":
    main()
'''

SCRIPT = '''
import jinja2

def render():
    return jinja2.Template("hi").render()

if __name__ == "__main__":
    render()
'''


class TestExposureLevels(unittest.TestCase):
    def test_route_handler_is_network_exposed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "web.py", WEB_APP)
            results = analyze_exposure(root, ["requests"])
        self.assertEqual(results["requests"].exposure, "network")
        self.assertEqual(results["requests"].path[0], "web.py:proxy")
        self.assertIn("requests.get()", results["requests"].path[-1])

    def test_cli_entrypoint_is_cli_exposed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "cli.py", CLI_APP)
            results = analyze_exposure(root, ["pyyaml"])
        res = results["pyyaml"]
        self.assertEqual(res.exposure, "cli")
        self.assertEqual(res.path, ["cli.py:main", "cli.py:run", "yaml.safe_load()"])
        self.assertEqual(res.depth, 1)

    def test_plain_main_script_is_local(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "render.py", SCRIPT)
            results = analyze_exposure(root, ["jinja2"])
        self.assertEqual(results["jinja2"].exposure, "local")

    def test_called_but_unlinked_from_entrypoints(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "web.py", WEB_APP)
            results = analyze_exposure(root, ["urllib3"])
        self.assertEqual(results["urllib3"].exposure, "unlinked")

    def test_unused_package_is_none(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "web.py", WEB_APP)
            results = analyze_exposure(root, ["django"])
        self.assertEqual(results["django"].exposure, "none")

    def test_import_time_call_has_no_entrypoint(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "boot.py", "import requests\nrequests.get('http://x')\n")
            results = analyze_exposure(root, ["requests"])
        self.assertEqual(results["requests"].exposure, "unlinked")


class TestExposureResolution(unittest.TestCase):
    def test_from_import_is_detected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "app.py", '''
from requests import get

def handler():
    return get("http://x")

if __name__ == "__main__":
    handler()
''')
            results = analyze_exposure(root, ["requests"])
        self.assertEqual(results["requests"].exposure, "local")
        self.assertEqual(results["requests"].path[-1], "get()")

    def test_cross_module_call_chain(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "app.py", '''
from service import fetch_data

if __name__ == "__main__":
    fetch_data()
''')
            _write(root, "service.py", '''
import requests

def fetch_data():
    return requests.get("https://x")
''')
            results = analyze_exposure(root, ["requests"])
        res = results["requests"]
        self.assertEqual(res.exposure, "local")
        self.assertEqual(res.path, ["service.py:fetch_data", "requests.get()"])
        self.assertEqual(res.depth, 0)

    def test_vulnerable_symbol_filter(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "cli.py", '''
import argparse
from yaml import safe_load, dump

def main():
    argparse.ArgumentParser().parse_args()
    return safe_load("x")

if __name__ == "__main__":
    main()
''')
            safe = analyze_exposure(root, ["pyyaml"],
                                    package_symbols={"pyyaml": ["safe_load"]})
            dump = analyze_exposure(root, ["pyyaml"],
                                    package_symbols={"pyyaml": ["dump"]})
        self.assertEqual(safe["pyyaml"].exposure, "cli")
        self.assertEqual(dump["pyyaml"].exposure, "unlinked")

    def test_network_beats_cli_on_longer_path(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "svc.py", '''
import argparse
import requests

def deep():
    return requests.get("http://x")

def mid():
    return deep()

def run():
    return mid()

def main():
    argparse.ArgumentParser().parse_args()
    return run()

if __name__ == "__main__":
    main()
''')
            results = analyze_exposure(root, ["requests"])
        self.assertEqual(results["requests"].exposure, "cli")
        self.assertEqual(results["requests"].depth, 3)

    def test_syntax_error_file_is_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "bad.py", "def broken(:\n")
            _write(root, "good.py", "import requests\n")
            results = analyze_exposure(root, ["requests"])
        self.assertEqual(results["requests"].exposure, "unlinked")

    def test_apply_sets_finding_fields(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "web.py", WEB_APP)
            findings = [
                Finding(cve_id="CVE-1", package="requests", version="2.6.0"),
                Finding(cve_id="CVE-2", package="django", version="1.11"),
            ]
            apply_exposure(findings, root)
        self.assertEqual(findings[0].exposure, "network")
        self.assertTrue(findings[0].exploit_path)
        self.assertEqual(findings[0].extra["exposure_entrypoint"], "web.py:proxy")
        self.assertEqual(findings[1].exposure, "none")
        self.assertEqual(findings[1].exploit_path, [])

    def test_empty_findings(self):
        self.assertEqual(apply_exposure([], Path(".")), [])


if __name__ == "__main__":
    unittest.main()
