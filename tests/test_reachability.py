"""Tests for Phase 5: AST-based reachability analysis."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from common.finding import Finding
from reachability.ast_checker import (
    import_names_for,
    analyze_package,
    symbol_reachable,
    apply_reachability,
)


def _write(root: Path, rel: str, content: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


class TestImportNames(unittest.TestCase):
    def test_alias_resolution(self):
        self.assertIn("yaml", import_names_for("pyyaml"))

    def test_dash_underscore_normalization(self):
        names = import_names_for("foo-bar")
        self.assertIn("foo_bar", names)
        self.assertIn("foo-bar", names)


class TestAnalyzePackage(unittest.TestCase):
    def test_detects_direct_import(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "app.py", "import requests\nrequests.get('x')\n")
            res = analyze_package("requests", root)
            self.assertTrue(res.imported)
            self.assertIn("app.py", res.files)

    def test_detects_from_import(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "app.py", "from flask import Flask\n")
            self.assertTrue(analyze_package("flask", root).imported)

    def test_absent_package_not_imported(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "app.py", "import os\n")
            self.assertFalse(analyze_package("requests", root).imported)

    def test_alias_package_detected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "app.py", "import yaml\nyaml.safe_load(open('c'))\n")
            # Trivy reports distribution name 'pyyaml'; code imports 'yaml'.
            self.assertTrue(analyze_package("pyyaml", root).imported)

    def test_symbol_level_detection(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "app.py", "import yaml\nyaml.safe_load(f)\n")
            res = analyze_package("pyyaml", root, symbols=["safe_load", "load"])
            self.assertTrue(res.imported)
            self.assertIn("safe_load", res.symbols_used)
            self.assertNotIn("load", res.symbols_used)

    def test_skips_syntax_errors(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "broken.py", "import requests\nthis is not python((\n")
            # Should not raise; broken file is skipped.
            res = analyze_package("requests", root)
            self.assertFalse(res.imported)

    def test_excludes_directories(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, ".venv/lib.py", "import requests\n")
            self.assertFalse(analyze_package("requests", root).imported)


class TestSymbolReachable(unittest.TestCase):
    def test_true_when_imported_and_called(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "app.py", "import yaml\nyaml.load(f)\n")
            self.assertTrue(symbol_reachable("pyyaml", "load", root))

    def test_false_when_imported_but_symbol_unused(self):
        """The Phase 5 checkpoint: vulnerable function never called."""
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            # yaml imported, but only safe_load used -- the vulnerable
            # yaml.load() is never called, so this finding is deprioritized.
            _write(root, "app.py", "import yaml\nyaml.safe_load(f)\n")
            self.assertFalse(symbol_reachable("pyyaml", "load", root))

    def test_false_when_not_imported(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "app.py", "import os\n")
            self.assertFalse(symbol_reachable("requests", "get", root))


class TestApplyReachability(unittest.TestCase):
    def test_sets_reachable_flags(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "app.py", "import requests\nrequests.get('x')\n")
            findings = [
                Finding(cve_id="CVE-1", package="requests", version="2.6.0"),
                Finding(cve_id="CVE-2", package="django", version="1.11"),
            ]
            apply_reachability(findings, root)
            by_id = {f.cve_id: f for f in findings}
            self.assertTrue(by_id["CVE-1"].reachable)
            self.assertFalse(by_id["CVE-2"].reachable)

    def test_symbol_level_marks_unreachable(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "app.py", "import yaml\nyaml.safe_load(f)\n")
            findings = [Finding(cve_id="CVE-Y", package="pyyaml", version="5.1")]
            apply_reachability(findings, root, package_symbols={"pyyaml": ["load"]})
            self.assertFalse(findings[0].reachable)

    def test_caches_per_package(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "app.py", "import requests\n")
            findings = [
                Finding(cve_id="CVE-1", package="requests", version="1"),
                Finding(cve_id="CVE-2", package="requests", version="1"),
            ]
            apply_reachability(findings, root)
            self.assertTrue(all(f.reachable for f in findings))


if __name__ == "__main__":
    unittest.main()
