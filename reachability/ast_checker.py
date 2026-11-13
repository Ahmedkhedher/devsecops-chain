"""Phase 5 -- Reachability analysis.

Cuts false positives by checking whether the codebase actually uses a flagged
package. Two levels of granularity:

  1. Is the package imported at all?  (module-level check)
  2. If a specific vulnerable symbol is known, is that function/attribute
     actually referenced or called anywhere?

This is deliberately simpler than a commercial tool's full call-graph analysis:
we use Python's `ast` module to walk source files and look for imports and
calls. That's enough to demote "dependency is present but never used" noise,
which is a large share of SCA false positives.

Note on naming: Trivy reports *distribution* names (e.g. `pyyaml`,
`scikit-learn`) while code imports *module* names (`yaml`, `sklearn`). We
resolve that with a known alias map plus a normalization heuristic.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from common.finding import Finding

# Distribution name -> import name, for packages where they differ.
# Extend as needed; the heuristic below covers the common -/_ cases.
PACKAGE_IMPORT_ALIASES = {
    "pyyaml": "yaml",
    "pillow": "PIL",
    "scikit-learn": "sklearn",
    "beautifulsoup4": "bs4",
    "python-dateutil": "dateutil",
    "opencv-python": "cv2",
    "pyjwt": "jwt",
    "psycopg2-binary": "psycopg2",
    "mysqlclient": "MySQLdb",
    "attrs": "attr",
    "werkzeug": "werkzeug",
}


@dataclass
class ReachabilityResult:
    imported: bool
    symbols_used: set[str] = field(default_factory=set)
    files: list[str] = field(default_factory=list)

    @property
    def reachable(self) -> bool:
        return self.imported


def import_names_for(package: str) -> set[str]:
    """Candidate module names a distribution might be imported as."""
    names = {package}
    if package in PACKAGE_IMPORT_ALIASES:
        names.add(PACKAGE_IMPORT_ALIASES[package])
    # Common normalizations: dashes -> underscores, and vice versa.
    for n in list(names):
        names.add(n.replace("-", "_"))
        names.add(n.replace("_", "-"))
    # Strip a trailing version specifier if one slipped in (e.g. "requests>=2").
    return {n.split(">")[0].split("<")[0].split("=")[0] for n in names if n}


@dataclass
class _FileSymbols:
    """Imports and referenced names collected from a single source file."""
    imported: set[str] = field(default_factory=set)
    referenced: set[str] = field(default_factory=set)
    called: set[str] = field(default_factory=set)


def _collect_from_ast(tree: ast.AST) -> _FileSymbols:
    out = _FileSymbols()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                out.imported.add(alias.name.split(".")[0])
                out.referenced.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                out.imported.add(node.module.split(".")[0])
                out.referenced.add(node.module.split(".")[0])
            for alias in node.names:
                out.referenced.add(alias.name)
        elif isinstance(node, ast.Name):
            out.referenced.add(node.id)
        elif isinstance(node, ast.Attribute):
            out.referenced.add(node.attr)
        elif isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name):
                out.called.add(fn.id)
            elif isinstance(fn, ast.Attribute):
                out.called.add(fn.attr)
    return out


def _iter_python_files(root: Path, exclude: Iterable[str] = ()) -> Iterable[Path]:
    skip = set(exclude) | {".git", ".venv", "venv", "__pycache__", "node_modules"}
    if root.is_file():
        if root.suffix == ".py":
            yield root
        return
    for path in root.rglob("*.py"):
        if any(part in skip for part in path.parts):
            continue
        yield path


def analyze_package(
    package: str,
    code_root: Path,
    symbols: Optional[Iterable[str]] = None,
    exclude: Iterable[str] = (),
) -> ReachabilityResult:
    """Check whether `package` (and optionally specific `symbols`) is used."""
    code_root = Path(code_root)
    candidates = import_names_for(package)
    wanted_symbols = set(symbols) if symbols else set()

    result = ReachabilityResult(imported=False)
    used_symbols: set[str] = set()

    for path in _iter_python_files(code_root, exclude):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (SyntaxError, UnicodeDecodeError, OSError):
            continue
        fs = _collect_from_ast(tree)

        if fs.imported & candidates:
            result.imported = True
            rel = str(path.relative_to(code_root)) if path.is_relative_to(code_root) else str(path)
            if rel not in result.files:
                result.files.append(rel)
            # Which of the specific vulnerable symbols appear here?
            hit = wanted_symbols & (fs.referenced | fs.called)
            used_symbols |= hit

    result.symbols_used = used_symbols
    return result


def symbol_reachable(
    package: str,
    symbol: str,
    code_root: Path,
    exclude: Iterable[str] = (),
) -> bool:
    """True only if the package is imported AND the specific symbol is used.

    If the package isn't imported at all, returns False. If imported but the
    symbol is never referenced, returns False (function-level deprioritization).
    """
    res = analyze_package(package, code_root, symbols=[symbol], exclude=exclude)
    return res.imported and symbol in res.symbols_used


def apply_reachability(
    findings: list[Finding],
    code_root: Path,
    # Optional map of package -> vulnerable symbol names to check granularity.
    package_symbols: Optional[dict[str, list[str]]] = None,
    exclude: Iterable[str] = (),
) -> list[Finding]:
    """Set `reachable` on each finding based on whether its package is used.

    Findings for packages that are never imported are marked reachable=False so
    downstream stages can demote them. Results are cached per package to avoid
    re-walking the tree for every finding of the same dependency.
    """
    package_symbols = package_symbols or {}
    cache: dict[str, ReachabilityResult] = {}

    for f in findings:
        pkg = f.package
        if pkg not in cache:
            cache[pkg] = analyze_package(
                pkg, code_root,
                symbols=package_symbols.get(pkg),
                exclude=exclude,
            )
        res = cache[pkg]
        if package_symbols.get(pkg):
            # Symbol-level: reachable only if a known-vulnerable symbol is used.
            f.reachable = res.imported and bool(res.symbols_used)
        else:
            f.reachable = res.imported
        f.extra["reachability_files"] = res.files
        if res.symbols_used:
            f.extra["reachable_symbols"] = sorted(res.symbols_used)

    return findings
