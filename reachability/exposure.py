"""Phase 5b -- Exploit-path exposure analysis.

Reachability answers "is this package used at all?". Exposure answers the
question that actually drives triage: *can an attacker reach it?* We build a
lightweight call graph of the project, mark entrypoints (web route handlers,
CLI mains), and trace the shortest path from an entrypoint to the function
that calls the vulnerable package.

    network > cli > local > unlinked > none

  network   reachable from a request handler (Flask/FastAPI/Django-style)
  cli       reachable from a command-line entrypoint (argparse/click/typer)
  local     reachable from a __main__ script that isn't CLI-shaped
  unlinked  imported/called, but no entrypoint leads to the call site
  none      package never imported

This is a heuristic over Python's AST, not a soundness proof: dynamic dispatch,
reflection, and framework magic can hide edges. It is still enough to
separate "the internet can trigger this" from "only a dead helper calls it",
which reachability alone cannot.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from common.finding import Finding
from reachability.ast_checker import _iter_python_files, import_names_for

EXPOSURE_RANK = {"none": 0, "unlinked": 1, "local": 2, "cli": 3, "network": 4}

_ROUTE_DECORATOR = re.compile(
    r"\.(route|get|post|put|patch|delete|head|options|websocket|api_route"
    r"|before_request|after_request|errorhandler)\s*\("
)
_ROUTE_DIRECT = re.compile(
    r"^(?:[A-Za-z_][\w.]*\.)?(api_view|require_http_methods|detail_route|list_route)\s*\("
)
_CLI_CALLS = {"parse_args", "ArgumentParser", "command", "Typer", "Option", "Argument"}
_CLI_MODULES = {"argparse", "click", "typer"}


@dataclass
class ExposureResult:
    """Where a vulnerable call site sits relative to the outside world."""

    exposure: str = "none"
    entrypoint: Optional[str] = None
    path: list[str] = field(default_factory=list)
    depth: Optional[int] = None

    @property
    def rank(self) -> int:
        return EXPOSURE_RANK[self.exposure]


@dataclass
class _Use:
    """A call that reaches into an imported package."""

    module: str          # full module path, e.g. "requests.sessions"
    symbol: str          # called attribute/function, e.g. "get"
    text: str            # source-ish rendering, e.g. "requests.get"
    function: Optional[str] = None  # owning function key; None at module level


@dataclass
class _Function:
    key: str
    module: str
    qualname: str
    file: str
    cls: Optional[str]
    is_cli: bool = False
    is_route: bool = False
    calls: list[ast.Call] = field(default_factory=list)
    uses: list[_Use] = field(default_factory=list)

    @property
    def display(self) -> str:
        return f"{self.file}:{self.qualname}"


@dataclass
class _Module:
    name: str
    file: str
    is_package: bool
    module_aliases: dict[str, str] = field(default_factory=dict)
    from_aliases: dict[str, tuple[str, str]] = field(default_factory=dict)
    roots: set[str] = field(default_factory=set)
    functions: dict[str, _Function] = field(default_factory=dict)
    main_calls: list[ast.Call] = field(default_factory=list)
    module_uses: list[_Use] = field(default_factory=list)
    classes: set[str] = field(default_factory=set)


def _attr_chain(node: ast.AST) -> Optional[list[str]]:
    """Flatten `a.b.c` into ["a", "b", "c"]; return None if not a pure chain."""
    chain: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        chain.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        chain.append(cur.id)
        chain.reverse()
        return chain
    return None


def _module_name(path: Path, root: Path) -> tuple[str, bool]:
    if root.is_file():
        rel = Path(path.name)
    else:
        try:
            rel = path.relative_to(root)
        except ValueError:
            rel = Path(path.name)
    parts = list(rel.with_suffix("").parts)
    is_package = bool(parts) and parts[-1] == "__init__"
    if is_package:
        parts.pop()
    return ".".join(parts), is_package


def _relative_module(current: str, is_package: bool, level: int,
                     module: Optional[str]) -> str:
    if level == 0:
        return module or ""
    parts = current.split(".") if current else []
    if not is_package:
        parts = parts[:-1]
    up = level - 1
    if up:
        parts = parts[:-up] if up <= len(parts) else []
    if module:
        parts += module.split(".")
    return ".".join(parts)


def _apply_import(stmt: ast.stmt, mod: _Module) -> None:
    if isinstance(stmt, ast.Import):
        for alias in stmt.names:
            root = alias.name.split(".")[0]
            mod.roots.add(root)
            if alias.asname:
                mod.module_aliases[alias.asname] = alias.name
            else:
                mod.module_aliases[root] = root
    elif isinstance(stmt, ast.ImportFrom):
        base = _relative_module(mod.name, mod.is_package, stmt.level, stmt.module)
        if base:
            mod.roots.add(base.split(".")[0])
        for alias in stmt.names:
            if alias.name == "*":
                continue
            mod.from_aliases[alias.asname or alias.name] = (base, alias.name)


def _iter_block_imports(stmts: Iterable[ast.stmt]) -> Iterable[ast.stmt]:
    for stmt in stmts:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            yield stmt
        for attr in ("body", "orelse", "finalbody"):
            block = getattr(stmt, attr, None)
            if isinstance(block, list):
                yield from _iter_block_imports(block)
        for handler in getattr(stmt, "handlers", []):
            yield from _iter_block_imports(handler.body)


def _walk_scope(body: Iterable[ast.stmt]) -> Iterable[ast.AST]:
    """Walk a function body without descending into nested definitions."""
    stack = list(body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef, ast.Lambda)):
            continue
        yield node
        stack.extend(ast.iter_child_nodes(node))


def _is_main_guard(stmt: ast.stmt) -> bool:
    if not isinstance(stmt, ast.If):
        return False
    test = stmt.test
    if not isinstance(test, ast.Compare) or len(test.ops) != 1:
        return False
    left, op, right = test.left, test.ops[0], test.comparators[0]
    return (
        isinstance(left, ast.Name) and left.id == "__name__"
        and isinstance(op, ast.Eq)
        and isinstance(right, ast.Constant) and right.value == "__main__"
    )


def _decorator_texts(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    out = []
    for dec in node.decorator_list:
        try:
            out.append(ast.unparse(dec))
        except Exception:
            pass
    return out


def _uses_for_call(call: ast.Call, mod: _Module, function: Optional[str],
                   module_aliases: dict[str, str],
                   from_aliases: dict[str, tuple[str, str]],
                   local_classes: set[str]) -> Optional[_Use]:
    """Classify a call as a package use, ignore it, or leave it for graph edges."""
    func = call.func
    if isinstance(func, ast.Name):
        if func.id in from_aliases:
            base, imported = from_aliases[func.id]
            return _Use(module=base or imported, symbol=imported,
                        text=func.id, function=function)
        return None

    chain = _attr_chain(func)
    if not chain or len(chain) < 2:
        return None
    root = chain[0]
    if root in module_aliases:
        return _Use(module=module_aliases[root], symbol=chain[-1],
                    text=ast.unparse(func), function=function)
    if root in from_aliases:
        base, imported = from_aliases[root]
        # `from pkg import sub; sub.fn()` -> module pkg.sub, symbol fn.
        module = f"{base}.{imported}" if base else imported
        return _Use(module=module, symbol=chain[-1],
                    text=ast.unparse(func), function=function)
    if root in local_classes:
        return None  # local class call, resolved as a graph edge
    return None


def _collect_function(node: ast.FunctionDef | ast.AsyncFunctionDef,
                      mod: _Module, qualname: str, cls: Optional[str],
                      module_aliases: dict[str, str],
                      from_aliases: dict[str, tuple[str, str]],
                      local_classes: set[str]) -> _Function:
    aliases = dict(module_aliases)
    froms = dict(from_aliases)
    for stmt in _iter_block_imports(node.body):
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                root = alias.name.split(".")[0]
                mod.roots.add(root)
                aliases[alias.asname or root] = alias.name if alias.asname else root
        else:
            base = _relative_module(mod.name, mod.is_package, stmt.level, stmt.module)
            if base:
                mod.roots.add(base.split(".")[0])
            for alias in stmt.names:
                if alias.name != "*":
                    froms[alias.asname or alias.name] = (base, alias.name)

    fn = _Function(
        key=f"{mod.name}:{qualname}", module=mod.name, qualname=qualname,
        file=mod.file, cls=cls,
    )
    decorators = _decorator_texts(node)
    fn.is_route = any(
        _ROUTE_DECORATOR.search(d) or _ROUTE_DIRECT.search(d) for d in decorators
    )
    fn.is_cli = any(
        marker in d for d in decorators for marker in ("command", "Typer")
    ) or any(m in mod.roots for m in _CLI_MODULES)

    for child in _walk_scope(node.body):
        if isinstance(child, ast.Call):
            fn.calls.append(child)
            called = child.func
            name = called.id if isinstance(called, ast.Name) else (
                called.attr if isinstance(called, ast.Attribute) else ""
            )
            if name in _CLI_CALLS:
                fn.is_cli = True
            use = _uses_for_call(child, mod, fn.key, aliases, froms, local_classes)
            if use:
                fn.uses.append(use)
    return fn


def _parse_module(path: Path, root: Path) -> Optional[_Module]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, UnicodeDecodeError, OSError):
        return None

    name, is_package = _module_name(path, root)
    mod = _Module(name=name, file=_display_path(path, root), is_package=is_package)

    for stmt in _iter_block_imports(tree.body):
        _apply_import(stmt, mod)

    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fn = _collect_function(stmt, mod, stmt.name, None,
                                   mod.module_aliases, mod.from_aliases, mod.classes)
            mod.functions[fn.key] = fn
        elif isinstance(stmt, ast.ClassDef):
            mod.classes.add(stmt.name)
    # Methods are collected after all class names are known.
    for stmt in tree.body:
        if isinstance(stmt, ast.ClassDef):
            for item in stmt.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    fn = _collect_function(
                        item, mod, f"{stmt.name}.{item.name}", stmt.name,
                        mod.module_aliases, mod.from_aliases, mod.classes,
                    )
                    mod.functions[fn.key] = fn

    # Module-level calls (and __main__ guard bodies).
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if _is_main_guard(stmt):
            for child in _walk_scope(stmt.body):
                if isinstance(child, ast.Call):
                    mod.main_calls.append(child)
            continue
        for child in _walk_scope([stmt]):
            if isinstance(child, ast.Call):
                use = _uses_for_call(child, mod, None, mod.module_aliases,
                                     mod.from_aliases, mod.classes)
                if use:
                    mod.module_uses.append(use)
    return mod


def _display_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _resolve_target(call: ast.Call, mod: _Module, rel: dict[str, _Function],
                    cls: Optional[str] = None) -> Optional[str]:
    """Resolve a call to a locally-defined function key, if possible."""
    func = call.func
    if isinstance(func, ast.Name):
        local = f"{mod.name}:{func.id}"
        if local in rel:
            return local
        if func.id in mod.from_aliases:
            base, imported = mod.from_aliases[func.id]
            candidate = f"{base}:{imported}" if base else ""
            if candidate in rel:
                return candidate
        if cls:
            method = f"{mod.name}:{cls}.{func.id}"
            if method in rel:
                return method
        return None

    chain = _attr_chain(func)
    if not chain or len(chain) < 2:
        return None
    root = chain[0]
    if root == "self" and cls:
        candidate = f"{mod.name}:{cls}.{chain[-1]}"
        return candidate if candidate in rel else None

    candidates: list[str] = []
    if root in mod.module_aliases:
        base = mod.module_aliases[root]
        if len(chain) == 2:
            candidates.append(f"{base}:{chain[1]}")
        else:
            candidates.append(f"{base}.{'.'.join(chain[1:-1])}:{chain[-1]}")
    if root in mod.from_aliases:
        base, imported = mod.from_aliases[root]
        candidates.append(f"{base}.{imported}:{chain[-1]}")
        candidates.append(f"{base}:{imported}.{chain[-1]}")
    if root in mod.classes:
        candidates.append(f"{mod.name}:{root}.{chain[-1]}")
    for candidate in candidates:
        if candidate in rel:
            return candidate
    return None


def _looks_like_cli(fn: _Function, mod: _Module) -> bool:
    return fn.is_cli or any(m in mod.roots for m in _CLI_MODULES)


def _best_exposure(
    tainted: set[str],
    uses: dict[str, _Use],
    entrypoints: list[tuple[str, str]],
    graph: dict[str, set[str]],
    rel: dict[str, _Function],
) -> ExposureResult:
    best: Optional[tuple[int, int, tuple[str, ...], str, str]] = None
    for kind, start in entrypoints:
        parent: dict[str, Optional[str]] = {start: None}
        queue = [start]
        found = None
        for current in queue:
            if current in tainted:
                found = current
                break
            for nxt in sorted(graph.get(current, ())):
                if nxt not in parent:
                    parent[nxt] = current
                    queue.append(nxt)
        if found is None:
            continue

        keys = []
        node: Optional[str] = found
        while node is not None:
            keys.append(node)
            node = parent[node]
        keys.reverse()
        path = [rel[k].display for k in keys if k in rel]
        use = uses.get(found)
        if use:
            path.append(f"{use.text}()")
        rank = EXPOSURE_RANK[kind]
        candidate = (rank, -len(keys), tuple(path), kind, keys[0])
        if best is None or candidate[:3] > best[:3]:
            best = candidate

    if best is None:
        return ExposureResult(exposure="unlinked")
    rank, neg_depth, path_tuple, kind, entry = best
    return ExposureResult(
        exposure=kind,
        entrypoint=rel[entry].display if entry in rel else entry,
        path=list(path_tuple),
        depth=(-neg_depth) - 1,
    )


def analyze_exposure(
    code_root: Path,
    packages: Iterable[str],
    package_symbols: Optional[dict[str, list[str]]] = None,
    exclude: Iterable[str] = (),
) -> dict[str, ExposureResult]:
    """Return exposure results for every package in `packages`."""
    code_root = Path(code_root)
    package_symbols = package_symbols or {}
    modules: list[_Module] = []
    for path in _iter_python_files(code_root, exclude):
        mod = _parse_module(path, code_root)
        if mod is not None:
            modules.append(mod)

    rel: dict[str, _Function] = {}
    graph: dict[str, set[str]] = {}
    all_uses: list[_Use] = []
    imports_by_root: set[str] = set()
    entrypoints: list[tuple[str, str]] = []

    for mod in modules:
        rel.update(mod.functions)
        imports_by_root |= mod.roots
        all_uses.extend(mod.module_uses)
        for fn in mod.functions.values():
            all_uses.extend(fn.uses)
            graph.setdefault(fn.key, set())

    # Resolution needs the full registry, so entrypoints and edges come second.
    for mod in modules:
        for fn in mod.functions.values():
            for call in fn.calls:
                target = _resolve_target(call, mod, rel, fn.cls)
                if target:
                    graph[fn.key].add(target)
        for fn in mod.functions.values():
            if fn.is_route:
                entrypoints.append(("network", fn.key))
        for call in mod.main_calls:
            target = _resolve_target(call, mod, rel)
            if target:
                kind = "cli" if _looks_like_cli(rel[target], mod) else "local"
                entrypoints.append((kind, target))

    results: dict[str, ExposureResult] = {}
    for package in set(packages):
        candidates = import_names_for(package)
        if not (imports_by_root & candidates):
            results[package] = ExposureResult(exposure="none")
            continue

        wanted = set(package_symbols.get(package) or [])
        matching = [
            u for u in all_uses
            if (u.module.split(".")[0] in candidates)
            and (not wanted or u.symbol in wanted)
        ]
        if not matching:
            results[package] = ExposureResult(exposure="unlinked")
            continue

        tainted: set[str] = set()
        uses_by_fn: dict[str, _Use] = {}
        for use in matching:
            if use.function:
                tainted.add(use.function)
                uses_by_fn.setdefault(use.function, use)
        if not tainted:
            # Called at import time: no entrypoint path, but not "none" either.
            results[package] = ExposureResult(exposure="unlinked")
            continue

        results[package] = _best_exposure(
            tainted, uses_by_fn, entrypoints, graph, rel
        )
    return results


def apply_exposure(
    findings: list[Finding],
    code_root: Path,
    package_symbols: Optional[dict[str, list[str]]] = None,
    exclude: Iterable[str] = (),
) -> list[Finding]:
    """Set `exposure` and `exploit_path` on each finding, one parse per run."""
    if not findings:
        return findings
    results = analyze_exposure(
        code_root, {f.package for f in findings},
        package_symbols=package_symbols, exclude=exclude,
    )
    for f in findings:
        result = results.get(f.package, ExposureResult())
        f.exposure = result.exposure
        f.exploit_path = list(result.path)
        if result.entrypoint:
            f.extra["exposure_entrypoint"] = result.entrypoint
    return findings
