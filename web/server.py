"""Local web interface for devsecops-chain.

A tiny, dependency-free HTTP server that puts the same pipeline the CLI and CI
use behind a browser UI:

    py -m web.server                 # then open http://127.0.0.1:8765
    py -m web.server --no-browser    # headless (for tests)

Security posture for a localhost tool:
  * binds to 127.0.0.1 only
  * rejects requests whose Host header is not localhost/127.0.0.1 (DNS rebinding)
  * every /api/* call needs a per-process bearer token embedded in the page
  * browsers get a strict CSP and no-store caching

The UI can run a fully offline demo from the shipped Trivy fixture, or perform a
live scan of any folder. Scans run in a background thread; the page polls
/api/state for stage progress and results.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import string
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request
import webbrowser
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from common.finding import Finding
from diagnostics.doctor import environment_report
from explanation.explainer import (
    DEFAULT_OLLAMA_MODEL, LLMUnavailable, check_ollama, ollama_host,
)
from pipeline import PipelineOptions, scan_and_run, _render_markdown
from remediation.planner import RemediationPlan, build_plan, render_markdown
from scanner.run_trivy import TrivyError

STATIC_DIR = Path(__file__).resolve().parent / "static"
PROJECT_POLICY = ROOT / ".security" / "policy.json"
DEMO_FIXTURE = ROOT / "tests" / "fixtures" / "trivy_report.json"
DEMO_ROOT = ROOT / "testproject"
WEB_HISTORY = ROOT / "data" / "web_history.db"

APP_ID = "devsecops-chain-web"
VERSION = "0.2.0"
VIEW_LIMIT = 500
MAX_BODY = 1_000_000
MAX_DIRS = 400
IDLE_TIMEOUT = 1800.0
# Model refs come from the browser: allow ordinary tag syntax, nothing else.
_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,119}")

_STATIC = {
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}

_CSP = (
    "default-src 'self'; script-src 'self'; "
    "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "
    "font-src 'self' https://fonts.gstatic.com data:; "
    "img-src 'self' data:; connect-src 'self'; form-action 'self'; "
    "frame-ancestors 'none'; base-uri 'none'"
)


@dataclass
class ScanJob:
    id: int
    target: str
    mode: str
    started_at: float
    status: str = "running"          # running | done | error
    stage: str = "Starting"
    stages: list[str] = field(default_factory=list)
    error: Optional[str] = None
    findings: list[Finding] = field(default_factory=list)
    gate: Optional[dict] = None
    delta: Optional[dict] = None
    plan: Optional[RemediationPlan] = None
    plan_error: Optional[str] = None
    finished_at: Optional[float] = None

    def public(self) -> dict:
        elapsed = (self.finished_at or time.monotonic()) - self.started_at
        shown = self.findings[:VIEW_LIMIT]
        return {
            "id": self.id,
            "status": self.status,
            "stage": self.stage,
            "stages": self.stages,
            "target": self.target,
            "mode": self.mode,
            "elapsed": round(elapsed, 1),
            "error": self.error,
            "gate": self.gate,
            "delta": self.delta,
            "remediation": self.remediation_payload(),
            "findings": [f.to_dict() for f in shown],
            "total": len(self.findings),
            "shown": len(shown),
        }

    def remediation_payload(self) -> dict:
        if self.plan is None:
            return {
                "steps": [],
                "manual": [],
                "error": self.plan_error or "no plan",
                "summary": {"cves_total": len(self.findings), "cves_cleared": 0,
                            "upgrades": 0, "needs_review": 0, "reduction_pct": 0.0},
            }
        payload = self.plan.to_dict()
        payload["has_patch"] = bool(self.plan.patch)
        return payload


class AppState:
    def __init__(self, idle_timeout: float = IDLE_TIMEOUT,
                 history_path: Optional[Path] = None):
        self.token = secrets.token_urlsafe(24)
        self.lock = threading.RLock()
        self.job: Optional[ScanJob] = None
        self._next_id = 1
        self.idle_timeout = idle_timeout
        self.history_path = history_path
        self.last_request = time.monotonic()

    def touch(self) -> None:
        self.last_request = time.monotonic()

    def try_new_job(self, target: str, mode: str) -> Optional[ScanJob]:
        """Atomically start a job; None when a scan is already running."""
        with self.lock:
            if self.job and self.job.status == "running":
                return None
            job = ScanJob(
                id=self._next_id, target=target, mode=mode,
                started_at=time.monotonic(),
            )
            self._next_id += 1
            self.job = job
            return job

    def running(self) -> bool:
        with self.lock:
            return bool(self.job and self.job.status == "running")

    def payload(self) -> dict:
        with self.lock:
            job = self.job.public() if self.job else None
        return {
            "app": APP_ID,
            "version": VERSION,
            "job": job,
            "policy_available": PROJECT_POLICY.exists(),
            "view_limit": VIEW_LIMIT,
        }


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _roots() -> list[str]:
    if os.name == "nt":
        return [
            f"{letter}:\\" for letter in string.ascii_uppercase
            if Path(f"{letter}:\\").exists()
        ]
    return ["/"]


def _safe_dir(raw: str) -> Path:
    path = Path(raw).expanduser()
    try:
        return path.resolve()
    except OSError:
        return path.absolute()


def directory_listing(raw: str = "") -> dict:
    """List child directories for the in-app folder picker."""
    current = _safe_dir(raw) if raw.strip() else _safe_dir(str(Path.home()))
    if not current.is_dir():
        raise ValueError(f"not a folder: {current}")

    entries = []
    try:
        for child in current.iterdir():
            try:
                if child.is_dir():
                    entries.append({"name": child.name or str(child), "path": str(child)})
            except OSError:
                continue
    except PermissionError as exc:
        raise ValueError(f"permission denied: {current}") from exc

    entries.sort(key=lambda entry: entry["name"].casefold())
    truncated = len(entries) > MAX_DIRS
    entries = entries[:MAX_DIRS]

    parent = current.parent if current.parent != current else None
    return {
        "current": str(current),
        "parent": str(parent) if parent else None,
        "entries": entries,
        "roots": _roots(),
        "home": str(Path.home()),
        "truncated": truncated,
    }


def _resolve_target(raw: object) -> Path:
    if not raw or not str(raw).strip():
        raise ValueError("a project folder is required")
    path = _safe_dir(str(raw))
    if not path.is_dir():
        raise ValueError(f"folder not found: {path}")
    return path


def _evaluate_policy(findings: list[Finding]) -> dict:
    if not PROJECT_POLICY.exists():
        return {"passed": None, "error": "no policy file at .security/policy.json"}
    try:
        from policy.gate import evaluate_gate, load_policy

        report = evaluate_gate(findings, load_policy(PROJECT_POLICY))
        return report.to_dict()
    except Exception as exc:  # policy problems must not hide scan results
        return {"passed": None, "error": str(exc)}


def _history_delta(
    path: Path, findings: list[Finding], target: str, mode: str
) -> dict:
    """Record this run and diff it against the previous run of the same target."""
    from history.store import HistoryStore

    with HistoryStore(path) as store:
        previous = next(
            (run for run in store.runs(200)
             if run.target == target and run.mode == mode),
            None,
        )
        run_id = store.record(findings, target=target, mode=mode)
        report = store.diff(run_id, previous.id if previous else None)
        store.prune()
        return report.to_dict()


def _plan_remediation(
    findings: list[Finding], root: Optional[Path]
) -> tuple[Optional[RemediationPlan], Optional[str]]:
    """Group findings into upgrade steps + a patch. Never fails a scan."""
    if root is None or not root.is_dir():
        return None, "no source folder to plan against"
    try:
        return build_plan(findings, root), None
    except Exception as exc:
        traceback.print_exc()
        return None, f"planning failed: {exc}"


def _run_job(
    state: AppState,
    job: ScanJob,
    opts: PipelineOptions,
    from_json: Optional[str],
    evaluate_policy: bool,
) -> None:
    def progress(message: str) -> None:
        with state.lock:
            job.stage = message
            job.stages.append(message)

    try:
        findings = scan_and_run(job.target, opts, from_json=from_json, progress=progress)
        with state.lock:
            job.findings = findings
            job.stage = "Planning remediation"
        plan, plan_error = _plan_remediation(findings, opts.code_root)
        with state.lock:
            job.plan = plan
            job.plan_error = plan_error
            job.stage = "Evaluating policy gate" if evaluate_policy else "Finishing"
        if evaluate_policy:
            gate = _evaluate_policy(findings)
            with state.lock:
                job.gate = gate
        if state.history_path is not None:
            with state.lock:
                job.stage = "Recording scan history"
            try:
                delta = _history_delta(
                    state.history_path, findings, job.target, job.mode
                )
            except Exception as exc:
                traceback.print_exc()
                delta = {"error": f"history unavailable: {exc}"}
            with state.lock:
                job.delta = delta
        with state.lock:
            job.status = "done"
            job.stage = f"Complete — {len(findings)} finding(s)"
            job.finished_at = time.monotonic()
    except TrivyError as exc:
        with state.lock:
            job.status = "error"
            job.error = str(exc)
            job.stage = "Scan failed"
            job.finished_at = time.monotonic()
    except Exception as exc:
        traceback.print_exc()
        with state.lock:
            job.status = "error"
            job.error = f"{type(exc).__name__}: {exc}"
            job.stage = "Scan failed"
            job.finished_at = time.monotonic()


def _watchdog(state: AppState, server: _Server) -> None:
    while True:
        time.sleep(30)
        if not state.idle_timeout:
            continue
        if state.running():
            continue
        if time.monotonic() - state.last_request > state.idle_timeout:
            server.shutdown()
            return


def existing_instance(port: int) -> bool:
    """True when the port already serves this app (avoids duplicate servers)."""
    try:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/api/health", timeout=0.5
        ) as response:
            return json.loads(response.read().decode("utf-8")).get("app") == APP_ID
    except (urllib.error.URLError, ValueError, OSError):
        return False


def make_handler(state: AppState):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"DevSecOpsChain/{VERSION}"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # quiet polling; errors still print
            pass

        def handle(self):
            # Browsers drop polling connections abruptly; that is not an error.
            try:
                super().handle()
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                pass

        # --- plumbing -------------------------------------------------
        def _host_ok(self) -> bool:
            host = (self.headers.get("Host") or "").strip().lower()
            port = self.server.server_address[1]
            return host in {f"127.0.0.1:{port}", f"localhost:{port}"}

        def _send(self, code: int, body: bytes, content_type: str,
                  headers: Optional[dict] = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, code: int, payload: dict, headers: Optional[dict] = None) -> None:
            body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
            self._send(code, body, "application/json; charset=utf-8", headers)

        def _error(self, code: int, message: str) -> None:
            self._json(code, {"error": message})

        def _guard(self) -> bool:
            state.touch()
            if not self._host_ok():
                self._error(403, "invalid Host header")
                return False
            return True

        def _authorized(self) -> bool:
            supplied = (self.headers.get("X-Scan-Token") or "").encode(
                "utf-8", "replace"
            )
            if secrets.compare_digest(supplied, state.token.encode("utf-8")):
                return True
            self._error(401, "missing or invalid scan token")
            return False

        def _read_json(self) -> dict:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                raise ValueError("invalid Content-Length")
            if length <= 0:
                raise ValueError("request body is required")
            if length > MAX_BODY:
                raise ValueError("request body is too large (maximum 1 MB)")
            try:
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise ValueError("request body must be JSON")
            if not isinstance(payload, dict):
                raise ValueError("request body must be a JSON object")
            return payload

        # --- routes ---------------------------------------------------
        def do_GET(self):
            if not self._guard():
                return
            path = urlparse(self.path).path

            if path in ("/", "/index.html"):
                return self._serve_index()
            if path in _STATIC:
                return self._serve_static(path)
            if path == "/favicon.ico":
                return self._send(204, b"", "image/x-icon")
            if path == "/api/health":
                return self._json(200, {"app": APP_ID, "version": VERSION})

            if path == "/api/state":
                if not self._authorized():
                    return
                return self._json(200, state.payload())

            if path == "/api/doctor":
                if not self._authorized():
                    return
                return self._json(200, environment_report(PROJECT_POLICY))

            if path == "/api/browse":
                if not self._authorized():
                    return
                raw = (parse_qs(urlparse(self.path).query).get("path") or [""])[0]
                try:
                    return self._json(200, directory_listing(raw))
                except ValueError as exc:
                    return self._error(400, str(exc))

            if path == "/api/export":
                if not self._authorized():
                    return
                fmt = (parse_qs(urlparse(self.path).query).get("format") or [""])[0]
                return self._export(fmt)

            return self._error(404, "not found")

        def do_POST(self):
            if not self._guard():
                return
            path = urlparse(self.path).path
            if not self._authorized():
                return

            if path == "/api/scan":
                return self._start_scan()
            if path == "/api/shutdown":
                self._json(200, {"ok": True})
                threading.Thread(
                    target=lambda: (time.sleep(0.3), self.server.shutdown()),
                    daemon=True,
                ).start()
                return
            return self._error(404, "not found")

        # --- handlers -------------------------------------------------
        def _serve_index(self) -> None:
            try:
                template = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
            except OSError:
                return self._error(500, "web assets are missing")
            html = template.replace("__TOKEN__", state.token)
            self._send(
                200, html.encode("utf-8"), "text/html; charset=utf-8",
                {"Content-Security-Policy": _CSP},
            )

        def _serve_static(self, path: str) -> None:
            name, content_type = _STATIC[path]
            try:
                body = (STATIC_DIR / name).read_bytes()
            except OSError:
                return self._error(404, "not found")
            self._send(200, body, content_type)

        def _start_scan(self) -> None:
            try:
                payload = self._read_json()
            except ValueError as exc:
                return self._error(400, str(exc))

            demo = bool(payload.get("demo"))
            offline = bool(payload.get("offline"))
            reachability = bool(payload.get("reachability", True))
            evaluate_policy = bool(payload.get("policy", True))
            llm = str(payload.get("llm") or "stub")
            if llm not in {"stub", "ollama", "openai"}:
                return self._error(400, "llm must be stub, ollama, or openai")

            if demo:
                if not DEMO_FIXTURE.exists():
                    return self._error(500, "demo fixture is missing")
                target = str(DEMO_ROOT)
                from_json: Optional[str] = str(DEMO_FIXTURE)
                offline = True
            else:
                try:
                    target = str(_resolve_target(payload.get("path")))
                except ValueError as exc:
                    return self._error(400, str(exc))
                from_json = None

            ollama_model = (
                str(payload.get("ollama_model") or "").strip()
                or os.environ.get("OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL)
            )
            if (llm == "openai" and not os.environ.get("OPENAI_API_KEY")
                    and not os.environ.get("OPENAI_BASE_URL")):
                return self._error(
                    400,
                    "OPENAI_API_KEY is not set. Set it, or point OPENAI_BASE_URL "
                    "at a local OpenAI-compatible server.",
                )
            if llm == "ollama":
                if not _MODEL_RE.fullmatch(ollama_model):
                    return self._error(400, "invalid Ollama model name")
                try:
                    check_ollama(ollama_model, host=ollama_host())
                except LLMUnavailable as exc:
                    return self._error(400, str(exc))

            opts = PipelineOptions(
                offline=offline,
                do_prioritize=True,
                do_reachability=reachability,
                do_exposure=reachability,
                do_explain=True,
                llm=llm,
                ollama_model=ollama_model,
                top=None,
                code_root=Path(target),
            )
            job = state.try_new_job(
                target=target, mode="demo" if demo else "live"
            )
            if job is None:
                return self._error(409, "a scan is already running")
            threading.Thread(
                target=_run_job,
                args=(state, job, opts, from_json, evaluate_policy),
                daemon=True,
            ).start()
            self._json(202, {"job_id": job.id, "mode": job.mode, "target": job.target})

        def _export(self, fmt: str) -> None:
            with state.lock:
                job = state.job
            if job is None or job.status != "done":
                return self._error(409, "no completed scan to export")

            if fmt == "json":
                body = json.dumps(
                    [f.to_dict() for f in job.findings], indent=2
                ).encode("utf-8")
                content_type, filename = "application/json; charset=utf-8", "findings.json"
            elif fmt == "markdown":
                body = _render_markdown(
                    job.findings, limit=max(1, len(job.findings))
                ).encode("utf-8")
                content_type, filename = "text/markdown; charset=utf-8", "security-report.md"
            elif fmt == "vex":
                from output.vex import render_vex

                body = render_vex(job.findings).encode("utf-8")
                content_type, filename = "application/json; charset=utf-8", "vex.json"
            elif fmt == "policy":
                if job.gate is None:
                    return self._error(409, "this scan has no policy report")
                body = json.dumps(job.gate, indent=2).encode("utf-8")
                content_type, filename = "application/json; charset=utf-8", "policy-gate.json"
            elif fmt == "remediation":
                if job.plan is None:
                    return self._error(409, job.plan_error or "no remediation plan")
                body = render_markdown(job.plan).encode("utf-8")
                content_type, filename = "text/markdown; charset=utf-8", "remediation-plan.md"
            elif fmt == "patch":
                if job.plan is None or not job.plan.patch:
                    return self._error(
                        409, "nothing is automatable in this scan's manifests"
                    )
                body = job.plan.patch.encode("utf-8")
                content_type, filename = "text/plain; charset=utf-8", "remediation.patch"
            else:
                return self._error(
                    400,
                    "format must be json, markdown, vex, policy, remediation, or patch",
                )

            self._send(
                200, body, content_type,
                {"Content-Disposition": f'attachment; filename="{filename}"'},
            )

        def do_HEAD(self):
            self.do_GET()

    return Handler


def create_server(port: int = 8765, state: Optional[AppState] = None,
                  idle_timeout: float = IDLE_TIMEOUT) -> _Server:
    """Bind a server, walking forward when the requested port is taken."""
    state = state or AppState(idle_timeout=idle_timeout, history_path=WEB_HISTORY)
    handler = make_handler(state)
    candidates = [0] if port == 0 else range(port, port + 25)
    last_error: Optional[OSError] = None
    for candidate in candidates:
        try:
            return _Server(("127.0.0.1", candidate), handler)
        except OSError as exc:
            last_error = exc
    raise OSError(f"no free port near {port}: {last_error}")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run the DevSecOps Chain web UI.")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument(
        "--idle-timeout", type=float, default=IDLE_TIMEOUT,
        help="seconds without requests before auto-shutdown (0 disables)",
    )
    args = parser.parse_args(argv)

    if existing_instance(args.port):
        url = f"http://127.0.0.1:{args.port}/"
        print(f"DevSecOps Chain is already running: {url}")
        if not args.no_browser:
            webbrowser.open(url)
        return 0

    state = AppState(idle_timeout=args.idle_timeout, history_path=WEB_HISTORY)
    server = create_server(args.port, state, args.idle_timeout)
    port = server.server_address[1]
    url = f"http://127.0.0.1:{port}/"

    print(f"DevSecOps Chain web UI: {url}")
    print("Press Ctrl+C to stop (or use the Stop server button).")
    threading.Thread(target=_watchdog, args=(state, server), daemon=True).start()
    if not args.no_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
