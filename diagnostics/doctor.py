"""Environment readiness: what a live scan needs, checked before it runs.

A scan fails for environment reasons far more often than for pipeline reasons
(Trivy missing or its DB stale, Ollama stopped, a policy file with typos). This
module turns those into one machine-readable report the UIs can show up front.
"""

from __future__ import annotations

import datetime as dt
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

from explanation.explainer import (
    DEFAULT_OLLAMA_MODEL, LLMUnavailable, ollama_host, ollama_models, ollama_version,
)
from scanner.run_trivy import resolve_trivy

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY = ROOT / ".security" / "policy.json"

DB_FRESH_HOURS = 48
_TRIVY_VERSION = re.compile(r"^Version:\s*(\S+)", re.MULTILINE)
_DB_UPDATED = re.compile(r"^\s+UpdatedAt:\s*(.+)$", re.MULTILINE)
_DB_TIMESTAMP = re.compile(r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})")


def _db_age_hours(raw: Optional[str]) -> Optional[float]:
    if not raw:
        return None
    match = _DB_TIMESTAMP.search(raw)
    if not match:
        return None
    try:
        stamp = dt.datetime.strptime(" ".join(match.groups()), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    return max(0.0, (dt.datetime.now(dt.timezone.utc) - stamp.replace(
        tzinfo=dt.timezone.utc)).total_seconds() / 3600)


def trivy_status(timeout: float = 25.0) -> dict:
    path = resolve_trivy()
    if not path:
        return {
            "status": "missing",
            "detail": "Trivy is not installed",
            "hint": "winget install AquaSecurity.Trivy (or get it from trivy.dev), "
                    "or use Demo mode.",
        }
    try:
        proc = subprocess.run(
            [path, "--version"], capture_output=True, text=True, timeout=timeout
        )
        output = proc.stdout
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "status": "error",
            "detail": f"Trivy could not be queried: {exc}",
            "hint": "Reinstall Trivy, or run it once from a terminal.",
        }

    version_match = _TRIVY_VERSION.search(output)
    version = version_match.group(1) if version_match else "unknown"
    updated = _DB_UPDATED.search(output)
    age = _db_age_hours(updated.group(1) if updated else None)
    if age is None:
        return {
            "status": "warn",
            "detail": f"Trivy {version} found, vulnerability DB state unknown",
            "hint": "The first scan downloads the DB; it can take several minutes.",
        }
    if age <= DB_FRESH_HOURS:
        return {
            "status": "ok",
            "detail": f"Trivy {version} · DB {int(age)}h old",
            "version": version,
            "db_age_hours": round(age, 1),
        }
    return {
        "status": "warn",
        "detail": f"Trivy {version} · DB {int(age)}h old",
        "hint": "The next scan refreshes the vulnerability DB. Run "
                "'trivy image --download-db-only --timeout 20m' to do it now.",
        "version": version,
        "db_age_hours": round(age, 1),
    }


def ollama_status(timeout: float = 3.0) -> dict:
    host = ollama_host()
    base = {
        "host": host,
        "model": os.environ.get("OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL),
    }
    try:
        models = ollama_models(host=host, timeout=timeout)
        version = ollama_version(host=host, timeout=timeout)
    except LLMUnavailable as exc:
        return {
            "status": "missing",
            "detail": str(exc),
            "hint": "Start the Ollama app, or run 'ollama serve' in a terminal.",
            "models": [],
            **base,
        }
    if not models:
        return {
            "status": "warn",
            "detail": f"Ollama {version} is running with no models",
            "hint": f"Pull one: 'ollama pull {base['model']}'.",
            "models": [],
            "version": version,
            **base,
        }
    wanted = base["model"]
    available = wanted in models or wanted in {m.split(":")[0] for m in models}
    if not available:
        return {
            "status": "warn",
            "detail": f"Ollama {version} is running, but '{wanted}' is not installed",
            "hint": f"Pick another model or run 'ollama pull {wanted}'.",
            "models": models,
            "version": version,
            **base,
        }
    return {
        "status": "ok",
        "detail": f"Ollama {version} · {len(models)} model(s) · {wanted}",
        "models": models,
        "version": version,
        **base,
    }


def openai_status() -> dict:
    base_url = os.environ.get("OPENAI_BASE_URL") or "https://api.openai.com/v1"
    has_key = bool(os.environ.get("OPENAI_API_KEY"))
    return {
        "status": "ok" if (has_key or os.environ.get("OPENAI_BASE_URL")) else "missing",
        "detail": (
            f"{os.environ.get('OPENAI_MODEL', 'gpt-4o-mini')} at {base_url}"
            + ("" if has_key else " (no API key)")
        ),
        "hint": "" if has_key else "Set OPENAI_API_KEY, or OPENAI_BASE_URL for a "
                                   "local OpenAI-compatible server.",
        "base_url": base_url,
        "model": os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
        "has_key": has_key,
    }


def policy_status(path: Optional[Path] = None) -> dict:
    path = path or DEFAULT_POLICY
    if not path.exists():
        return {"status": "missing", "detail": f"no policy file at {path.name}",
                "hint": "Add .security/policy.json to gate merges."}
    try:
        from policy.gate import load_policy

        policy = load_policy(path)
    except Exception as exc:  # a bad policy must be reported, not raised
        return {"status": "error", "detail": f"policy invalid: {exc}",
                "hint": "Fix .security/policy.json; typos fail closed."}
    today = dt.date.today()
    expired = [w for w in policy.waivers if w.expires < today]
    detail = f"{len(policy.rules)} rule(s) · {len(policy.waivers)} waiver(s)"
    if expired:
        detail += f" · {len(expired)} expired"
    return {
        "status": "warn" if expired else "ok",
        "detail": detail,
        "hint": "Expired waivers still count against findings; renew or remove them."
                if expired else "",
        "expired_waivers": [
            {"id": w.id, "cve": w.cve, "expired": w.expires.isoformat()}
            for w in expired
        ],
    }


def environment_report(policy_path: Optional[Path] = None) -> dict:
    trivy, ollama = trivy_status(), ollama_status()
    policy = policy_status(policy_path)
    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "python": sys.version.split()[0],
        "trivy": trivy,
        "ollama": ollama,
        "openai": openai_status(),
        "policy": policy,
        "capabilities": {
            "demo": True,
            "live_scan": trivy["status"] in ("ok", "warn"),
            "ollama_explanations": ollama["status"] == "ok",
            "policy_gate": policy["status"] in ("ok", "warn"),
        },
    }
