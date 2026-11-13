"""Phase 3 -- Explanation engine.

Turns a raw Finding into a plain-language explanation, a "why it matters here"
note, and a concrete fix. The LLM is grounded on retrieved NVD context (and
reachability, once Phase 5 has run) so it explains the *actual* CVE rather than
hallucinating details from parametric memory.

The LLM is behind an injectable client so the whole stage is testable offline:
  - OllamaLLM      -> local model (Llama 3.2 / Qwen) via http://localhost:11434
  - OpenAICompatLLM-> any OpenAI-style /v1/chat/completions endpoint
  - StubLLM        -> deterministic responses for tests

A confidence indicator is attached using a simple heuristic (a clearly-stated
fixed version => high confidence), matching the pattern used elsewhere.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional, Protocol

from common.finding import Finding
from explanation.cve_context import CVEContext
from explanation.grounding import audit_explanation


DEFAULT_OLLAMA_HOST = "http://localhost:11434"
DEFAULT_OLLAMA_MODEL = "llama3.2"


class LLMUnavailable(RuntimeError):
    """Raised when the configured LLM backend cannot be reached or lacks a model."""


def ollama_host() -> str:
    host = os.environ.get("OLLAMA_HOST", DEFAULT_OLLAMA_HOST).strip().rstrip("/")
    if not host.startswith(("http://", "https://")):
        host = "http://" + host
    return host


def _ollama_get(path: str, host: Optional[str] = None,
                timeout: float = 4.0) -> dict:
    base = (host or ollama_host()).rstrip("/")
    try:
        with urllib.request.urlopen(f"{base}{path}", timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        raise LLMUnavailable(
            f"Ollama is not running at {base}. Launch the Ollama app or run "
            f"'ollama serve', then retry. ({exc})"
        ) from exc


def ollama_models(host: Optional[str] = None, timeout: float = 4.0) -> list[str]:
    """Installed model names; raises LLMUnavailable when the server is down."""
    data = _ollama_get("/api/tags", host=host, timeout=timeout)
    return [
        str(entry["name"])
        for entry in data.get("models") or []
        if entry.get("name")
    ]


def ollama_version(host: Optional[str] = None, timeout: float = 4.0) -> str:
    data = _ollama_get("/api/version", host=host, timeout=timeout)
    return str(data.get("version") or "unknown")


def check_ollama(
    model: str = DEFAULT_OLLAMA_MODEL,
    host: Optional[str] = None,
    timeout: float = 4.0,
) -> None:
    """Raise LLMUnavailable with an actionable message when Ollama can't serve."""
    models = ollama_models(host=host, timeout=timeout)
    if not models:
        base = (host or ollama_host()).rstrip("/")
        raise LLMUnavailable(
            f"Ollama is running at {base} but has no models. "
            f"Run 'ollama pull {model}' first."
        )
    if model not in models and model not in {name.split(":")[0] for name in models}:
        raise LLMUnavailable(
            f"Ollama model '{model}' is not installed. Available: "
            f"{', '.join(models)}. Run 'ollama pull {model}'."
        )


# --- LLM clients -----------------------------------------------------------

class LLMClient(Protocol):
    def complete(self, prompt: str) -> str: ...


@dataclass
class OllamaLLM:
    """Local inference via Ollama's generate API."""
    model: str = DEFAULT_OLLAMA_MODEL
    host: str = DEFAULT_OLLAMA_HOST
    timeout: int = 120

    def complete(self, prompt: str) -> str:
        url = f"{self.host}/api/generate"
        body = json.dumps({
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.2},
        }).encode("utf-8")
        req = urllib.request.Request(
            url, data=body, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data.get("response", "").strip()


@dataclass
class OpenAICompatLLM:
    """Any OpenAI-compatible chat completions endpoint."""
    model: str = "gpt-4o-mini"
    base_url: str = "https://api.openai.com/v1"
    api_key: str = ""
    timeout: int = 120

    def complete(self, prompt: str) -> str:
        url = f"{self.base_url.rstrip('/')}/chat/completions"
        body = json.dumps({
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
        }).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(url, data=body, headers=headers)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data["choices"][0]["message"]["content"].strip()


class StubLLM:
    """Deterministic offline client for tests and dry runs.

    When no canned response is supplied it answers from the facts in the
    prompt, so offline runs still produce claims the grounding audit can
    verify instead of a content-free sentence.
    """

    _CVE = re.compile(r"^- CVE: (\S+)$", re.MULTILINE)
    _PACKAGE = re.compile(r"^- Package: (\S+) version (\S+)$", re.MULTILINE)
    _SEVERITY = re.compile(r"^- Severity: (.+)$", re.MULTILINE)
    _FIXED = re.compile(r"^- Fixed in: (.+)$", re.MULTILINE)
    _EPSS = re.compile(
        r"^- EPSS exploit probability \(30d\): ([\d.]+)$", re.MULTILINE
    )
    _REACH = re.compile(r"^- Reachability: (.+)$", re.MULTILINE)
    _DUE = re.compile(r"^- CISA remediation due date: (\S+)$", re.MULTILINE)

    def __init__(self, response: Optional[str] = None):
        self.response = response
        self.last_prompt: Optional[str] = None

    def complete(self, prompt: str) -> str:
        self.last_prompt = prompt
        if self.response is not None:
            return self.response

        package = self._PACKAGE.search(prompt)
        cve = self._CVE.search(prompt)
        if not (package and cve):
            return (
                "This package version has a known vulnerability. Upgrade to the "
                "fixed version to remediate it."
            )

        name, version = package.groups()
        sentences = []
        severity = self._SEVERITY.search(prompt)
        detail = f" — severity {severity.group(1)}" if severity else ""
        sentences.append(f"{cve.group(1)} affects {name} {version}{detail}.")

        fixed = self._FIXED.search(prompt)
        if fixed and not fixed.group(1).startswith("no known"):
            sentences.append(f"Upgrade {name} to {fixed.group(1)} or later.")

        reach = self._REACH.search(prompt)
        if reach:
            if reach.group(1).startswith("the vulnerable package IS"):
                sentences.append("The package is imported and reachable in this codebase.")
            elif "does NOT" in reach.group(1):
                sentences.append("The package is not imported or used in this codebase.")

        epss = self._EPSS.search(prompt)
        if epss:
            pct = float(epss.group(1)) * 100
            sentences.append(
                f"EPSS estimates a {pct:.1f}% chance of exploitation in the next 30 days."
            )

        if "- CISA KEV: YES" in prompt:
            sentences.append("It is listed in CISA KEV as exploited in the wild.")
        if "- CISA ransomware: known campaign use" in prompt:
            sentences.append("CISA reports known ransomware campaign use.")
        due = self._DUE.search(prompt)
        if due:
            sentences.append(f"The CISA remediation deadline is {due.group(1)}.")
        return " ".join(sentences)


# --- Prompt construction ---------------------------------------------------

def build_prompt(f: Finding, context: Optional[CVEContext] = None) -> str:
    """Assemble a grounded prompt from the finding + retrieved CVE context."""
    lines = [
        "You are a security engineer explaining a dependency vulnerability to a developer.",
        "Use ONLY the facts below. If something is unknown, say so -- do not invent details.",
        "",
        "## Finding",
        f"- CVE: {f.cve_id}",
        f"- Package: {f.package} version {f.version}",
        f"- Severity: {f.severity or 'unknown'} (CVSS {f.cvss if f.cvss is not None else 'n/a'})",
        f"- Fixed in: {f.fixed_version or 'no known fixed version'}",
    ]
    if f.epss is not None:
        lines.append(f"- EPSS exploit probability (30d): {f.epss:.3f}")
    if f.kev_listed:
        lines.append("- CISA KEV: YES (confirmed exploited in the wild)")
    if f.known_ransomware:
        lines.append("- CISA ransomware: known campaign use")
    if f.kev_due_date:
        lines.append(f"- CISA remediation due date: {f.kev_due_date}")
    if f.reachable is not None:
        reach = "the vulnerable package IS imported/used in this codebase" if f.reachable \
            else "the vulnerable package does NOT appear to be used in this codebase"
        lines.append(f"- Reachability: {reach}")
    if f.exposure and f.exposure != "none":
        path = " -> ".join(f.exploit_path) if f.exploit_path else "no traced path"
        lines.append(f"- Exploit-path exposure: {f.exposure} ({path})")

    if context:
        lines += ["", "## Official CVE context (NVD)"]
        if context.description:
            lines.append(context.description)
        if context.cwe_ids:
            lines.append(f"- Weakness: {', '.join(context.cwe_ids)}")

    lines += [
        "",
        "## Task",
        "Respond with exactly three short sections:",
        "1. A plain-language explanation of the vulnerability (2-3 sentences).",
        "2. Why it matters in THIS codebase (account for reachability and KEV/EPSS).",
        "3. A concrete fix (prefer the exact version upgrade).",
        "Keep it under 150 words. No preamble.",
    ]
    return "\n".join(lines)


# --- Confidence heuristic --------------------------------------------------

def confidence_for(f: Finding) -> str:
    """Simple, explainable confidence indicator.

    High: a fixed version is clearly known AND we have strong risk signal.
    Low:  no fixed version available (fix advice is inherently uncertain).
    Medium: otherwise.
    """
    if not f.fixed_version:
        return "low"
    if f.kev_listed or (f.epss is not None and f.epss >= 0.5):
        return "high"
    return "medium"


def default_fix(f: Finding) -> Optional[str]:
    """Deterministic fix suggestion used as a fallback / appended to LLM output."""
    if f.fixed_version:
        return f"Upgrade {f.package} to {f.fixed_version} or later."
    return None


# --- Explainer -------------------------------------------------------------

class Explainer:
    def __init__(self, llm: Optional[LLMClient] = None, nvd_client=None):
        self.llm = llm or StubLLM()
        self.nvd_client = nvd_client  # optional; context may be pre-attached

    def _context_for(self, f: Finding) -> Optional[CVEContext]:
        # Prefer context already stashed on the finding.
        cached = f.extra.get("cve_context")
        if isinstance(cached, CVEContext):
            return cached
        if self.nvd_client is not None:
            return self.nvd_client.context(f.cve_id)
        return None

    def explain(self, f: Finding) -> Finding:
        context = self._context_for(f)
        if context is not None:
            # Persist the evidence so the grounding audit and JSON export can
            # see exactly what the LLM was given.
            f.extra["nvd_description"] = context.description
            if context.cwe_ids:
                f.extra["cwe_ids"] = list(context.cwe_ids)
            if context.cvss_v3 is not None:
                f.extra["nvd_cvss"] = context.cvss_v3
        prompt = build_prompt(f, context)
        failed = False
        try:
            text = self.llm.complete(prompt)
        except Exception as exc:  # network/inference failure -> deterministic fallback
            text = f"(explanation unavailable: {exc})"
            failed = True

        fix = default_fix(f)
        f.explanation = text
        f.suggested_fix = fix or "No fixed version is available; consider mitigations or removal."
        f.confidence = confidence_for(f)
        if failed or not text.strip():
            f.grounded = None
        else:
            result = audit_explanation(f)
            f.grounded = result.grounded
            f.extra["grounding"] = result.to_dict()
        return f

    def explain_all(
        self,
        findings: list[Finding],
        progress: Optional[Callable[[int, int], None]] = None,
    ) -> list[Finding]:
        total = len(findings)
        explained: list[Finding] = []
        for index, finding in enumerate(findings, 1):
            if progress is not None:
                progress(index, total)
            explained.append(self.explain(finding))
        return explained
