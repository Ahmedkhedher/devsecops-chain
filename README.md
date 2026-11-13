# devsecops-chain

A vulnerability pipeline that doesn't just list CVEs — it decides what to fix
first, proves why, and enforces the decision in CI.

Trivy finds **what is present**. This chain answers the harder questions:
*is it actually exploitable here, who exploits it in the wild, is the vulnerable
code reachable from a real entrypoint, can we ship a machine-readable VEX
statement for it, and should this pull request be blocked?* Every answer is
traceable to evidence, and every run is diffed against the last one.

```
[Codebase / PR]
      │
      ▼
[Trivy] ──────────────► raw findings (CVE, package, version, CVSS)
      │
      ▼
[Prioritization] ─────► EPSS + CISA KEV + ransomware flag + CISA due date
      │
      ▼
[Reachability] ───────► distribution name → import name → symbol usage
      │
      ▼
[Exploit paths] ──────► call graph from network/CLI/local entrypoints
      │
      ▼
[Explanation] ────────► NVD-grounded LLM output → claim-level audit
      │
      ▼
[Decision layer] ─────► OpenVEX + policy gate + SQLite scan delta
      │
      ▼
[Delivery] ───────────► CLI · PR comment · GUI · offline HTML lab · CI artifacts
```

Every stage consumes and produces the same core shape — a `Finding` object
(`common/finding.py`) — so stages stay decoupled and independently testable.

## Status

- [x] **Phase 1 — Detection** (Trivy wrapper → `Finding` objects)
- [x] **Phase 2 — Risk prioritization** (EPSS + KEV + ransomware + CISA deadlines)
- [x] **Phase 3 — Grounded explanations** (NVD context + injectable LLM + claim audit)
- [x] **Phase 4 — CI/CD** (GitHub Actions → idempotent PR comment)
- [x] **Phase 5 — Reachability** (AST imports, symbol usage, exploit-path exposure)
- [x] **Phase 6 — Evaluation** (recall / precision / FP reduction / hallucination rate)
- [x] **Decision layer** (OpenVEX 0.2.0, policy-as-code with expiring waivers)
- [x] **History** (SQLite deltas: new / fixed / reopened / persisting / escalated)
- [x] **Remediation autopilot** (grouped upgrade plan, risk cleared, manifest patch)
- [x] **Environment readiness** (Trivy/Ollama/OpenAI/policy preflight in every UI)
- [x] **Interfaces** (tkinter desktop app, local web console, self-contained offline HTML lab)

## What's in the box

| Capability | Why it matters |
|---|---|
| Exploitability-aware ranking | CVSS measures worst-case impact; EPSS measures whether anyone actually exploits it. A KEV-listed medium outranks a non-exploited critical. |
| Ransomware + CISA deadlines | `knownRansomwareCampaignUse` adds weight; `dueDate` turns a score into a compliance deadline. Overdue findings can fail the gate. |
| Exploit-path exposure | Not just "is it imported" but *how an attacker reaches it*: `app.py:load_config → yaml.safe_load()`, from a Flask route, CLI, or `__main__`. |
| OpenVEX 0.2.0 output | Machine-readable `affected` / `not_affected` / `under_investigation` statements other tools can consume, with deterministic document IDs. |
| Policy-as-code | Declarative fail/warn rules over severity, exposure, KEV, ransomware, fixes, and deadlines. No permanent exceptions: every waiver needs an owner, reason, and expiry. |
| LLM claim auditing | The explanation is checked claim-by-claim against NVD/KEV/EPSS evidence. Conflicts and unsupported claims mark the finding ungrounded; eval reports hallucination rate. |
| Scan history + delta | SQLite fingerprints produce new/fixed/reopened/persisting counts and priority escalation between runs — the "did we actually improve?" signal. |
| Offline decision lab | A single self-contained HTML file with a remediation simulator, evidence inspector, and exposure inventory. No CDN, no server, no network. |
| Local web console | The whole pipeline behind a browser UI on `127.0.0.1` — progress streaming, filters, exploit-path drawer, policy verdict, exports. Stdlib only, token-guarded, browser-tested. |
| Remediation autopilot | Findings are grouped per manifest and package into the fewest version bumps that clear the most priority mass, with `pip`/`npm` commands, a reviewable unified diff, and an explicit "needs a human" list for transitive or unfixed CVEs. |
| Environment readiness | Before a scan fails, the UI says why: Trivy version and vulnerability-DB age, whether Ollama is up and which models it has, OpenAI configuration (never the key), policy validity and expired waivers. |
| Hardened Trivy wrapper | GHCR DB mirror by default (the `mirror.gcr.io` endpoint is often slow/blocked), 30-minute download timeout, and a long subprocess deadline. |

## Layout

```
devsecops-chain/
├── common/finding.py             # shared Finding dataclass (core data shape)
├── scanner/run_trivy.py          # P1: Trivy wrapper + JSON parser + mirror hardening
├── prioritization/
│   ├── epss_client.py            # P2: EPSS exploit probability (cached)
│   ├── kev_client.py             # P2: KEV membership, ransomware flag, due dates
│   ├── scorer.py                 # P2: CVSS + EPSS + KEV + ransomware → priority
│   └── enrich.py                 # P2: orchestrates enrichment + re-ranking
├── reachability/
│   ├── ast_checker.py            # P5: import / symbol reachability
│   └── exposure.py               # P5+: call graph → entrypoints → exploit paths
├── explanation/
│   ├── cve_context.py            # P3: NVD retrieval (cached)
│   ├── explainer.py              # P3: LLM explanation + fix + confidence
│   └── grounding.py              # P3+: claim-level hallucination audit
├── output/vex.py                 # OpenVEX 0.2.0 document builder
├── policy/gate.py                # policy-as-code gate + expiring waivers
├── remediation/planner.py        # upgrade grouping + risk math + manifest patch
├── diagnostics/doctor.py         # environment readiness preflight report
├── history/store.py              # SQLite run history + delta reports
├── reporting/dashboard.py        # self-contained offline HTML decision lab
├── ci/post_pr_comment.py         # P4: idempotent GitHub PR commenter
├── gui/app.py                    # tkinter desktop front-end
├── web/server.py                 # localhost HTTP server + scan API (stdlib)
├── web/static/                   # index.html, style.css, app.js (no framework)
├── launch.pyw                    # double-click desktop launcher (no console)
├── launch_web.pyw                # one-click web console launcher
├── Launch DevSecOps Chain.bat    # fallback launcher if .pyw is unassociated
├── Launch DevSecOps Web.bat      # fallback web launcher
├── scripts/make_shortcut.ps1     # optional Desktop shortcut
├── eval/benchmark.py             # P6: labeled evaluation harness
├── pipeline.py                   # orchestrator + CLI
├── .security/policy.json         # sample production merge gate
├── .github/workflows/security-scan.yml
├── testproject/                  # deliberately vulnerable seed project
└── tests/                        # 301 offline unit tests + Trivy fixture
```

## Requirements

- Python 3.10+ (developed on 3.15). **Everything runs on the standard library** —
  HTTP via `urllib`, source analysis via `ast`, storage via `sqlite3`.
- [Trivy](https://trivy.dev) for live scans. Optional: every stage can be
  exercised offline against `tests/fixtures/trivy_report.json`.
- An LLM for live explanations — [Ollama](https://ollama.com) locally (start
  the app and `ollama pull llama3.2`), or any OpenAI-compatible endpoint via
  `OPENAI_API_KEY` / `OPENAI_BASE_URL`. Optional: a deterministic `StubLLM`
  keeps the pipeline fully functional offline.

On Windows, Python is invoked via the `py` launcher; on Linux/CI use `python3`.

## Quickstart (offline: no Trivy, LLM, or network)

```bash
# Full pipeline over the shipped fixture + seed project
py -m pipeline --from-json tests/fixtures/trivy_report.json \
    --code-root testproject --offline --top 5

# Produce every artifact: VEX, gate report, delta, remediation plan, HTML lab
py -m pipeline --from-json tests/fixtures/trivy_report.json \
    --code-root testproject --offline \
    --vex-out data/vex.json \
    --policy .security/policy.json \
    --policy-out data/policy_gate.json \
    --policy-markdown-out data/policy_gate.md \
    --no-policy-fail \
    --history data/history.db \
    --delta-markdown-out data/delta.md \
    --remediation-out data/remediation_plan.md \
    --patch-out data/remediation.patch \
    --html-out data/decision_lab.html

# Local web console (browser UI, same pipeline)
py -m web.server

# 301-test suite (all offline, deterministic)
py -m unittest discover -s tests

# Evaluation harness — the "proof it works" numbers
py -m eval.benchmark --top 2
```

## Live usage

```bash
# Scan a real target with Trivy, enrich from EPSS/KEV/NVD, explain via Ollama
py -m pipeline myproject --code-root myproject --llm ollama \
    --ollama-model llama3.2 --top 15 \
    --json-out data/findings.json --markdown-out data/pr_comment.md \
    --remediation-out data/remediation_plan.md --patch-out data/remediation.patch

# Apply the plan after reviewing it
git apply data/remediation.patch

# Hosted LLM instead of local
set OPENAI_API_KEY=...   # Windows
py -m pipeline myproject --code-root myproject --llm openai
```

### Trivy database downloads

The wrapper sets `TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db:2` unless the
environment already defines it, and passes `--timeout 30m`. This avoids the
default `mirror.gcr.io` endpoint, which is frequently rate-limited or blocked.
Override the env var to use another mirror; the subprocess deadline is 1900s.

## CLI surface

| Flag | Effect |
|---|---|
| `--offline` | No network: CVSS-only ranking, no EPSS/KEV/NVD. An explicitly chosen `--llm` still runs. |
| `--top N` | Trim printed/exported findings. Analysis, policy, and history still see the full set. |
| `--json-out` / `--markdown-out` | Findings JSON / PR-comment markdown. |
| `--vex-out` | OpenVEX 0.2.0 document. |
| `--remediation-out` | Upgrade plan as markdown: bumps, CVEs and risk cleared, commands, "needs a human" list. |
| `--patch-out` | Unified diff of the manifest bumps — review it, then `git apply`. |
| `--policy FILE` | Evaluate a JSON policy; exit 1 when the gate fails. |
| `--policy-out` / `--policy-markdown-out` | Gate evidence as JSON / PR-ready markdown. |
| `--no-policy-fail` | Publish the gate result but always exit 0 (CI enforces later). |
| `--history [DB]` | Record this run in SQLite and print the delta (default `data/history.db`). |
| `--delta-markdown-out` | Delta as PR-comment markdown. |
| `--html-out` | Self-contained offline decision lab. |
| `--no-exposure` | Skip call-graph exploit-path tracing. |
| `--no-reachability` / `--no-prioritize` / `--no-explain` | Disable individual stages. |

## How the stages work

**Prioritization (P2).**

```
priority = CVSS·0.4 + EPSS·100·0.4 + 20 (KEV) + 10 (ransomware)
```

Weights live in `ScorerConfig`. Unused dependencies receive a `0.5×` penalty
after reachability, so dead-dependency noise sinks without being zeroed (SCA
cannot see dynamic imports). Ties break on CVSS, then CVE ID, for deterministic
output.

**Reachability (P5).** Trivy reports *distribution* names (`pyyaml`); code
imports *module* names (`yaml`). The AST checker resolves aliases, detects
imports, and can verify that a specific vulnerable symbol is actually called.

**Exploit-path exposure (P5+).** `reachability/exposure.py` builds a call graph
across modules and resolves entrypoints: web route decorators
(Flask/FastAPI/Django/DRF), CLI frameworks (`argparse`, `click`, `typer`), and
`if __name__ == "__main__"` blocks. Each finding gets an exposure level and a
shortest path:

```
none < unlinked < local < cli < network
```

```
Exposure:     local
Entrypoint:   app.py:load_config
Exploit path: app.py:load_config -> yaml.safe_load()
```

This is what powers VEX justifications and the `exposure` conditions in policy.

**Grounded explanation (P3).** The prompt is grounded on retrieved NVD context
plus the finding's EPSS/KEV/reachability signals. After generation,
`explanation/grounding.py` extracts concrete claims — CVE IDs, CVSS/EPSS values,
fix versions, exploitation/ransomware assertions, vulnerability classes,
reachability statements — and checks each against the evidence. Conflicts and
unsupported claims set `grounded=False`; unverifiable claims lower the score but
do not fail. The eval harness reports the aggregate hallucination rate.

**OpenVEX.** Exposure maps to standards-compliant statements:

| Evidence | VEX status | Justification |
|---|---|---|
| package absent from code | `not_affected` | `vulnerable_code_not_present` |
| present but unreachable | `not_affected` | `vulnerable_code_not_in_execute_path` |
| local / cli / network path | `affected` | action statement with fix |
| no reachability evidence | `under_investigation` | — |

Statements are deduplicated by `(CVE, purl)` and the document ID is a
deterministic UUIDv5 derived from content, so identical scans produce identical
documents.

**Policy-as-code.** `.security/policy.json` defines defaults and rules
(abridged below):

```json
{
  "version": 1,
  "name": "production-merge-gate",
  "defaults": {
    "fail_on_severity": "CRITICAL",
    "fail_on_ransomware": true,
    "fail_on_overdue": true
  },
  "rules": [
    {
      "id": "no-kev-in-reachable-code",
      "when": { "kev_listed": true, "exposure": ["local", "cli", "network"] },
      "action": "fail",
      "waivable": false
    }
  ],
  "waivers": [
    {
      "id": "W-2026-001",
      "cve": "CVE-2018-20225",
      "package": "pip",
      "reason": "Build-time tool, not shipped at runtime.",
      "owner": "appsec@example.com",
      "ticket": "SEC-1421",
      "expires": "2027-06-30"
    }
  ]
}
```

Rules support compound conditions over severity, exposure, KEV, ransomware,
reachability, fix availability, CISA overdue status, priority/CVSS/EPSS
thresholds, CVE, and package. Every waiver requires an id, owner, reason, and
expiry. Expired waivers never suppress a violation and are always reported;
unused unexpired waivers are reported as stale; `waivable: false` rules ignore
waivers entirely.

**History and deltas.** `history/store.py` persists each run to SQLite, keyed by
a `(CVE, package, version, target)` fingerprint. The delta classifies findings
as **new**, **fixed**, **reopened** (absent last run, present in an older one),
or **persisting**, and flags persisting findings whose priority escalated.
`prune()` keeps the database bounded. CI caches the DB between runs.

**Remediation autopilot.** A list of 40 CVEs is not a work plan.
`remediation/planner.py` reads the scanned folder's editable manifests
(`requirements*.txt`, `package.json` — `node_modules`, virtualenvs and build
dirs are skipped), groups every finding by manifest and package, and picks the
single highest published fix that covers the group. Each step reports the CVEs
it clears, the priority mass it removes, and the exact `pip` / `npm` command;
the bumps are also emitted as one unified diff you can review and `git apply`.
Findings with no upstream fix, or that arrive only transitively or through a
lockfile, are never silently dropped — they land in a "needs a human" list with
the reason. Version ordering is a stdlib numeric-key comparison, so the whole
stage is deterministic and offline.

**Environment readiness.** `diagnostics/doctor.py` answers "why would this
scan fail?" before it does: Trivy's version and vulnerability-DB age, whether
Ollama answers and which models it has, whether an OpenAI-compatible endpoint is
configured (the API key is never included in the report), and whether the policy
file parses and still has live waivers. The web console, the desktop app, and
`POST /api/scan` all use the same checks, so a stopped Ollama becomes one clear
400 instead of five "explanation unavailable" rows.

**Evaluation (P6).** Labeled cases report detection recall, precision,
false-positive reduction (noise correctly pushed below the top-N cutoff), rank
quality (must-rank CVEs actually in the top N), and explanation hallucination
rate. On the seed project at a top-2 cutoff:

```
recall=1.00  precision=1.00  fp_reduction=1.00  top_rank_ok=True
true_positives=5  noise_demoted=3/3
hallucination_rate=0.00 (0/5 audited)
```

All three unused-dependency CVEs are demoted while both reachable findings stay
on top.

## Desktop interface (GUI)

A native tkinter front door to the same pipeline — pick a folder, click Scan,
read the results in a table. Ships with Python, no extra installs.

**Rapid launch (Windows).** Double-click `launch.pyw` — it runs under
`pythonw`, so the window opens immediately with no terminal left behind. If
`.pyw` files aren't associated with Python on your machine, run
`Launch DevSecOps Chain.bat` instead. For a permanent icon on the Desktop:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\make_shortcut.ps1
```

From a terminal, `py gui/app.py` still works.

- **Browse…** opens your OS folder picker; point it at any project.
- **Scan** runs Trivy → prioritization → reachability → exposure → explanation
  in a background thread (the window stays responsive). A progress bar animates,
  a live elapsed timer ticks, and the status line names the current stage, then
  reports the total time when the table fills.
- Rows are color-coded by severity and show KEV, ransomware, reachability, and
  exposure. Click a row to see the explanation, fix, CISA deadline, exploit
  path, and grounding verdict in the right pane.
- The right pane has two tabs: **Selected finding** detail and the
  **Remediation plan** — the upgrade steps with copy-ready commands, the
  "needs a human" list, and the manifest patch.
- Toggles: **Reachability** (also controls exposure tracing), **Live network
  enrichment** (EPSS + KEV + NVD), the **Explanations** backend
  (stub / ollama / openai), and a **Top N** limit.
- **Readiness** checks Trivy, Ollama, OpenAI configuration, and the policy file
  in the background and reports each as ok / warn / missing with a fix hint.
  Choosing `ollama` and starting a scan also preflights it, so a stopped Ollama
  tells you to run `ollama serve` or `ollama pull` instead of filling the table
  with empty explanations.
- **Export JSON / Markdown / Plan + Patch** save the results (and the upgrade
  plan with its `.patch` alongside) to disk.

## Web interface (browser)

The same pipeline as a self-contained local web console — no FastAPI, no
React, no build step, no CDN. A Python stdlib server serves one page and a
small JSON API.

**Rapid launch (Windows).** Double-click `launch_web.pyw`; the server starts on
`127.0.0.1` and your default browser opens. If `.pyw` files are unassociated,
run `Launch DevSecOps Web.bat`. For a permanent Desktop icon:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\make_shortcut.ps1 -Web
```

From a terminal:

```bash
py -m web.server                  # opens http://127.0.0.1:8765
py -m web.server --port 9000     # pick a starting port (walks forward if busy)
py -m web.server --no-browser    # headless
```

- **Layout.** A two-pane working console on wide screens: a sticky control rail
  (scan form + environment readiness) beside the work surface (progress, stats,
  policy gate, delta, remediation, findings). Below 1240px it collapses to one
  column, and the detail drawer becomes a bottom sheet on narrow screens.
  Severity is encoded three ways at once (colour, shape, text), the findings
  table keeps a sticky rank column and scrolls inside its own container instead
  of stretching the page, `/` jumps to the filter, and the pipeline ribbon
  explains the five stages until the first scan renders. Pure CSS — no fonts,
  icons, or scripts from a CDN.
- **Demo fixture** runs instantly, fully offline, against the shipped Trivy
  report and `testproject/` so the whole evidence chain can be explored before
  Trivy is installed. It skips Trivy and enrichment, but an LLM you select
  explicitly still runs.
- Ollama is preflighted before a scan starts: a stopped server or missing model
  returns an actionable message instead of one failed explanation per finding.
  **Environment** in the top bar (which also runs when the page loads) shows the
  full readiness report — Trivy version and vulnerability-DB age, Ollama models,
  OpenAI configuration, policy validity, expired waivers — and picking Ollama
  turns the model dropdown into whatever is actually installed locally.
- **Live folder** takes any path, either typed or chosen with the built-in
  folder picker (server-side directory browsing, no upload). Toggle
  reachability/exposure, offline enrichment, the policy gate, and the LLM
  backend (stub / Ollama / OpenAI-compatible). Your folder and toggles are
  remembered in `localStorage`, so reopening the console starts where you left
  off.
- Scans run in a background thread; the page polls `/api/state` and streams the
  current stage — including `Explaining 7 of 41` — an elapsed timer, and the
  last eight log lines. Refreshing the page reattaches to a running or finished
  scan.
- Results are filterable by text and severity. Click any row for the full
  exploit path, entrypoint, EPSS/KEV/ransomware/CISA-due signals, grounded
  explanation, claim audit, and suggested fix. The policy verdict (violations,
  warnings, active and expired waivers) renders above the table.
- Each scan is recorded in `data/web_history.db` and diffed against the
  previous run of the same target and mode, so the page shows new, fixed,
  reopened, and persisting findings — no cross-project noise.
- **Remediation autopilot** renders under the gate: how many CVEs each bump
  clears, the priority mass it removes, one-click copy of the `pip` / `npm`
  command, the findings that need a human, and the manifest patch inline for
  review.
- Exports: findings JSON, PR markdown, remediation plan markdown, manifest
  patch, OpenVEX, and the policy gate report.
- **Stop server** shuts it down; otherwise the process exits after 30 idle
  minutes. A second launcher opens the existing instance instead of starting
  another.

**Security posture.** It is a localhost tool, and the server treats it that way:
binds to loopback only, rejects foreign `Host` headers (DNS rebinding),
requires a per-process bearer token embedded in the page for every `/api/*`
call, sends a strict CSP (`script-src 'self'`, no inline script/style) and
`no-store`, serves only a fixed static allowlist, and caps request bodies at
1 MB. It never uploads source code; only LLM prompts go to the backend you
select.

The JSON API is small enough to script against:

| Endpoint | Purpose |
|---|---|
| `GET /api/state` | Current job: status, stage log, findings (top 500), gate, delta, remediation plan. |
| `POST /api/scan` | `{demo}` or `{path, offline, reachability, policy, llm, ollama_model}`. |
| `GET /api/doctor` | Environment readiness report (Trivy, Ollama, OpenAI, policy). |
| `GET /api/browse?path=` | Directory listing for the folder picker. |
| `GET /api/export?format=json\|markdown\|vex\|policy\|remediation\|patch` | Download an artifact. |
| `POST /api/shutdown` | Stop the server. |

## Offline decision lab

`--html-out` writes one portable HTML file (no scripts from CDNs, no server) that
opens directly from disk:

- **Remediation simulator** — select fixes and see the remaining risk and count.
- **Evidence inspector** — every finding's signals, fixes, and explanations.
- **Exposure inventory** — filter by known-exploited, import observed,
  reachability unknown, or no supplied fix.
- **Export plan** — download the selected remediation plan as JSON.

## CI/CD

`.github/workflows/security-scan.yml` runs three jobs:

1. **Unit tests** — the full suite gates everything else.
2. **Self-scan + policy gate** — installs Trivy (GHCR DB mirror, cached DB),
   scans the repository while excluding the intentionally vulnerable
   `testproject/` and `tests/`, then runs the pipeline with VEX, policy,
   remediation plan/patch, HTML, and history outputs. The gate is enforced in a
   **final** step, after artifacts have been uploaded and the PR comment
   updated, so a failing policy still leaves reviewers with evidence. PR
   comments are skipped for fork PRs (no write token).
3. **Demo (push/dispatch only)** — runs the full chain offline against the
   vulnerable fixture, uploads VEX/policy/delta/remediation/lab artifacts, and
   publishes a step summary with the upgrade plan. Its gate is expected to
   fail; it never blocks the build.

Scan and demo history databases are cached between runs, so PR comments include
a real delta rather than a permanent baseline. Set `OPENAI_API_KEY` as a repo
secret for live LLM explanations; without it the job uses the offline stub.

## Tests

```bash
py -m unittest discover -s tests -v
```

301 tests cover every stage, all runnable offline: network clients are injected
as fakes, the LLM defaults to a deterministic stub, and the scanner has a
fixture path. Coverage includes scanner command construction and DB-mirror
resolution, exposure graph resolution, VEX status mapping, policy/waiver edge
cases, grounding conflict detection, history diff semantics, evaluation
metrics, GUI window-independent logic, the web server's auth/Host/CSP guards,
folder API, demo scan, exports, readiness preflight (with Trivy and Ollama
subprocess/HTTP edges patched), and the remediation planner's manifest
discovery, version ordering, patch output, and "needs a human" routing.
