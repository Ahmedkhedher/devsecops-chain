"""Desktop interface for devsecops-chain (tkinter).

Pick a project folder, click Scan, see the risk-ranked vulnerabilities in a
table with explanations. Reuses the exact same pipeline modules the CLI/CI use
(scanner -> prioritization -> reachability -> explanation) -- the GUI is just a
front door, so results are identical.

Run from the devsecops-chain directory:
    py gui/app.py
"""

from __future__ import annotations

import json
import queue
import sys
import threading
import time
from pathlib import Path
from tkinter import (
    Tk, ttk, Text, StringVar, BooleanVar, IntVar, Toplevel, filedialog, messagebox,
)

# Make the project root importable (this file lives in devsecops-chain/gui/).
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scanner.run_trivy import TrivyError
from explanation.explainer import check_ollama, LLMUnavailable
from diagnostics.doctor import environment_report
from pipeline import PipelineOptions, scan_and_run, _render_markdown
from remediation.planner import build_plan, render_markdown


COLUMNS = [
    ("priority", "Priority", 70),
    ("severity", "Severity", 90),
    ("cve", "CVE", 150),
    ("package", "Package", 130),
    ("version", "Version", 90),
    ("reachable", "Used?", 70),
    ("exposure", "Exposure", 85),
    ("kev", "KEV", 55),
    ("epss", "EPSS", 65),
    ("fix", "Fix", 120),
]


class ScanApp:
    def __init__(self, root: Tk):
        self.root = root
        self.findings: list = []
        self.plan = None
        self.queue: "queue.Queue" = queue.Queue()
        self.worker: threading.Thread | None = None
        self._scan_started = 0.0
        self._scanning = False

        root.title("devsecops-chain — Security Scanner")
        root.geometry("1140x680")

        self.folder_var = StringVar()
        self.reach_var = BooleanVar(value=True)
        self.enrich_var = BooleanVar(value=False)   # network EPSS/KEV/NVD
        self.llm_var = StringVar(value="stub")
        self.top_var = IntVar(value=0)              # 0 = all
        self.status_var = StringVar(value="Ready.")

        self._build()
        self._poll()

    # --- UI construction ---
    def _build(self):
        pad = {"padx": 8, "pady": 6}

        top = ttk.Frame(self.root)
        top.pack(fill="x", **pad)

        ttk.Label(top, text="Project folder:").pack(side="left")
        self.entry = ttk.Entry(top, textvariable=self.folder_var, width=64)
        self.entry.pack(side="left", padx=6, fill="x", expand=True)
        ttk.Button(top, text="Browse…", command=self.browse).pack(side="left")

        opts = ttk.Frame(self.root)
        opts.pack(fill="x", **pad)
        ttk.Checkbutton(opts, text="Reachability (check .py usage)",
                        variable=self.reach_var).pack(side="left")
        ttk.Checkbutton(opts, text="Live network enrichment (EPSS + KEV + NVD)",
                        variable=self.enrich_var).pack(side="left", padx=12)
        ttk.Label(opts, text="Explanations:").pack(side="left")
        ttk.Combobox(opts, textvariable=self.llm_var, width=8, state="readonly",
                     values=["stub", "ollama", "openai"]).pack(side="left", padx=4)
        ttk.Label(opts, text="Top N (0=all):").pack(side="left", padx=(12, 0))
        ttk.Spinbox(opts, from_=0, to=500, textvariable=self.top_var, width=5).pack(side="left")

        bar = ttk.Frame(self.root)
        bar.pack(fill="x", **pad)
        self.scan_btn = ttk.Button(bar, text="Scan", command=self.scan)
        self.scan_btn.pack(side="left")
        ttk.Button(bar, text="Readiness", command=self.readiness).pack(side="left", padx=6)
        ttk.Button(bar, text="Export JSON", command=lambda: self.export("json")).pack(side="left")
        ttk.Button(bar, text="Export Markdown", command=lambda: self.export("md")).pack(side="left", padx=6)
        ttk.Button(bar, text="Export Plan + Patch",
                   command=lambda: self.export("plan")).pack(side="left")
        ttk.Label(bar, textvariable=self.status_var).pack(side="left", padx=16)

        # Progress row: animated indeterminate bar + live elapsed timer.
        # Hidden until a scan starts.
        self._elapsed_var = StringVar(value="0:00")
        prog = ttk.Frame(self.root)
        self.prog_frame = prog
        self.progress = ttk.Progressbar(prog, mode="indeterminate", length=240)
        self.progress.pack(side="left")
        ttk.Label(prog, textvariable=self._elapsed_var, width=6,
                  anchor="e").pack(side="left", padx=8)
        ttk.Label(prog, text="elapsed").pack(side="left")
        prog.pack_forget()   # reveal only while scanning

        body = ttk.Panedwindow(self.root, orient="horizontal")
        body.pack(fill="both", expand=True, **pad)

        # Results table
        table_wrap = ttk.Frame(body)
        cols = [c[0] for c in COLUMNS]
        self.tree = ttk.Treeview(table_wrap, columns=cols, show="headings", selectmode="browse")
        for key, label, width in COLUMNS:
            self.tree.heading(key, text=label)
            anchor = "w" if key in ("cve", "package", "fix") else "center"
            self.tree.column(key, width=width, anchor=anchor, stretch=False)
        for sev, color in [("CRITICAL", "#ffd0d0"), ("HIGH", "#ffe0c0"),
                           ("MEDIUM", "#fff3c0"), ("LOW", "#e8f0e8")]:
            self.tree.tag_configure(sev, background=color)
        vsb = ttk.Scrollbar(table_wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        body.add(table_wrap, weight=3)

        # Detail tabs: the selected finding, and the remediation autopilot plan.
        tabs = ttk.Notebook(body)
        finding_tab = ttk.Frame(tabs)
        self.detail = self._read_only_text(finding_tab)
        self.detail.pack(fill="both", expand=True, padx=4, pady=4)
        tabs.add(finding_tab, text="Selected finding")

        plan_tab = ttk.Frame(tabs)
        self.plan_view = self._read_only_text(plan_tab)
        self.plan_view.pack(fill="both", expand=True, padx=4, pady=4)
        tabs.add(plan_tab, text="Remediation plan")

        self.tabs = tabs
        body.add(tabs, weight=2)

    def _read_only_text(self, parent):
        return Text(parent, wrap="word", height=10, width=40,
                    font=("Segoe UI", 10), background="#fbfbfb")

    # --- actions ---
    def browse(self):
        chosen = filedialog.askdirectory(title="Select the project folder to scan")
        if chosen:
            self.folder_var.set(Path(chosen))

    def readiness(self):
        """Check Trivy/Ollama/policy up front, off the UI thread."""
        self._status("Checking environment…")

        def work():
            try:
                report = environment_report()
            except Exception as exc:  # never leave the dialog unreported
                report = {"error": f"{type(exc).__name__}: {exc}"}
            self.queue.put(("readiness", report))

        threading.Thread(target=work, daemon=True).start()

    def scan(self):
        folder = self.folder_var.get().strip()
        if not folder:
            messagebox.showwarning("Pick a folder", "Browse to a project folder first.")
            return
        if not Path(folder).is_dir():
            messagebox.showerror("Folder not found", f"Not a directory:\n{folder}")
            return
        if self.llm_var.get() == "ollama":
            try:
                check_ollama()
            except LLMUnavailable as exc:
                messagebox.showerror("Ollama unavailable", str(exc))
                return

        self.findings = []
        for row in self.tree.get_children():
            self.tree.delete(row)
        self._set_detail("")
        self.scan_btn.configure(state="disabled")
        self._start_progress()

        opts = self._build_options(Path(folder))
        target = str(folder)
        self._status("Scanning… (Trivy + enrichment, this can take a minute)")
        self.worker = threading.Thread(
            target=self._worker, args=(target, opts), daemon=True
        )
        self.worker.start()

    def _start_progress(self):
        self._scanning = True
        self._scan_started = time.time()
        self._elapsed_var.set("0:00")
        self.prog_frame.pack(fill="x", padx=8, pady=(0, 4))
        self.progress.start(18)
        self._tick()

    def _stop_progress(self):
        self._scanning = False
        self.progress.stop()
        self.prog_frame.pack_forget()

    def _tick(self):
        if not self._scanning:
            return
        self._elapsed_var.set(fmt_elapsed(time.time() - self._scan_started))
        self.root.after(200, self._tick)

    def _build_options(self, folder: Path) -> PipelineOptions:
        return make_options(
            folder=folder,
            online=self.enrich_var.get(),
            reach=self.reach_var.get(),
            llm=self.llm_var.get(),
            top=self.top_var.get(),
        )

    def _worker(self, target: str, opts: PipelineOptions):
        def report(msg: str):
            # Runs on the worker thread -- hand stage text to the UI thread.
            self.queue.put(("stage", msg))

        try:
            results = scan_and_run(target, opts, from_json=None, progress=report)
            report("Planning remediation")
            plan, plan_note = None, None
            root = opts.code_root or Path(target)
            if root.is_dir():
                try:
                    plan = build_plan(results, root)
                except Exception as exc:  # the plan is a bonus, never fatal
                    plan_note = f"Remediation planning failed: {exc}"
            else:
                plan_note = "No project folder to plan manifests against."
            self.queue.put(("ok", (results, plan, plan_note)))
        except TrivyError as exc:
            self.queue.put(("error", f"Trivy error: {exc}"))
        except Exception as exc:  # noqa: BLE001 - surface anything to the UI
            self.queue.put(("error", f"{type(exc).__name__}: {exc}"))

    # --- main-thread UI updates via queue polling ---
    def _poll(self):
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "stage":
                    self._status(payload + "…")
                elif kind == "ok":
                    self._populate(payload)
                elif kind == "readiness":
                    self._status("Environment checked.")
                    self._show_readiness(payload)
                else:
                    self._stop_progress()
                    self._status("Error.")
                    messagebox.showerror("Scan failed", payload)
                    self.scan_btn.configure(state="normal")
        except queue.Empty:
            pass
        self.root.after(120, self._poll)

    def _populate(self, payload):
        results, plan, plan_note = payload
        self._stop_progress()
        elapsed = fmt_elapsed(time.time() - self._scan_started)
        self.findings = results
        self.plan = plan
        for i, f in enumerate(results):
            self.tree.insert(
                "", "end", iid=str(i),
                values=(
                    _num(f.priority_score),
                    f.severity or "?",
                    f.cve_id,
                    f.package,
                    f.version,
                    _yes_no(f.reachable),
                    f.exposure or "—",
                    "YES" if f.kev_listed else "—",
                    _num(f.epss),
                    f.fixed_version or "—",
                ),
                tags=(f.severity or "",),
            )
        self.scan_btn.configure(state="normal")
        self._set_plan(render_plan_text(plan) if plan else (plan_note or "No plan."))
        if results:
            self._status(
                f"{len(results)} finding(s) in {elapsed}"
                + (f", {len(plan.steps)} upgrade(s) ready." if plan and plan.steps else ".")
                + " Click a row for detail."
            )
            self.tree.selection_set("0")
        else:
            self._status(f"No vulnerabilities found (took {elapsed}).")

    def _on_select(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        f = self.findings[int(sel[0])]
        self._set_detail(render_detail(f))

    def export(self, fmt: str):
        if not self.findings:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        if fmt == "plan" and self.plan is None:
            messagebox.showinfo("No plan", "Nothing was plannable in this scan's manifests.")
            return
        defaults = {"json": ("findings.json", ".json"),
                    "md": ("pr_comment.md", ".md"),
                    "plan": ("remediation-plan.md", ".md")}[fmt]
        path = filedialog.asksaveasfilename(
            title="Save export", defaultextension=defaults[1],
            initialfile=defaults[0],
        )
        if not path:
            return
        if fmt == "json":
            data = [f.to_dict() for f in self.findings]
            Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
        elif fmt == "md":
            Path(path).write_text(_render_markdown(self.findings), encoding="utf-8")
        else:
            Path(path).write_text(render_markdown(self.plan), encoding="utf-8")
            if self.plan.patch:
                Path(path).with_suffix(".patch").write_text(
                    self.plan.patch, encoding="utf-8"
                )
        self._status(f"Exported to {path}")

    def _show_readiness(self, report: dict):
        window = Toplevel(self.root)
        window.title("Environment readiness")
        window.geometry("640x520")
        view = self._read_only_text(window)
        view.pack(fill="both", expand=True, padx=6, pady=6)
        view.insert("1.0", render_readiness_text(report))
        view.configure(state="disabled")
        ttk.Button(window, text="Close", command=window.destroy).pack(
            anchor="e", padx=8, pady=(0, 8)
        )

    def _status(self, msg: str):
        self.status_var.set(msg)
        self.root.update_idletasks()

    def _set_detail(self, text: str):
        self._write(self.detail, text)

    def _set_plan(self, text: str):
        self._write(self.plan_view, text)

    @staticmethod
    def _write(widget, text: str):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")


def _num(x) -> str:
    if x is None:
        return "—"
    return f"{x:.2f}" if isinstance(x, float) else str(x)


def make_options(folder: Path, online: bool, reach: bool,
                 llm: str, top: int) -> PipelineOptions:
    """Translate the GUI toggles into pipeline options.

    Kept as a pure function (no tkinter) so the mapping is unit-testable:
      - offline when live enrichment is off -> CVSS-only ranking, no NVD
      - the chosen LLM is independent of network enrichment
      - code_root only set when reachability is on
      - top of 0/None means "show all"
    """
    return PipelineOptions(
        offline=not online,
        do_prioritize=True,
        do_reachability=reach,
        do_exposure=reach,
        do_explain=True,
        llm=llm,
        code_root=Path(folder) if reach else None,
        top=top or None,
    )


def _yes_no(v) -> str:
    if v is True:
        return "yes"
    if v is False:
        return "no"
    return "—"


def fmt_elapsed(seconds: float) -> str:
    """Format an elapsed duration as m:ss (or h:mm:ss past an hour)."""
    seconds = max(0, int(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"


def render_detail(f) -> str:
    """Build the plain-text detail shown in the right pane for a finding."""
    lines = [
        f"{f.cve_id}",
        f"{f.package}  version {f.version}",
        "",
        f"Severity:     {f.severity or 'unknown'}   CVSS: {_num(f.cvss)}",
        f"Priority:     {_num(f.priority_score)}",
        f"EPSS:         {_num(f.epss)}",
        f"KEV listed:   {'YES (actively exploited)' if f.kev_listed else 'no'}",
        f"Ransomware:   {'YES (known campaign use)' if f.known_ransomware else 'no'}",
        f"CISA due:     {f.kev_due_date or '—'}",
        f"Used in code: {_yes_no(f.reachable)}",
        f"Exposure:     {f.exposure or '—'}",
    ]
    if f.exploit_path:
        lines.append("Exploit path: " + " → ".join(f.exploit_path))
    if f.title:
        lines += ["", f"Title: {f.title}"]
    if f.explanation:
        lines += ["", "Explanation:", wrap(f.explanation)]
    lines += ["", f"Suggested fix: {f.suggested_fix or 'none'}"]
    if f.confidence:
        lines.append(f"Confidence: {f.confidence}")
    if f.grounded is not None:
        lines.append(f"Grounded: {'yes' if f.grounded else 'NO — unsupported claims'}")
    return "\n".join(lines)


def wrap(text: str, width: int = 68) -> str:
    import textwrap
    return textwrap.fill(" ".join(text.split()), width=width)


def render_plan_text(plan) -> str:
    """Plain-text remediation plan for the desktop tab."""
    lines = [
        f"{plan.cves_cleared} of {plan.cves_total} CVE(s) cleared by "
        f"{len(plan.steps)} upgrade(s).",
        f"Priority mass down {plan.reduction_pct}% "
        f"({plan.risk_before:.2f} -> {plan.risk_after:.2f}).",
        "",
    ]
    for step in plan.steps:
        lines += [
            f"{step.package}  {step.current_version} -> {step.target_version}"
            f"   [{step.manifest}]",
            f"    clears {len(step.cleared_cves)} CVE(s)"
            f"{', KEV ' + str(step.kev_cleared) if step.kev_cleared else ''}"
            f", risk {step.risk_cleared:.2f}",
            f"    {step.command}",
            "",
        ]
    if plan.manual:
        lines.append("Needs a human:")
        for item in plan.manual:
            lines.append(
                f"  {item['cve_id']}  {item['package']}=={item['version']}"
                f"  ({item['severity'] or 'UNKNOWN'})"
            )
            lines.append(f"      {item['reason']}")
        lines.append("")
    if plan.patch:
        lines += ["Manifest patch:", plan.patch.rstrip()]
    return "\n".join(lines)


def render_readiness_text(report: dict) -> str:
    """Plain-text environment readiness report."""
    if report.get("error"):
        return f"Readiness check failed: {report['error']}"
    lines = [f"Python {report.get('python', '?')}", ""]
    for key in ("trivy", "ollama", "openai", "policy"):
        entry = report.get(key) or {}
        label = {"trivy": "Trivy scanner", "ollama": "Ollama (local LLM)",
                 "openai": "OpenAI-compatible API", "policy": "Policy file"}[key]
        lines.append(f"[{(entry.get('status') or 'unknown').upper():7}] {label}")
        lines.append(f"          {entry.get('detail', '')}")
        if entry.get("hint"):
            lines.append(f"          -> {entry['hint']}")
    lines += ["", "Capabilities"]
    for name, enabled in (report.get("capabilities") or {}).items():
        lines.append(f"  {name.replace('_', ' ')}: {'yes' if enabled else 'no'}")
    return "\n".join(lines)


def main():
    root = Tk()
    ScanApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
