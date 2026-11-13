"""Phase 6 (advanced) -- SQLite run history and scan deltas.

A scan in isolation says "here are today's findings". A security program needs
"what changed since yesterday, and did we actually fix anything?" This module
persists each run to SQLite and diffs it against the previous run:

  new         present now, absent before
  fixed       present before, absent now
  reopened    absent in the previous run but present in an older one
  persisting  present in both (with priority movement)

Fingerprints are (CVE, package, version, target), so a package upgrade that
moves to a new vulnerable version is a genuinely new finding, while a re-run
of the same scan is a no-op.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from common.finding import Finding

DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "history.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    target TEXT,
    mode TEXT,
    finding_count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    package TEXT NOT NULL,
    version TEXT NOT NULL,
    target TEXT,
    severity TEXT,
    priority_score REAL,
    exposure TEXT,
    reachable INTEGER,
    kev_listed INTEGER,
    fixed_version TEXT,
    PRIMARY KEY (run_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(fingerprint);
"""


@dataclass
class RunRecord:
    id: int
    started_at: str
    target: Optional[str]
    mode: Optional[str]
    finding_count: int

    def to_dict(self) -> dict:
        return {
            "id": self.id, "started_at": self.started_at,
            "target": self.target, "mode": self.mode,
            "finding_count": self.finding_count,
        }


@dataclass
class DeltaEntry:
    cve_id: str
    package: str
    version: str
    severity: str = ""
    priority_score: Optional[float] = None
    previous_priority: Optional[float] = None
    exposure: Optional[str] = None
    fixed_version: Optional[str] = None

    @property
    def priority_change(self) -> Optional[float]:
        if self.priority_score is None or self.previous_priority is None:
            return None
        return round(self.priority_score - self.previous_priority, 2)

    def to_dict(self) -> dict:
        return {
            "cve": self.cve_id, "package": self.package, "version": self.version,
            "severity": self.severity, "priority": self.priority_score,
            "previous_priority": self.previous_priority,
            "priority_change": self.priority_change,
            "exposure": self.exposure, "fixed_version": self.fixed_version,
        }


@dataclass
class DeltaReport:
    current_run: RunRecord
    previous_run: Optional[RunRecord]
    new: list[DeltaEntry] = field(default_factory=list)
    fixed: list[DeltaEntry] = field(default_factory=list)
    persisting: list[DeltaEntry] = field(default_factory=list)
    reopened: list[DeltaEntry] = field(default_factory=list)

    @property
    def has_previous(self) -> bool:
        return self.previous_run is not None

    def to_dict(self) -> dict:
        return {
            "current_run": self.current_run.to_dict(),
            "previous_run": self.previous_run.to_dict() if self.previous_run else None,
            "counts": {
                "new": len(self.new), "fixed": len(self.fixed),
                "persisting": len(self.persisting), "reopened": len(self.reopened),
            },
            "new": [e.to_dict() for e in self.new],
            "fixed": [e.to_dict() for e in self.fixed],
            "persisting": [e.to_dict() for e in self.persisting],
            "reopened": [e.to_dict() for e in self.reopened],
        }

    def render_text(self, limit: int = 10) -> str:
        if not self.has_previous:
            return (
                f"History: baseline recorded (run #{self.current_run.id}, "
                f"{self.current_run.finding_count} finding(s))."
            )
        lines = [
            f"Delta vs run #{self.previous_run.id} "
            f"({self.previous_run.started_at}): "
            f"+{len(self.new)} new, -{len(self.fixed)} fixed, "
            f"{len(self.persisting)} persisting, {len(self.reopened)} reopened"
        ]
        for label, entries in (("NEW", self.new), ("FIXED", self.fixed),
                               ("REOPENED", self.reopened)):
            for e in entries[:limit]:
                extra = f" priority={e.priority_score:.1f}" if e.priority_score is not None else ""
                lines.append(f"  {label:<8} {e.cve_id}  {e.package}=={e.version}{extra}")
        escalated = [e for e in self.persisting
                     if (e.priority_change or 0.0) > 0]
        escalated.sort(key=lambda e: -(e.priority_change or 0.0))
        for e in escalated[:limit]:
            lines.append(
                f"  ESCALATED {e.cve_id}  {e.package}  "
                f"+{e.priority_change:.2f} priority"
            )
        return "\n".join(lines)

    def render_markdown(self, limit: int = 10) -> str:
        if not self.has_previous:
            return (
                f"_History: baseline recorded ({self.current_run.finding_count} finding(s))._"
            )
        lines = [
            "### Scan delta",
            "",
            "| New | Fixed | Persisting | Reopened |",
            "|-----|-------|------------|----------|",
            f"| {len(self.new)} | {len(self.fixed)} | {len(self.persisting)} | {len(self.reopened)} |",
        ]
        for label, entries in (("New", self.new), ("Fixed", self.fixed),
                               ("Reopened", self.reopened)):
            for e in entries[:limit]:
                lines.append(f"- **{label}:** {e.cve_id} (`{e.package}=={e.version}`)")
        return "\n".join(lines)


def fingerprint(f: Finding) -> str:
    return "|".join((f.cve_id, f.package, f.version, f.target or ""))


def _sort_entries(entries: Iterable[DeltaEntry]) -> list[DeltaEntry]:
    return sorted(
        entries,
        key=lambda e: (-(e.priority_score or 0.0), e.cve_id, e.package),
    )


def _entry_from_row(row: sqlite3.Row, previous_priority: Optional[float] = None) -> DeltaEntry:
    return DeltaEntry(
        cve_id=row["cve_id"], package=row["package"], version=row["version"],
        severity=row["severity"] or "",
        priority_score=row["priority_score"],
        previous_priority=previous_priority,
        exposure=row["exposure"],
        fixed_version=row["fixed_version"],
    )


class HistoryStore:
    """Thin SQLite wrapper; one row per finding per run."""

    def __init__(self, path: str | Path = DEFAULT_DB):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "HistoryStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # --- runs ---------------------------------------------------------
    def record(
        self,
        findings: list[Finding],
        target: Optional[str] = None,
        mode: Optional[str] = None,
        started_at: Optional[str] = None,
    ) -> int:
        started_at = started_at or datetime.now(timezone.utc).replace(
            microsecond=0).isoformat().replace("+00:00", "Z")
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO runs (started_at, target, mode, finding_count) "
                "VALUES (?, ?, ?, ?)",
                (started_at, target, mode, len(findings)),
            )
            run_id = int(cur.lastrowid)
            self.conn.executemany(
                "INSERT INTO findings (run_id, fingerprint, cve_id, package, "
                "version, target, severity, priority_score, exposure, reachable, "
                "kev_listed, fixed_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        run_id, fingerprint(f), f.cve_id, f.package, f.version,
                        f.target, f.severity, f.priority_score, f.exposure,
                        None if f.reachable is None else int(f.reachable),
                        int(f.kev_listed), f.fixed_version,
                    )
                    for f in findings
                ],
            )
        return run_id

    def _run_from_row(self, row: sqlite3.Row) -> RunRecord:
        return RunRecord(
            id=row["id"], started_at=row["started_at"], target=row["target"],
            mode=row["mode"], finding_count=row["finding_count"],
        )

    def get_run(self, run_id: int) -> Optional[RunRecord]:
        row = self.conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        return self._run_from_row(row) if row else None

    def latest_run(self) -> Optional[RunRecord]:
        row = self.conn.execute(
            "SELECT * FROM runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return self._run_from_row(row) if row else None

    def runs(self, limit: int = 20) -> list[RunRecord]:
        rows = self.conn.execute(
            "SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [self._run_from_row(r) for r in rows]

    def findings_for_run(self, run_id: int) -> list[DeltaEntry]:
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE run_id = ? ORDER BY priority_score DESC",
            (run_id,),
        ).fetchall()
        return [self._entry_from_row(r) for r in rows]

    def prune(self, keep: int = 100) -> int:
        """Delete all but the newest `keep` runs. Returns rows removed."""
        rows = self.conn.execute(
            "SELECT id FROM runs ORDER BY id DESC LIMIT -1 OFFSET ?", (keep,)
        ).fetchall()
        ids = [r["id"] for r in rows]
        if not ids:
            return 0
        placeholders = ",".join("?" for _ in ids)
        with self.conn:
            self.conn.execute(
                f"DELETE FROM runs WHERE id IN ({placeholders})", ids
            )
        return len(ids)

    # --- deltas -------------------------------------------------------
    def diff(
        self,
        current_run_id: int,
        previous_run_id: Optional[int] = None,
    ) -> DeltaReport:
        current = self.get_run(current_run_id)
        if current is None:
            raise ValueError(f"unknown run id: {current_run_id}")
        previous = self.get_run(previous_run_id) if previous_run_id else None

        current_rows = {
            r["fingerprint"]: r for r in self.conn.execute(
                "SELECT * FROM findings WHERE run_id = ?", (current_run_id,)
            ).fetchall()
        }
        previous_rows = {}
        older_fingerprints: set[str] = set()
        if previous is not None:
            previous_rows = {
                r["fingerprint"]: r for r in self.conn.execute(
                    "SELECT * FROM findings WHERE run_id = ?", (previous.id,)
                ).fetchall()
            }
            older_fingerprints = {
                r["fingerprint"] for r in self.conn.execute(
                    "SELECT DISTINCT fingerprint FROM findings WHERE run_id < ?",
                    (previous.id,),
                ).fetchall()
            }

        new, fixed, persisting, reopened = [], [], [], []
        for fp, row in current_rows.items():
            if previous is None:
                new.append(_entry_from_row(row))
            elif fp in previous_rows:
                persisting.append(_entry_from_row(
                    row, previous_priority=previous_rows[fp]["priority_score"],
                ))
            elif fp in older_fingerprints:
                reopened.append(_entry_from_row(row))
            else:
                new.append(_entry_from_row(row))

        for fp, row in previous_rows.items():
            if fp not in current_rows:
                fixed.append(_entry_from_row(row))

        return DeltaReport(
            current_run=current,
            previous_run=previous,
            new=_sort_entries(new),
            fixed=_sort_entries(fixed),
            persisting=_sort_entries(persisting),
            reopened=_sort_entries(reopened),
        )

    def record_and_diff(
        self,
        findings: list[Finding],
        target: Optional[str] = None,
        mode: Optional[str] = None,
        started_at: Optional[str] = None,
        keep: int = 100,
    ) -> DeltaReport:
        previous = self.latest_run()
        run_id = self.record(findings, target=target, mode=mode, started_at=started_at)
        report = self.diff(run_id, previous.id if previous else None)
        self.prune(keep)
        return report
