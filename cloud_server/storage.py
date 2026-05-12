"""Sqlite-backed event store for Cordon Cloud.

Why sqlite?
-----------
The v0 of Cordon Cloud runs as a single-process FastAPI server on a
Hugging Face Space. Sqlite in WAL mode gives us concurrent reads during
writes with a single dependency-free file, and the workload (~10–100
events/sec, weeks of retention) sits comfortably inside its limits.

When a customer needs multi-region writes, horizontal scaling, or >100M
events, we swap this module out for a Postgres adapter that exposes the
same public interface. Until then, simplicity wins.

Data shape
----------
One table, one row per verdict event. We persist the full JSON wire
payload alongside the queryable columns so dashboards never have to
re-parse to display a detail view, and so we can add columns without
losing history.

Thread safety
-------------
The connection is created with ``check_same_thread=False`` and every
call grabs ``self._lock`` before touching it. This is good enough for a
single-process FastAPI server; the ASGI workers we run on Spaces are
single-threaded anyway.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable


# Match the SDK's wire format. Every field is optional in the input
# (we tolerate missing keys from older SDK versions); only ``ts``,
# ``decision`` and ``blocked`` are required for the dashboard to work.
_INGEST_COLUMNS = (
    "ts", "project", "action_id", "kind",
    "command_preview", "decision", "blocked",
    "suspicion_score", "top_probe", "top_severity",
    "top_evidence", "guard_profile", "sdk_version",
    "raw_json",
)


class EventStore:
    """Thin wrapper around a sqlite database file.

    Parameters
    ----------
    path
        Path to the sqlite file. ``":memory:"`` is allowed for tests.
    """

    def __init__(self, path: str | Path = "cordon_cloud.db") -> None:
        self.path = str(path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            self.path,
            check_same_thread=False,
            isolation_level=None,  # autocommit; we use explicit BEGIN
        )
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA synchronous=NORMAL;")
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts              REAL    NOT NULL,
                    project         TEXT    NOT NULL,
                    action_id       TEXT,
                    kind            TEXT,
                    command_preview TEXT,
                    decision        TEXT    NOT NULL,
                    blocked         INTEGER NOT NULL,
                    suspicion_score REAL,
                    top_probe       TEXT,
                    top_severity    TEXT,
                    top_evidence    TEXT,
                    guard_profile   TEXT,
                    sdk_version     TEXT,
                    raw_json        TEXT    NOT NULL,
                    created_at      REAL    NOT NULL DEFAULT (
                        strftime('%s','now') + 0.0
                    )
                );

                CREATE INDEX IF NOT EXISTS idx_events_ts
                    ON events (project, ts DESC);
                CREATE INDEX IF NOT EXISTS idx_events_blocked
                    ON events (project, blocked, ts DESC);
                CREATE INDEX IF NOT EXISTS idx_events_probe
                    ON events (project, top_probe, ts DESC);
                """
            )

    # ─── Writes ───────────────────────────────────────────────────────────────

    def insert_batch(
        self,
        project: str,
        events: Iterable[dict[str, Any]],
    ) -> int:
        """Insert one batch atomically. Returns the count actually written."""
        rows: list[tuple[Any, ...]] = []
        for ev in events:
            decision = (ev.get("decision") or "").lower()
            if decision not in {"block", "flag", "allow"}:
                # Skip malformed events instead of raising — the SDK is
                # supposed to never crash an agent, so the server should
                # be just as forgiving on the receiving end.
                continue
            rows.append(
                (
                    float(ev.get("ts", time.time())),
                    project,
                    ev.get("action_id"),
                    ev.get("kind"),
                    ev.get("command_preview"),
                    decision,
                    1 if ev.get("blocked") else 0,
                    _float_or_none(ev.get("suspicion_score")),
                    ev.get("top_probe"),
                    ev.get("top_severity"),
                    ev.get("top_evidence"),
                    ev.get("guard_profile"),
                    ev.get("sdk_version"),
                    json.dumps(ev, separators=(",", ":")),
                )
            )

        if not rows:
            return 0

        placeholders = ",".join(["?"] * len(_INGEST_COLUMNS))
        sql = (
            f"INSERT INTO events ({','.join(_INGEST_COLUMNS)}) "
            f"VALUES ({placeholders})"
        )
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                self._conn.executemany(sql, rows)
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        return len(rows)

    # ─── Reads ────────────────────────────────────────────────────────────────

    def list_events(
        self,
        project: str,
        *,
        limit: int = 50,
        before_ts: float | None = None,
        decision: str | None = None,
        probe: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return the most recent ``limit`` events matching the filters."""
        limit = max(1, min(int(limit), 500))
        clauses = ["project = ?"]
        params: list[Any] = [project]
        if before_ts is not None:
            clauses.append("ts < ?")
            params.append(float(before_ts))
        if decision in {"block", "flag", "allow"}:
            clauses.append("decision = ?")
            params.append(decision)
        if probe:
            clauses.append("top_probe = ?")
            params.append(probe)
        sql = (
            "SELECT id, ts, project, action_id, kind, command_preview, "
            "decision, blocked, suspicion_score, top_probe, top_severity, "
            "top_evidence, guard_profile, sdk_version, raw_json "
            "FROM events WHERE " + " AND ".join(clauses) +
            " ORDER BY ts DESC, id DESC LIMIT ?"
        )
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_event(r) for r in rows]

    def get_event(self, project: str, event_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, ts, project, action_id, kind, command_preview, "
                "decision, blocked, suspicion_score, top_probe, top_severity, "
                "top_evidence, guard_profile, sdk_version, raw_json "
                "FROM events WHERE project = ? AND id = ?",
                (project, int(event_id)),
            ).fetchone()
        return _row_to_event(row) if row else None

    def metrics(
        self,
        project: str,
        *,
        window_s: float = 24 * 3600,
    ) -> dict[str, Any]:
        """Aggregate counts + percentiles over the last ``window_s`` seconds."""
        cutoff = time.time() - float(window_s)
        with self._lock:
            agg = self._conn.execute(
                "SELECT "
                "COUNT(*) AS n_total, "
                "SUM(blocked) AS n_blocked, "
                "SUM(CASE WHEN decision='flag' THEN 1 ELSE 0 END) AS n_flagged, "
                "AVG(suspicion_score) AS mean_score "
                "FROM events WHERE project = ? AND ts >= ?",
                (project, cutoff),
            ).fetchone()
            top_probes = self._conn.execute(
                "SELECT top_probe, COUNT(*) AS n "
                "FROM events WHERE project = ? AND ts >= ? "
                "AND top_probe IS NOT NULL "
                "GROUP BY top_probe ORDER BY n DESC LIMIT 5",
                (project, cutoff),
            ).fetchall()
            # 30-bucket histogram for the sparkline (counts per bucket).
            buckets = self._conn.execute(
                "SELECT "
                "CAST(((? - ts) / ?) AS INTEGER) AS bucket, "
                "COUNT(*) AS n, "
                "SUM(blocked) AS n_blocked "
                "FROM events WHERE project = ? AND ts >= ? "
                "GROUP BY bucket ORDER BY bucket DESC",
                (time.time(), max(1.0, window_s / 30), project, cutoff),
            ).fetchall()

        n_total = int(agg["n_total"] or 0)
        n_blocked = int(agg["n_blocked"] or 0)
        n_flagged = int(agg["n_flagged"] or 0)
        block_rate = (n_blocked / n_total) if n_total else 0.0
        flag_rate = (n_flagged / n_total) if n_total else 0.0

        # Build a dense 30-bucket series, bucket index 0 = most recent.
        dense = [{"n": 0, "n_blocked": 0} for _ in range(30)]
        for row in buckets:
            idx = int(row["bucket"] or 0)
            if 0 <= idx < 30:
                dense[idx] = {
                    "n": int(row["n"]),
                    "n_blocked": int(row["n_blocked"] or 0),
                }

        return {
            "window_s": window_s,
            "n_total": n_total,
            "n_blocked": n_blocked,
            "n_flagged": n_flagged,
            "n_allowed": n_total - n_blocked - n_flagged,
            "block_rate": round(block_rate, 4),
            "flag_rate": round(flag_rate, 4),
            "mean_score": round(float(agg["mean_score"] or 0.0), 4),
            "top_probes": [
                {"probe": r["top_probe"], "count": int(r["n"])}
                for r in top_probes
            ],
            "sparkline": dense,  # newest bucket first
        }

    def count(self, project: str | None = None) -> int:
        with self._lock:
            if project is None:
                row = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM events"
                ).fetchone()
            else:
                row = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM events WHERE project = ?",
                    (project,),
                ).fetchone()
        return int(row["n"] or 0)

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# ─── Helpers ───────────────────────────────────────────────────────────────────


def _float_or_none(x: Any) -> float | None:
    try:
        return float(x) if x is not None else None
    except (TypeError, ValueError):
        return None


def _row_to_event(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id":               row["id"],
        "ts":               row["ts"],
        "project":          row["project"],
        "action_id":        row["action_id"],
        "kind":             row["kind"],
        "command_preview":  row["command_preview"],
        "decision":         row["decision"],
        "blocked":          bool(row["blocked"]),
        "suspicion_score":  row["suspicion_score"],
        "top_probe":        row["top_probe"],
        "top_severity":     row["top_severity"],
        "top_evidence":     row["top_evidence"],
        "guard_profile":    row["guard_profile"],
        "sdk_version":      row["sdk_version"],
        "raw":              json.loads(row["raw_json"]),
    }
