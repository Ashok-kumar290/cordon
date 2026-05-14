"""Event store for Cordon Cloud — sqlite + postgres adapters.

Two backends behind one interface
---------------------------------

* :class:`SqliteEventStore` — the default. Zero-config: one file on
  disk, WAL mode, no external dependencies. Fine for the closed-beta
  demo on Hugging Face Spaces (~10–100 events/sec, ephemeral) and for
  self-hosted single-tenant deployments.
* :class:`PostgresEventStore` — persistent multi-tenant production
  backend. Same wire shape, same queries; differences live entirely
  inside this module. Driven by the ``psycopg`` package, only
  imported when actually used so the sqlite path has no extra deps.

The :func:`make_store` factory dispatches on the URL scheme:

==================================  ===========================
URL                                  Returns
==================================  ===========================
``None`` / ``""``                    :class:`SqliteEventStore`
``sqlite:///path/to/file.db``        :class:`SqliteEventStore`
``postgresql://user:pw@host/db``     :class:`PostgresEventStore`
``postgres://user:pw@host/db``       :class:`PostgresEventStore`
==================================  ===========================

The :class:`EventStore` Protocol pins the public surface (six methods).
Anything that satisfies it slots into ``app.py`` without changes.

Data shape
----------
One table, one row per verdict event. We persist the full JSON wire
payload alongside the queryable columns so dashboards never have to
re-parse to display a detail view, and so we can add columns without
losing history.

Thread safety
-------------
Sqlite: a single connection with ``check_same_thread=False`` plus a
per-instance lock. Postgres: psycopg's built-in connection pool;
operations are short and we never hold a transaction across calls.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable, Protocol, runtime_checkable
from urllib.parse import urlparse


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


@runtime_checkable
class EventStore(Protocol):
    """The shape every backend must satisfy.

    This is a Protocol, not a base class — concrete adapters
    (:class:`SqliteEventStore`, :class:`PostgresEventStore`) implement
    it structurally. The methods below are the *entire* surface that
    ``cloud_server.app`` depends on; if you add a backend, implement
    these six methods and you're done.
    """

    def insert_batch(self, project: str, events: Iterable[dict[str, Any]]) -> int: ...
    def list_events(
        self,
        project: str,
        *,
        limit: int = 50,
        before_ts: float | None = None,
        decision: str | None = None,
        probe: str | None = None,
    ) -> list[dict[str, Any]]: ...
    def get_event(self, project: str, event_id: int) -> dict[str, Any] | None: ...
    def metrics(self, project: str, *, window_s: float = 24 * 3600) -> dict[str, Any]: ...
    def count(self, project: str | None = None) -> int: ...
    def close(self) -> None: ...

    # ── Data-subject endpoints (data-policy.md §5) ─────────────────────────
    # Required for the export / delete REST endpoints that the data
    # policy promises. Implementations must return the number of rows
    # actually deleted (so the response can report "deleted: 12483").
    def delete_events(self, project: str) -> int: ...

    # ── Per-project policy storage (Lane 4) ────────────────────────────────
    # Stored as the verbatim policy text plus a monotonic version + an
    # updated_at timestamp. Returns None when no policy has ever been
    # configured for the project — callers fall back to whichever
    # default Guard profile they prefer.
    def get_policy(self, project: str) -> dict[str, Any] | None: ...
    def put_policy(self, project: str, text: str) -> dict[str, Any]: ...
    def delete_policy(self, project: str) -> bool: ...


class SqliteEventStore:
    """Single-file sqlite backend. The default.

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

                CREATE TABLE IF NOT EXISTS policies (
                    project    TEXT PRIMARY KEY,
                    text       TEXT NOT NULL,
                    version    INTEGER NOT NULL DEFAULT 1,
                    updated_at REAL    NOT NULL
                );
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

    def delete_events(self, project: str) -> int:
        """Delete every event for ``project``. Returns the row count.

        Required by the public data-policy commitment (§5). Idempotent —
        re-running with the same project after a successful delete
        returns 0.
        """
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM events WHERE project = ?", (project,),
            )
        return cur.rowcount

    # ─── Policy storage ───────────────────────────────────────────────────────

    def get_policy(self, project: str) -> dict[str, Any] | None:
        """Return ``{text, version, updated_at}`` or ``None`` if unset."""
        with self._lock:
            row = self._conn.execute(
                "SELECT text, version, updated_at FROM policies WHERE project = ?",
                (project,),
            ).fetchone()
        if row is None:
            return None
        return {
            "project":    project,
            "text":       row["text"],
            "version":    int(row["version"]),
            "updated_at": float(row["updated_at"]),
        }

    def put_policy(self, project: str, text: str) -> dict[str, Any]:
        """Upsert the policy for ``project``; auto-increments ``version``."""
        now = time.time()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO policies (project, text, version, updated_at)
                VALUES (?, ?, 1, ?)
                ON CONFLICT(project) DO UPDATE SET
                    text       = excluded.text,
                    version    = policies.version + 1,
                    updated_at = excluded.updated_at
                """,
                (project, text, now),
            )
            row = self._conn.execute(
                "SELECT version, updated_at FROM policies WHERE project = ?",
                (project,),
            ).fetchone()
        return {
            "project":    project,
            "text":       text,
            "version":    int(row["version"]),
            "updated_at": float(row["updated_at"]),
        }

    def delete_policy(self, project: str) -> bool:
        """Delete the policy for ``project``. Returns True if a row was removed."""
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM policies WHERE project = ?", (project,),
            )
        return cur.rowcount > 0

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
    return _row_dict_to_event(dict(row))


def _row_dict_to_event(row: dict[str, Any]) -> dict[str, Any]:
    """Backend-agnostic row → wire dict.

    Both sqlite (``sqlite3.Row``, dict-like) and psycopg (real ``dict``
    from a dict_row factory) end up here. The only piece either
    backend handles differently is `raw_json` (text in sqlite, JSONB in
    pg), but we always store/return it as a parsed dict.
    """
    raw = row["raw_json"]
    if isinstance(raw, str):
        raw = json.loads(raw)
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
        "raw":              raw,
    }


def _build_event_rows(
    project: str, events: Iterable[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Validate + normalize a batch into dicts shaped for the INSERT.

    Used by both backends so the wire-shape validation lives in one
    place. Malformed events (no decision, or a decision outside
    block/flag/allow) are silently dropped — the SDK promises never to
    crash an agent, the server matches that promise on the wire.
    """
    rows: list[dict[str, Any]] = []
    for ev in events:
        decision = (ev.get("decision") or "").lower()
        if decision not in {"block", "flag", "allow"}:
            continue
        rows.append(
            {
                "ts":              float(ev.get("ts", time.time())),
                "project":         project,
                "action_id":       ev.get("action_id"),
                "kind":            ev.get("kind"),
                "command_preview": ev.get("command_preview"),
                "decision":        decision,
                "blocked":         bool(ev.get("blocked")),
                "suspicion_score": _float_or_none(ev.get("suspicion_score")),
                "top_probe":       ev.get("top_probe"),
                "top_severity":    ev.get("top_severity"),
                "top_evidence":    ev.get("top_evidence"),
                "guard_profile":   ev.get("guard_profile"),
                "sdk_version":     ev.get("sdk_version"),
                "raw_json":        json.dumps(ev, separators=(",", ":")),
            }
        )
    return rows


# ─── Postgres backend ─────────────────────────────────────────────────────────


class PostgresEventStore:
    """Postgres backend. Same surface as :class:`SqliteEventStore`.

    Connection management is delegated to ``psycopg_pool.ConnectionPool``
    so multiple ASGI workers can share one pool without a custom lock.
    The schema is created idempotently on first connect — first boot
    on a fresh database "just works", subsequent boots re-attach to
    the existing data.

    Parameters
    ----------
    dsn
        A ``postgresql://`` URL. Both the ``postgresql://`` and the
        legacy ``postgres://`` schemes are accepted.
    min_size, max_size
        Connection pool bounds. The defaults are tuned for a single
        FastAPI process serving a low-volume dashboard; raise
        ``max_size`` if you put this behind a multi-worker gunicorn.
    """

    def __init__(self, dsn: str, *, min_size: int = 1, max_size: int = 4) -> None:
        try:
            import psycopg
            from psycopg.rows import dict_row
            from psycopg_pool import ConnectionPool
        except ImportError as exc:  # pragma: no cover — runtime guard
            raise RuntimeError(
                "PostgresEventStore requires the `psycopg[binary,pool]` "
                "package. Install with: pip install 'psycopg[binary,pool]'"
            ) from exc

        # psycopg only accepts ``postgresql://``; normalize.
        if dsn.startswith("postgres://"):
            dsn = "postgresql://" + dsn[len("postgres://"):]
        self.dsn = dsn
        self._psycopg = psycopg
        self._dict_row = dict_row

        self._pool = ConnectionPool(
            conninfo=dsn,
            min_size=min_size,
            max_size=max_size,
            kwargs={"row_factory": dict_row},
            open=True,
        )
        self._ensure_schema()

    # ── schema ─────────────────────────────────────────────────────────────

    _SCHEMA_SQL = """
    CREATE TABLE IF NOT EXISTS events (
        id              BIGSERIAL    PRIMARY KEY,
        ts              DOUBLE PRECISION NOT NULL,
        project         TEXT         NOT NULL,
        action_id       TEXT,
        kind            TEXT,
        command_preview TEXT,
        decision        TEXT         NOT NULL,
        blocked         BOOLEAN      NOT NULL,
        suspicion_score DOUBLE PRECISION,
        top_probe       TEXT,
        top_severity    TEXT,
        top_evidence    TEXT,
        guard_profile   TEXT,
        sdk_version     TEXT,
        raw_json        JSONB        NOT NULL,
        created_at      DOUBLE PRECISION NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())
    );

    CREATE INDEX IF NOT EXISTS idx_events_ts
        ON events (project, ts DESC);
    CREATE INDEX IF NOT EXISTS idx_events_blocked
        ON events (project, blocked, ts DESC);
    CREATE INDEX IF NOT EXISTS idx_events_probe
        ON events (project, top_probe, ts DESC);

    CREATE TABLE IF NOT EXISTS policies (
        project    TEXT PRIMARY KEY,
        text       TEXT NOT NULL,
        version    INTEGER NOT NULL DEFAULT 1,
        updated_at DOUBLE PRECISION NOT NULL
    );
    """

    def _ensure_schema(self) -> None:
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(self._SCHEMA_SQL)

    # ── writes ─────────────────────────────────────────────────────────────

    def insert_batch(
        self,
        project: str,
        events: Iterable[dict[str, Any]],
    ) -> int:
        rows = _build_event_rows(project, events)
        if not rows:
            return 0

        sql = (
            "INSERT INTO events "
            f"({','.join(_INGEST_COLUMNS)}) "
            "VALUES (%(ts)s, %(project)s, %(action_id)s, %(kind)s, "
            "%(command_preview)s, %(decision)s, %(blocked)s, "
            "%(suspicion_score)s, %(top_probe)s, %(top_severity)s, "
            "%(top_evidence)s, %(guard_profile)s, %(sdk_version)s, "
            "%(raw_json)s::jsonb)"
        )
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.executemany(sql, rows)
        return len(rows)

    # ── reads ──────────────────────────────────────────────────────────────

    _SELECT_COLS = (
        "id, ts, project, action_id, kind, command_preview, "
        "decision, blocked, suspicion_score, top_probe, top_severity, "
        "top_evidence, guard_profile, sdk_version, raw_json"
    )

    def list_events(
        self,
        project: str,
        *,
        limit: int = 50,
        before_ts: float | None = None,
        decision: str | None = None,
        probe: str | None = None,
    ) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        clauses = ["project = %s"]
        params: list[Any] = [project]
        if before_ts is not None:
            clauses.append("ts < %s")
            params.append(float(before_ts))
        if decision in {"block", "flag", "allow"}:
            clauses.append("decision = %s")
            params.append(decision)
        if probe:
            clauses.append("top_probe = %s")
            params.append(probe)

        sql = (
            f"SELECT {self._SELECT_COLS} FROM events "
            f"WHERE {' AND '.join(clauses)} "
            "ORDER BY ts DESC, id DESC LIMIT %s"
        )
        params.append(limit)
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        return [_row_dict_to_event(r) for r in rows]

    def get_event(self, project: str, event_id: int) -> dict[str, Any] | None:
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                f"SELECT {self._SELECT_COLS} FROM events "
                "WHERE project = %s AND id = %s",
                (project, int(event_id)),
            )
            row = cur.fetchone()
        return _row_dict_to_event(row) if row else None

    def metrics(
        self,
        project: str,
        *,
        window_s: float = 24 * 3600,
    ) -> dict[str, Any]:
        cutoff = time.time() - float(window_s)
        bucket_w = max(1.0, window_s / 30)

        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS n_total, "
                "SUM(CASE WHEN blocked THEN 1 ELSE 0 END) AS n_blocked, "
                "SUM(CASE WHEN decision='flag' THEN 1 ELSE 0 END) AS n_flagged, "
                "AVG(suspicion_score) AS mean_score "
                "FROM events WHERE project = %s AND ts >= %s",
                (project, cutoff),
            )
            agg = cur.fetchone() or {}

            cur.execute(
                "SELECT top_probe, COUNT(*) AS n FROM events "
                "WHERE project = %s AND ts >= %s AND top_probe IS NOT NULL "
                "GROUP BY top_probe ORDER BY n DESC LIMIT 5",
                (project, cutoff),
            )
            top_probes = cur.fetchall()

            cur.execute(
                "SELECT CAST(((%s - ts) / %s) AS INTEGER) AS bucket, "
                "COUNT(*) AS n, "
                "SUM(CASE WHEN blocked THEN 1 ELSE 0 END) AS n_blocked "
                "FROM events WHERE project = %s AND ts >= %s "
                "GROUP BY bucket ORDER BY bucket DESC",
                (time.time(), bucket_w, project, cutoff),
            )
            buckets = cur.fetchall()

        n_total = int(agg.get("n_total") or 0)
        n_blocked = int(agg.get("n_blocked") or 0)
        n_flagged = int(agg.get("n_flagged") or 0)
        block_rate = (n_blocked / n_total) if n_total else 0.0
        flag_rate = (n_flagged / n_total) if n_total else 0.0

        dense = [{"n": 0, "n_blocked": 0} for _ in range(30)]
        for row in buckets:
            idx = int(row.get("bucket") or 0)
            if 0 <= idx < 30:
                dense[idx] = {
                    "n":         int(row["n"]),
                    "n_blocked": int(row.get("n_blocked") or 0),
                }

        return {
            "window_s":   window_s,
            "n_total":    n_total,
            "n_blocked":  n_blocked,
            "n_flagged":  n_flagged,
            "n_allowed":  n_total - n_blocked - n_flagged,
            "block_rate": round(block_rate, 4),
            "flag_rate":  round(flag_rate, 4),
            "mean_score": round(float(agg.get("mean_score") or 0.0), 4),
            "top_probes": [
                {"probe": r["top_probe"], "count": int(r["n"])}
                for r in top_probes
            ],
            "sparkline": dense,
        }

    def count(self, project: str | None = None) -> int:
        with self._pool.connection() as conn, conn.cursor() as cur:
            if project is None:
                cur.execute("SELECT COUNT(*) AS n FROM events")
            else:
                cur.execute(
                    "SELECT COUNT(*) AS n FROM events WHERE project = %s",
                    (project,),
                )
            row = cur.fetchone() or {}
        return int(row.get("n") or 0)

    def delete_events(self, project: str) -> int:
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM events WHERE project = %s", (project,),
            )
            n = cur.rowcount
        return int(n or 0)

    # ─── Policy storage ───────────────────────────────────────────────────

    def get_policy(self, project: str) -> dict[str, Any] | None:
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT text, version, updated_at FROM policies WHERE project = %s",
                (project,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return {
            "project":    project,
            "text":       row["text"],
            "version":    int(row["version"]),
            "updated_at": float(row["updated_at"]),
        }

    def put_policy(self, project: str, text: str) -> dict[str, Any]:
        now = time.time()
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO policies (project, text, version, updated_at)
                VALUES (%s, %s, 1, %s)
                ON CONFLICT (project) DO UPDATE SET
                    text       = EXCLUDED.text,
                    version    = policies.version + 1,
                    updated_at = EXCLUDED.updated_at
                RETURNING version, updated_at
                """,
                (project, text, now),
            )
            row = cur.fetchone() or {}
        return {
            "project":    project,
            "text":       text,
            "version":    int(row.get("version") or 1),
            "updated_at": float(row.get("updated_at") or now),
        }

    def delete_policy(self, project: str) -> bool:
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM policies WHERE project = %s", (project,))
            n = cur.rowcount
        return n > 0

    def close(self) -> None:
        self._pool.close()


# ─── Factory ──────────────────────────────────────────────────────────────────


def make_store(db_url: str | None = None) -> EventStore:
    """Pick an :class:`EventStore` backend based on a URL.

    Reads ``CORDON_CLOUD_DB`` from the environment when ``db_url`` is
    ``None``. Falls back to a local sqlite file at
    ``cordon_cloud.db`` when nothing is set — that's the zero-config
    development path.

    ``sqlite:///`` URLs use the *triple*-slash form (the standard
    SQLAlchemy/RFC convention). The path after the third slash is
    taken literally — relative for ``sqlite:///foo.db``, absolute for
    ``sqlite:////var/lib/cordon.db``.
    """
    if db_url is None:
        db_url = (os.environ.get("CORDON_CLOUD_DB") or "").strip()

    if not db_url:
        return SqliteEventStore("cordon_cloud.db")

    scheme = urlparse(db_url).scheme.lower()

    if scheme in {"", "sqlite"}:
        path = db_url[len("sqlite:///"):] if db_url.startswith("sqlite:///") else db_url
        return SqliteEventStore(path or "cordon_cloud.db")

    if scheme in {"postgres", "postgresql"}:
        return PostgresEventStore(db_url)

    raise ValueError(
        f"Unsupported CORDON_CLOUD_DB scheme {scheme!r}. "
        "Use 'sqlite:///path/to/file.db' or 'postgresql://...'."
    )


__all__ = [
    "EventStore",
    "SqliteEventStore",
    "PostgresEventStore",
    "make_store",
]
