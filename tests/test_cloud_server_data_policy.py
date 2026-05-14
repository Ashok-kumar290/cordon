"""HTTP contract tests for the data-subject endpoints (data-policy.md §5).

These tests pin the wire shape that the data-policy doc promises a
design-partner security review can curl-test:

* ``GET    /v1/events/export?project=<p>&format=jsonl|csv``
* ``DELETE /v1/events?project=<p>``

A failure here means the documented data policy lies. Treat
regressions as P0.
"""

from __future__ import annotations

import csv
import importlib
import io
import json
import os
import sys
import time

import pytest


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """Fresh app + sqlite DB + known dashboard token, per test."""
    monkeypatch.setenv("CORDON_CLOUD_DB", str(tmp_path / "test.db"))
    monkeypatch.setenv("CORDON_CLOUD_DASHBOARD_TOKEN", "test-token")
    monkeypatch.setenv("CORDON_CLOUD_INGEST_KEYS", "cdn_test:demo,cdn_other:other")
    monkeypatch.setenv("CORDON_CLOUD_SEED_DEMO", "0")
    sys.modules.pop("cloud_server.app", None)

    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(here)
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)

    from fastapi.testclient import TestClient
    mod = importlib.import_module("cloud_server.app")
    return TestClient(mod.app)


H_TOKEN = {"X-Cordon-Dashboard-Token": "test-token"}


def _ingest(client, project_key: str, events: list[dict]):
    """Helper: POST to /v1/ingest with the right Bearer key."""
    return client.post(
        "/v1/ingest",
        json={"events": events},
        headers={"Authorization": f"Bearer {project_key}"},
    )


def _event(action_id: str, decision: str = "allow", **overrides) -> dict:
    ev = {
        "ts": time.time(),
        "action_id": action_id,
        "kind": "shell",
        "command_preview": f"cmd-for-{action_id}",
        "decision": decision,
        "blocked": decision == "block",
        "suspicion_score": 0.95 if decision == "block" else 0.0,
        "top_probe": "destructive_shell" if decision == "block" else None,
        "top_severity": "critical" if decision == "block" else None,
        "top_evidence": "blocked" if decision == "block" else None,
        "guard_profile": "strict",
        "sdk_version": "0.2.3",
        "raw_json": "{}",
    }
    ev.update(overrides)
    return ev


# ─── Auth ─────────────────────────────────────────────────────────────────


def test_export_requires_dashboard_token(client):
    r = client.get("/v1/events/export?project=demo")
    assert r.status_code == 401


def test_delete_requires_dashboard_token(client):
    r = client.delete("/v1/events?project=demo")
    assert r.status_code == 401


# ─── Routing — make sure export doesn't conflict with /v1/events/{id} ────


def test_export_route_does_not_shadow_event_by_id(client):
    """The literal /v1/events/export must NOT be matched by /v1/events/{event_id}.

    This is the trap that caught us in development: FastAPI dispatches
    in declaration order. If someone refactors and accidentally re-orders
    the routes, this test catches it before production.
    """
    r = client.get("/v1/events/export?project=demo", headers=H_TOKEN)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/x-ndjson")


# ─── Export — JSONL (default) ─────────────────────────────────────────────


def test_export_jsonl_empty_project_returns_empty_body(client):
    r = client.get("/v1/events/export?project=demo", headers=H_TOKEN)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/x-ndjson")
    assert r.text == ""


def test_export_jsonl_round_trips_ingested_events(client):
    """End-to-end: ingest 3, export, parse, count, and sample fields."""
    _ingest(client, "cdn_test", [
        _event("a-1", "block"),
        _event("a-2", "allow"),
        _event("a-3", "flag"),
    ])

    r = client.get("/v1/events/export?project=demo", headers=H_TOKEN)
    assert r.status_code == 200

    lines = r.text.strip().split("\n")
    assert len(lines) == 3
    objs = [json.loads(line) for line in lines]

    # Newest first (matches /v1/events list ordering)
    decisions = [o["decision"] for o in objs]
    assert set(decisions) == {"block", "allow", "flag"}

    # Every documented column is present on at least the block row
    block = next(o for o in objs if o["decision"] == "block")
    for column in ("ts", "project", "action_id", "kind", "command_preview",
                   "decision", "blocked", "suspicion_score",
                   "top_probe", "top_severity", "top_evidence",
                   "guard_profile", "sdk_version"):
        assert column in block, f"missing column: {column}"


def test_export_filename_header_includes_project(client):
    """The Content-Disposition header drives the browser's download filename."""
    r = client.get("/v1/events/export?project=demo", headers=H_TOKEN)
    assert 'demo-events.jsonl' in r.headers["content-disposition"]


def test_export_is_project_scoped(client):
    """Project-A's export must not contain Project-B's events."""
    _ingest(client, "cdn_test",  [_event("d-1")])
    _ingest(client, "cdn_other", [_event("o-1"), _event("o-2")])

    r = client.get("/v1/events/export?project=demo", headers=H_TOKEN)
    lines = [line for line in r.text.strip().split("\n") if line]
    assert len(lines) == 1

    r = client.get("/v1/events/export?project=other", headers=H_TOKEN)
    lines = [line for line in r.text.strip().split("\n") if line]
    assert len(lines) == 2


# ─── Export — CSV ─────────────────────────────────────────────────────────


def test_export_csv_returns_valid_csv_with_header(client):
    _ingest(client, "cdn_test", [_event("a-1", "block")])

    r = client.get("/v1/events/export?project=demo&format=csv", headers=H_TOKEN)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")

    reader = csv.DictReader(io.StringIO(r.text))
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["decision"] == "block"
    # The header includes the documented primary columns
    assert "command_preview" in reader.fieldnames
    assert "top_probe"       in reader.fieldnames


def test_export_csv_filename_header(client):
    r = client.get("/v1/events/export?project=demo&format=csv", headers=H_TOKEN)
    assert 'demo-events.csv' in r.headers["content-disposition"]


def test_export_invalid_format_returns_422(client):
    r = client.get("/v1/events/export?project=demo&format=xml", headers=H_TOKEN)
    assert r.status_code == 422


# ─── Delete ───────────────────────────────────────────────────────────────


def test_delete_returns_count_of_deleted_rows(client):
    _ingest(client, "cdn_test", [_event("a-1"), _event("a-2"), _event("a-3")])

    r = client.delete("/v1/events?project=demo", headers=H_TOKEN)
    assert r.status_code == 200
    body = r.json()
    assert body == {"project": "demo", "deleted": 3}


def test_delete_idempotent_returns_zero_on_second_call(client):
    _ingest(client, "cdn_test", [_event("a-1")])

    r1 = client.delete("/v1/events?project=demo", headers=H_TOKEN)
    r2 = client.delete("/v1/events?project=demo", headers=H_TOKEN)
    assert r1.json() == {"project": "demo", "deleted": 1}
    assert r2.json() == {"project": "demo", "deleted": 0}


def test_delete_is_project_scoped(client):
    """Delete on one project must not touch another."""
    _ingest(client, "cdn_test",  [_event("d-1"), _event("d-2")])
    _ingest(client, "cdn_other", [_event("o-1")])

    client.delete("/v1/events?project=demo", headers=H_TOKEN)

    # Other project still has its row
    r = client.get("/v1/events/export?project=other", headers=H_TOKEN)
    lines = [line for line in r.text.strip().split("\n") if line]
    assert len(lines) == 1


def test_delete_empty_project_returns_zero_not_404(client):
    """An unconfigured / never-used project deletes 0 rows, not 404.

    Important contract bit: the data policy promises idempotency,
    which is incompatible with 404 on first-call-of-unused-project.
    """
    r = client.delete("/v1/events?project=never-existed", headers=H_TOKEN)
    assert r.status_code == 200
    assert r.json() == {"project": "never-existed", "deleted": 0}


# ─── Full data-subject flow (the demo I'd run on a partner call) ──────────


def test_full_export_then_delete_then_empty_export_flow(client):
    """Ingest → export → delete → re-export. The end-to-end story."""
    _ingest(client, "cdn_test", [_event("a-1"), _event("a-2")])

    # Export
    r = client.get("/v1/events/export?project=demo", headers=H_TOKEN)
    assert len([line for line in r.text.strip().split("\n") if line]) == 2

    # Delete
    r = client.delete("/v1/events?project=demo", headers=H_TOKEN)
    assert r.json()["deleted"] == 2

    # Re-export → empty
    r = client.get("/v1/events/export?project=demo", headers=H_TOKEN)
    assert r.text == ""
