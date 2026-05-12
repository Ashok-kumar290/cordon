"""HTTP contract tests for the cloud-server policy endpoints (Lane 4).

These tests pin the wire shape that the dashboard JS depends on. If
a backend developer changes a status code or a field name without
realising the editor reads it, the test suite catches it before the
dashboard goes black.

Covers:

* ``GET    /v1/policies/{project}`` — dashboard-gated read.
* ``PUT    /v1/policies/{project}`` — dashboard-gated write, parses
  the policy before storing.
* ``DELETE /v1/policies/{project}`` — dashboard-gated.
* ``POST   /v1/policies/validate`` — public, syntax-only.
* ``POST   /v1/try`` with an inline ``policy`` field — public, runs
  the policy against an action.
"""

from __future__ import annotations

import importlib
import os
import sys

import pytest


# Each test gets a fresh app + sqlite DB. We can't share the module
# across tests because the FastAPI ``app`` reads its config (DB path,
# dashboard token, ingest keys) at import time.


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """Fresh ``TestClient`` with a tmp sqlite DB and a known token."""
    monkeypatch.setenv("CORDON_CLOUD_DB", str(tmp_path / "test.db"))
    monkeypatch.setenv("CORDON_CLOUD_DASHBOARD_TOKEN", "test-token")
    monkeypatch.setenv("CORDON_CLOUD_INGEST_KEYS", "cdn_test:demo")
    monkeypatch.setenv("CORDON_CLOUD_SEED_DEMO", "0")
    # Force a fresh import so the module reads our env, not the
    # previous test's.
    sys.modules.pop("cloud_server.app", None)

    # The repo root must be importable; tests run with cwd=repo root,
    # but be defensive in case someone runs from elsewhere.
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(here)
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)

    from fastapi.testclient import TestClient
    mod = importlib.import_module("cloud_server.app")
    return TestClient(mod.app)


H_TOKEN = {"X-Cordon-Dashboard-Token": "test-token"}


# ─── Read path ──────────────────────────────────────────────────────────────


def test_get_unset_returns_404(client):
    r = client.get("/v1/policies/demo", headers=H_TOKEN)
    assert r.status_code == 404


def test_get_requires_dashboard_token(client):
    r = client.get("/v1/policies/demo")
    assert r.status_code == 401


# ─── Write path ─────────────────────────────────────────────────────────────


def test_put_round_trip(client):
    r = client.put(
        "/v1/policies/demo",
        json={"text": "profile: strict\nallow when command_starts_with: \"rm -rf node_modules\""},
        headers=H_TOKEN,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["project"] == "demo"
    assert body["version"] == 1
    assert "rm -rf node_modules" in body["text"]

    got = client.get("/v1/policies/demo", headers=H_TOKEN).json()
    assert got["text"] == body["text"]


def test_put_bumps_version(client):
    client.put("/v1/policies/demo", json={"text": "profile: strict"}, headers=H_TOKEN)
    r = client.put("/v1/policies/demo", json={"text": "profile: default"}, headers=H_TOKEN)
    assert r.json()["version"] == 2


def test_put_invalid_policy_returns_400_with_line(client):
    """The dashboard editor needs ``line`` and ``snippet`` to highlight the error."""
    r = client.put("/v1/policies/demo", json={"text": "profile: paranoid"}, headers=H_TOKEN)
    assert r.status_code == 400
    detail = r.json()["detail"]
    assert "paranoid" in detail["message"]
    assert detail["line"] == 1
    assert "paranoid" in detail["snippet"]


def test_put_requires_dashboard_token(client):
    r = client.put("/v1/policies/demo", json={"text": "profile: strict"})
    assert r.status_code == 401


def test_delete_idempotent(client):
    client.put("/v1/policies/demo", json={"text": "profile: strict"}, headers=H_TOKEN)
    r1 = client.delete("/v1/policies/demo", headers=H_TOKEN)
    r2 = client.delete("/v1/policies/demo", headers=H_TOKEN)
    assert r1.status_code == r2.status_code == 200
    assert r1.json()["removed"] is True
    assert r2.json()["removed"] is False


# ─── Validate (public) ──────────────────────────────────────────────────────


def test_validate_public_no_auth(client):
    """Validate must work without the dashboard token — it powers the public editor."""
    r = client.post(
        "/v1/policies/validate",
        json={"text": "profile: strict\nallow when command_starts_with: \"rm\""},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["profile"] == "strict"
    assert body["n_rules"] == 1


def test_validate_bad_policy_returns_ok_false_with_line(client):
    r = client.post("/v1/policies/validate", json={"text": "profile: paranoid"})
    body = r.json()
    assert body["ok"] is False
    assert body["line"] == 1
    assert "paranoid" in body["snippet"]


# ─── /v1/try with inline policy ─────────────────────────────────────────────


def test_try_with_inline_policy_carveout(client):
    """A carve-out policy must downgrade BLOCK to ALLOW for matching commands."""
    policy = (
        "profile: strict\n"
        "allow when command_starts_with: \"rm -rf node_modules\""
    )
    r = client.post("/v1/try", json={
        "kind": "shell",
        "command": "rm -rf node_modules",
        "policy": policy,
    })
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "allow"
    assert body["profile"] == "strict+policy"


def test_try_with_inline_policy_no_match_keeps_base_decision(client):
    """If no rule matches, the base profile's verdict stands."""
    policy = "profile: strict\nallow when command_starts_with: \"rm -rf node_modules\""
    r = client.post("/v1/try", json={
        "kind": "shell",
        "command": "rm -rf --no-preserve-root /",
        "policy": policy,
    })
    body = r.json()
    assert body["decision"] == "block"
    assert body["profile"] == "strict+policy"


def test_try_with_invalid_policy_returns_400_with_line(client):
    r = client.post("/v1/try", json={
        "kind": "shell", "command": "x",
        "policy": "profile: paranoid",
    })
    assert r.status_code == 400
    detail = r.json()["detail"]
    assert detail["line"] == 1
    assert "paranoid" in detail["snippet"]


def test_try_without_policy_uses_profile(client):
    """Backward-compat: omitting `policy` keeps the existing profile path."""
    r = client.post("/v1/try", json={
        "kind": "shell", "command": "pytest -q", "profile": "strict",
    })
    body = r.json()
    assert body["decision"] == "allow"
    assert body["profile"] == "strict"
