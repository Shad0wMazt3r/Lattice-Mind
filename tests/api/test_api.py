import json
import os
import tempfile
import uuid
from pathlib import Path

"""Sanity tests for the FastAPI interface."""

# API import performs restart recovery. Keep test collection away from a
# developer's live ~/.lattice-mind database and upload directory.
_test_state_dir = tempfile.TemporaryDirectory(prefix="lattice-mind-api-tests-")
os.environ["LATTICE_MIND_DB"] = str(Path(_test_state_dir.name) / "runs.db")
os.environ["LATTICE_MIND_UPLOAD_DIR"] = str(Path(_test_state_dir.name) / "uploads")

from fastapi.testclient import TestClient
from fastapi import HTTPException
import pytest
from starlette.websockets import WebSocketDisconnect

from lattice_mind.api import server
from lattice_mind.core.types import ChallengeDescriptor, ChallengeType

client = TestClient(server.app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_frontend_served():
    response = client.get("/")
    assert response.status_code == 200
    assert "Lattice Mind" in response.text


def test_solve_endpoint(monkeypatch):
    expected_flag = "flag{demo}"

    def fake_execute(challenge: ChallengeDescriptor):
        return expected_flag, {
            "challenge": challenge,
            "tree_history": ["asset_classify"],
            "observations": {"asset_type": challenge.type},
            "flag_found": expected_flag,
        }

    def fake_start_solver(run_id: str, descriptor: ChallengeDescriptor):
        state = server.get_run_state(run_id)
        assert state
        state.update(status="running", started_at="now")
        state.add_step(
            {"event": "node_start", "node_name": "asset_classify", "timestamp": "now"}
        )
        flag, raw_log = fake_execute(descriptor)
        state.add_step(
            {
                "event": "node_end",
                "node_name": "asset_classify",
                "status": "success",
                "timestamp": "now",
            }
        )
        state.update(
            status="success",
            flag=flag,
            log=server._serialize_log(raw_log),
            finished_at="now",
        )

    monkeypatch.setattr(server, "_execute_solver", fake_execute)
    monkeypatch.setattr(server, "_start_solver_task", fake_start_solver)

    def fake_decode_token(token: str):
        return {"sub": "admin", "role": "admin"}

    monkeypatch.setattr(server, "_decode_token", fake_decode_token)

    payload = {
        "challenge_type": ChallengeType.WEB.value,
        "name": "Demo",
        "url": "http://example.com",
        "metadata": {"description": "demo"},
    }

    headers = {"Authorization": "Bearer fake_token"}
    response = client.post("/solve", json=payload, headers=headers)
    assert response.status_code == 200

    submission = response.json()
    assert submission["status"] in ("queued", "success", "completed")
    run_id = submission["run_id"]

    run_status = client.get(f"/runs/{run_id}", headers=headers)
    assert run_status.status_code == 200

    body = run_status.json()
    assert body["flag"] == expected_flag
    assert body["status"] == "success"
    assert body["log"]["flag_found"] == expected_flag
    assert body["log"]["tree_history"] == ["asset_classify"]
    assert len(body["steps"]) == 2


def test_serialize_log_includes_evidence_records():
    challenge = ChallengeDescriptor(
        type=ChallengeType.WEB,
        name="Demo",
        url="http://example.com",
    )
    raw_log = {
        "challenge": challenge,
        "tree_history": ["tree:a"],
        "observations": {"k": "v"},
        "evidence_records": [{"kind": "response_delta", "severity": "high"}],
        "flag_found": None,
    }
    out = server._serialize_log(raw_log)
    assert out["evidence_records"] == [{"kind": "response_delta", "severity": "high"}]


def test_strategy_memory_endpoints(monkeypatch):
    monkeypatch.setattr(
        server,
        "list_strategy_memory",
        lambda limit=200: [{"mutation_kind": "param_remove", "score": 0.8}],
    )
    monkeypatch.setattr(server, "reset_strategy_memory", lambda scope_type=None, scope_value=None: 3)

    headers = {"Authorization": "Bearer fake_token"}
    monkeypatch.setattr(server, "_decode_token", lambda token: {"sub": "admin", "role": "admin"})

    r1 = client.get("/strategy-memory", headers=headers)
    assert r1.status_code == 200
    assert r1.json()["items"][0]["mutation_kind"] == "param_remove"

    r2 = client.request("DELETE", "/strategy-memory", headers=headers, json={})
    assert r2.status_code == 200
    assert r2.json()["deleted"] == 3


def test_settings_include_and_update_form_submission_budget(monkeypatch):
    monkeypatch.setattr(server, "_decode_token", lambda token: {"sub": "admin", "role": "admin"})
    headers = {"Authorization": "Bearer fake_token"}
    current = client.get("/settings", headers=headers)
    assert current.status_code == 200
    original = current.json().get("crawl_max_form_submissions", 10)
    assert "crawl_max_form_submissions" in current.json()

    try:
        updated = client.put(
            "/settings",
            headers=headers,
            json={"crawl_max_form_submissions": 0},
        )
        assert updated.status_code == 200
        body = updated.json()
        assert body["updated"]["crawl_max_form_submissions"] == 0
        assert body["settings"]["crawl_max_form_submissions"] == 0
    finally:
        client.put(
            "/settings",
            headers=headers,
            json={"crawl_max_form_submissions": original},
        )


def test_password_reset_token_is_signed_scoped_and_single_use(monkeypatch):
    user = {
        "email": "alice@example.test",
        "hashed_password": "hash-before-reset",
    }
    monkeypatch.setattr(
        server,
        "_db_get_user_by_email",
        lambda email: user if email == user["email"] else None,
    )

    token = server._make_password_reset_token(
        user["email"], user["hashed_password"]
    )
    assert server._decode_password_reset_token(token) == user["email"]
    assert server._decode_token(token) is None
    assert server._decode_password_reset_token(token + "tampered") is None
    assert server._decode_password_reset_token(
        server._make_token({"sub": user["email"], "role": "operator"})
    ) is None

    user["hashed_password"] = "hash-after-reset"
    assert server._decode_password_reset_token(token) is None


def test_run_access_is_owner_scoped_with_admin_override(monkeypatch):
    run_id = f"test-{uuid.uuid4()}"
    state = server.RunState(
        run_id=run_id,
        challenge={"name": "private"},
        owner="alice",
    )
    server._runs[run_id] = state

    identities = {
        "alice-token": {"sub": "alice", "role": "operator"},
        "bob-token": {"sub": "bob", "role": "operator"},
        "admin-token": {"sub": "root", "role": "admin"},
    }
    monkeypatch.setattr(server, "_decode_token", identities.get)
    try:
        assert client.get(
            f"/runs/{run_id}",
            headers={"Authorization": "Bearer alice-token"},
        ).status_code == 200
        assert client.get(
            f"/runs/{run_id}",
            headers={"Authorization": "Bearer bob-token"},
        ).status_code == 404
        assert client.get(
            f"/runs/{run_id}",
            headers={"Authorization": "Bearer admin-token"},
        ).status_code == 200
    finally:
        server._runs.pop(run_id, None)


def test_mcp_and_websocket_run_access_are_owner_scoped(monkeypatch):
    run_id = f"test-{uuid.uuid4()}"
    state = server.RunState(run_id=run_id, challenge={"name": "private"}, owner="alice")
    server._runs[run_id] = state
    identities = {
        "alice-token": {"sub": "alice", "role": "operator"},
        "bob-token": {"sub": "bob", "role": "operator"},
        "admin-token": {"sub": "root", "role": "admin"},
    }
    monkeypatch.setattr(server, "_decode_token", identities.get)
    try:
        with pytest.raises(HTTPException) as denied:
            import asyncio

            asyncio.run(
                server._mcp_dispatch(
                    "get_run_summary", {"run_id": run_id}, username="bob", role="operator"
                )
            )
        assert denied.value.status_code == 404

        with client.websocket_connect(f"/ws/{run_id}?token=alice-token") as websocket:
            assert websocket.receive_json()["data"]["run_id"] == run_id
        with client.websocket_connect(f"/ws/{run_id}?token=admin-token") as websocket:
            assert websocket.receive_json()["data"]["run_id"] == run_id
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(f"/ws/{run_id}?token=bob-token"):
                pass
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(f"/ws/missing?token=alice-token"):
                pass
    finally:
        server._runs.pop(run_id, None)


def test_global_rule_mutations_require_admin(monkeypatch):
    identities = {
        "operator-token": {"sub": "alice", "role": "operator"},
        "admin-token": {"sub": "root", "role": "admin"},
    }
    monkeypatch.setattr(server, "_decode_token", identities.get)

    denied = client.patch(
        "/rules/not-a-rule",
        json={"enabled": False},
        headers={"Authorization": "Bearer operator-token"},
    )
    assert denied.status_code == 403

    admin = client.patch(
        "/rules/not-a-rule",
        json={"enabled": False},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert admin.status_code == 404


def test_registration_does_not_grant_admin_without_bootstrap_token(monkeypatch):
    monkeypatch.delenv("LATTICE_MIND_BOOTSTRAP_TOKEN", raising=False)
    monkeypatch.setattr(server, "_db_get_user", lambda username: None)
    monkeypatch.setattr(server, "_db_get_user_by_email", lambda email: None)
    monkeypatch.setattr(
        server,
        "_db_create_user",
        lambda username, password, email, role: {
            "username": username,
            "email": email,
            "role": role,
        },
    )

    response = client.post(
        "/auth/register",
        json={
            "username": "newuser",
            "password": "safe-password",
            "email": "new@example.test",
        },
    )
    assert response.status_code == 200
    assert response.json()["role"] == "operator"


def test_upload_uses_opaque_shell_safe_server_filename(monkeypatch):
    monkeypatch.setattr(
        server, "_decode_token", lambda token: {"sub": "alice", "role": "operator"}
    )
    response = client.post(
        "/upload",
        files={"file": ("payload&whoami&.BIN", b"sample")},
        headers={"Authorization": "Bearer token"},
    )

    assert response.status_code == 200
    stored = Path(response.json()["path"])
    assert stored.parent == server.UPLOAD_DIR.resolve()
    assert stored.suffix == ".bin"
    assert "&" not in stored.name
    assert stored.read_bytes() == b"sample"


def test_startup_marks_persisted_inflight_runs_interrupted(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "DB_PATH", str(tmp_path / "runs.db"))
    server._init_db()
    now = server._now()
    with server._db() as conn:
        conn.execute(
            """
            INSERT INTO runs
                (run_id, status, challenge, steps, created_at, updated_at, owner)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            ("queued-run", "queued", json.dumps({}), "[]", now, now, "alice"),
        )

    assert server._mark_interrupted_runs() == 1
    row = server._db_load("queued-run")
    assert row["status"] == "error"
    assert row["error"] == "Run interrupted by server restart"
    assert row["finished_at"]
