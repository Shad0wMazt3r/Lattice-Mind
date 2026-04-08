"""Sanity tests for the FastAPI interface."""

from fastapi.testclient import TestClient

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
