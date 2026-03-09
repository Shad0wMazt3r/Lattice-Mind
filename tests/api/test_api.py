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
