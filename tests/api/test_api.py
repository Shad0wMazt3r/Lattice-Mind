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

    def fake_start_solver(
        run_id: str,
        descriptor: ChallengeDescriptor,
        *,
        selected_tree_ids=None,
        run_mode: str = "ctf",
    ):
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
            run_mode=run_mode,
            impact_score=9.1,
            impact_breakdown={"model": "cvss-like-v1"},
            poc_evidence=[{"severity": "high", "reason": "demo"}],
            mutation_summary={"total_mutations": 0},
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
    assert submission["run_mode"] == "ctf"
    run_id = submission["run_id"]

    run_status = client.get(f"/runs/{run_id}", headers=headers)
    assert run_status.status_code == 200

    body = run_status.json()
    assert body["flag"] == expected_flag
    assert body["status"] == "success"
    assert body["run_mode"] == "ctf"
    assert body["impact_score"] == 9.1
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
    assert current.json()["scan_mode_default"] in ("ctf", "bug_bounty")

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


def test_run_events_and_trace_endpoints(monkeypatch):
    monkeypatch.setattr(server, "_decode_token", lambda token: {"sub": "admin", "role": "admin"})
    headers = {"Authorization": "Bearer fake_token"}

    run_id = "run-events-1"
    state = server.RunState(
        run_id=run_id,
        challenge={"type": "web", "name": "demo", "url": "http://example.com"},
    )
    server._register_run(state)
    state.add_step(
        {
            "event": "node_start",
            "node_id": "web_eval_injection:eval_probe_math",
            "node_name": "eval_probe_math",
            "status": "running",
            "timestamp": "now",
        }
    )
    state.add_step(
        {
            "event": "node_end",
            "node_id": "web_eval_injection:eval_probe_math",
            "node_name": "eval_probe_math",
            "status": "success",
            "timestamp": "now",
        }
    )

    ev = client.get(f"/runs/{run_id}/events?since_seq=0&limit=5", headers=headers)
    assert ev.status_code == 200
    payload = ev.json()
    assert payload["events"]
    assert payload["next_seq"] >= 1

    trace = client.get(f"/runs/{run_id}/trees/web_eval_injection/trace", headers=headers)
    assert trace.status_code == 200
    assert len(trace.json()["events"]) >= 1


def test_confidence_explain_and_notebook_export(monkeypatch):
    monkeypatch.setattr(server, "_decode_token", lambda token: {"sub": "admin", "role": "admin"})
    headers = {"Authorization": "Bearer fake_token"}

    run_id = "run-explain-1"
    state = server.RunState(
        run_id=run_id,
        challenge={"type": "web", "name": "demo", "url": "http://example.com"},
        confidence={"web_eval_injection": 0.7},
        observations={
            "decision_receipts": [
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "observation": "forbidden keyword",
                    "inference": "filter present",
                    "action": "pivot payload",
                    "result": "still executing",
                }
            ]
        },
    )
    server._register_run(state)

    explain = client.get(f"/runs/{run_id}/confidence/explain", headers=headers)
    assert explain.status_code == 200
    e = explain.json()
    assert e["ranked_confidence"][0]["tree_id"] == "web_eval_injection"
    assert e["decision_receipts"]

    notebook = client.get(f"/runs/{run_id}/export/notebook", headers=headers)
    assert notebook.status_code == 200
    assert "Lattice Mind Attack Notebook" in notebook.json()["markdown"]


def test_solve_accepts_bug_bounty_mode(monkeypatch):
    monkeypatch.setattr(server, "_decode_token", lambda token: {"sub": "admin", "role": "admin"})

    def fake_start_solver(
        run_id: str,
        descriptor: ChallengeDescriptor,
        *,
        selected_tree_ids=None,
        run_mode: str = "ctf",
    ):
        state = server.get_run_state(run_id)
        assert state is not None
        state.update(status="completed", run_mode=run_mode, finished_at="now")

    monkeypatch.setattr(server, "_start_solver_task", fake_start_solver)
    headers = {"Authorization": "Bearer fake_token"}
    resp = client.post(
        "/solve",
        headers=headers,
        json={"challenge_type": "web", "url": "http://example.com", "mode": "bug_bounty"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["run_mode"] == "bug_bounty"
