"""Tests for response differential and evidence scoring (F3)."""

import asyncio
from types import SimpleNamespace

import pytest

import lattice_mind.adapters.curl_adapter as curl_module
from lattice_mind.core.confidence import ConfidencePool
from lattice_mind.core.executor import TreeExecutor
from lattice_mind.core.tree_loader import DetectionPath, DetectionStep
from lattice_mind.web.evidence import score_response_delta
from lattice_mind.web.response_diff import compute_response_delta, delta_summary


def _resp(
    status: int,
    body: str = "",
    *,
    headers=None,
    redirect_chain=None,
    response_time: float = 10.0,
) -> dict:
    return {
        "status": status,
        "body": body,
        "headers": headers or {},
        "redirect_chain": redirect_chain or [],
        "response_time": response_time,
    }


def test_delta_status_401_to_200():
    b = _resp(401, "denied")
    v = _resp(200, "welcome")
    d = compute_response_delta(b, v)
    assert d["status_changed"] is True
    assert d["baseline_status"] == 401
    assert d["variant_status"] == 200
    recs = score_response_delta(d)
    assert any(r.severity == "high" and "401" in r.reason for r in recs)


def test_delta_timing_evidence():
    b = _resp(200, "ok", response_time=100.0)
    v = _resp(200, "ok", response_time=1000.0)
    d = compute_response_delta(b, v)
    assert d["timing_delta_ms"] == pytest.approx(900.0, rel=0.01)
    recs = score_response_delta(d)
    assert any("Timing delta" in r.reason for r in recs)


def test_delta_redirect_changed():
    b = _resp(200, "", redirect_chain=["http://a/login"])
    v = _resp(200, "", redirect_chain=["http://a/home"])
    d = compute_response_delta(b, v)
    assert d["redirect_changed"] is True
    recs = score_response_delta(d)
    assert any("Redirect" in r.reason for r in recs)


def test_delta_high_similarity_token_change():
    long = "Lorem ipsum dolor sit amet " * 8
    b = _resp(200, f"<html>{long} user role is guest {long}</html>")
    v = _resp(200, f"<html>{long} admin role is guest {long}</html>")
    d = compute_response_delta(b, v)
    assert d["body_similarity_score"] >= 0.92
    assert "admin" in d["interesting_tokens_added"] or "user" in d["interesting_tokens_removed"]
    recs = score_response_delta(d)
    assert any("similar" in r.reason.lower() for r in recs)


def test_delta_summary_includes_status():
    d = compute_response_delta(_resp(403, "x"), _resp(200, "y"))
    s = delta_summary(d)
    assert "403" in s and "200" in s


def test_executor_mutation_batch_attaches_delta_and_evidence(monkeypatch):
    calls = []

    class FakeAdapter:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, target: str, args: dict):
            calls.append((target, args))
            n = len(calls)
            if n == 1:
                return {
                    "status": 401,
                    "headers": {},
                    "body": "no",
                    "redirect_chain": [],
                }
            return {
                "status": 200,
                "headers": {},
                "body": "yes",
                "redirect_chain": [],
            }

    monkeypatch.setattr(curl_module, "RequestsAdapter", FakeAdapter)

    step = DetectionStep(
        id="probe",
        action="http_request",
        params={
            "inject_into": "none",
            "payloads": ["x"],
            "mutation_families": ["param_remove"],
            "mutation_budget": {"max_total_variants": 4, "max_per_family": 2},
        },
        signals=[],
    )
    path = DetectionPath(
        id="p1",
        name="p",
        description="test",
        min_confidence=0.0,
        steps=[step],
    )
    tree = SimpleNamespace(
        id="t_mut",
        min_confidence=0.0,
        confidence_seeds=[],
        detection_paths=[path],
        exploitation_paths=[],
        stop_on_flag=False,
    )
    executor = TreeExecutor(ConfidencePool())
    ctx = {
        "challenge": SimpleNamespace(url="http://example.com/?id=1&otp=abc"),
        "observations": {},
    }
    asyncio.run(executor._run_detection_path(tree, path, ctx))

    assert len(calls) >= 2
    assert ctx.get("evidence_records"), "expected global evidence list populated"
    assert any("401" in str(e.get("reason", "")) for e in ctx["evidence_records"])
