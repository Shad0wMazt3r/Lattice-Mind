from lattice_mind.config import FEATURE_FLAGS
from lattice_mind.web.request_builder import (
    filter_probe_specs_by_candidate_filter,
    resolve_probe_base_specs,
    target_params_for_selector,
)
from lattice_mind.web.request_models import HTTPRequestSpec, request_spec_to_jsonable


def test_resolve_probe_base_specs_respects_config_cap(monkeypatch):
    monkeypatch.setattr(FEATURE_FLAGS, "max_probe_base_specs", 4)
    cands = [
        request_spec_to_jsonable(HTTPRequestSpec(url=f"http://cap.test/{i}"))
        for i in range(10)
    ]
    ctx = {"observations": {"request_candidates": cands}}
    specs = resolve_probe_base_specs(ctx, "http://cap.test/")
    assert len(specs) == 4


def test_target_params_prefers_request_local_fields_over_global_observations():
    ctx = {
        "observations": {
            "params": ["email", "password"],
            "potential_params": ["email", "password"],
        }
    }
    spec = HTTPRequestSpec(
        url="https://ex.test/verify",
        method="POST",
        body_params={"otp": "123456"},
    )
    selected = target_params_for_selector("all_inputs", ctx, spec)
    assert selected == ["otp"]


def test_resolve_probe_base_specs_challenge_url_ignores_candidates():
    cand = request_spec_to_jsonable(HTTPRequestSpec(url="https://other.test/api"))
    ctx = {"observations": {"request_candidates": [cand]}}
    specs = resolve_probe_base_specs(ctx, "https://challenge.test/entry", request_source="challenge_url")
    assert len(specs) == 1
    assert specs[0].url.startswith("https://challenge.test")
    assert specs[0].source == "challenge_url"


def test_resolve_probe_base_specs_discovered_forms_skips_candidates():
    cand = request_spec_to_jsonable(HTTPRequestSpec(url="https://crawl.test/x"))
    form = {
        "action": "https://forms.test/y",
        "method": "GET",
        "fields": [{"name": "q", "value": "1"}],
    }
    ctx = {"observations": {"request_candidates": [cand], "forms": [form]}}
    specs = resolve_probe_base_specs(ctx, "https://fallback.test/", request_source="discovered_forms")
    assert len(specs) >= 1
    assert all("forms.test" in s.url or s.source == "challenge_url" for s in specs)
    assert not any("crawl.test" in s.url for s in specs)


def test_filter_probe_specs_by_candidate_filter_workflow_step():
    ctx = {"challenge": None, "observations": {}}
    a = HTTPRequestSpec(url="https://t/a", method="GET", workflow_step="otp")
    b = HTTPRequestSpec(url="https://t/b", method="GET", workflow_step="login")
    out = filter_probe_specs_by_candidate_filter([a, b], ctx, "request.workflow_step == 'otp'")
    assert len(out) == 1
    assert out[0].url == "https://t/a"


def test_resolve_probe_base_specs_attaches_session_cookies_to_candidates_and_fallback():
    cand = request_spec_to_jsonable(
        HTTPRequestSpec(url="https://sess.test/path", method="POST", body_params={"q": "1"}, cookies={"legacy": "v"})
    )
    ctx = {
        "observations": {
            "request_candidates": [cand],
            "session_cookies": {"session": "abc123", "csrf": "tok"},
        }
    }
    specs = resolve_probe_base_specs(ctx, "https://challenge.test/entry")
    assert specs
    for spec in specs:
        assert spec.cookies is not None
        assert spec.cookies.get("session") == "abc123"
        assert spec.cookies.get("csrf") == "tok"
    assert specs[0].cookies.get("legacy") == "v"

