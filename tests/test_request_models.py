"""Tests for lattice_mind.web.request_models (F1)."""

import json
import pytest

from lattice_mind.web.request_models import (
    HTTPRequestSpec,
    apply_param_payload,
    record_from_adapter_response,
    request_spec_for_challenge_url,
    request_spec_from_form_record,
    request_spec_from_jsonable,
    request_spec_to_jsonable,
    request_view,
    round_trip_request_spec_json,
    spec_to_adapter_args,
)


def test_spec_to_adapter_args_get_query_only():
    spec = HTTPRequestSpec(
        url="https://ex.test/path",
        method="GET",
        query_params={"a": "1"},
        body_params=None,
    )
    args = spec_to_adapter_args(spec)
    assert args["method"] == "GET"
    assert args["params"] == {"a": "1"}


def test_spec_to_adapter_args_post_body_separate_from_query():
    spec = HTTPRequestSpec(
        url="https://ex.test/q",
        method="POST",
        query_params={"q": "x"},
        body_params={"user": "u"},
        content_type="application/x-www-form-urlencoded",
    )
    args = spec_to_adapter_args(spec)
    assert args["method"] == "POST"
    assert args["params"] == {"q": "x"}
    assert args["data"] == {"user": "u"}
    assert "application/x-www-form-urlencoded" in args["headers"]["Content-Type"].lower()


def test_json_body_mutually_exclusive_with_body_params():
    spec = HTTPRequestSpec(
        url="https://ex.test/api",
        method="POST",
        json_body={"k": 1},
        body_params={"x": "y"},
    )
    with pytest.raises(ValueError, match="json_body and body_params"):
        spec_to_adapter_args(spec)


def test_request_spec_json_round_trip():
    spec = HTTPRequestSpec(
        url="https://ex.test/",
        method="POST",
        body_params={"hidden": "tok", "q": ""},
        source="html_form",
        form_id="f1",
    )
    back = round_trip_request_spec_json(spec)
    assert back.url == spec.url
    assert back.body_params == spec.body_params
    assert back.form_id == "f1"


def test_request_spec_from_jsonable_minimal():
    d = {"url": "https://x/", "method": "GET"}
    spec = request_spec_from_jsonable(d)
    assert spec.query_params is None
    assert spec.body_params is None


def test_request_spec_from_form_record_post_hidden():
    form = {
        "action": "https://ex.test/submit",
        "method": "POST",
        "enctype": "application/x-www-form-urlencoded",
        "id": "login",
        "fields": [
            {"name": "csrf", "value": "abc", "type": "hidden"},
            {"name": "user", "value": "", "type": "text"},
        ],
    }
    spec = request_spec_from_form_record(form)
    assert spec.method == "POST"
    assert spec.body_params["csrf"] == "abc"
    assert spec.body_params["user"] == ""
    args = spec_to_adapter_args(spec)
    assert args["data"]["csrf"] == "abc"


def test_apply_param_payload_preserves_other_post_fields():
    base = request_spec_from_form_record(
        {
            "action": "https://ex.test/p",
            "method": "POST",
            "enctype": "application/x-www-form-urlencoded",
            "fields": [
                {"name": "csrf", "value": "s3cr3t", "type": "hidden"},
                {"name": "q", "value": "", "type": "text"},
            ],
        }
    )
    inj = apply_param_payload(base, "q", "' OR 1=1--")
    assert inj.body_params["csrf"] == "s3cr3t"
    assert inj.body_params["q"] == "' OR 1=1--"


def test_record_from_adapter_response():
    spec = request_spec_for_challenge_url("https://ex.test/")
    adapter_out = {
        "status": 200,
        "headers": {"X-Test": "1"},
        "body": "ok",
        "redirect_chain": ["https://ex.test/redirect", "https://ex.test/"],
    }
    rec = record_from_adapter_response(spec, adapter_out, 12.5, adapter_out["redirect_chain"])
    assert rec.response_time_ms == 12.5
    assert rec.request_spec["url"] == "https://ex.test/"
    assert rec.redirect_chain[-1].endswith("ex.test/")


def test_record_from_adapter_response_mutation_fields():
    spec = request_spec_for_challenge_url("https://ex.test/")
    adapter_out = {"status": 200, "headers": {}, "body": ""}
    rec = record_from_adapter_response(
        spec, adapter_out, 1.0, mutation_id="m1", baseline_id="b0"
    )
    assert rec.mutation_id == "m1"
    assert rec.baseline_id == "b0"


def test_spec_to_adapter_args_query_param_pairs_duplicate_keys():
    spec = HTTPRequestSpec(
        url="https://ex.test/path",
        method="GET",
        query_params=None,
        query_param_pairs=[("k", "1"), ("k", "2")],
    )
    args = spec_to_adapter_args(spec)
    assert args["params"] == [("k", "1"), ("k", "2")]


def test_spec_to_adapter_args_rejects_query_pairs_with_query_dict():
    spec = HTTPRequestSpec(
        url="https://ex.test/",
        method="GET",
        query_params={"a": "1"},
        query_param_pairs=[("b", "2")],
    )
    with pytest.raises(ValueError, match="query_param_pairs and query_params"):
        spec_to_adapter_args(spec)


def test_request_spec_pairs_json_round_trip():
    spec = HTTPRequestSpec(
        url="https://ex.test/",
        method="GET",
        query_param_pairs=[("a", "1"), ("a", "2")],
    )
    back = round_trip_request_spec_json(spec)
    assert back.query_param_pairs == [("a", "1"), ("a", "2")]


def test_request_spec_for_challenge_url_preserves_duplicate_keys():
    spec = request_spec_for_challenge_url("https://ex.test/path?id=1&id=2&x=y")
    assert spec.query_params is None
    assert spec.query_param_pairs == [("id", "1"), ("id", "2"), ("x", "y")]
    args = spec_to_adapter_args(spec)
    assert args["params"] == [("id", "1"), ("id", "2"), ("x", "y")]


def test_request_spec_from_form_record_get_preserves_duplicate_action_query():
    form = {
        "action": "https://ex.test/search?id=1&id=2",
        "method": "GET",
        "fields": [{"name": "q", "value": "term", "type": "text"}],
    }
    spec = request_spec_from_form_record(form)
    assert spec.query_param_pairs == [("id", "1"), ("id", "2"), ("q", "term")]
    args = spec_to_adapter_args(spec)
    assert args["params"] == [("id", "1"), ("id", "2"), ("q", "term")]


def test_jsonable_omits_none_fields():
    spec = HTTPRequestSpec(url="https://a/", method="GET")
    d = request_spec_to_jsonable(spec)
    dumped = json.dumps(d)
    assert "null" not in dumped


def test_request_view_includes_path_and_workflow_step():
    spec = HTTPRequestSpec(
        url="https://ex.test/foo/bar?x=1",
        method="post",
        workflow_step="otp",
        source="html_form",
        form_id="f1",
    )
    v = request_view(spec)
    assert v["method"] == "POST"
    assert v["path"] == "/foo/bar"
    assert v["workflow_step"] == "otp"
    assert v["source"] == "html_form"
    assert v["form_id"] == "f1"


def test_request_spec_from_form_record_workflow_step():
    form = {
        "action": "https://ex.test/login",
        "method": "GET",
        "workflow_step": "otp",
        "fields": [{"name": "code", "value": ""}],
    }
    spec = request_spec_from_form_record(form)
    assert spec.workflow_step == "otp"
