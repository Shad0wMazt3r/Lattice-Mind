"""Tests for HTTP request mutation patches."""

import pytest

from lattice_mind.web.request_models import request_spec_for_challenge_url
from lattice_mind.web.request_patch import RequestPatchError, apply_request_patch


def test_set_query_and_header():
    spec = request_spec_for_challenge_url("http://example.com/page?id=1")
    out = apply_request_patch(
        spec,
        {
            "set": {
                "query.id": "2",
                "headers.X-Test": "probe",
            }
        },
    )
    assert "id=2" in out.url or out.query_param_pairs
    assert out.headers.get("X-Test") == "probe"


def test_rejects_crlf_in_header():
    spec = request_spec_for_challenge_url("http://example.com/")
    with pytest.raises(RequestPatchError):
        apply_request_patch(
            spec,
            {"set": {"headers.X": "evil\r\nx: y"}},
        )


def test_blocks_host_header():
    spec = request_spec_for_challenge_url("http://example.com/")
    with pytest.raises(RequestPatchError):
        apply_request_patch(spec, {"set": {"headers.Host": "evil.com"}})
