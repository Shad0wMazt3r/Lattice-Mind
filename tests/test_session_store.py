"""Tests for run-scoped session store."""

import pytest

from lattice_mind.core.session_store import SessionStore


def test_merge_and_replace():
    s = SessionStore()
    s.create_or_update(
        "run-1",
        [{"name": "a", "value": "1"}, {"name": "b", "value": "2"}],
        replace=False,
    )
    s.create_or_update("run-1", [{"name": "a", "value": "3"}], replace=False)
    assert s.get("run-1").cookies == {"a": "3", "b": "2"}
    s.create_or_update("run-1", [{"name": "x", "value": "y"}], replace=True)
    assert s.get("run-1").cookies == {"x": "y"}


def test_rotate_version_conflict():
    s = SessionStore()
    s.create_or_update("run-1", [{"name": "s", "value": "1"}])
    v = s.get("run-1").version
    with pytest.raises(ValueError):
        s.rotate("run-1", [{"name": "s", "value": "2"}], expected_version=v + 99)


def test_view_redact():
    s = SessionStore()
    s.create_or_update("run-1", [{"name": "s", "value": "secret"}])
    out = s.view("run-1", include_values=False)
    assert out["cookies"][0]["value_redacted"] is True
