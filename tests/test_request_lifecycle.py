"""Tests for request interception manager."""

import pytest

from lattice_mind.core.request_lifecycle import RequestLifecycleManager


def test_poll_unknown_interception():
    mgr = RequestLifecycleManager()
    r = mgr.poll_interception("int_nonexistent")
    assert r["status"] == "expired"


def test_submit_without_pending_raises():
    mgr = RequestLifecycleManager()
    with pytest.raises(ValueError):
        mgr.submit_mutation("int_x", "req_y", {"set": {"query.a": "1"}})
