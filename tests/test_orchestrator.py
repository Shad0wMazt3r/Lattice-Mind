"""
Deep tests for Orchestrator and SignalBus.

Covers:
- SignalBus.emit: full signal stored, returned value correct
- SignalBus.has_signal: found / not found
- SignalBus: isolation of different tree_ids
- Orchestrator.set_challenge: resets all per-challenge state
- Orchestrator.run_tree: requires challenge set first
- Orchestrator.run_tree: walks nodes, stops on FAILURE
- Orchestrator.run_tree: stops on ASK_HUMAN
- Orchestrator.run_tree: returns flag when recognizer finds one
- Orchestrator.run_tree: traverses linked nodes until None
- Orchestrator.get_execution_log: correct structure
- Orchestrator.set_progress_callback / clear_progress_callback
- Orchestrator._emit_progress: calls callback with correct payload shape
- Orchestrator.set_branch_parent
- Global singleton identity
"""
from unittest.mock import MagicMock, patch

import pytest

from lattice_mind.core.executor import SignalBus
from lattice_mind.core.nodes import DecisionNode, SimpleNode
from lattice_mind.core.orchestrator import Orchestrator, get_orchestrator
from lattice_mind.core.types import (
    ChallengeDescriptor,
    ChallengeType,
    NodeResult,
    NodeStatus,
)

# ──────────────────────────────────────────────────────────────────────────────
# SignalBus
# ──────────────────────────────────────────────────────────────────────────────

class TestSignalBus:

    def mk(self):
        return SignalBus()

    def test_emit_returns_full_signal(self):
        bus = self.mk()
        result = bus.emit("sqli_tree", "sqli_reflected")
        assert result == "sqli_tree:sqli_reflected"

    def test_has_signal_true_after_emit(self):
        bus = self.mk()
        bus.emit("tree_x", "signal_y")
        assert bus.has_signal("tree_x", "signal_y") is True

    def test_has_signal_false_before_emit(self):
        bus = self.mk()
        assert bus.has_signal("tree_x", "signal_y") is False

    def test_different_tree_isolation(self):
        bus = self.mk()
        bus.emit("tree_a", "sig")
        assert bus.has_signal("tree_b", "sig") is False

    def test_different_signal_same_tree(self):
        bus = self.mk()
        bus.emit("tree_x", "signal_one")
        assert bus.has_signal("tree_x", "signal_two") is False

    def test_emit_multiple_signals(self):
        bus = self.mk()
        bus.emit("tree_x", "a")
        bus.emit("tree_x", "b")
        assert bus.has_signal("tree_x", "a")
        assert bus.has_signal("tree_x", "b")

    def test_emit_same_signal_twice_no_error(self):
        bus = self.mk()
        bus.emit("tree_x", "sig")
        bus.emit("tree_x", "sig")  # duplicate — no crash
        assert bus.has_signal("tree_x", "sig")

    def test_signals_stored_as_set(self):
        bus = self.mk()
        assert isinstance(bus.signals, set)


# ──────────────────────────────────────────────────────────────────────────────
# Orchestrator helpers
# ──────────────────────────────────────────────────────────────────────────────

def _make_challenge(url="http://test.local/"):
    return ChallengeDescriptor(type=ChallengeType.WEB, name="Test", url=url)


def _make_node_with_result(status: NodeStatus, data=None, next_node=None):
    """Create a mock DecisionNode that returns a fixed result."""
    # ``run_tree`` intentionally accepts concrete DecisionNode instances for
    # the legacy direct-node path, so keep the test double faithful to that
    # public contract.
    node = MagicMock(spec=DecisionNode)
    node.node_id = f"mock_node_{status.value}"
    node.name = f"Node({status.value})"
    result = NodeResult(status=status, data=data or {})
    node.run.return_value = result
    node.next_node.return_value = next_node
    return node, result


# ──────────────────────────────────────────────────────────────────────────────
# Orchestrator.set_challenge
# ──────────────────────────────────────────────────────────────────────────────

class TestOrchestratorSetChallenge:

    def mk(self):
        return Orchestrator()

    def test_challenge_stored(self):
        orch = self.mk()
        ch = _make_challenge()
        orch.set_challenge(ch)
        assert orch.challenge is ch

    def test_execution_context_reset(self):
        orch = self.mk()
        orch.execution_context = {"old": "data"}
        orch.set_challenge(_make_challenge())
        assert "old" not in orch.execution_context

    def test_execution_context_has_challenge(self):
        orch = self.mk()
        ch = _make_challenge()
        orch.set_challenge(ch)
        assert orch.execution_context["challenge"] is ch

    def test_execution_context_observations_empty(self):
        orch = self.mk()
        orch.set_challenge(_make_challenge())
        assert orch.execution_context["observations"] == {}

    def test_tree_history_cleared(self):
        orch = self.mk()
        orch.tree_history = ["old_node"]
        orch.set_challenge(_make_challenge())
        assert orch.tree_history == []

    def test_flag_recognizer_cleared(self):
        orch = self.mk()
        orch.flag_recognizer.found_flags = ["flag{leftover}"]
        orch.set_challenge(_make_challenge())
        assert orch.flag_recognizer.found_flags == []


# ──────────────────────────────────────────────────────────────────────────────
# Orchestrator.run_tree
# ──────────────────────────────────────────────────────────────────────────────

class TestOrchestratorRunTree:

    def mk(self):
        orch = Orchestrator()
        orch.set_challenge(_make_challenge())
        return orch

    def test_raises_if_no_challenge(self):
        orch = Orchestrator()
        node, _ = _make_node_with_result(NodeStatus.SUCCESS)
        with pytest.raises(ValueError, match="Challenge not set"):
            orch.run_tree(node)

    def test_executes_root_node(self):
        orch = self.mk()
        node, _ = _make_node_with_result(NodeStatus.SUCCESS)
        orch.run_tree(node)
        node.run.assert_called_once()

    def test_appends_to_tree_history(self):
        orch = self.mk()
        node, _ = _make_node_with_result(NodeStatus.SUCCESS)
        orch.run_tree(node)
        assert node.node_id in orch.tree_history

    def test_stops_on_failure_status(self):
        orch = self.mk()
        n1, _ = _make_node_with_result(NodeStatus.FAILURE)
        n2, _ = _make_node_with_result(NodeStatus.SUCCESS)
        n1.next_node.return_value = n2
        orch.run_tree(n1)
        n2.run.assert_not_called()

    def test_stops_on_ask_human_status(self):
        orch = self.mk()
        n1, _ = _make_node_with_result(NodeStatus.ASK_HUMAN)
        n2, _ = _make_node_with_result(NodeStatus.SUCCESS)
        n1.next_node.return_value = n2
        orch.run_tree(n1)
        n2.run.assert_not_called()

    def test_traverses_chain_of_nodes(self):
        orch = self.mk()
        n3, _ = _make_node_with_result(NodeStatus.SUCCESS)
        n2, _ = _make_node_with_result(NodeStatus.SUCCESS, next_node=n3)
        n1, _ = _make_node_with_result(NodeStatus.SUCCESS, next_node=n2)
        orch.run_tree(n1)
        n1.run.assert_called_once()
        n2.run.assert_called_once()
        n3.run.assert_called_once()

    def test_returns_none_when_no_flag(self):
        orch = self.mk()
        node, _ = _make_node_with_result(NodeStatus.SUCCESS)
        result = orch.run_tree(node)
        assert result is None

    def test_returns_flag_found_in_result_data(self):
        orch = self.mk()
        node, _ = _make_node_with_result(
            NodeStatus.SUCCESS,
            data={"output": "The answer is: flag{found_the_flag}"}
        )
        result = orch.run_tree(node)
        assert result == "flag{found_the_flag}"

    def test_flag_stored_in_execution_context(self):
        orch = self.mk()
        node, _ = _make_node_with_result(
            NodeStatus.SUCCESS,
            data={"out": "flag{ctx_flag}"}
        )
        orch.run_tree(node)
        assert orch.execution_context.get("flag_found") == "flag{ctx_flag}"

    def test_simple_node_returns_success(self):
        orch = self.mk()
        node = SimpleNode("sn1", "Simple Node")
        result = orch.run_tree(node)
        # SimpleNode returns SUCCESS with no flag → None
        assert result is None

    def test_context_passthrough(self):
        """run_tree must pass the shared execution_context dict to node.run."""
        orch = self.mk()
        received_ctx = {}

        def capture_ctx(ctx):
            received_ctx.update(ctx)
            return NodeResult(status=NodeStatus.SUCCESS)

        node = MagicMock()
        node.node_id = "spy_node"
        node.name = "Spy"
        node.run.side_effect = capture_ctx
        node.next_node.return_value = None
        orch.run_tree(node)
        assert "challenge" in received_ctx

    def test_timeout_status_stops_traversal(self):
        orch = self.mk()
        n1, _ = _make_node_with_result(NodeStatus.TIMEOUT)
        n2, _ = _make_node_with_result(NodeStatus.SUCCESS)
        n1.next_node.return_value = n2
        orch.run_tree(n1)
        n2.run.assert_not_called()


# ──────────────────────────────────────────────────────────────────────────────
# Orchestrator.get_execution_log
# ──────────────────────────────────────────────────────────────────────────────

class TestOrchestratorGetExecutionLog:

    def mk(self):
        orch = Orchestrator()
        orch.set_challenge(_make_challenge())
        return orch

    def test_returns_dict(self):
        orch = self.mk()
        log = orch.get_execution_log()
        assert isinstance(log, dict)

    def test_log_has_challenge(self):
        orch = self.mk()
        log = orch.get_execution_log()
        assert "challenge" in log

    def test_log_has_tree_history(self):
        orch = self.mk()
        log = orch.get_execution_log()
        assert "tree_history" in log
        assert isinstance(log["tree_history"], list)

    def test_log_has_observations(self):
        orch = self.mk()
        log = orch.get_execution_log()
        assert "observations" in log

    def test_log_has_flag_found(self):
        orch = self.mk()
        log = orch.get_execution_log()
        assert "flag_found" in log

    def test_log_has_evidence_records(self):
        orch = self.mk()
        orch.execution_context["evidence_records"] = [{"kind": "response_delta"}]
        log = orch.get_execution_log()
        assert "evidence_records" in log
        assert log["evidence_records"] == [{"kind": "response_delta"}]

    def test_flag_found_none_initially(self):
        orch = self.mk()
        log = orch.get_execution_log()
        assert log["flag_found"] is None


# ──────────────────────────────────────────────────────────────────────────────
# Progress callback
# ──────────────────────────────────────────────────────────────────────────────

class TestOrchestratorProgressCallback:

    def mk(self):
        orch = Orchestrator()
        orch.set_challenge(_make_challenge())
        return orch

    def test_set_and_call_progress_callback(self):
        orch = self.mk()
        events = []
        orch.set_progress_callback(events.append)

        node, _ = _make_node_with_result(NodeStatus.SUCCESS)
        orch.run_tree(node)
        assert len(events) >= 2  # node_start + node_end

    def test_event_payload_has_event_field(self):
        orch = self.mk()
        events = []
        orch.set_progress_callback(events.append)
        node, _ = _make_node_with_result(NodeStatus.SUCCESS)
        orch.run_tree(node)
        for ev in events:
            assert "event" in ev

    def test_event_payload_has_timestamp(self):
        orch = self.mk()
        events = []
        orch.set_progress_callback(events.append)
        node, _ = _make_node_with_result(NodeStatus.SUCCESS)
        orch.run_tree(node)
        for ev in events:
            assert "timestamp" in ev

    def test_clear_progress_callback_stops_events(self):
        orch = self.mk()
        events = []
        orch.set_progress_callback(events.append)
        orch.clear_progress_callback()
        node, _ = _make_node_with_result(NodeStatus.SUCCESS)
        orch.run_tree(node)
        assert events == []

    def test_no_callback_no_error(self):
        orch = self.mk()  # no callback set
        node, _ = _make_node_with_result(NodeStatus.SUCCESS)
        orch.run_tree(node)  # Should not raise


# ──────────────────────────────────────────────────────────────────────────────
# set_branch_parent
# ──────────────────────────────────────────────────────────────────────────────

class TestOrchestratorSetBranchParent:

    def test_set_branch_parent(self):
        orch = Orchestrator()
        orch.set_branch_parent("parent_node_id")
        assert orch._branch_parent == "parent_node_id"

    def test_branch_parent_consumed_after_run_tree(self):
        orch = Orchestrator()
        orch.set_challenge(_make_challenge())
        orch.set_branch_parent("my_parent")
        node, _ = _make_node_with_result(NodeStatus.SUCCESS)
        orch.run_tree(node)
        # Consumed by the first node
        assert orch._branch_parent is None


# ──────────────────────────────────────────────────────────────────────────────
# Global singleton
# ──────────────────────────────────────────────────────────────────────────────

class TestGetOrchestrator:

    def test_returns_orchestrator_instance(self):
        orch = get_orchestrator()
        assert isinstance(orch, Orchestrator)

    def test_singleton_identity(self):
        o1 = get_orchestrator()
        o2 = get_orchestrator()
        assert o1 is o2
