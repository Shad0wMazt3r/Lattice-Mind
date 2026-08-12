"""
Deep tests for MVPSolver.

Covers:
- Tree prioritization by confidence (highest confidence executed first)
- Stop-on-flag: stops executing after first flag found
- No flag: returns None when no trees produce a flag
- _classify_asset exception is caught and returns None
- solve() resets confidence pool each call

All tests use full mocking of external I/O and asyncio.run to prevent hangs.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from lattice_mind.core.tree_loader import DecisionTree
from lattice_mind.core.types import ChallengeDescriptor, ChallengeType
from lattice_mind.mvp import normalize_recon_context

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────


def _make_challenge(challenge_type=ChallengeType.WEB, url="http://test.local/"):
    return ChallengeDescriptor(type=challenge_type, name="Test", url=url)


def test_normalize_recon_context_unifies_legacy_shapes():
    context = {
        "observations": {
            "technologies": {"server": "Apache-Coyote/1.1"},
            "found_paths": [{"path": "admin"}],
            "crawled_endpoints": ["/login?next=/admin"],
            "directories": [{"path": "/uploads"}],
            "params": ["id"],
            "potential_params": ["id", "file"],
        }
    }

    normalize_recon_context(context)

    assert context["found_paths"] == ["/admin", "/login", "/uploads"]
    assert context["params"] == ["id", "file"]
    assert {"apache-coyote/1.1", "jsp", "java", "apache"} <= set(
        context["tech_stack"]
    )


def _make_tree(tree_id: str, enabled: bool = True):
    """Create a minimal mock DecisionTree."""
    t = MagicMock(spec=DecisionTree)
    t.id = tree_id
    t.enabled = enabled
    t.applies_when = []
    t.confidence_seeds = []
    t.depends_on = []
    return t


def _make_solver_with_mocks():
    """
    Create an MVPSolver with all expensive __init__ side-effects mocked out:
    - registry.load_from_directory() skipped
    - TreeExecutor replaced with a MagicMock
    - Orchestrator replaced with a MagicMock
    Returns (solver, mock_registry, mock_executor, mock_orchestrator)
    """
    with patch("lattice_mind.mvp.get_tree_registry") as mock_get_reg, patch(
        "lattice_mind.mvp.TreeExecutor"
    ) as mock_executor_cls, patch(
        "lattice_mind.mvp.Orchestrator"
    ) as mock_orch_cls, patch(
        "lattice_mind.mvp.get_flag_recognizer"
    ) as mock_fr:

        mock_registry = MagicMock()
        mock_registry.load_from_directory.return_value = None
        mock_registry.list_trees.return_value = []
        mock_get_reg.return_value = mock_registry

        mock_executor = MagicMock()
        mock_executor_cls.return_value = mock_executor

        mock_orch = MagicMock()
        mock_orch.execution_context = {
            "challenge": None,
            "observations": {
                "asset_type": ChallengeType.WEB,
                "tech_stack": [],
                "found_paths": [],
                "params": [],
            },
            "flag_found": None,
        }
        mock_orch._progress_callback = None
        mock_orch_cls.return_value = mock_orch

        from lattice_mind.mvp import MVPSolver

        solver = MVPSolver()

    return solver, mock_registry, mock_executor, mock_orch


# ──────────────────────────────────────────────────────────────────────────────
# MVPSolver.__init__ and basic construction
# ──────────────────────────────────────────────────────────────────────────────


class TestMVPSolverInit:

    def test_solver_can_be_constructed(self):
        solver, _, _, _ = _make_solver_with_mocks()
        assert solver is not None

    def test_confidence_pool_created(self):
        solver, _, _, _ = _make_solver_with_mocks()
        assert solver.confidence_pool is not None

    def test_registry_load_called(self):
        solver, mock_registry, _, _ = _make_solver_with_mocks()
        mock_registry.load_from_directory.assert_called_once()

    def test_executor_created(self):
        solver, _, mock_executor, _ = _make_solver_with_mocks()
        assert solver.executor is mock_executor


# ──────────────────────────────────────────────────────────────────────────────
# Tree prioritization by confidence
# ──────────────────────────────────────────────────────────────────────────────


class TestMVPSolverPrioritization:

    def _make_confidence_getter(self, scores: dict):
        """Return a side_effect function for get_tree_confidence."""

        def fn(tid):
            mc = MagicMock()
            mc.score = scores.get(tid, 0.0)
            return mc

        return fn

    def test_high_confidence_tree_executed_first(self):
        solver, mock_registry, mock_executor, mock_orch = _make_solver_with_mocks()

        tree_low = _make_tree("tree_low")
        tree_high = _make_tree("tree_high")
        mock_registry.list_trees.return_value = [tree_low, tree_high]

        # Patch confidence pool
        solver.confidence_pool.get_tree_confidence = MagicMock(
            side_effect=self._make_confidence_getter(
                {"tree_low": 0.2, "tree_high": 0.8}
            )
        )

        # evaluate_seeds is a no-op in executor mock
        mock_executor.evaluate_seeds.return_value = None

        # asyncio.run returns None for each tree (no flag)
        with patch("asyncio.run", return_value=None) as mock_run:
            solver._classify_asset = MagicMock(return_value=ChallengeType.WEB)
            # Skip web recon
            mock_orch.run_tree.return_value = None

            solver.solve(_make_challenge())

        # asyncio.run should have been called twice (once per tree)
        assert mock_run.call_count == 2
        # First call should have been for tree_high
        first_tree_arg = mock_run.call_args_list[0][0][0]
        # That's a coroutine — just verify execute_tree was called with tree_high first
        execute_calls = mock_executor.execute_tree.call_args_list
        assert execute_calls[0][0][0].id == "tree_high"
        assert execute_calls[1][0][0].id == "tree_low"

    def test_low_confidence_below_threshold_still_run(self):
        solver, mock_registry, mock_executor, mock_orch = _make_solver_with_mocks()

        tree_a = _make_tree("tree_a")
        mock_registry.list_trees.return_value = [tree_a]

        solver.confidence_pool.get_tree_confidence = MagicMock(
            side_effect=self._make_confidence_getter({"tree_a": 0.1})
        )
        mock_executor.evaluate_seeds.return_value = None

        with patch("asyncio.run", return_value=None):
            solver._classify_asset = MagicMock(return_value=ChallengeType.WEB)
            mock_orch.run_tree.return_value = None
            solver.solve(_make_challenge())

        # Still called once
        mock_executor.execute_tree.assert_called_once()


class TestMVPSolverDynamicReranking:

    def test_reranks_to_highest_unexecuted_after_score_change(self):
        """After each tree run, the next pick uses fresh scores (not fixed list order)."""
        solver, mock_registry, mock_executor, mock_orch = _make_solver_with_mocks()

        tree_a = _make_tree("tree_a")
        tree_b = _make_tree("tree_b")
        tree_c = _make_tree("tree_c")
        mock_registry.list_trees.return_value = [tree_a, tree_b, tree_c]

        runs_done = [0]

        def get_tree_confidence(tid):
            mc = MagicMock()
            if runs_done[0] == 0:
                scores = {"tree_a": 0.35, "tree_b": 0.30, "tree_c": 0.25}
            else:
                scores = {"tree_a": 0.35, "tree_b": 0.30, "tree_c": 0.90}
            mc.score = scores.get(tid, 0.0)
            return mc

        solver.confidence_pool.get_tree_confidence = MagicMock(
            side_effect=get_tree_confidence
        )
        mock_executor.evaluate_seeds.return_value = None

        def asyncio_run_side_effect(_coro):
            runs_done[0] += 1
            return None

        with patch("asyncio.run", side_effect=asyncio_run_side_effect):
            solver._classify_asset = MagicMock(return_value=ChallengeType.WEB)
            mock_orch.run_tree.return_value = None

            solver.solve(_make_challenge())

        ids = [c[0][0].id for c in mock_executor.execute_tree.call_args_list]
        assert ids == ["tree_a", "tree_c", "tree_b"]

    def test_selected_scan_preserves_dependency_order_over_confidence(self):
        solver, mock_registry, mock_executor, mock_orch = _make_solver_with_mocks()
        parent = _make_tree("parent")
        child = _make_tree("child")
        child.depends_on = ["parent"]
        mock_registry.list_trees.return_value = [child, parent]
        solver.confidence_pool.get_tree_confidence = MagicMock(
            side_effect=self._score_getter({"parent": 0.1, "child": 0.9})
        )
        mock_executor.evaluate_seeds.return_value = None

        with patch("asyncio.run", return_value=None):
            solver._classify_asset = MagicMock(return_value=ChallengeType.WEB)
            mock_orch.run_tree.return_value = None
            solver.solve(
                _make_challenge(),
                selected_tree_ids=["child", "parent"],
            )

        ids = [c[0][0].id for c in mock_executor.execute_tree.call_args_list]
        assert ids == ["parent", "child"]

    @staticmethod
    def _score_getter(scores):
        def _get(tree_id):
            return MagicMock(score=scores[tree_id])

        return _get


# ──────────────────────────────────────────────────────────────────────────────
# Stop-on-flag behaviour
# ──────────────────────────────────────────────────────────────────────────────


class TestMVPSolverStopOnFlag:

    def test_stops_after_first_flag(self):
        solver, mock_registry, mock_executor, mock_orch = _make_solver_with_mocks()

        tree1 = _make_tree("tree1")
        tree2 = _make_tree("tree2")
        mock_registry.list_trees.return_value = [tree1, tree2]

        solver.confidence_pool.get_tree_confidence = MagicMock(
            side_effect=lambda tid: MagicMock(score=0.5)
        )
        mock_executor.evaluate_seeds.return_value = None

        # tree1 returns a flag, tree2 should NOT be executed
        with patch("asyncio.run", side_effect=["flag{tree1_flag}", None]) as mock_run:
            solver._classify_asset = MagicMock(return_value=ChallengeType.WEB)
            mock_orch.run_tree.return_value = None

            result = solver.solve(_make_challenge())

        assert result == "flag{tree1_flag}"
        assert mock_run.call_count == 1  # Stopped after first tree
        assert mock_executor.execute_tree.call_count == 1

    def test_returns_flag_from_tree(self):
        solver, mock_registry, mock_executor, mock_orch = _make_solver_with_mocks()

        tree1 = _make_tree("tree1")
        mock_registry.list_trees.return_value = [tree1]
        solver.confidence_pool.get_tree_confidence = MagicMock(
            side_effect=lambda tid: MagicMock(score=0.9)
        )
        mock_executor.evaluate_seeds.return_value = None

        with patch("asyncio.run", return_value="flag{from_yaml_tree}"):
            solver._classify_asset = MagicMock(return_value=ChallengeType.WEB)
            mock_orch.run_tree.return_value = None

            result = solver.solve(_make_challenge())

        assert result == "flag{from_yaml_tree}"

    def test_returns_none_when_no_flag(self):
        solver, mock_registry, mock_executor, mock_orch = _make_solver_with_mocks()
        mock_registry.list_trees.return_value = []

        solver._classify_asset = MagicMock(return_value=ChallengeType.WEB)
        mock_orch.run_tree.return_value = None
        mock_orch.execution_context["flag_found"] = None

        result = solver.solve(_make_challenge())
        assert result is None

    def test_flag_from_orchestrator_context_returned(self):
        solver, mock_registry, _, mock_orch = _make_solver_with_mocks()
        mock_registry.list_trees.return_value = []

        solver._classify_asset = MagicMock(return_value=ChallengeType.WEB)
        mock_orch.run_tree.return_value = None
        mock_orch.execution_context["flag_found"] = "flag{ctx_flag}"

        result = solver.solve(_make_challenge())
        assert result == "flag{ctx_flag}"


# ──────────────────────────────────────────────────────────────────────────────
# Confidence pool reset per solve() call
# ──────────────────────────────────────────────────────────────────────────────


class TestMVPSolverConfidenceReset:

    def test_confidence_pool_cleared_each_solve(self):
        solver, mock_registry, _, mock_orch = _make_solver_with_mocks()
        mock_registry.list_trees.return_value = []

        clear_mock = MagicMock()
        solver.confidence_pool.clear = clear_mock

        solver._classify_asset = MagicMock(return_value=ChallengeType.WEB)
        mock_orch.run_tree.return_value = None

        solver.solve(_make_challenge())
        solver.solve(_make_challenge())

        assert clear_mock.call_count == 2


# ──────────────────────────────────────────────────────────────────────────────
# _classify_asset
# ──────────────────────────────────────────────────────────────────────────────


class TestMVPSolverClassifyAsset:

    def test_classify_asset_exception_returns_none(self):
        solver, _, _, mock_orch = _make_solver_with_mocks()
        mock_orch.run_tree.side_effect = RuntimeError("nmap failed")

        with patch(
            "lattice_mind.mvp.AssetClassifyNetworkNode", return_value=MagicMock()
        ):
            result = solver._classify_asset(_make_challenge())
        assert result is None

    def test_classify_asset_returns_type_from_context(self):
        solver, _, _, mock_orch = _make_solver_with_mocks()
        mock_orch.run_tree.return_value = None
        mock_orch.execution_context["observations"]["asset_type"] = ChallengeType.PWN

        with patch(
            "lattice_mind.mvp.AssetClassifyNetworkNode", return_value=MagicMock()
        ):
            result = solver._classify_asset(_make_challenge())
        assert result == ChallengeType.PWN

    def test_classify_asset_returns_none_when_not_set(self):
        solver, _, _, mock_orch = _make_solver_with_mocks()
        mock_orch.run_tree.return_value = None
        mock_orch.execution_context["observations"].pop("asset_type", None)

        with patch(
            "lattice_mind.mvp.AssetClassifyNetworkNode", return_value=MagicMock()
        ):
            result = solver._classify_asset(_make_challenge())
        assert result is None


# ──────────────────────────────────────────────────────────────────────────────
# solve() — asset classification fallback
# ──────────────────────────────────────────────────────────────────────────────


class TestMVPSolverSolveEdgeCases:

    def test_classify_fail_with_url_continues_as_web(self):
        solver, mock_registry, _, mock_orch = _make_solver_with_mocks()
        mock_registry.list_trees.return_value = []

        solver._classify_asset = MagicMock(return_value=None)
        mock_orch.run_tree.return_value = None

        # Should not raise; continues with WEB type
        result = solver.solve(_make_challenge(url="http://example.com"))
        assert result is None

    def test_classify_fail_no_url_returns_none(self):
        solver, mock_registry, _, mock_orch = _make_solver_with_mocks()
        mock_registry.list_trees.return_value = []

        solver._classify_asset = MagicMock(return_value=None)

        challenge = ChallengeDescriptor(type=ChallengeType.MISC, name="No URL")
        result = solver.solve(challenge)
        assert result is None

    def test_disabled_tree_not_run(self):
        solver, mock_registry, mock_executor, mock_orch = _make_solver_with_mocks()

        tree_disabled = _make_tree("disabled_tree", enabled=False)
        tree_enabled = _make_tree("enabled_tree", enabled=True)
        mock_registry.list_trees.return_value = [tree_disabled, tree_enabled]

        solver.confidence_pool.get_tree_confidence = MagicMock(
            side_effect=lambda tid: MagicMock(score=0.5)
        )
        mock_executor.evaluate_seeds.return_value = None

        with patch("asyncio.run", return_value=None):
            solver._classify_asset = MagicMock(return_value=ChallengeType.WEB)
            mock_orch.run_tree.return_value = None
            solver.solve(_make_challenge())

        # execute_tree should only be called once (for enabled tree)
        assert mock_executor.execute_tree.call_count == 1
        assert mock_executor.execute_tree.call_args[0][0].id == "enabled_tree"
