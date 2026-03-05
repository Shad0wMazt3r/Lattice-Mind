
import pytest
import logging
from unittest.mock import MagicMock, patch
from lattice_mind.mvp import MVPSolver
from lattice_mind.core.types import ChallengeDescriptor, ChallengeType, NodeStatus
from lattice_mind.core.tree_loader import DecisionTree

@pytest.fixture
def mock_registry():
    with patch("lattice_mind.mvp.get_tree_registry") as mock:
        registry = MagicMock()
        mock.return_value = registry
        yield registry

@pytest.fixture
def mock_executor():
    with patch("lattice_mind.mvp.TreeExecutor") as mock:
        executor = MagicMock()
        mock.return_value = executor
        yield executor

def test_mvp_solver_prioritization(mock_registry, mock_executor):
    """Test that MVPSolver sorts trees by confidence before execution."""
    solver = MVPSolver()
    
    # Create two mock trees
    tree_low = MagicMock(spec=DecisionTree)
    tree_low.id = "tree_low"
    tree_low.enabled = True
    tree_low.applies_when = []
    
    tree_high = MagicMock(spec=DecisionTree)
    tree_high.id = "tree_high"
    tree_high.enabled = True
    tree_high.applies_when = []
    
    mock_registry.list_trees.return_value = [tree_low, tree_high]
    
    # Mock confidence pool behavior
    def get_conf(tid):
        mock_conf = MagicMock()
        mock_conf.score = 0.2 if tid == "tree_low" else 0.8
        return mock_conf
    
    solver.confidence_pool.get_tree_confidence = MagicMock(side_effect=get_conf)
    
    # Mock executor behavior (async)
    import asyncio
    future = asyncio.Future()
    future.set_result(None)
    mock_executor.execute_tree.return_value = future
    
    challenge = ChallengeDescriptor(type=ChallengeType.WEB, url="http://test.com")
    
    # We need to mock _classify_asset and _run_detection_tree to avoid real recon
    solver._classify_asset = MagicMock(return_value=ChallengeType.WEB)
    solver._run_detection_tree = MagicMock(return_value=None)
    
    # Mock WebReconProbeNode to avoid real HTTP
    with patch("lattice_mind.mvp.WebReconProbeNode"):
        solver.solve(challenge)
    
    # Check that high confidence tree was executed first
    calls = mock_executor.execute_tree.call_args_list
    assert len(calls) == 2
    assert calls[0][0][0].id == "tree_high"
    assert calls[1][0][0].id == "tree_low"

def test_mvp_solver_stop_on_flag(mock_registry, mock_executor):
    """Test that MVPSolver stops execution once a flag is found."""
    solver = MVPSolver()
    
    tree1 = MagicMock(spec=DecisionTree)
    tree1.id = "tree1"
    tree1.enabled = True
    tree1.applies_when = []
    
    tree2 = MagicMock(spec=DecisionTree)
    tree2.id = "tree2"
    tree2.enabled = True
    tree2.applies_when = []
    
    mock_registry.list_trees.return_value = [tree1, tree2]
    
    # Mock executor behavior: tree1 finds a flag
    import asyncio
    future1 = asyncio.Future()
    future1.set_result("flag{success}")
    mock_executor.execute_tree.side_effect = [future1, asyncio.Future()]
    
    challenge = ChallengeDescriptor(type=ChallengeType.WEB, url="http://test.com")
    solver._classify_asset = MagicMock(return_value=ChallengeType.WEB)
    
    with patch("lattice_mind.mvp.WebReconProbeNode"):
        flag = solver.solve(challenge)
    
    assert flag == "flag{success}"
    assert mock_executor.execute_tree.call_count == 1

if __name__ == "__main__":
    pytest.main([__file__])
