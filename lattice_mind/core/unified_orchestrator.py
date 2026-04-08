"""Unified tree orchestrator that executes both Python and YAML trees.

This module bridges the gap between Python DecisionNode-based trees and
YAML declarative trees, providing a single execution interface that shares
state (SignalBus, ConfidencePool) between both systems.
"""
import logging
import asyncio
from typing import Any, Dict, List, Optional, Union

from lattice_mind.core.types import ChallengeDescriptor, NodeResult, NodeStatus
from lattice_mind.core.nodes import DecisionNode
from lattice_mind.core.orchestrator import Orchestrator
from lattice_mind.core.executor import TreeExecutor, SignalBus
from lattice_mind.core.confidence import ConfidencePool
from lattice_mind.core.tree_loader import DecisionTree, TreeRegistry
from lattice_mind.core.flag_recognizer import get_flag_recognizer
from lattice_mind.core.knowledge_base import get_knowledge_base
from lattice_mind.core.node_registry import get_node_registry

logger = logging.getLogger(__name__)


class UnifiedTreeOrchestrator:
    """Single orchestrator for both Python and YAML decision trees.
    
    Provides unified execution with shared:
    - SignalBus (cross-tree signal emission)
    - ConfidencePool (confidence tracking)
    - Execution context (observations, flags)
    - Flag recognition (global flag detector)
    
    This allows Python trees to emit signals that YAML trees can consume,
    and vice versa, enabling hybrid exploitation workflows.
    """
    
    def __init__(self):
        self.challenge: Optional[ChallengeDescriptor] = None
        self.execution_context: Dict = {}
        
        # Shared state between Python and YAML trees
        self.signal_bus = SignalBus()
        self.confidence_pool = ConfidencePool()
        self.flag_recognizer = get_flag_recognizer()
        self.knowledge_base = get_knowledge_base()
        
        # Python tree execution (via existing Orchestrator)
        self.python_orchestrator = Orchestrator()
        
        # YAML tree execution (via existing TreeExecutor)
        self.yaml_executor = TreeExecutor(self.confidence_pool)
        
        # Tree registries
        self.node_registry = get_node_registry()
        self.yaml_registry = TreeRegistry()
        
        # Execution tracking
        self.tree_history: List[str] = []
        self._progress_callback = None
    
    def set_challenge(self, challenge: ChallengeDescriptor):
        """Set the challenge and initialize shared context.
        
        Args:
            challenge: Challenge to solve
        """
        self.challenge = challenge
        self.execution_context = {
            "challenge": challenge,
            "observations": {},
            "flag_found": None,
            "confirmed_vulns": [],
        }
        
        # Reset shared state
        self.signal_bus = SignalBus()
        self.confidence_pool = ConfidencePool()
        self.flag_recognizer.clear()
        self.knowledge_base.clear()
        self.tree_history.clear()
        
        # Configure sub-orchestrators with shared state
        self.python_orchestrator.set_challenge(challenge)
        self.python_orchestrator.signal_bus = self.signal_bus
        self.python_orchestrator.confidence_pool = self.confidence_pool
        self.python_orchestrator.execution_context = self.execution_context
        
        self.yaml_executor.signal_bus = self.signal_bus
        self.yaml_executor.confidence_pool = self.confidence_pool
    
    def set_progress_callback(self, callback):
        """Set progress callback for UI updates."""
        self._progress_callback = callback
        self.python_orchestrator.set_progress_callback(callback)
        self.yaml_executor.set_progress_callback(callback)
    
    async def solve_async(self) -> Optional[str]:
        """Execute all applicable trees (Python and YAML) to find flag.
        
        Returns:
            Found flag or None
        """
        if not self.challenge:
            raise ValueError("Challenge not set. Call set_challenge() first.")
        
        logger.info(f"[unified] Solving challenge: {self.challenge.name or self.challenge.type}")
        
        # Get applicable trees for this challenge type
        python_trees = self._get_python_trees()
        yaml_trees = self._get_yaml_trees()
        
        logger.info(f"[unified] Found {len(python_trees)} Python trees, {len(yaml_trees)} YAML trees")
        
        # Execute trees in priority order
        all_trees = self._prioritize_trees(python_trees, yaml_trees)
        
        for tree_info in all_trees:
            tree_type = tree_info["type"]
            tree_id = tree_info["id"]
            
            logger.info(f"[unified] Executing {tree_type} tree: {tree_id}")
            self.tree_history.append(f"{tree_type}:{tree_id}")
            
            try:
                if tree_type == "python":
                    # Execute Python DecisionNode chain
                    root_node = tree_info["root_node"]
                    flag = self._run_python_tree(root_node)
                    
                    if flag:
                        logger.info(f"[unified] FLAG FOUND by Python tree {tree_id}: {flag}")
                        return flag
                
                elif tree_type == "yaml":
                    # Execute YAML declarative tree
                    yaml_tree = tree_info["tree"]
                    flag = await self._run_yaml_tree(yaml_tree)
                    
                    if flag:
                        logger.info(f"[unified] FLAG FOUND by YAML tree {tree_id}: {flag}")
                        return flag
            
            except Exception as e:
                logger.error(f"[unified] Tree {tree_id} failed: {str(e)}")
                continue
        
        # No flag found
        logger.warning("[unified] No flag found after executing all trees")
        return self.execution_context.get("flag_found")
    
    def solve(self) -> Optional[str]:
        """Synchronous wrapper for solve_async."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self.solve_async())
        finally:
            loop.close()
    
    def _get_python_trees(self) -> List[str]:
        """Get Python tree node IDs applicable for challenge type."""
        # Map challenge types to Python tree root nodes
        challenge_type = self.challenge.type
        
        tree_map = {
            "web": ["web_recon_probe", "sqli_detect_reflection", "lfi_detect_traversal"],
            "pwn": ["pwn_detect_metadata"],
            "crypto": ["crypto_detect_encoding"],
            "forensics": ["asset_type_classify"],
            # Add more mappings as trees are implemented
        }
        
        return tree_map.get(challenge_type.value, [])
    
    def _get_yaml_trees(self) -> List[DecisionTree]:
        """Get YAML trees applicable for challenge type."""
        try:
            challenge_type = self.challenge.type.value
            yaml_trees = self.yaml_registry.get_trees_by_category(challenge_type)
            return yaml_trees
        except Exception as e:
            logger.warning(f"[unified] Failed to load YAML trees: {e}")
            return []
    
    def _prioritize_trees(self, python_trees: List[str], yaml_trees: List[DecisionTree]) -> List[Dict]:
        """Prioritize and interleave Python and YAML trees.
        
        Strategy:
        1. Run recon/detection trees first (both Python and YAML)
        2. Run exploitation trees after detection signals emitted
        3. Prioritize trees with higher initial confidence
        
        Returns:
            List of tree info dicts with keys: type, id, root_node/tree
        """
        all_trees = []
        
        # Add Python trees
        for node_id in python_trees:
            all_trees.append({
                "type": "python",
                "id": node_id,
                "root_node": self.node_registry.create(node_id),
                "priority": self._get_python_tree_priority(node_id),
            })
        
        # Add YAML trees
        for yaml_tree in yaml_trees:
            all_trees.append({
                "type": "yaml",
                "id": yaml_tree.id,
                "tree": yaml_tree,
                "priority": self._get_yaml_tree_priority(yaml_tree),
            })
        
        # Sort by priority (lower number = higher priority)
        all_trees.sort(key=lambda x: x["priority"])
        
        return all_trees
    
    def _get_python_tree_priority(self, node_id: str) -> int:
        """Assign priority to Python tree (lower = higher priority)."""
        # Recon/detection first
        if "recon" in node_id or "detect" in node_id:
            return 10
        # Exploitation second
        elif "exploit" in node_id:
            return 50
        else:
            return 30
    
    def _get_yaml_tree_priority(self, tree: DecisionTree) -> int:
        """Assign priority to YAML tree."""
        # Use min_confidence as priority indicator
        # Lower confidence threshold = more exploratory = run first
        return int(tree.min_confidence * 100)
    
    def _run_python_tree(self, root_node: DecisionNode) -> Optional[str]:
        """Execute Python DecisionNode chain.
        
        Args:
            root_node: Starting node of tree
            
        Returns:
            Found flag or None
        """
        try:
            # Set current tree ID for signal emission
            self.python_orchestrator.current_tree_id = root_node.node_id
            
            # Execute tree
            flag = self.python_orchestrator.run_tree(root_node)
            
            # Sync context back (observations may have been updated)
            self.execution_context = self.python_orchestrator.execution_context
            
            return flag
        
        except Exception as e:
            logger.error(f"[unified] Python tree {root_node.node_id} failed: {e}")
            return None
    
    async def _run_yaml_tree(self, tree: DecisionTree) -> Optional[str]:
        """Execute YAML declarative tree.
        
        Args:
            tree: YAML DecisionTree instance
            
        Returns:
            Found flag or None
        """
        try:
            # Execute tree with shared context
            await self.yaml_executor.execute_tree(tree, self.execution_context)
            
            # Check if flag was found
            flag = self.execution_context.get("flag_found")
            
            # Also check yaml_executor captures
            if not flag:
                for capture_value in self.yaml_executor.captures.values():
                    if isinstance(capture_value, str):
                        flag = self.flag_recognizer.recognize(capture_value)
                        if flag:
                            self.execution_context["flag_found"] = flag
                            break
            
            return flag
        
        except Exception as e:
            logger.error(f"[unified] YAML tree {tree.id} failed: {e}")
            return None
    
    def get_execution_log(self) -> Dict:
        """Get execution log for debugging.
        
        Returns:
            Dictionary with execution history and findings
        """
        return {
            "challenge": self.challenge,
            "tree_history": self.tree_history,
            "observations": self.execution_context.get("observations", {}),
            "confirmed_vulns": self.execution_context.get("confirmed_vulns", []),
            "signals": list(self.signal_bus.signals),
            "confidence_scores": {
                tree_id: self.confidence_pool.get_tree_confidence(tree_id).score
                for tree_id in self.tree_history
            },
            "flag_found": self.execution_context.get("flag_found"),
        }
    
    def get_learning_hints(self) -> List[Dict]:
        """Get learning hints from YAML executor.
        
        Returns:
            List of learning hint dictionaries
        """
        return self.yaml_executor.consume_learning_hints()


# Convenience function for quick usage
def solve_challenge(challenge: ChallengeDescriptor) -> Optional[str]:
    """Solve challenge using unified orchestrator.
    
    Args:
        challenge: Challenge descriptor
        
    Returns:
        Found flag or None
    """
    orchestrator = UnifiedTreeOrchestrator()
    orchestrator.set_challenge(challenge)
    return orchestrator.solve()
