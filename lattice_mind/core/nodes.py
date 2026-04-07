"""Decision tree node interface and base classes."""
from abc import ABC, abstractmethod
from typing import Dict, Optional, TYPE_CHECKING
import logging

from lattice_mind.core.types import NodeResult, NodeStatus, ChallengeDescriptor

if TYPE_CHECKING:
    from lattice_mind.core.executor import SignalBus
    from lattice_mind.core.confidence import ConfidencePool

logger = logging.getLogger(__name__)


class DecisionNode(ABC):
    """Abstract base class for decision tree nodes."""
    
    def __init__(self, node_id: str, name: str):
        self.node_id = node_id
        self.name = name
        # Dependencies injected by orchestrator
        self.signal_bus: Optional['SignalBus'] = None
        self.confidence_pool: Optional['ConfidencePool'] = None
        self.tree_id: Optional[str] = None  # Tree this node belongs to
    
    @abstractmethod
    def run(self, context: Dict) -> NodeResult:
        """Execute this node with the given context.
        
        Args:
            context: Shared execution context (challenge descriptor, observations, etc.)
        
        Returns:
            NodeResult with status, data, and optional next node ID.
        """
        pass
    
    def next_node(self, result: NodeResult) -> Optional[str]:
        """Determine the next node based on this result.
        
        Override in subclasses for branching logic.
        
        Args:
            result: Result from this node's execution
        
        Returns:
            Next node ID (string) to execute, or None to terminate.
        """
        return None
    
    def emit_signal(self, signal_name: str, confidence_boost: float = 0.0):
        """Emit a signal and optionally boost tree confidence.
        
        Signals enable YAML-style confidence-based orchestration in Python nodes.
        
        Args:
            signal_name: Signal identifier (e.g., "sqli_confirmed", "lfi_detected")
            confidence_boost: Amount to boost tree confidence (0.0 to 1.0)
            
        Returns:
            Full signal name (tree_id:signal_name) or None if signal_bus not set
        """
        if not self.signal_bus:
            logger.warning(f"[{self.node_id}] Cannot emit signal - signal_bus not injected")
            return None
        
        if not self.tree_id:
            logger.warning(f"[{self.node_id}] Cannot emit signal - tree_id not set")
            return None
        
        full_signal = self.signal_bus.emit(self.tree_id, signal_name)
        logger.info(f"[{self.node_id}] Emitted signal: {full_signal}")
        
        if self.confidence_pool and confidence_boost > 0:
            self.confidence_pool.boost_tree(self.tree_id, confidence_boost)
            logger.info(f"[{self.node_id}] Boosted tree {self.tree_id} confidence by {confidence_boost}")
        
        return full_signal
    
    def has_signal(self, signal_name: str, tree_id: Optional[str] = None) -> bool:
        """Check if a signal has been emitted.
        
        Args:
            signal_name: Signal identifier to check
            tree_id: Tree ID to check (defaults to self.tree_id)
            
        Returns:
            True if signal was emitted, False otherwise
        """
        if not self.signal_bus:
            return False
        
        check_tree_id = tree_id or self.tree_id
        if not check_tree_id:
            return False
        
        return self.signal_bus.has_signal(check_tree_id, signal_name)
    
    def __repr__(self):
        return f"{self.__class__.__name__}(id={self.node_id}, name={self.name})"


class SimpleNode(DecisionNode):
    """A simple passthrough node for testing."""
    
    def run(self, context: Dict) -> NodeResult:
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={"message": f"Executed {self.name}"}
        )
