"""Decision tree node interface and base classes."""
from abc import ABC, abstractmethod
from typing import Dict, Optional

from lattice_mind.core.types import NodeResult, NodeStatus, ChallengeDescriptor


class DecisionNode(ABC):
    """Abstract base class for decision tree nodes."""
    
    def __init__(self, node_id: str, name: str):
        self.node_id = node_id
        self.name = name
    
    @abstractmethod
    def run(self, context: Dict) -> NodeResult:
        """Execute this node with the given context.
        
        Args:
            context: Shared execution context (challenge descriptor, observations, etc.)
        
        Returns:
            NodeResult with status, data, and optional next node ID.
        """
        pass
    
    def next_node(self, result: NodeResult) -> Optional['DecisionNode']:
        """Determine the next node based on this result.
        
        Override in subclasses for branching logic.
        
        Args:
            result: Result from this node's execution
        
        Returns:
            Next DecisionNode to execute, or None to terminate.
        """
        return None
    
    def __repr__(self):
        return f"{self.__class__.__name__}(id={self.node_id}, name={self.name})"


class SimpleNode(DecisionNode):
    """A simple passthrough node for testing."""
    
    def run(self, context: Dict) -> NodeResult:
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={"message": f"Executed {self.name}"}
        )
