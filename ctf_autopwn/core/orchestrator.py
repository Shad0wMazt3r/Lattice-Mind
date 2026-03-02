"""Central orchestrator for challenge analysis and exploitation."""
import logging
from typing import Dict, Optional, List

from ctf_autopwn.core.types import ChallengeDescriptor, NodeStatus, NodeResult
from ctf_autopwn.core.nodes import DecisionNode
from ctf_autopwn.core.flag_recognizer import get_flag_recognizer
from ctf_autopwn.core.knowledge_base import get_knowledge_base

logger = logging.getLogger(__name__)


class Orchestrator:
    """Central engine that coordinates detection, exploitation, and flag recovery."""
    
    def __init__(self):
        self.challenge: Optional[ChallengeDescriptor] = None
        self.execution_context: Dict = {}
        self.tree_history: List[str] = []
        self.flag_recognizer = get_flag_recognizer()
        self.knowledge_base = get_knowledge_base()
    
    def set_challenge(self, challenge: ChallengeDescriptor):
        """Set the challenge to solve.
        
        Args:
            challenge: ChallengeDescriptor with challenge metadata
        """
        self.challenge = challenge
        self.execution_context = {
            "challenge": challenge,
            "observations": {},
            "flag_found": None,
        }
        self.flag_recognizer.clear()
        self.knowledge_base.clear()
        self.tree_history.clear()
    
    def run_tree(self, root_node: DecisionNode) -> Optional[str]:
        """Execute a decision tree starting from the given node.
        
        Args:
            root_node: Root DecisionNode of the tree to execute
        
        Returns:
            Found flag if successful, None otherwise.
        """
        if not self.challenge:
            raise ValueError("Challenge not set. Call set_challenge() first.")
        
        current_node = root_node
        
        while current_node:
            logger.info(f"Executing node: {current_node}")
            self.tree_history.append(current_node.node_id)
            
            # Run the node
            result = current_node.run(self.execution_context)
            
            # Check for flags in the result
            if result.data:
                for value in result.data.values():
                    if isinstance(value, str):
                        flag = self.flag_recognizer.recognize(value)
                        if flag:
                            logger.info(f"Flag found: {flag}")
                            self.execution_context["flag_found"] = flag
                            return flag
            
            # Check terminal conditions
            if result.status in [NodeStatus.SUCCESS, NodeStatus.FAILURE, NodeStatus.TIMEOUT]:
                logger.info(f"Node completed with status: {result.status}")
                break
            
            if result.status == NodeStatus.ASK_HUMAN:
                logger.warning(f"Node requires human input: {result}")
                break
            
            # Move to next node
            current_node = current_node.next_node(result) if hasattr(current_node, 'next_node') else None
        
        return self.execution_context.get("flag_found")
    
    def get_execution_log(self) -> Dict:
        """Get the execution log for debugging/reproducibility.
        
        Returns:
            Dictionary with tree history and observations.
        """
        return {
            "challenge": self.challenge,
            "tree_history": self.tree_history,
            "observations": self.execution_context.get("observations", {}),
            "flag_found": self.execution_context.get("flag_found"),
        }


# Global instance
_global_orchestrator = Orchestrator()


def get_orchestrator() -> Orchestrator:
    """Get the global orchestrator instance."""
    return _global_orchestrator
