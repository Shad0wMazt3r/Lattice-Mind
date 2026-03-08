"""Central orchestrator for challenge analysis and exploitation."""
import logging
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from lattice_mind.core.types import ChallengeDescriptor, NodeResult, NodeStatus
from lattice_mind.core.nodes import DecisionNode
from lattice_mind.core.flag_recognizer import get_flag_recognizer
from lattice_mind.core.knowledge_base import get_knowledge_base

logger = logging.getLogger(__name__)


class Orchestrator:
    """Central engine that coordinates detection, exploitation, and flag recovery."""

    def __init__(self):
        self.challenge: Optional[ChallengeDescriptor] = None
        self.execution_context: Dict = {}
        self.tree_history: List[str] = []
        self.flag_recognizer = get_flag_recognizer()
        self.knowledge_base = get_knowledge_base()
        self._progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None
        # Tree parent tracking — used to build the tree in the UI
        self._last_node_id: Optional[str] = None
        self._branch_parent: Optional[str] = None

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
        self._last_node_id = None
        self._branch_parent = None

    def set_progress_callback(self, callback: Optional[Callable[[Dict[str, Any]], None]]):
        """Register a callback that receives progress events during execution."""
        self._progress_callback = callback

    def clear_progress_callback(self):
        """Remove any registered progress callback."""
        self._progress_callback = None

    def set_branch_parent(self, parent_node_id: str):
        """Mark that the next run_tree() root should appear as a child of this node in the UI."""
        self._branch_parent = parent_node_id

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
        is_root_node = True

        while current_node:
            logger.info(f"Executing node: {current_node}")
            self.tree_history.append(current_node.node_id)

            # Determine parent: explicit branch_parent for first node of a new tree,
            # otherwise the last completed node (linear chain).
            if is_root_node:
                parent_id = self._branch_parent or self._last_node_id
                self._branch_parent = None  # consume once
                is_root_node = False
            else:
                parent_id = self._last_node_id

            self._emit_progress("node_start", current_node, parent_node_id=parent_id)

            # Run the node
            result = current_node.run(self.execution_context)
            self._last_node_id = current_node.node_id

            if not isinstance(result, NodeResult):
                logger.warning(f"Node {current_node} returned invalid result {result}; stopping tree.")
                break
            
            # Determine next node BEFORE emitting node_end so we can include it
            next_node = current_node.next_node(result) if hasattr(current_node, "next_node") else None
            if next_node:
                result.next_node = getattr(next_node, "node_id", next_node.__class__.__name__)
            
            self._emit_progress("node_end", current_node, result, parent_node_id=parent_id)

            # Check for flags in the result
            if result.data:
                for value in result.data.values():
                    if isinstance(value, str):
                        flag = self.flag_recognizer.recognize(value)
                        if flag:
                            logger.info(f"Flag found: {flag}")
                            self.execution_context["flag_found"] = flag
                            self._emit_progress("flag_found", current_node, result, parent_node_id=parent_id)
                            return flag

            # Check terminal conditions
            if result.status in [NodeStatus.FAILURE, NodeStatus.TIMEOUT]:
                logger.info(f"Node halted with status: {result.status}")
                break

            if result.status == NodeStatus.ASK_HUMAN:
                logger.warning(f"Node requires human input: {result}")
                break

            # Move to next node
            current_node = next_node

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

    def _emit_progress(self, event: str, node: DecisionNode, result: Optional[NodeResult] = None, parent_node_id: Optional[str] = None):
        """Emit structured progress events to registered observers."""
        if not self._progress_callback:
            return

        payload = {
            "event": event,
            "node_id": getattr(node, "node_id", node.__class__.__name__),
            "node_name": getattr(node, "name", node.__class__.__name__),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "parent_node_id": parent_node_id,
        }

        if result:
            payload["status"] = getattr(result.status, "value", str(result.status))
            if result.error:
                payload["error"] = result.error
            if result.next_node:
                payload["next_node"] = result.next_node
            if result.data:
                payload["data_keys"] = list(result.data.keys())
                # Include actual values, truncated to keep events lean
                safe = {}
                for k, v in result.data.items():
                    if isinstance(v, (str, int, float, bool)) or v is None:
                        safe[k] = str(v)[:300] if isinstance(v, str) else v
                    elif isinstance(v, (list, dict)):
                        try:
                            import json as _json
                            s = _json.dumps(v, default=str)
                            safe[k] = _json.loads(s[:1000]) if len(s) > 1000 else v
                        except Exception:
                            safe[k] = str(v)[:300]
                    else:
                        safe[k] = str(v)[:300]
                payload["data"] = safe

        try:
            self._progress_callback(payload)
        except Exception:  # pragma: no cover - defensive logging
            logger.exception("Progress callback failed")


# Global instance
_global_orchestrator = Orchestrator()


def get_orchestrator() -> Orchestrator:
    """Get the global orchestrator instance."""
    return _global_orchestrator
