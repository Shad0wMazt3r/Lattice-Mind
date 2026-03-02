"""Central orchestrator for challenge analysis and exploitation."""
import logging
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from ctf_autopwn.core.types import ChallengeDescriptor, NodeResult, NodeStatus
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
        self._progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None

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

    def set_progress_callback(self, callback: Optional[Callable[[Dict[str, Any]], None]]):
        """Register a callback that receives progress events during execution."""
        self._progress_callback = callback

    def clear_progress_callback(self):
        """Remove any registered progress callback."""
        self._progress_callback = None

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
            self._emit_progress("node_start", current_node)

            # Run the node
            result = current_node.run(self.execution_context)
            self._emit_progress("node_end", current_node, result)

            # Check for flags in the result
            if result.data:
                for value in result.data.values():
                    if isinstance(value, str):
                        flag = self.flag_recognizer.recognize(value)
                        if flag:
                            logger.info(f"Flag found: {flag}")
                            self.execution_context["flag_found"] = flag
                            self._emit_progress("flag_found", current_node, result)
                            return flag

            # Check terminal conditions — only FAILURE/TIMEOUT halt the tree;
            # SUCCESS continues to next_node (which returns None at leaf nodes).
            if result.status in [NodeStatus.FAILURE, NodeStatus.TIMEOUT]:
                logger.info(f"Node halted with status: {result.status}")
                break

            if result.status == NodeStatus.ASK_HUMAN:
                logger.warning(f"Node requires human input: {result}")
                break

            # Move to next node (returns None at leaf → loop exits naturally)
            current_node = current_node.next_node(result) if hasattr(current_node, "next_node") else None

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

    def _emit_progress(self, event: str, node: DecisionNode, result: Optional[NodeResult] = None):
        """Emit structured progress events to registered observers."""
        if not self._progress_callback:
            return

        payload = {
            "event": event,
            "node_id": getattr(node, "node_id", node.__class__.__name__),
            "node_name": getattr(node, "name", node.__class__.__name__),
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }

        if result:
            payload["status"] = getattr(result.status, "value", str(result.status))
            if result.error:
                payload["error"] = result.error
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
