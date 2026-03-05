"""Human-in-the-loop interaction manager — thread-safe API queue."""
import threading
import uuid
from typing import Any, Dict, List, Optional


class HumanLoopManager:
    """
    Thread-safe queue for human-in-the-loop decision points.

    Decision nodes call ask_user() which BLOCKS the solver thread until
    the operator answers via the web API (POST /hitl/{id}/answer).
    Non-interactive mode (interactive=False) returns None immediately.
    """

    def __init__(self, interactive: bool = True, default_timeout: float = 300.0):
        self.interactive = interactive
        self.default_timeout = default_timeout
        self.hints: Dict[str, Any] = {}
        self.overrides: Dict[str, bool] = {}
        self._pending: Dict[str, Dict] = {}
        self._lock = threading.Lock()

    def ask_user(
        self,
        question: str,
        options: Optional[List[str]] = None,
        node_id: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Optional[str]:
        """
        Enqueue a question and block the caller until an answer arrives.

        Returns the operator's answer, or None on timeout / non-interactive.
        """
        if not self.interactive:
            return None

        qid = str(uuid.uuid4())[:12]
        event = threading.Event()
        with self._lock:
            self._pending[qid] = {
                "id": qid,
                "question": question,
                "options": options or [],
                "node_id": node_id,
                "answer": None,
                "_event": event,
            }

        wait_secs = timeout if timeout is not None else self.default_timeout
        answered = event.wait(timeout=wait_secs)

        with self._lock:
            q = self._pending.pop(qid, None)

        return q["answer"] if (answered and q) else None

    def answer(self, qid: str, answer: str) -> bool:
        """Provide an answer to a pending question. Returns True if found."""
        with self._lock:
            q = self._pending.get(qid)
            if not q:
                return False
            q["answer"] = answer
            q["_event"].set()
        return True

    def get_pending(self) -> List[Dict]:
        """Return pending questions safe for JSON serialisation."""
        with self._lock:
            return [
                {k: v for k, v in q.items() if not k.startswith("_")}
                for q in self._pending.values()
            ]

    def set_hint(self, key: str, value: Any):
        self.hints[key] = value

    def get_hint(self, key: str) -> Optional[Any]:
        return self.hints.get(key)

    def set_override(self, key: str, enabled: bool):
        self.overrides[key] = enabled

    def is_overridden(self, key: str) -> bool:
        return self.overrides.get(key, False)

    def clear(self):
        """Reset hints, overrides, and unblock any waiting threads."""
        self.hints.clear()
        self.overrides.clear()
        with self._lock:
            for q in self._pending.values():
                q["_event"].set()
            self._pending.clear()


# Global singleton
_global_human_loop = HumanLoopManager(interactive=True)


def get_human_loop_manager() -> HumanLoopManager:
    """Get the global human loop manager instance."""
    return _global_human_loop
