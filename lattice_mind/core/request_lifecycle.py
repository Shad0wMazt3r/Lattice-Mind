"""Pause / resume HTTP sends during YAML execution (MCP request mutation)."""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from lattice_mind.web.request_models import (
    HTTPRequestSpec,
    request_spec_from_jsonable,
    request_spec_to_jsonable,
)
from lattice_mind.web.request_patch import RequestPatchError, apply_request_patch


def _as_jsonable_spec(spec: HTTPRequestSpec) -> Dict[str, Any]:
    """Serialize spec for MCP payloads."""
    try:
        return request_spec_to_jsonable(spec)
    except Exception:
        return {"url": spec.url, "method": spec.method}


@dataclass
class ArmedInterception:
    interception_id: str
    run_id: str
    match: Dict[str, Any]
    mode: str  # "first" | "all"
    expires_at: Optional[float]
    hits: int = 0


@dataclass
class PendingPause:
    run_id: str
    request_id: str
    tree_id: str
    step_id: str
    spec_snapshot: Dict[str, Any]
    event: threading.Event = field(default_factory=threading.Event)
    result_spec: Optional[HTTPRequestSpec] = None
    error: Optional[str] = None


@dataclass
class MutationRecord:
    mutation_record_id: str
    run_id: str
    interception_id: str
    request_id: str
    applied_fields: List[str]
    note: str


class RequestLifecycleManager:
    """Global interception + mutation audit (keyed by run_id / interception_id)."""

    def __init__(self):
        self._lock = threading.RLock()
        self._armed: Dict[str, ArmedInterception] = {}
        self._run_to_interceptions: Dict[str, List[str]] = {}
        self._pending: Dict[str, PendingPause] = {}
        self._mutations: Dict[str, List[MutationRecord]] = {}

    def register_interception(
        self,
        run_id: str,
        match: Dict[str, Any],
        mode: str = "first",
        ttl_seconds: Optional[int] = None,
    ) -> str:
        if mode not in ("first", "all"):
            raise ValueError("mode must be 'first' or 'all'")
        iid = f"int_{uuid.uuid4().hex[:16]}"
        exp = None
        if ttl_seconds is not None and ttl_seconds > 0:
            exp = time.monotonic() + float(ttl_seconds)
        arm = ArmedInterception(
            interception_id=iid,
            run_id=run_id,
            match=dict(match),
            mode=mode,
            expires_at=exp,
        )
        with self._lock:
            self._armed[iid] = arm
            self._run_to_interceptions.setdefault(run_id, []).append(iid)
        return iid

    def _disarm_if_expired(self, arm: ArmedInterception) -> bool:
        if arm.expires_at is not None and time.monotonic() >= arm.expires_at:
            with self._lock:
                self._armed.pop(arm.interception_id, None)
            return True
        return False

    def _matches(self, arm: ArmedInterception, tree_id: str, step_id: str, spec: HTTPRequestSpec) -> bool:
        m = arm.match
        if m.get("tree_id") and str(m["tree_id"]) != tree_id:
            return False
        if m.get("step_id") and str(m["step_id"]) != step_id:
            return False
        if m.get("method"):
            if (spec.method or "GET").upper() != str(m["method"]).upper():
                return False
        if m.get("url_contains"):
            if str(m["url_contains"]) not in (spec.url or ""):
                return False
        return True

    def intercept_before_send(
        self,
        run_id: str,
        tree_id: str,
        step_id: str,
        spec: HTTPRequestSpec,
        *,
        wait_timeout: float = 300.0,
    ) -> HTTPRequestSpec:
        """Block until mutation submitted or timeout; return spec to send."""
        if not run_id:
            return spec

        with self._lock:
            iids = list(self._run_to_interceptions.get(run_id, []))

        chosen: Optional[ArmedInterception] = None
        for iid in iids:
            arm = self._armed.get(iid)
            if not arm:
                continue
            if self._disarm_if_expired(arm):
                continue
            if not self._matches(arm, tree_id, step_id, spec):
                continue
            if arm.mode == "first" and arm.hits > 0:
                continue
            chosen = arm
            break

        if chosen is None:
            return spec

        req_id = f"req_{uuid.uuid4().hex[:12]}"
        pending = PendingPause(
            run_id=run_id,
            request_id=req_id,
            tree_id=tree_id,
            step_id=step_id,
            spec_snapshot=_as_jsonable_spec(spec),
        )
        with self._lock:
            self._pending[chosen.interception_id] = pending

        pending.event.wait(timeout=wait_timeout)

        with self._lock:
            self._pending.pop(chosen.interception_id, None)
            arm2 = self._armed.get(chosen.interception_id)
            if arm2:
                arm2.hits += 1

        if pending.error:
            # Fail open: send original spec but error is visible via poll/history
            return spec
        if pending.result_spec is not None:
            return pending.result_spec
        return spec

    def poll_interception(self, interception_id: str) -> Dict[str, Any]:
        with self._lock:
            arm = self._armed.get(interception_id)
            pending = self._pending.get(interception_id)
        if not arm:
            return {"status": "expired", "paused_request": None}
        if self._disarm_if_expired(arm):
            return {"status": "expired", "paused_request": None}
        if pending:
            return {
                "status": "pending",
                "paused_request": {
                    "request_id": pending.request_id,
                    "tree_id": pending.tree_id,
                    "step_id": pending.step_id,
                    "request": pending.spec_snapshot,
                },
            }
        return {"status": "none", "paused_request": None}

    def find_pending_for_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            iids = list(self._run_to_interceptions.get(run_id, []))
            for iid in iids:
                pending = self._pending.get(iid)
                if pending:
                    return {
                        "interception_id": iid,
                        "request_id": pending.request_id,
                        "tree_id": pending.tree_id,
                        "step_id": pending.step_id,
                        "request": pending.spec_snapshot,
                    }
        return None

    def submit_mutation(
        self,
        interception_id: str,
        request_id: str,
        mutation: Dict[str, Any],
        *,
        note: Optional[str] = None,
    ) -> Dict[str, Any]:
        with self._lock:
            pending = self._pending.get(interception_id)

        if not pending or pending.request_id != request_id:
            raise ValueError("no pending request for that interception_id/request_id pair")

        try:
            base = request_spec_from_jsonable(pending.spec_snapshot)
            patched = apply_request_patch(base, mutation)
            applied = list((mutation.get("set") or {}).keys())
        except (RequestPatchError, ValueError, KeyError) as e:
            pending.error = str(e)
            pending.event.set()
            raise

        pending.result_spec = patched
        rec_id = f"mut_{uuid.uuid4().hex[:12]}"
        run_id = pending.run_id
        record = MutationRecord(
            mutation_record_id=rec_id,
            run_id=run_id,
            interception_id=interception_id,
            request_id=request_id,
            applied_fields=[str(x) for x in applied],
            note=(note or "")[:2000],
        )
        with self._lock:
            self._mutations.setdefault(run_id, []).append(record)

        pending.event.set()
        return {
            "resumed": True,
            "mutation_record_id": rec_id,
            "applied_fields": record.applied_fields,
        }

    def resume_without_mutation(self, interception_id: str, request_id: str) -> Dict[str, Any]:
        with self._lock:
            pending = self._pending.get(interception_id)
        if not pending or pending.request_id != request_id:
            raise ValueError("no pending request for that interception_id/request_id pair")
        pending.result_spec = request_spec_from_jsonable(pending.spec_snapshot)
        pending.event.set()
        return {"resumed": True, "mutation_record_id": None, "applied_fields": []}

    def drop_interception(self, interception_id: str) -> Dict[str, Any]:
        with self._lock:
            arm = self._armed.pop(interception_id, None)
            pending = self._pending.pop(interception_id, None)
            if arm:
                ids = self._run_to_interceptions.get(arm.run_id, [])
                self._run_to_interceptions[arm.run_id] = [
                    iid for iid in ids if iid != interception_id
                ]
        if pending:
            pending.error = "interception dropped by operator"
            pending.event.set()
        return {"dropped": bool(arm or pending)}

    def list_mutations(self, run_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            rows = list(self._mutations.get(run_id, []))
        rows = rows[-limit:]
        return [
            {
                "mutation_record_id": r.mutation_record_id,
                "interception_id": r.interception_id,
                "request_id": r.request_id,
                "applied_fields": r.applied_fields,
                "note": r.note,
            }
            for r in rows
        ]


_global_rlm = RequestLifecycleManager()


def get_request_lifecycle_manager() -> RequestLifecycleManager:
    return _global_rlm
