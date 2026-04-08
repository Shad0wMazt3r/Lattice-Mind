"""Run-scoped cookie/session state for MCP-mediated authenticated scans."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SessionRecord:
    """Cookie jar for one run_id (name -> value)."""

    run_id: str
    cookies: Dict[str, str] = field(default_factory=dict)
    version: int = 0
    expires_at: Optional[float] = None  # monotonic deadline if ttl set

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.monotonic() >= self.expires_at


class SessionStore:
    """Thread-safe in-memory session storage keyed by run_id."""

    def __init__(self):
        self._lock = threading.RLock()
        self._by_run: Dict[str, SessionRecord] = {}

    def get(self, run_id: str) -> Optional[SessionRecord]:
        with self._lock:
            rec = self._by_run.get(run_id)
            if rec and rec.is_expired():
                del self._by_run[run_id]
                return None
            return rec

    def create_or_update(
        self,
        run_id: str,
        cookies: List[Dict[str, Any]],
        *,
        replace: bool = False,
        ttl_seconds: Optional[int] = None,
    ) -> SessionRecord:
        """Merge or replace cookies. Each cookie dict must have name and value."""
        now = time.monotonic()
        exp = None
        if ttl_seconds is not None and ttl_seconds > 0:
            exp = now + float(ttl_seconds)

        with self._lock:
            rec = self._by_run.get(run_id)
            if rec and rec.is_expired():
                rec = None
            if rec is None:
                rec = SessionRecord(run_id=run_id, cookies={}, version=0, expires_at=exp)
            else:
                rec.expires_at = exp if exp is not None else rec.expires_at

            new_jar: Dict[str, str] = {}
            for c in cookies:
                if not isinstance(c, dict):
                    continue
                name = str(c.get("name", "")).strip()
                if not name or len(name) > 256:
                    continue
                val = c.get("value")
                if val is None:
                    continue
                val_s = str(val)
                if len(val_s) > 8192:
                    raise ValueError(f"cookie {name!r} value too large")
                # Minimal validation: block obvious header injection in names
                if "\n" in name or "\r" in name:
                    raise ValueError("invalid cookie name")
                new_jar[name] = val_s

            if replace:
                rec.cookies = dict(new_jar)
            else:
                rec.cookies.update(new_jar)
            rec.version += 1
            self._by_run[run_id] = rec
            return rec

    def rotate(
        self,
        run_id: str,
        cookies: List[Dict[str, Any]],
        *,
        expected_version: Optional[int] = None,
        ttl_seconds: Optional[int] = None,
    ) -> SessionRecord:
        with self._lock:
            rec = self._by_run.get(run_id)
            if rec and rec.is_expired():
                rec = None
            if rec is None:
                raise KeyError(f"no session for run_id {run_id!r}")
            if expected_version is not None and rec.version != int(expected_version):
                raise ValueError(
                    f"session version mismatch: expected {expected_version}, have {rec.version}"
                )
        return self.create_or_update(run_id, cookies, replace=True, ttl_seconds=ttl_seconds)

    def view(self, run_id: str, *, include_values: bool) -> Dict[str, Any]:
        rec = self.get(run_id)
        if not rec:
            return {"session_id": None, "cookies": [], "version": 0}
        cookies_out: List[Dict[str, Any]] = []
        for name, val in sorted(rec.cookies.items()):
            if include_values:
                cookies_out.append({"name": name, "value": val})
            else:
                cookies_out.append({"name": name, "value_redacted": True, "value_len": len(val)})
        return {
            "session_id": f"sess_{run_id}",
            "cookies": cookies_out,
            "version": rec.version,
        }


_global_sessions = SessionStore()


def get_session_store() -> SessionStore:
    return _global_sessions
