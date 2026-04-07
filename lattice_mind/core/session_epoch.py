"""Run-scoped session epochs with optimistic rotation semantics."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class Epoch:
    version: int
    cookies: Dict[str, str]
    created_at: float
    ttl_seconds: Optional[int]


class SessionEpochManager:
    def __init__(self) -> None:
        self._epochs: Dict[str, Epoch] = {}
        self._lock = threading.RLock()

    def commit(
        self,
        run_id: str,
        cookies: List[Dict[str, str]],
        ttl_seconds: Optional[int],
        *,
        replace: bool = False,
    ) -> Epoch:
        clean: Dict[str, str] = {}
        for c in cookies:
            name = str(c.get("name", "")).strip()
            value = str(c.get("value", ""))
            if not name:
                raise ValueError("cookie name is required")
            if len(name) > 256 or len(value) > 8192:
                raise ValueError("cookie exceeds max length")
            if any(x in name for x in ("\r", "\n")) or any(
                x in value for x in ("\r", "\n")
            ):
                raise ValueError("cookie contains control characters")
            clean[name] = value

        now = time.monotonic()
        with self._lock:
            prev = self._epochs.get(run_id)
            prev_cookies = dict(prev.cookies) if prev else {}
            if replace:
                merged = clean
            else:
                merged = prev_cookies
                merged.update(clean)
            version = (prev.version + 1) if prev else 1
            epoch = Epoch(
                version=version,
                cookies=merged,
                created_at=now,
                ttl_seconds=ttl_seconds,
            )
            self._epochs[run_id] = epoch
            return epoch

    def read(self, run_id: str) -> Optional[Epoch]:
        with self._lock:
            epoch = self._epochs.get(run_id)
            if not epoch:
                return None
            if epoch.ttl_seconds is not None:
                if time.monotonic() >= epoch.created_at + float(epoch.ttl_seconds):
                    self._epochs.pop(run_id, None)
                    return None
            return Epoch(
                version=epoch.version,
                cookies=dict(epoch.cookies),
                created_at=epoch.created_at,
                ttl_seconds=epoch.ttl_seconds,
            )

    def rotate(
        self,
        run_id: str,
        cookies: List[Dict[str, str]],
        *,
        expected_version: Optional[int] = None,
        ttl_seconds: Optional[int] = None,
    ) -> Epoch:
        with self._lock:
            current = self.read(run_id)
            if not current:
                raise KeyError(f"no session for run_id {run_id!r}")
            if expected_version is not None and current.version != int(expected_version):
                raise ValueError(
                    f"session version mismatch: expected {expected_version}, have {current.version}"
                )
        return self.commit(run_id, cookies, ttl_seconds, replace=True)

    def expire(self, run_id: str) -> None:
        with self._lock:
            self._epochs.pop(run_id, None)


_global_epoch_manager = SessionEpochManager()


def get_session_epoch_manager() -> SessionEpochManager:
    return _global_epoch_manager

