"""Persistent tactic memory for mutation-family ranking (F6)."""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

DEFAULT_DB_PATH = os.environ.get(
    "LATTICE_MIND_DB", str(Path.home() / ".lattice-mind" / "runs.db")
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _db_path() -> str:
    return DEFAULT_DB_PATH


def _connect() -> sqlite3.Connection:
    path = _db_path()
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_schema() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS strategy_memory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scope_type TEXT NOT NULL,
                scope_value TEXT NOT NULL,
                endpoint_pattern TEXT NOT NULL,
                mutation_kind TEXT NOT NULL,
                success_count INTEGER NOT NULL DEFAULT 0,
                signal_count INTEGER NOT NULL DEFAULT 0,
                failure_count INTEGER NOT NULL DEFAULT 0,
                last_used_at TEXT,
                notes TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS uq_strategy_memory_scope
            ON strategy_memory(scope_type, scope_value, endpoint_pattern, mutation_kind)
            """
        )


def host_fingerprint_from_url(url: str) -> str:
    return (urlparse(url).netloc or "").lower()


def endpoint_pattern_from_url(url: str) -> str:
    path = urlparse(url).path or "/"
    bits = [b for b in path.split("/") if b]
    if not bits:
        return "/"
    if len(bits) == 1:
        return "/" + bits[0]
    return "/" + bits[0] + "/*"


def _extract_input_names(request_spec: Dict[str, Any]) -> List[str]:
    names: List[str] = []
    for k in (request_spec.get("query_params") or {}).keys():
        if k not in names:
            names.append(str(k))
    for k, _ in (request_spec.get("query_param_pairs") or []):
        ks = str(k)
        if ks not in names:
            names.append(ks)
    for k in (request_spec.get("body_params") or {}).keys():
        if k not in names:
            names.append(str(k))
    for k, _ in (request_spec.get("body_param_pairs") or []):
        ks = str(k)
        if ks not in names:
            names.append(ks)
    return names


def _quality_score(row: Dict[str, Any]) -> float:
    s = int(row.get("success_count") or 0)
    g = int(row.get("signal_count") or 0)
    f = int(row.get("failure_count") or 0)
    total = s + g + f
    if total <= 0:
        return 0.0
    # Conservative weighting: failures reduce but do not dominate permanently.
    return (2.0 * s + 1.0 * g - 0.6 * f) / (total + 2.0)


def _otp_bias(request_spec: Dict[str, Any], mutation_kind: str) -> float:
    method = str(request_spec.get("method") or "GET").upper()
    names = {n.lower() for n in _extract_input_names(request_spec)}
    otpish = {
        "otp",
        "mfa",
        "2fa",
        "totp",
        "one_time_code",
        "verification_code",
        "code",
    }
    if method == "POST" and names.intersection(otpish):
        if mutation_kind in {"param_remove", "value_empty", "body_drop"}:
            return 0.8
    return 0.0


def list_strategy_memory(limit: int = 200) -> List[Dict[str, Any]]:
    ensure_schema()
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT id, scope_type, scope_value, endpoint_pattern, mutation_kind,
                   success_count, signal_count, failure_count, last_used_at, notes
            FROM strategy_memory
            ORDER BY COALESCE(last_used_at, '') DESC, id DESC
            LIMIT ?
            """,
            (max(1, min(int(limit), 2000)),),
        ).fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        d["score"] = round(_quality_score(d), 4)
        out.append(d)
    return out


def reset_strategy_memory(scope_type: Optional[str] = None, scope_value: Optional[str] = None) -> int:
    ensure_schema()
    with _connect() as conn:
        if scope_type and scope_value:
            cur = conn.execute(
                "DELETE FROM strategy_memory WHERE scope_type=? AND scope_value=?",
                (scope_type, scope_value),
            )
        elif scope_type:
            cur = conn.execute(
                "DELETE FROM strategy_memory WHERE scope_type=?",
                (scope_type,),
            )
        else:
            cur = conn.execute("DELETE FROM strategy_memory")
        return int(cur.rowcount or 0)


def _fetch_rows(
    challenge_type: str,
    host_fingerprint: str,
    endpoint_pattern: str,
) -> List[Dict[str, Any]]:
    ensure_schema()
    eps = {endpoint_pattern, "*"}
    if endpoint_pattern.endswith("/*"):
        eps.add(endpoint_pattern[:-2])
    elif endpoint_pattern not in {"/", "*"}:
        bits = [b for b in endpoint_pattern.split("/") if b]
        if bits:
            eps.add("/" + bits[0] + "/*")
    ep_list = sorted(eps)
    placeholders = ",".join("?" for _ in ep_list)
    with _connect() as conn:
        rows = conn.execute(
            f"""
            SELECT scope_type, scope_value, endpoint_pattern, mutation_kind,
                   success_count, signal_count, failure_count, last_used_at, notes
            FROM strategy_memory
            WHERE endpoint_pattern IN ({placeholders})
              AND (
                (scope_type='challenge_type' AND scope_value=?)
                OR (scope_type='host_fingerprint' AND scope_value=?)
              )
            """,
            (*ep_list, challenge_type, host_fingerprint),
        ).fetchall()
    return [dict(r) for r in rows]


def rank_mutation_families(
    families: Sequence[str],
    *,
    challenge_type: str,
    host_fingerprint: str,
    endpoint_pattern: str,
    request_spec: Dict[str, Any],
) -> Tuple[List[str], List[Dict[str, Any]]]:
    """Return re-ranked families and concise applied hints."""
    uniq: List[str] = []
    for f in families:
        if f not in uniq:
            uniq.append(f)
    if len(uniq) <= 1:
        return uniq, []

    rows = _fetch_rows(challenge_type, host_fingerprint, endpoint_pattern)
    by_family: Dict[str, float] = {f: 0.0 for f in uniq}
    reasons: Dict[str, List[str]] = {f: [] for f in uniq}
    for row in rows:
        mk = row.get("mutation_kind")
        if mk not in by_family:
            continue
        score = _quality_score(row)
        scope_weight = 1.5 if row.get("scope_type") == "host_fingerprint" else 1.0
        by_family[mk] += score * scope_weight
        reasons[mk].append(f"{row.get('scope_type')}:{row.get('scope_value')}")

    for f in uniq:
        by_family[f] += _otp_bias(request_spec, f)

    static_bias = {
        "param_remove": 0.20,
        "value_empty": 0.15,
        "body_drop": 0.10,
    }
    for f in uniq:
        by_family[f] += static_bias.get(f, 0.0)

    order_index = {f: i for i, f in enumerate(uniq)}
    ranked = sorted(uniq, key=lambda f: (-by_family.get(f, 0.0), order_index[f]))

    hints: List[Dict[str, Any]] = []
    for f in ranked[:5]:
        sc = by_family.get(f, 0.0)
        if sc <= 0:
            continue
        src = sorted(set(reasons.get(f) or []))
        hints.append(
            {
                "mutation_kind": f,
                "score": round(sc, 4),
                "reason": ", ".join(src) if src else "heuristic",
                "endpoint_pattern": endpoint_pattern,
            }
        )
    return ranked, hints


def _upsert_delta(
    scope_type: str,
    scope_value: str,
    endpoint_pattern: str,
    mutation_kind: str,
    *,
    success_delta: int,
    signal_delta: int,
    failure_delta: int,
    notes: str = "",
) -> None:
    now = _now()
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO strategy_memory (
                scope_type, scope_value, endpoint_pattern, mutation_kind,
                success_count, signal_count, failure_count, last_used_at, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scope_type, scope_value, endpoint_pattern, mutation_kind)
            DO UPDATE SET
                success_count = strategy_memory.success_count + excluded.success_count,
                signal_count = strategy_memory.signal_count + excluded.signal_count,
                failure_count = strategy_memory.failure_count + excluded.failure_count,
                last_used_at = excluded.last_used_at,
                notes = CASE
                    WHEN excluded.notes IS NOT NULL AND excluded.notes != ''
                    THEN excluded.notes
                    ELSE strategy_memory.notes
                END
            """,
            (
                scope_type,
                scope_value,
                endpoint_pattern or "*",
                mutation_kind,
                int(max(0, success_delta)),
                int(max(0, signal_delta)),
                int(max(0, failure_delta)),
                now,
                notes[:400] if notes else "",
            ),
        )


def record_strategy_outcomes(outcomes: Iterable[Dict[str, Any]]) -> int:
    """Persist mutation outcomes captured during a run."""
    ensure_schema()
    written = 0
    for o in outcomes:
        mk = str(o.get("mutation_kind") or "")
        if not mk or mk == "baseline":
            continue
        endpoint_pattern = str(o.get("endpoint_pattern") or "*")
        challenge_type = str(o.get("challenge_type") or "")
        host = str(o.get("host_fingerprint") or "")
        if not challenge_type:
            continue
        success = bool(o.get("led_to_flag"))
        signal = bool(o.get("meaningful_delta") or o.get("strong_candidate"))
        failure = not success and not signal
        notes = str(o.get("notes") or "")

        scopes = [("challenge_type", challenge_type)]
        if host:
            scopes.append(("host_fingerprint", host))
        for st, sv in scopes:
            _upsert_delta(
                st,
                sv,
                endpoint_pattern,
                mk,
                success_delta=1 if success else 0,
                signal_delta=1 if signal else 0,
                failure_delta=1 if failure else 0,
                notes=notes,
            )
            written += 1
    return written

