"""Rule-based evidence records from response deltas (F3)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from lattice_mind import config


@dataclass
class EvidenceRecord:
    kind: str
    severity: str
    reason: str
    tree_id: Optional[str] = None
    step_id: Optional[str] = None
    mutation_kind: Optional[str] = None
    baseline_id: Optional[str] = None
    mutation_id: Optional[str] = None

    def to_jsonable(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


def _severity_rank(s: str) -> int:
    return {"low": 1, "medium": 2, "high": 3}.get(s.lower(), 0)


def max_severity(records: List[EvidenceRecord]) -> str:
    if not records:
        return ""
    best = max(records, key=lambda r: _severity_rank(r.severity))
    return best.severity


def score_response_delta(
    delta: Dict[str, Any],
    *,
    tree_id: Optional[str] = None,
    step_id: Optional[str] = None,
    mutation_kind: Optional[str] = None,
    baseline_id: Optional[str] = None,
    mutation_id: Optional[str] = None,
) -> List[EvidenceRecord]:
    """Return zero or more evidence rows for an interesting differential."""
    out: List[EvidenceRecord] = []
    timing_thr = getattr(config, "RESPONSE_DIFF_TIMING_EVIDENCE_MS", 800.0)
    sim_high = getattr(config, "RESPONSE_DIFF_BODY_SIMILARITY_HIGH", 0.92)

    def _meta(**extra: Any) -> Dict[str, Any]:
        return {
            "tree_id": tree_id,
            "step_id": step_id,
            "mutation_kind": mutation_kind,
            "baseline_id": baseline_id,
            "mutation_id": mutation_id,
            **extra,
        }

    sb = delta.get("baseline_status")
    sv = delta.get("variant_status")
    status_relaxed_from_auth = False

    if delta.get("status_changed"):
        try:
            denied = {401, 403}
            if int(sb) in denied and 200 <= int(sv) < 300:
                status_relaxed_from_auth = True
                out.append(
                    EvidenceRecord(
                        kind="response_delta",
                        severity="high",
                        reason=f"HTTP status relaxed: {sb} -> {sv}",
                        **_meta(),
                    )
                )
            elif 200 <= int(sb) < 300 and int(sv) in denied:
                out.append(
                    EvidenceRecord(
                        kind="response_delta",
                        severity="medium",
                        reason=f"HTTP status hardened: {sb} -> {sv}",
                        **_meta(),
                    )
                )
        except (TypeError, ValueError):
            pass

    if delta.get("auth_state_changed") and not status_relaxed_from_auth:
        out.append(
            EvidenceRecord(
                kind="response_delta",
                severity="high",
                reason="Auth-related signal: WWW-Authenticate / session cookies changed",
                **_meta(),
            )
        )

    if delta.get("redirect_changed"):
        out.append(
            EvidenceRecord(
                kind="response_delta",
                severity="medium",
                reason="Redirect target or chain changed vs baseline",
                **_meta(),
            )
        )

    td = delta.get("timing_delta_ms")
    try:
        if isinstance(td, (int, float)) and abs(float(td)) >= timing_thr:
            out.append(
                EvidenceRecord(
                    kind="response_delta",
                    severity="medium",
                    reason=f"Timing delta {td}ms vs baseline (possible blind/timing channel)",
                    **_meta(),
                )
            )
    except (TypeError, ValueError):
        pass

    sim = delta.get("body_similarity_score")
    try:
        sval = float(sim)
    except (TypeError, ValueError):
        sval = 0.0
    if sval >= sim_high and (
        delta.get("interesting_tokens_added") or delta.get("interesting_tokens_removed")
    ):
        out.append(
            EvidenceRecord(
                kind="response_delta",
                severity="medium",
                reason="Body very similar to baseline but key tokens differ",
                **_meta(),
            )
        )

    if delta.get("error_signature_changed"):
        out.append(
            EvidenceRecord(
                kind="response_delta",
                severity="medium",
                reason=f"Error class changed ({delta.get('error_signature_baseline')!r} -> {delta.get('error_signature_variant')!r})",
                **_meta(),
            )
        )

    # De-dupe identical reasons while preserving order
    seen = set()
    deduped: List[EvidenceRecord] = []
    for r in out:
        key = (r.kind, r.severity, r.reason)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(r)
    return deduped
