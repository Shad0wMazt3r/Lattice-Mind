"""Compare HTTP adapter responses to a baseline for differential detection (F3)."""

from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Set, Tuple

from lattice_mind import config

# Volatile patterns reduced before tokenization / similarity (cosmetic noise).
_ISO_LIKE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b"
)
_UNIX_TS = re.compile(r"\b1[5-9]\d{9}\b|\b\d{13}\b")
_LONG_HEX = re.compile(r"\b[0-9a-fA-F]{24,}\b")
_CSRFISH = re.compile(
    r"\b(csrf|_token|authenticity_token|nonce|state)=[^&\s\"']+",
    re.IGNORECASE,
)

_SKIP_HEADERS = frozenset(
    k.lower()
    for k in (
        "Date",
        "Age",
        "Expires",
        "Last-Modified",
        "ETag",
        "X-Request-Id",
        "X-Trace-Id",
        "Connection",
        "Keep-Alive",
        "Transfer-Encoding",
        "Content-Length",
    )
)

_ERROR_BUCKETS: List[Tuple[str, re.Pattern[str]]] = [
    ("sql", re.compile(r"sql syntax|mysql_|postgres|sqlite|ORA-\d|syntax error near", re.I)),
    ("jwt", re.compile(r"invalid token|jwt|signature|malformed.*token", re.I)),
    ("stack", re.compile(r"at \w+\.\w+\(|Traceback|Exception in thread|stack trace", re.I)),
    ("php", re.compile(r"PHP (?:Warning|Notice|Fatal|Parse error)", re.I)),
]


def _final_redirect_url(chain: Any) -> str:
    if not chain:
        return ""
    if isinstance(chain, list) and chain:
        return str(chain[-1])
    return ""


def _normalize_body_for_diff(body: str) -> str:
    if not body:
        return ""
    s = body
    s = _ISO_LIKE.sub("<ts>", s)
    s = _UNIX_TS.sub("<ts>", s)
    s = _LONG_HEX.sub("<hex>", s)
    s = _CSRFISH.sub(r"\1=<redacted>", s)
    s = re.sub(r"\s+", " ", s).strip().lower()
    return s


def _body_tokens(norm: str) -> Set[str]:
    if not norm:
        return set()
    parts = re.split(r"[^\w]+", norm)
    out = {p for p in parts if len(p) >= 2 and not p.isdigit()}
    cap = getattr(config, "RESPONSE_DIFF_MAX_TOKENS", 40) * 2
    if len(out) > cap:
        out = set(sorted(out)[:cap])
    return out


def _interesting_header_items(
    base_h: Dict[str, Any],
    var_h: Dict[str, Any],
) -> List[Dict[str, str]]:
    max_ch = getattr(config, "RESPONSE_DIFF_MAX_HEADER_CHANGES", 12)
    keys = set(base_h.keys()) | set(var_h.keys())
    interesting: List[Dict[str, str]] = []
    for k in sorted(keys, key=lambda x: x.lower()):
        lk = k.lower()
        if lk in _SKIP_HEADERS:
            continue
        if lk not in ("content-type", "location", "www-authenticate", "set-cookie"):
            continue
        bv = str(base_h.get(k, ""))[:160]
        vv = str(var_h.get(k, ""))[:160]
        if bv != vv:
            interesting.append({"name": k, "baseline": bv, "variant": vv})
        if len(interesting) >= max_ch:
            break
    return interesting


def _set_cookie_names(header_val: str) -> Set[str]:
    names: Set[str] = set()
    for part in header_val.split(","):
        m = re.match(r"\s*([^=;\s]+)\s*=", part)
        if m:
            names.add(m.group(1).lower())
    return names


def _auth_cookie_overlap(set_cookie_header: str) -> Set[str]:
    names = _set_cookie_names(set_cookie_header)
    auth_names = {x.lower() for x in getattr(config, "RESPONSE_DIFF_AUTH_COOKIE_NAMES", ())}
    return names & auth_names


def _error_signature(body: str) -> str:
    for label, rx in _ERROR_BUCKETS:
        if rx.search(body):
            return label
    return ""


def compute_response_delta(baseline: Dict[str, Any], variant: Dict[str, Any]) -> Dict[str, Any]:
    """Compare variant response dict to baseline; return JSON-serializable delta."""
    sb = baseline.get("status")
    sv = variant.get("status")
    status_changed = sb != sv

    chain_b = baseline.get("redirect_chain") or []
    chain_v = variant.get("redirect_chain") or []
    final_b = _final_redirect_url(chain_b)
    final_v = _final_redirect_url(chain_v)
    redirect_changed = final_b != final_v or chain_b != chain_v

    body_b = baseline.get("body") or ""
    body_v = variant.get("body") or ""
    length_delta = len(body_v) - len(body_b)

    tb = float(baseline.get("response_time") or 0)
    tv = float(variant.get("response_time") or 0)
    timing_delta_ms = tv - tb

    hb = {str(k): v for k, v in (baseline.get("headers") or {}).items()}
    hv = {str(k): v for k, v in (variant.get("headers") or {}).items()}
    header_changes = _interesting_header_items(hb, hv)

    nb = _normalize_body_for_diff(body_b)
    nv = _normalize_body_for_diff(body_v)
    if not nb and not nv:
        body_similarity_score = 1.0
    else:
        body_similarity_score = SequenceMatcher(None, nb, nv).ratio()

    tok_b = _body_tokens(nb)
    tok_v = _body_tokens(nv)
    max_tok = getattr(config, "RESPONSE_DIFF_MAX_TOKENS", 40)
    added = sorted(tok_v - tok_b)[:max_tok]
    removed = sorted(tok_b - tok_v)[:max_tok]

    sig_b = _error_signature(body_b)
    sig_v = _error_signature(body_v)
    error_signature_changed = sig_b != sig_v and (sig_b or sig_v)

    auth_changed = False
    # Status-based auth relaxation / hardening
    def _is_denied(x: Any) -> bool:
        try:
            return int(x) in (401, 403)
        except (TypeError, ValueError):
            return False

    def _is_ok(x: Any) -> bool:
        try:
            return 200 <= int(x) < 300
        except (TypeError, ValueError):
            return False

    if _is_denied(sb) and _is_ok(sv):
        auth_changed = True
    if _is_ok(sb) and _is_denied(sv):
        auth_changed = True

    wwb = str(hb.get("WWW-Authenticate") or hb.get("www-authenticate") or "")
    wwv = str(hv.get("WWW-Authenticate") or hv.get("www-authenticate") or "")
    if wwb != wwv and (wwb or wwv):
        auth_changed = True

    scb = str(hb.get("Set-Cookie") or hb.get("set-cookie") or "")
    scv = str(hv.get("Set-Cookie") or hv.get("set-cookie") or "")
    auth_names = getattr(config, "RESPONSE_DIFF_AUTH_COOKIE_NAMES", ())
    if auth_names:
        ab = _auth_cookie_overlap(scb)
        av = _auth_cookie_overlap(scv)
        if ab != av or (not ab and av) or (ab and not av):
            auth_changed = True

    return {
        "status_changed": status_changed,
        "baseline_status": sb,
        "variant_status": sv,
        "redirect_changed": redirect_changed,
        "redirect_final_baseline": final_b[:300],
        "redirect_final_variant": final_v[:300],
        "length_delta": length_delta,
        "timing_delta_ms": round(timing_delta_ms, 2),
        "header_changes": header_changes,
        "body_similarity_score": round(body_similarity_score, 4),
        "interesting_tokens_added": added,
        "interesting_tokens_removed": removed,
        "error_signature_changed": bool(error_signature_changed),
        "error_signature_baseline": sig_b,
        "error_signature_variant": sig_v,
        "auth_state_changed": auth_changed,
    }


def delta_summary(delta: Dict[str, Any]) -> str:
    """One-line human-readable summary for progress events."""
    parts: List[str] = []
    if delta.get("status_changed"):
        parts.append(f"status {delta.get('baseline_status')}->{delta.get('variant_status')}")
    if delta.get("redirect_changed"):
        parts.append("redirect changed")
    if delta.get("auth_state_changed"):
        parts.append("auth state changed")
    td = delta.get("timing_delta_ms")
    if isinstance(td, (int, float)) and abs(float(td)) >= getattr(
        config, "RESPONSE_DIFF_TIMING_THRESHOLD_MS", 500.0
    ):
        parts.append(f"timing Δ {td}ms")
    if delta.get("error_signature_changed"):
        parts.append("error signature changed")
    sim = delta.get("body_similarity_score")
    if isinstance(sim, (int, float)) and sim >= getattr(config, "RESPONSE_DIFF_BODY_SIMILARITY_HIGH", 0.92):
        if delta.get("interesting_tokens_added") or delta.get("interesting_tokens_removed"):
            parts.append("high similarity, token delta")
    return "; ".join(parts) if parts else "minor delta"


def attach_response_deltas_to_mutation_batch(batch: List[Dict[str, Any]]) -> None:
    """Mutates variant dicts in place; baseline row unchanged. No-op if batch too small."""
    if len(batch) < 2:
        return
    base = batch[0]
    if base.get("mutation_kind") != "baseline":
        return
    for row in batch[1:]:
        row["response_delta"] = compute_response_delta(base, row)
