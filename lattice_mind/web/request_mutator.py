"""Structural HTTP request mutations: one-axis variants from a baseline spec (F2)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from lattice_mind.web.request_models import HTTPRequestSpec, clone_http_request_spec, normalize_request_url

FAMILY_PRIORITY: List[str] = [
    "param_remove",
    "value_empty",
    "param_duplicate",
    "param_reorder",
    "method_flip",
    "content_type_flip",
    "body_drop",
    "header_drop",
    "value_replace",
]

DEFAULT_MUTATION_BUDGET: Dict[str, int] = {
    "max_total_variants": 24,
    "max_per_family": 8,
}


@dataclass
class PlannedVariant:
    spec: HTTPRequestSpec
    mutation_kind: str
    mutation_reason: str
    is_baseline: bool = False


def _sort_families(families: List[str]) -> List[str]:
    order = {f: i for i, f in enumerate(FAMILY_PRIORITY)}
    known: Set[str] = set(FAMILY_PRIORITY)
    ranked = [(order[f], f) for f in families if f in known]
    ranked.sort(key=lambda x: (x[0], x[1]))
    return [f for _, f in ranked]


def _query_pairs_from_spec(spec: HTTPRequestSpec) -> Tuple[List[Tuple[str, str]], str]:
    base, url_q = normalize_request_url(spec.url)
    if spec.query_param_pairs is not None:
        return list(spec.query_param_pairs), base
    pairs: List[Tuple[str, str]] = list(url_q)
    if spec.query_params:
        for k, v in spec.query_params.items():
            pairs = [(a, b) for a, b in pairs if a != k]
            pairs.append((k, v))
    return pairs, base


def _body_pairs_from_spec(spec: HTTPRequestSpec) -> List[Tuple[str, str]]:
    if spec.body_param_pairs is not None:
        return list(spec.body_param_pairs)
    if spec.body_params:
        return list(spec.body_params.items())
    return []


def _strip_key(pairs: List[Tuple[str, str]], key: str) -> List[Tuple[str, str]]:
    return [(a, b) for a, b in pairs if a != key]


def _empty_key_values(pairs: List[Tuple[str, str]], key: str) -> List[Tuple[str, str]]:
    return [(a, "" if a == key else b) for a, b in pairs]


def _spec_from_query_body(
    template: HTTPRequestSpec,
    base: str,
    qpairs: List[Tuple[str, str]],
    bpairs: List[Tuple[str, str]],
) -> HTTPRequestSpec:
    out = clone_http_request_spec(template)
    out.url = base
    out.query_params = None
    out.body_params = None
    out.query_param_pairs = qpairs if qpairs else None
    out.body_param_pairs = bpairs if bpairs else None
    return out


def _variant_param_remove(baseline: HTTPRequestSpec, param: str) -> Optional[HTTPRequestSpec]:
    if baseline.json_body is not None:
        return None
    qpairs, base = _query_pairs_from_spec(baseline)
    bpairs = _body_pairs_from_spec(baseline)
    nq = _strip_key(qpairs, param)
    nb = _strip_key(bpairs, param)
    if nq == qpairs and nb == bpairs:
        return None
    return _spec_from_query_body(baseline, base, nq, nb)


def _variant_value_empty(baseline: HTTPRequestSpec, param: str) -> Optional[HTTPRequestSpec]:
    if baseline.json_body is not None:
        return None
    qpairs, base = _query_pairs_from_spec(baseline)
    bpairs = _body_pairs_from_spec(baseline)
    nq = _empty_key_values(qpairs, param)
    nb = _empty_key_values(bpairs, param)
    if nq == qpairs and nb == bpairs:
        return None
    return _spec_from_query_body(baseline, base, nq, nb)


def _variant_param_duplicate(baseline: HTTPRequestSpec, param: str) -> Optional[HTTPRequestSpec]:
    if baseline.json_body is not None:
        return None
    qpairs, base = _query_pairs_from_spec(baseline)
    bpairs = _body_pairs_from_spec(baseline)
    dup_q: Optional[List[Tuple[str, str]]] = None
    for i, (k, v) in enumerate(qpairs):
        if k == param:
            dup_q = list(qpairs)
            dup_q.insert(i + 1, (k, v))
            break
    if dup_q is not None:
        return _spec_from_query_body(baseline, base, dup_q, bpairs)
    dup_b: Optional[List[Tuple[str, str]]] = None
    for i, (k, v) in enumerate(bpairs):
        if k == param:
            dup_b = list(bpairs)
            dup_b.insert(i + 1, (k, v))
            break
    if dup_b is not None:
        return _spec_from_query_body(baseline, base, qpairs, dup_b)
    return None


def _variant_param_reorder(baseline: HTTPRequestSpec) -> Optional[HTTPRequestSpec]:
    if baseline.json_body is not None:
        return None
    qpairs, base = _query_pairs_from_spec(baseline)
    bpairs = _body_pairs_from_spec(baseline)
    if len(bpairs) < 2:
        return None
    rev = list(reversed(bpairs))
    if rev == bpairs:
        return None
    return _spec_from_query_body(baseline, base, qpairs, rev)


def _variant_method_flip(baseline: HTTPRequestSpec) -> Optional[HTTPRequestSpec]:
    if baseline.method.upper() != "POST":
        return None
    if baseline.json_body is not None:
        return None
    qpairs, base = _query_pairs_from_spec(baseline)
    bpairs = _body_pairs_from_spec(baseline)
    if not bpairs:
        return None
    merged = list(qpairs) + list(bpairs)
    out = clone_http_request_spec(baseline)
    out.method = "GET"
    out.url = base
    out.query_params = None
    out.query_param_pairs = merged if merged else None
    out.body_params = None
    out.body_param_pairs = None
    out.content_type = None
    if out.headers:
        h = {k: v for k, v in out.headers.items() if k.lower() != "content-type"}
        out.headers = h if h else None
    return out


def _variant_content_type_flip(baseline: HTTPRequestSpec) -> Optional[HTTPRequestSpec]:
    if baseline.method.upper() not in ("POST", "PUT", "PATCH"):
        return None
    if baseline.json_body is not None:
        return None
    bpairs = _body_pairs_from_spec(baseline)
    if not bpairs:
        return None
    qpairs, base = _query_pairs_from_spec(baseline)
    out = _spec_from_query_body(baseline, base, qpairs, bpairs)
    ct = (baseline.content_type or "").lower()
    if "json" in ct:
        return None
    if "text/plain" in ct:
        out.content_type = "application/x-www-form-urlencoded"
    else:
        out.content_type = "text/plain"
    return out


def _variant_body_drop(baseline: HTTPRequestSpec) -> Optional[HTTPRequestSpec]:
    if baseline.method.upper() not in ("POST", "PUT", "PATCH"):
        return None
    if baseline.json_body is not None:
        return None
    bpairs = _body_pairs_from_spec(baseline)
    if not bpairs:
        return None
    qpairs, base = _query_pairs_from_spec(baseline)
    out = _spec_from_query_body(baseline, base, qpairs, [])
    out.body_params = None
    out.body_param_pairs = None
    out.content_type = None
    if out.headers:
        h = {k: v for k, v in out.headers.items() if k.lower() != "content-type"}
        out.headers = h if h else None
    return out


def _variant_header_drop(baseline: HTTPRequestSpec, header_key: str) -> Optional[HTTPRequestSpec]:
    if not baseline.headers or header_key not in baseline.headers:
        return None
    out = clone_http_request_spec(baseline)
    out.headers = {k: v for k, v in out.headers.items() if k != header_key}
    if not out.headers:
        out.headers = None
    return out


def plan_mutation_variants(
    baseline: HTTPRequestSpec,
    families: List[str],
    target_param_names: List[str],
    budget: Optional[Dict[str, Any]] = None,
) -> List[PlannedVariant]:
    """Return baseline first, then structural variants (one mutation axis each)."""
    b = dict(DEFAULT_MUTATION_BUDGET)
    if budget:
        for k, v in budget.items():
            if v is not None:
                b[k] = int(v)

    max_total = max(0, b.get("max_total_variants", 24))
    max_per_family = max(0, b.get("max_per_family", 8))

    result: List[PlannedVariant] = [
        PlannedVariant(
            clone_http_request_spec(baseline),
            "baseline",
            "Unmodified request shape after payload injection",
            is_baseline=True,
        )
    ]
    used: int = 0
    fams = _sort_families(families)
    targets = list(target_param_names) if target_param_names else []

    for family in fams:
        fam_count = 0
        if used >= max_total:
            break

        if family == "param_remove":
            for param in targets:
                if used >= max_total or fam_count >= max_per_family:
                    break
                v = _variant_param_remove(baseline, param)
                if v:
                    result.append(
                        PlannedVariant(v, family, f"Removed parameter {param!r} from query and/or body")
                    )
                    used += 1
                    fam_count += 1

        elif family == "value_empty":
            for param in targets:
                if used >= max_total or fam_count >= max_per_family:
                    break
                v = _variant_value_empty(baseline, param)
                if v:
                    result.append(
                        PlannedVariant(v, family, f"Emptied values for parameter {param!r}")
                    )
                    used += 1
                    fam_count += 1

        elif family == "param_duplicate":
            for param in targets:
                if used >= max_total or fam_count >= max_per_family:
                    break
                v = _variant_param_duplicate(baseline, param)
                if v:
                    result.append(
                        PlannedVariant(v, family, f"Duplicated key {param!r} in query or body")
                    )
                    used += 1
                    fam_count += 1

        elif family == "param_reorder":
            if used < max_total and fam_count < max_per_family:
                v = _variant_param_reorder(baseline)
                if v:
                    result.append(PlannedVariant(v, family, "Reversed application/x-www-form-urlencoded field order"))
                    used += 1
                    fam_count += 1

        elif family == "method_flip":
            if used < max_total and fam_count < max_per_family:
                v = _variant_method_flip(baseline)
                if v:
                    result.append(
                        PlannedVariant(
                            v,
                            family,
                            "POST with form body converted to GET with merged query string",
                        )
                    )
                    used += 1
                    fam_count += 1

        elif family == "content_type_flip":
            if used < max_total and fam_count < max_per_family:
                v = _variant_content_type_flip(baseline)
                if v:
                    alt = v.content_type or ""
                    result.append(
                        PlannedVariant(
                            v,
                            family,
                            f"Switched Content-Type for form body to {alt!r}",
                        )
                    )
                    used += 1
                    fam_count += 1

        elif family == "body_drop":
            if used < max_total and fam_count < max_per_family:
                v = _variant_body_drop(baseline)
                if v:
                    result.append(PlannedVariant(v, family, "Dropped POST body; query string preserved"))
                    used += 1
                    fam_count += 1

        elif family == "header_drop":
            if baseline.headers:
                for hk in list(baseline.headers.keys()):
                    if used >= max_total or fam_count >= max_per_family:
                        break
                    v = _variant_header_drop(baseline, hk)
                    if v:
                        result.append(PlannedVariant(v, family, f"Removed header {hk!r}"))
                        used += 1
                        fam_count += 1

        # value_replace: reserved; payloads cover value substitution for vuln testing.

    return result
