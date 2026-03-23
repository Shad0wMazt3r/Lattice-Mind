"""Resolve baseline HTTPRequestSpec probes from recon context (F2)."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from lattice_mind.config import FEATURE_FLAGS
from lattice_mind.core.expressions import evaluate_condition
from lattice_mind.web.request_models import (
    HTTPRequestSpec,
    request_spec_for_challenge_url,
    request_spec_from_form_record,
    request_spec_from_jsonable,
    request_view,
)

logger = logging.getLogger(__name__)

# YAML request_source values (F5); default matches legacy resolution order.
_REQUEST_SOURCE_ALIASES = {
    "default": None,
    "auto": None,
    "discovered_forms": "discovered_forms",
    "html_forms": "discovered_forms",
    "request_candidates": "request_candidates",
    "crawl_candidates": "request_candidates",
    "challenge_url": "challenge_url",
}


def _normalize_request_source(raw: Optional[str]) -> Optional[str]:
    if raw is None or raw == "":
        return None
    key = str(raw).strip().lower().replace("-", "_")
    return _REQUEST_SOURCE_ALIASES.get(key, key)


def resolve_probe_base_specs(
    context: Dict[str, Any],
    challenge_url: str,
    request_source: Optional[str] = None,
) -> List[HTTPRequestSpec]:
    """Resolve probe specs from recon; optional request_source overrides resolution order.

    request_source:
      - default / omitted: request_candidates, then forms, then challenge URL (legacy).
      - discovered_forms / html_forms: forms only, then challenge URL if none.
      - request_candidates / crawl_candidates: candidates only, then challenge URL if none.
      - challenge_url: only the challenge entry URL.
    """
    obs = context.get("observations", {})
    specs: List[HTTPRequestSpec] = []
    cap = max(1, int(FEATURE_FLAGS.max_probe_base_specs))
    mode = _normalize_request_source(request_source)
    session_cookies = obs.get("session_cookies") if isinstance(obs.get("session_cookies"), dict) else {}

    def _attach_session_cookies(spec: HTTPRequestSpec) -> HTTPRequestSpec:
        if not session_cookies:
            return spec
        if spec.cookies:
            merged = dict(spec.cookies)
            merged.update(session_cookies)
            spec.cookies = merged
            return spec
        spec.cookies = dict(session_cookies)
        return spec

    def _from_candidates() -> None:
        nonlocal specs
        for item in (obs.get("request_candidates") or [])[:cap]:
            if isinstance(item, dict):
                try:
                    specs.append(_attach_session_cookies(request_spec_from_jsonable(item)))
                except Exception as e:
                    logger.warning("Skipping invalid request_candidate: %s", e)

    def _from_forms() -> None:
        nonlocal specs
        for f in (obs.get("forms") or [])[:cap]:
            try:
                specs.append(_attach_session_cookies(request_spec_from_form_record(f)))
            except Exception as e:
                logger.warning("Skipping invalid form for probe spec: %s", e)

    if mode == "challenge_url":
        return [_attach_session_cookies(request_spec_for_challenge_url(challenge_url))]
    if mode == "discovered_forms":
        _from_forms()
        if not specs:
            return [_attach_session_cookies(request_spec_for_challenge_url(challenge_url))]
        if not any(s.method.upper() == "GET" for s in specs):
            specs.append(_attach_session_cookies(request_spec_for_challenge_url(challenge_url)))
        return specs
    if mode == "request_candidates":
        _from_candidates()
        if not specs:
            return [_attach_session_cookies(request_spec_for_challenge_url(challenge_url))]
        if not any(s.method.upper() == "GET" for s in specs):
            specs.append(_attach_session_cookies(request_spec_for_challenge_url(challenge_url)))
        return specs

    # Legacy default
    _from_candidates()
    if not specs:
        _from_forms()
    if not specs:
        return [_attach_session_cookies(request_spec_for_challenge_url(challenge_url))]
    if not any(s.method.upper() == "GET" for s in specs):
        specs.append(_attach_session_cookies(request_spec_for_challenge_url(challenge_url)))
    return specs


def filter_probe_specs_by_candidate_filter(
    specs: List[HTTPRequestSpec],
    context: Dict[str, Any],
    candidate_filter: Optional[str],
) -> List[HTTPRequestSpec]:
    """Keep specs where candidate_filter evaluates true; empty filter keeps all."""
    if not candidate_filter or not str(candidate_filter).strip():
        return specs
    out: List[HTTPRequestSpec] = []
    for spec in specs:
        try:
            if evaluate_condition(
                str(candidate_filter),
                context,
                extra_roots={"request": request_view(spec)},
            ):
                out.append(spec)
        except Exception as e:
            logger.debug("candidate_filter skipped for spec: %s", e)
    return out


def target_params_for_selector(selector: str, context: Dict[str, Any], base_spec: HTTPRequestSpec) -> List[str]:
    """Map target_selector (YAML) to parameter names for structural mutations."""
    if selector == "all_inputs":
        names: List[str] = []
        if base_spec.query_param_pairs:
            for k, _ in base_spec.query_param_pairs:
                if k not in names:
                    names.append(k)
        if base_spec.body_param_pairs:
            for k, _ in base_spec.body_param_pairs:
                if k not in names:
                    names.append(k)
        if base_spec.query_params:
            names.extend(k for k in base_spec.query_params.keys() if k not in names)
        if base_spec.body_params:
            names.extend(k for k in base_spec.body_params.keys() if k not in names)
        if names:
            return names

        obs = context.get("observations", {})
        discovered = obs.get("params") or obs.get("potential_params") or []
        if discovered:
            return list(discovered)
        return ["id", "query", "name", "user"]
    return []
