"""Normalized HTTP request/response models for replay and evidence (F1)."""

from __future__ import annotations

import copy
import json
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlparse, urlunparse


@dataclass
class HTTPRequestSpec:
    """Serializable description of an HTTP request (no live socket or session state)."""

    url: str
    method: str = "GET"
    query_params: Optional[Dict[str, str]] = None
    body_params: Optional[Dict[str, str]] = None
    # When set, these replace dict-based encoding so duplicate keys are preserved.
    query_param_pairs: Optional[List[Tuple[str, str]]] = None
    body_param_pairs: Optional[List[Tuple[str, str]]] = None
    json_body: Optional[Any] = None
    raw_body: Optional[Any] = None
    headers: Optional[Dict[str, str]] = None
    cookies: Optional[Dict[str, str]] = None
    content_type: Optional[str] = None
    source: Optional[str] = None
    form_id: Optional[str] = None
    workflow_step: Optional[str] = None


@dataclass
class HTTPResponseRecord:
    """Normalized response plus linkage back to the request that produced it."""

    status: Optional[int]
    headers: Dict[str, str]
    body: str
    response_time_ms: float
    redirect_chain: List[str]
    request_spec: Optional[Dict[str, Any]]
    mutation_id: Optional[str] = None
    baseline_id: Optional[str] = None


def request_view(spec: HTTPRequestSpec) -> Dict[str, Any]:
    """Small dict for YAML expression context (candidate_filter, signals)."""
    parsed = urlparse(spec.url)
    path = parsed.path or "/"
    return {
        "method": (spec.method or "GET").upper(),
        "url": spec.url,
        "path": path,
        "source": spec.source,
        "form_id": spec.form_id,
        "workflow_step": spec.workflow_step,
    }


def normalize_request_url(url: str) -> Tuple[str, List[Tuple[str, str]]]:
    """Split URL into base (no query fragment) and ordered query pairs."""
    parsed = urlparse(url)
    base = urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", "")
    )
    q = [(str(k), str(v)) for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
    return base, q


def _pairs_to_dict_if_unique(pairs: List[Tuple[str, str]]) -> Optional[Dict[str, str]]:
    out: Dict[str, str] = {}
    for k, v in pairs:
        if k in out:
            return None
        out[k] = v
    return out


def clone_http_request_spec(spec: HTTPRequestSpec) -> HTTPRequestSpec:
    qpairs = None
    if spec.query_param_pairs is not None:
        qpairs = list(spec.query_param_pairs)
    bpairs = None
    if spec.body_param_pairs is not None:
        bpairs = list(spec.body_param_pairs)
    return HTTPRequestSpec(
        url=spec.url,
        method=spec.method,
        query_params=dict(spec.query_params) if spec.query_params is not None else None,
        body_params=dict(spec.body_params) if spec.body_params is not None else None,
        query_param_pairs=qpairs,
        body_param_pairs=bpairs,
        json_body=copy.deepcopy(spec.json_body) if spec.json_body is not None else None,
        raw_body=copy.deepcopy(spec.raw_body) if spec.raw_body is not None else None,
        headers=dict(spec.headers) if spec.headers is not None else None,
        cookies=dict(spec.cookies) if spec.cookies is not None else None,
        content_type=spec.content_type,
        source=spec.source,
        form_id=spec.form_id,
        workflow_step=spec.workflow_step,
    )


def apply_param_payload(
    spec: HTTPRequestSpec,
    param: Optional[str],
    payload: Optional[Any],
) -> HTTPRequestSpec:
    """Return a copy of spec with payload applied to param in query or body as appropriate."""
    out = clone_http_request_spec(spec)
    if param is None or payload is None:
        return out

    final_p = str(payload)
    method = out.method.upper()
    base, url_query_pairs = normalize_request_url(out.url)
    out.url = base
    had_query_pairs = out.query_param_pairs is not None

    query_pairs: List[Tuple[str, str]]
    if out.query_param_pairs is not None:
        query_pairs = list(out.query_param_pairs)
    else:
        query_pairs = list(url_query_pairs)
        if out.query_params:
            for k in out.query_params.keys():
                query_pairs = [(a, b) for a, b in query_pairs if a != k]
            query_pairs.extend((str(k), str(v)) for k, v in out.query_params.items())

    query_pairs = [(a, b) for a, b in query_pairs if a != param]
    query_pairs.append((param, final_p))
    unique_q = _pairs_to_dict_if_unique(query_pairs)
    if had_query_pairs or unique_q is None:
        out.query_param_pairs = query_pairs
        out.query_params = None
    else:
        out.query_params = unique_q if unique_q else None
        out.query_param_pairs = None

    if method in ("GET", "HEAD", "DELETE"):
        out.body_params = None if method == "GET" else out.body_params
    else:
        bp = dict(out.body_params or {})
        bp[param] = final_p
        out.body_params = bp
    return out


def request_spec_from_form_record(form: Dict[str, Any]) -> HTTPRequestSpec:
    """Build an HTTPRequestSpec from recon's enriched form dict (action, method, fields, ...)."""
    action = form.get("action") or ""
    method = (form.get("method") or "GET").upper()
    base, url_query_pairs = normalize_request_url(action)
    fields = form.get("fields") or []
    enctype = form.get("enctype") or "application/x-www-form-urlencoded"
    form_id = form.get("id")
    workflow_step = form.get("workflow_step")

    if method == "GET":
        q_pairs = list(url_query_pairs)
        for f in fields:
            name = f.get("name")
            if name:
                q_pairs.append((str(name), str(f.get("value") or "")))
        unique_q = _pairs_to_dict_if_unique(q_pairs)
        return HTTPRequestSpec(
            url=base,
            method=method,
            query_params=unique_q,
            query_param_pairs=None if unique_q is not None else q_pairs,
            body_params=None,
            json_body=None,
            headers=None,
            cookies=None,
            content_type=None,
            source="html_form",
            form_id=str(form_id) if form_id is not None else None,
            workflow_step=str(workflow_step) if workflow_step is not None else None,
        )

    bp: Dict[str, str] = {}
    for f in fields:
        name = f.get("name")
        if name:
            bp[name] = f.get("value") or ""
    unique_q = _pairs_to_dict_if_unique(url_query_pairs)
    return HTTPRequestSpec(
        url=base,
        method=method,
        query_params=unique_q,
        query_param_pairs=None if unique_q is not None else list(url_query_pairs),
        body_params=bp,
        json_body=None,
        headers=None,
        cookies=None,
        content_type=enctype,
        source="html_form",
        form_id=str(form_id) if form_id is not None else None,
        workflow_step=str(workflow_step) if workflow_step is not None else None,
    )


def request_spec_for_challenge_url(url: str) -> HTTPRequestSpec:
    """Minimal GET spec for the challenge entry URL."""
    base, url_query_pairs = normalize_request_url(url)
    unique_q = _pairs_to_dict_if_unique(url_query_pairs)
    return HTTPRequestSpec(
        url=base,
        method="GET",
        query_params=unique_q,
        query_param_pairs=None if unique_q is not None else list(url_query_pairs),
        body_params=None,
        json_body=None,
        headers=None,
        cookies=None,
        content_type=None,
        source="challenge_url",
        form_id=None,
        workflow_step=None,
    )


def request_spec_to_jsonable(spec: HTTPRequestSpec) -> Dict[str, Any]:
    """JSON-serializable dict (omit keys that are None)."""
    d = asdict(spec)
    if spec.query_param_pairs is not None:
        d["query_param_pairs"] = [[a, b] for a, b in spec.query_param_pairs]
    if spec.body_param_pairs is not None:
        d["body_param_pairs"] = [[a, b] for a, b in spec.body_param_pairs]
    return {k: v for k, v in d.items() if v is not None}


def request_spec_from_jsonable(d: Dict[str, Any]) -> HTTPRequestSpec:
    """Restore HTTPRequestSpec from request_spec_to_jsonable output."""
    qpairs = d.get("query_param_pairs")
    bpairs = d.get("body_param_pairs")
    return HTTPRequestSpec(
        url=d["url"],
        method=d.get("method", "GET"),
        query_params=d.get("query_params"),
        body_params=d.get("body_params"),
        query_param_pairs=[(str(p[0]), str(p[1])) for p in qpairs] if qpairs else None,
        body_param_pairs=[(str(p[0]), str(p[1])) for p in bpairs] if bpairs else None,
        json_body=d.get("json_body"),
        raw_body=d.get("raw_body"),
        headers=d.get("headers"),
        cookies=d.get("cookies"),
        content_type=d.get("content_type"),
        source=d.get("source"),
        form_id=d.get("form_id"),
        workflow_step=d.get("workflow_step"),
    )


def spec_to_adapter_args(spec: HTTPRequestSpec) -> Dict[str, Any]:
    """Map to RequestsAdapter / CurlAdapter run() args. Raises if json_body and body_params both set."""
    if spec.json_body is not None and spec.body_params:
        raise ValueError("json_body and body_params cannot both be set")
    if spec.json_body is not None and spec.body_param_pairs:
        raise ValueError("json_body and body_param_pairs cannot both be set")
    body_sources = sum(
        source is not None and source != {}
        for source in (spec.json_body, spec.raw_body, spec.body_params, spec.body_param_pairs)
    )
    if body_sources > 1:
        raise ValueError("request body must use exactly one body representation")
    if spec.query_param_pairs is not None and spec.query_params:
        raise ValueError("query_param_pairs and query_params cannot both be set")
    if spec.body_param_pairs is not None and spec.body_params:
        raise ValueError("body_param_pairs and body_params cannot both be set")

    base_url, url_query_pairs = normalize_request_url(spec.url)

    if spec.query_param_pairs is not None:
        query_for_adapter: Any = list(spec.query_param_pairs)
    else:
        query_pairs = list(url_query_pairs)
        if spec.query_params:
            for k in spec.query_params.keys():
                query_pairs = [(a, b) for a, b in query_pairs if a != k]
            query_pairs.extend((str(k), str(v)) for k, v in spec.query_params.items())
        unique_q = _pairs_to_dict_if_unique(query_pairs)
        query_for_adapter = query_pairs if unique_q is None else unique_q

    headers: Dict[str, str] = {}
    if spec.headers:
        headers.update(spec.headers)

    ct = spec.content_type
    if ct:
        if not any(k.lower() == "content-type" for k in headers):
            headers["Content-Type"] = ct

    args: Dict[str, Any] = {
        "method": spec.method.upper(),
        "headers": headers,
        "follow_redirects": True,
    }

    if spec.cookies:
        args["cookies"] = spec.cookies

    if spec.json_body is not None:
        args["json"] = spec.json_body
        args["params"] = query_for_adapter
        return args

    if spec.raw_body is not None:
        args["data"] = spec.raw_body
        args["params"] = query_for_adapter
        return args

    method = args["method"]
    if method in ("GET", "HEAD", "DELETE"):
        args["params"] = query_for_adapter
        return args

    args["params"] = query_for_adapter
    if spec.body_param_pairs is not None:
        args["data"] = list(spec.body_param_pairs)
    elif spec.body_params:
        args["data"] = dict(spec.body_params)
    return args


def record_from_adapter_response(
    spec: HTTPRequestSpec,
    adapter_dict: Dict[str, Any],
    response_time_ms: float,
    redirect_chain: Optional[List[str]] = None,
    mutation_id: Optional[str] = None,
    baseline_id: Optional[str] = None,
) -> HTTPResponseRecord:
    """Build HTTPResponseRecord from adapter output dict."""
    raw_headers = adapter_dict.get("headers") or {}
    headers = {str(k): str(v) for k, v in raw_headers.items()}
    chain = redirect_chain
    if chain is None:
        chain = list(adapter_dict.get("redirect_chain") or [])
    return HTTPResponseRecord(
        status=adapter_dict.get("status"),
        headers=headers,
        body=adapter_dict.get("body") or "",
        response_time_ms=response_time_ms,
        redirect_chain=chain,
        request_spec=request_spec_to_jsonable(spec),
        mutation_id=mutation_id,
        baseline_id=baseline_id,
    )


def response_record_to_jsonable(record: HTTPResponseRecord) -> Dict[str, Any]:
    d = asdict(record)
    return d


def round_trip_request_spec_json(spec: HTTPRequestSpec) -> HTTPRequestSpec:
    """Serialize to JSON and back (for tests / DB)."""
    s = json.dumps(request_spec_to_jsonable(spec), sort_keys=True)
    return request_spec_from_jsonable(json.loads(s))
