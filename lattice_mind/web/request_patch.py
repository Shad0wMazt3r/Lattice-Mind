"""Apply structured mutations to HTTPRequestSpec (MCP interception)."""

from __future__ import annotations

import re
from typing import Any, Dict

from lattice_mind.web.request_models import (
    HTTPRequestSpec,
    clone_http_request_spec,
    normalize_request_url,
)

_FORBIDDEN_HEADER_NAMES = {"host", "content-length", "transfer-encoding"}
_CRLF = re.compile(r"[\r\n]")


class RequestPatchError(ValueError):
    """Invalid mutation for the given spec."""


def _reject_crlf(s: str, what: str) -> None:
    if _CRLF.search(s):
        raise RequestPatchError(f"invalid {what}: CRLF not allowed")


def apply_request_patch(spec: HTTPRequestSpec, patch: Dict[str, Any]) -> HTTPRequestSpec:
    """
    patch format:
      set: dict of dotted keys:
        method, url
        query.NAME, body.NAME, headers.Name (case-insensitive header match)
        json_body — if value is object/array, replaces json_body
    """
    if not isinstance(patch, dict):
        raise RequestPatchError("patch must be an object")
    sets = patch.get("set")
    if not isinstance(sets, dict):
        raise RequestPatchError("patch.set must be an object")

    out = clone_http_request_spec(spec)

    for raw_key, raw_val in sets.items():
        key = str(raw_key).strip()
        if not key:
            continue
        lower = key.lower()
        if lower == "method":
            if not isinstance(raw_val, str):
                raise RequestPatchError("method must be a string")
            m = raw_val.strip().upper()
            _reject_crlf(m, "method")
            out.method = m
            continue
        if lower == "url":
            if not isinstance(raw_val, str):
                raise RequestPatchError("url must be a string")
            _reject_crlf(raw_val, "url")
            out.url = raw_val
            continue
        if lower == "json_body":
            out.json_body = raw_val
            out.raw_body = None
            out.body_params = None
            out.body_param_pairs = None
            continue

        if lower.startswith("query."):
            qname = key.split(".", 1)[1]
            _reject_crlf(qname, "query param name")
            base, pairs = normalize_request_url(out.url)
            out.url = base
            pairs = [(a, b) for a, b in pairs if a != qname]
            pairs.append((qname, str(raw_val)))
            out.query_param_pairs = pairs
            out.query_params = None
            continue

        if lower.startswith("body.") or lower.startswith("form."):
            bname = key.split(".", 1)[1]
            _reject_crlf(bname, "body param name")
            bp = dict(out.body_params or {})
            bp[bname] = str(raw_val)
            out.body_params = bp
            continue

        if lower.startswith("headers."):
            hname = key.split(".", 1)[1].strip()
            if not hname:
                raise RequestPatchError("empty header name")
            canon = "-".join(p.capitalize() for p in hname.split("-") if p)
            lk = hname.lower()
            if lk in _FORBIDDEN_HEADER_NAMES:
                raise RequestPatchError(f"header {hname!r} cannot be set via patch")
            hv = str(raw_val)
            _reject_crlf(hv, "header value")
            hdr = dict(out.headers or {})
            hdr[canon] = hv
            out.headers = hdr
            continue

        raise RequestPatchError(f"unsupported patch key: {key!r}")

    return out
