"""HTTP request reconstruction and sanitization helpers."""

from __future__ import annotations

import json as _json
import re
import secrets
from typing import Any, Dict


class RequestReconstructionEngine:
    MAX_BODY_BYTES = 1_048_576
    _CRLF_RE = re.compile(r"[\r\n]")

    def reconstruct(self, req_args: Dict[str, Any]) -> Dict[str, Any]:
        out = dict(req_args or {})
        headers = self._sanitize_headers(dict(out.get("headers") or {}))
        body = out.get("data")
        json_source = body is None and "json" in out
        if body is None:
            body = out.get("json")
        if isinstance(body, (dict, list)) and json_source:
            body_bytes = _json.dumps(body, separators=(",", ":")).encode("utf-8")
        elif isinstance(body, str):
            body_bytes = body.encode("utf-8", errors="ignore")
        elif isinstance(body, (bytes, bytearray)):
            body_bytes = bytes(body)
        elif body is None:
            body_bytes = b""
        else:
            body_bytes = str(body).encode("utf-8", errors="ignore")
        ctype = headers.get("Content-Type", "")
        if json_source and not ctype:
            headers["Content-Type"] = "application/json"
            ctype = "application/json"
        if "multipart/form-data" in ctype and "boundary=" in ctype and body_bytes:
            boundary = ctype.split("boundary=", 1)[1].strip().strip('"')
            if boundary:
                body_bytes, new_boundary = self._regenerate_multipart_boundary(
                    body_bytes, boundary
                )
                headers["Content-Type"] = f"multipart/form-data; boundary={new_boundary}"
        if len(body_bytes) > self.MAX_BODY_BYTES:
            raise ValueError("request body exceeds max size")
        if body_bytes:
            headers["Content-Length"] = str(len(body_bytes))
        else:
            headers.pop("Content-Length", None)
        out["headers"] = headers
        if "data" in out or "json" in out:
            out["data"] = body_bytes
            out.pop("json", None)
        return out

    def _sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        clean: Dict[str, str] = {}
        for raw_k, raw_v in headers.items():
            k = str(raw_k).strip()
            v = str(raw_v)
            if not k:
                raise ValueError("empty header name")
            if self._CRLF_RE.search(k):
                raise ValueError("header name contains CRLF")
            if self._CRLF_RE.search(v):
                raise ValueError(f"header {k!r} contains CRLF")
            clean[k] = v
        return clean

    def _regenerate_multipart_boundary(
        self, body: bytes, old_boundary: str
    ) -> tuple[bytes, str]:
        old = old_boundary.encode("utf-8", errors="ignore")
        token = f"lm_{secrets.token_hex(12)}"
        new = token.encode("utf-8")
        rebuilt = body.replace(b"--" + old, b"--" + new)
        return rebuilt, token

