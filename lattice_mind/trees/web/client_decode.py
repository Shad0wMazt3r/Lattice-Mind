"""Client-side decoding heuristics for web challenges.

Targets challenges that embed encoded/encrypted flags in JavaScript/bookmarklets.
"""
from __future__ import annotations

import base64
import html
import logging
import re
from typing import Any, Dict, List, Optional

from lattice_mind.adapters.curl_adapter import CurlAdapter
from lattice_mind.core.flag_recognizer import get_flag_recognizer
from lattice_mind.core.nodes import DecisionNode
from lattice_mind.core.types import NodeResult, NodeStatus

logger = logging.getLogger(__name__)


class WebClientDecodeNode(DecisionNode):
    """Decode client-side encoded payloads and recover flags when possible."""

    def __init__(self):
        super().__init__("web_client_decode", "Web: Client-Side Decode")
        self.curl = CurlAdapter()
        self.flag_recognizer = get_flag_recognizer()

    def run(self, context: Dict[str, Any]) -> NodeResult:
        challenge = context.get("challenge")
        observations = context.get("observations", {})
        body = observations.get("http_response", {}).get("body", "")

        if not body and challenge and challenge.url:
            try:
                result = self.curl.run(challenge.url, {"follow_redirects": True})
                body = result.get("body", "")
            except Exception as exc:
                logger.warning(f"[client-decode] Fetch failed: {exc}")

        if not body:
            return NodeResult(status=NodeStatus.FAILURE, error="No response body to analyze")

        decoded_candidates = decode_client_side(body)
        for candidate in decoded_candidates:
            flag = self.flag_recognizer.recognize(candidate)
            if flag:
                context["flag_found"] = flag
                return NodeResult(
                    status=NodeStatus.SUCCESS,
                    data={
                        "decoded_flag": flag,
                        "decoded_preview": candidate[:300],
                        "decoder": "client_side_js",
                    },
                )

        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={
                "decoded_candidates": decoded_candidates[:8],
                "decoded_count": len(decoded_candidates),
            },
        )

        # Note: decoding logic lives in decode_client_side for YAML executor reuse.


def decode_client_side(body: str) -> List[str]:
    candidates: List[str] = []
    text = html.unescape(body or "")

    scripts = [text]
    scripts.extend(_extract_bookmarklet_scripts(text))

    for script in scripts:
        sub = _decode_subtractive_charcode(script)
        if sub:
            candidates.append(sub)

        xor = _decode_xor_charcode(script)
        if xor:
            candidates.append(xor)

        candidates.extend(_decode_base64_literals(script))

    # Deduplicate while preserving order
    return list(dict.fromkeys([c for c in candidates if c]))


def _extract_bookmarklet_scripts(text: str) -> List[str]:
    scripts: List[str] = []
    for quoted in re.findall(r"javascript:\(function\(\)\s*\{.*?\}\)\(\);?", text, re.IGNORECASE | re.DOTALL):
        scripts.append(quoted)
    return scripts


def _decode_subtractive_charcode(script: str) -> Optional[str]:
    # Common pattern:
    # (encrypted.charCodeAt(i) - key.charCodeAt(i % key.length) + 256) % 256
    if "charCodeAt" not in script or "% 256" not in script:
        return None
    if "-" not in script:
        return None

    enc_match = re.search(r'var\s+encrypted\w*\s*=\s*"([^"]+)"', script, re.IGNORECASE)
    key_match = re.search(r'var\s+key\s*=\s*"([^"]+)"', script, re.IGNORECASE)
    if not enc_match or not key_match:
        return None

    enc = enc_match.group(1)
    key = key_match.group(1)
    if not key:
        return None

    best_printable: Optional[str] = None
    for enc_variant in _string_variants(enc):
        for key_variant in _string_variants(key):
            if not key_variant:
                continue
            decoded = "".join(
                chr((ord(ch) - ord(key_variant[i % len(key_variant)]) + 256) % 256)
                for i, ch in enumerate(enc_variant)
            )
            low = decoded.lower()
            if "flag{" in low or "picoctf{" in low or "ctf{" in low:
                return decoded
            if _is_mostly_printable(decoded):
                best_printable = best_printable or decoded

    return best_printable


def _decode_xor_charcode(script: str) -> Optional[str]:
    # Pattern example:
    # encrypted.charCodeAt(i) ^ key.charCodeAt(i % key.length)
    if "charCodeAt" not in script or "^" not in script:
        return None

    enc_match = re.search(r'var\s+encrypted\w*\s*=\s*"([^"]+)"', script, re.IGNORECASE)
    key_match = re.search(r'var\s+key\s*=\s*"([^"]+)"', script, re.IGNORECASE)
    if not enc_match or not key_match:
        return None

    enc = enc_match.group(1)
    key = key_match.group(1)
    if not key:
        return None

    best_printable: Optional[str] = None
    for enc_variant in _string_variants(enc):
        for key_variant in _string_variants(key):
            if not key_variant:
                continue
            decoded = "".join(
                chr(ord(ch) ^ ord(key_variant[i % len(key_variant)]))
                for i, ch in enumerate(enc_variant)
            )
            low = decoded.lower()
            if "flag{" in low or "picoctf{" in low or "ctf{" in low:
                return decoded
            if _is_mostly_printable(decoded):
                best_printable = best_printable or decoded

    return best_printable


def _decode_base64_literals(script: str) -> List[str]:
    out: List[str] = []

    # Target explicit atob("...") first.
    for m in re.finditer(r'atob\(\s*["\']([A-Za-z0-9+/=]{8,})["\']\s*\)', script):
        raw = m.group(1)
        try:
            out.append(base64.b64decode(raw).decode("utf-8", errors="ignore"))
        except Exception:
            pass

    return out


def _string_variants(value: str) -> List[str]:
    variants: List[str] = [value]
    # Repair common mojibake: UTF-8 bytes decoded as latin1/cp1252.
    for src_enc in ("latin1", "cp1252"):
        try:
            repaired = value.encode(src_enc, errors="ignore").decode("utf-8", errors="ignore")
            if repaired:
                variants.append(repaired)
        except Exception:
            pass
    return list(dict.fromkeys(variants))


def _is_mostly_printable(value: str) -> bool:
    if not value:
        return False
    printable = sum(1 for c in value if 32 <= ord(c) <= 126 or c in "\r\n\t")
    return printable / max(1, len(value)) >= 0.85
