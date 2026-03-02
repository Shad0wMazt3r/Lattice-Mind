"""Cryptography vulnerability detection trees (C-Detect).

Implements crypto detection from detections.md:
- C-D.1: Encoding vs. encryption detection (base64, hex, URL, multi-layer)
- C-D.2: Substitution/Vigenère detection (Index of Coincidence)
- C-D.3: XOR/Caesar detection (brute-force all keys, scored by English IC)
- C-D.4: RSA/number-theoretic detection and attack
- C-D.5: Stream cipher reuse detection
"""
from typing import Dict, Any, Optional, List
import logging
import re
import base64
import string

from ctf_autopwn.core.nodes import DecisionNode
from ctf_autopwn.core.types import NodeResult, NodeStatus

logger = logging.getLogger(__name__)

# English letter frequency for scoring
_ENGLISH_FREQ = {
    'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97, 'n': 6.75,
    's': 6.33, 'h': 6.09, 'r': 5.99, 'd': 4.25, 'l': 4.03, 'c': 2.78,
    'u': 2.76, 'm': 2.41, 'w': 2.36, 'f': 2.23, 'g': 2.02, 'y': 1.97,
    'p': 1.93, 'b': 1.49, 'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15,
    'q': 0.10, 'z': 0.07,
}


def _english_score(text: str) -> float:
    """Score text by how English-like it is (higher = more English)."""
    text = text.lower()
    n = sum(1 for c in text if c.isalpha())
    if n == 0:
        return 0.0
    score = sum(_ENGLISH_FREQ.get(c, 0) for c in text if c.isalpha())
    return score / n


def _index_of_coincidence(text: str) -> float:
    """Compute Index of Coincidence (English ≈ 0.065, random ≈ 0.038)."""
    text = text.lower()
    freqs = {}
    for c in text:
        if c.isalpha():
            freqs[c] = freqs.get(c, 0) + 1
    n = sum(freqs.values())
    if n < 2:
        return 0.0
    return sum(f * (f - 1) for f in freqs.values()) / (n * (n - 1))


class CryptoDetectEncodingNode(DecisionNode):
    """C-D.1: Detect and iteratively decode common encodings."""

    def __init__(self):
        super().__init__("crypto_detect_encoding", "Crypto: Encoding Detection")

    def run(self, context: Dict[str, Any]) -> NodeResult:
        challenge = context.get("challenge")
        if not challenge:
            return NodeResult(status=NodeStatus.FAILURE, error="No challenge")

        content = self._get_content(challenge)
        if not content:
            return NodeResult(status=NodeStatus.FAILURE, error="No content to analyse")

        logger.info(f"[crypto] Detecting encoding in: {content[:80]}")

        steps, final = self._iterative_decode(content.strip(), max_depth=6)
        encoding_type = self._identify_encoding(content.strip())

        context["observations"]["crypto_content"] = content
        context["observations"]["decoded_text"] = final
        context["observations"]["decode_steps"] = steps

        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={
                "original": content[:500],
                "decoded": final[:500],
                "decode_steps": steps,
                "encoding_type": encoding_type,
            }
        )

    def _get_content(self, challenge) -> str:
        if challenge.file_path:
            try:
                with open(challenge.file_path, 'r', errors='ignore') as f:
                    return f.read(4000)
            except Exception:
                pass
        return challenge.metadata.get("content", "")

    def _iterative_decode(self, text: str, max_depth: int = 6):
        current = text
        steps = []
        for _ in range(max_depth):
            prev = current
            # base64
            if self._is_valid_base64(current):
                try:
                    decoded = base64.b64decode(current).decode('utf-8', errors='replace')
                    if decoded != current:
                        steps.append({"method": "base64", "result": decoded[:200]})
                        current = decoded
                        continue
                except Exception:
                    pass
            # hex
            stripped = current.replace(' ', '').replace('\n', '')
            if self._is_valid_hex(stripped):
                try:
                    decoded = bytes.fromhex(stripped).decode('utf-8', errors='replace')
                    if decoded != current:
                        steps.append({"method": "hex", "result": decoded[:200]})
                        current = decoded
                        continue
                except Exception:
                    pass
            # URL encoding
            if '%' in current:
                try:
                    import urllib.parse
                    decoded = urllib.parse.unquote(current)
                    if decoded != current:
                        steps.append({"method": "url_decode", "result": decoded[:200]})
                        current = decoded
                        continue
                except Exception:
                    pass
            break
        return steps, current

    def _is_valid_base64(self, text: str) -> bool:
        t = text.replace('\n', '').replace('\r', '')
        if not t or len(t) % 4 != 0:
            return False
        return bool(re.fullmatch(r'[A-Za-z0-9+/]*={0,2}', t)) and len(t) >= 4

    def _is_valid_hex(self, text: str) -> bool:
        return bool(text) and len(text) % 2 == 0 and bool(re.fullmatch(r'[0-9a-fA-F]+', text)) and len(text) >= 4

    def _identify_encoding(self, text: str) -> str:
        stripped = text.replace(' ', '').replace('\n', '')
        if self._is_valid_hex(stripped):
            return "hex"
        if self._is_valid_base64(text):
            return "base64"
        if '%' in text:
            return "url_encoded"
        return "unknown"

    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        if result.status == NodeStatus.SUCCESS:
            return CryptoDetectSubstitutionNode()
        return None


class CryptoDetectSubstitutionNode(DecisionNode):
    """C-D.2: Detect substitution/Vigenère ciphers via Index of Coincidence."""

    def __init__(self):
        super().__init__("crypto_detect_substitution", "Crypto: Substitution Detection")

    def run(self, context: Dict[str, Any]) -> NodeResult:
        text = context.get("observations", {}).get("decoded_text", "")
        if not text:
            return NodeResult(status=NodeStatus.SUCCESS, data={"is_substitution": False})

        ic = _index_of_coincidence(text)
        is_substitution = ic > 0.05
        logger.info(f"[crypto] IC={ic:.4f} → substitution={is_substitution}")

        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={"is_substitution": is_substitution, "index_of_coincidence": round(ic, 4)},
        )

    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        if result.status == NodeStatus.SUCCESS:
            if result.data.get("is_substitution"):
                return CryptoDetectXORNode()  # also covers vigenere brute-force
            return CryptoDetectXORNode()
        return None


class CryptoDetectXORNode(DecisionNode):
    """C-D.3: Brute-force Caesar (all 26 shifts) and XOR (all 256 byte keys)."""

    def __init__(self):
        super().__init__("crypto_detect_xor", "Crypto: XOR / Caesar Brute-Force")

    def run(self, context: Dict[str, Any]) -> NodeResult:
        text = context.get("observations", {}).get("decoded_text", "")
        if not text:
            return NodeResult(status=NodeStatus.SUCCESS, data={"attempts": []})

        results = []

        # ── Caesar / ROT shifts ──────────────────────────────────────────────
        caesar_results = []
        for shift in range(26):
            attempt = self._caesar(text, shift)
            score = _english_score(attempt)
            has_flag = bool(re.search(r'flag\{[^}]+\}|ctf\{[^}]+\}', attempt, re.IGNORECASE))
            caesar_results.append({
                "method": f"caesar_{shift}",
                "shift": shift,
                "output": attempt[:300],
                "score": round(score, 2),
                "flag": has_flag,
            })
        # Sort by English score, keep top-5 + any with flags
        caesar_results.sort(key=lambda x: x["score"], reverse=True)
        results.extend(caesar_results[:5])
        results.extend(r for r in caesar_results[5:] if r["flag"])

        # ── Single-byte XOR ───────────────────────────────────────────────────
        xor_results = []
        raw = text.encode('latin-1', errors='replace')
        for key in range(256):
            attempt_bytes = bytes(b ^ key for b in raw)
            try:
                attempt = attempt_bytes.decode('utf-8', errors='replace')
            except Exception:
                attempt = attempt_bytes.decode('latin-1', errors='replace')
            score = _english_score(attempt)
            has_flag = bool(re.search(r'flag\{[^}]+\}|ctf\{[^}]+\}', attempt, re.IGNORECASE))
            if score > 5.0 or has_flag:
                xor_results.append({
                    "method": f"xor_0x{key:02x}",
                    "key": key,
                    "output": attempt[:300],
                    "score": round(score, 2),
                    "flag": has_flag,
                })
        xor_results.sort(key=lambda x: x["score"], reverse=True)
        results.extend(xor_results[:5])

        # Look for any captured flag
        all_flags = [r["output"] for r in results if r.get("flag")]
        found_flag = None
        if all_flags:
            m = re.search(r'flag\{[^}]+\}|ctf\{[^}]+\}', all_flags[0], re.IGNORECASE)
            if m:
                found_flag = m.group(0)

        logger.info(f"[crypto] Caesar/XOR brute-force: {len(results)} candidates, flag={'yes' if found_flag else 'no'}")
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={
                "attempts": results,
                "best_caesar": caesar_results[0]["output"][:200] if caesar_results else "",
                "flag_candidate": found_flag,
                "decrypted": found_flag or (results[0]["output"] if results else ""),
            }
        )

    def _caesar(self, text: str, shift: int) -> str:
        out = []
        for c in text:
            if c.isupper():
                out.append(chr((ord(c) - ord('A') + shift) % 26 + ord('A')))
            elif c.islower():
                out.append(chr((ord(c) - ord('a') + shift) % 26 + ord('a')))
            else:
                out.append(c)
        return ''.join(out)

    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        if result.status == NodeStatus.SUCCESS:
            if result.data.get("flag_candidate"):
                return None  # flag found, stop
            return CryptoDetectRSANode()
        return None


class CryptoDetectRSANode(DecisionNode):
    """C-D.4: Parse RSA parameters and attempt common attacks."""

    def __init__(self):
        super().__init__("crypto_detect_rsa", "Crypto: RSA Detection & Attack")

    def run(self, context: Dict[str, Any]) -> NodeResult:
        challenge = context.get("challenge")
        if not challenge:
            return NodeResult(status=NodeStatus.SUCCESS, data={"is_rsa": False})

        content = challenge.metadata.get("content", "")
        params = self._parse_rsa_params(content)
        is_rsa = len(params) >= 2

        attacks_tried = []
        decrypted = None

        if is_rsa and params.get("n") and params.get("e") and params.get("c"):
            n, e, c = params["n"], params["e"], params["c"]
            attacks_tried, decrypted = self._attack_rsa(n, e, c, params)

        logger.info(f"[crypto] RSA params={list(params.keys())}, attacks={attacks_tried}")
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={
                "is_rsa": is_rsa,
                "rsa_params": {k: str(v)[:80] for k, v in params.items()},
                "attacks_tried": attacks_tried,
                "decrypted": decrypted or "",
            }
        )

    def _parse_rsa_params(self, content: str) -> dict:
        params = {}
        patterns = {
            "n": r'\bn\s*[=:]\s*([0-9]+)',
            "e": r'\be\s*[=:]\s*([0-9]+)',
            "d": r'\bd\s*[=:]\s*([0-9]+)',
            "c": r'\bc(?:iphertext)?\s*[=:]\s*([0-9]+)',
            "p": r'\bp\s*[=:]\s*([0-9]+)',
            "q": r'\bq\s*[=:]\s*([0-9]+)',
        }
        for key, pattern in patterns.items():
            m = re.search(pattern, content, re.IGNORECASE)
            if m:
                try:
                    params[key] = int(m.group(1))
                except ValueError:
                    pass
        return params

    def _attack_rsa(self, n: int, e: int, c: int, params: dict):
        attacks = []
        decrypted = None

        # If p and q known — direct decryption
        if params.get("p") and params.get("q"):
            try:
                p, q = params["p"], params["q"]
                phi = (p - 1) * (q - 1)
                d = pow(e, -1, phi)
                m = pow(c, d, n)
                decrypted = self._int_to_str(m)
                attacks.append("direct_pq_decrypt")
            except Exception:
                pass

        # Small e — cube root attack (e=3)
        if not decrypted and e in (3, 5, 7, 17, 65537):
            try:
                import math
                root = round(c ** (1 / e))
                for candidate in range(max(0, root - 2), root + 3):
                    if candidate ** e == c:
                        decrypted = self._int_to_str(candidate)
                        attacks.append(f"small_e_root(e={e})")
                        break
            except Exception:
                pass

        # d known
        if not decrypted and params.get("d"):
            try:
                m = pow(c, params["d"], n)
                decrypted = self._int_to_str(m)
                attacks.append("known_d_decrypt")
            except Exception:
                pass

        if not attacks:
            attacks.append("no_attack_succeeded")

        return attacks, decrypted

    def _int_to_str(self, m: int) -> str:
        try:
            length = (m.bit_length() + 7) // 8
            return m.to_bytes(length, 'big').decode('utf-8', errors='replace')
        except Exception:
            return str(m)

    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        if result.status == NodeStatus.SUCCESS and not result.data.get("is_rsa"):
            return CryptoDetectStreamNode()
        return None


class CryptoDetectStreamNode(DecisionNode):
    """C-D.5: Detect stream cipher / XOR key-reuse across multiple ciphertexts."""

    def __init__(self):
        super().__init__("crypto_detect_stream", "Crypto: Stream Cipher Reuse")

    def run(self, context: Dict[str, Any]) -> NodeResult:
        content = context.get("challenge", object()).metadata.get("content", "") if context.get("challenge") else ""
        lines = [l.strip() for l in content.split('\n') if l.strip() and re.fullmatch(r'[0-9a-fA-F]+', l.strip())]
        is_reuse = len(lines) > 1 and len(set(len(l) for l in lines[:5])) == 1

        result_data = {
            "is_stream_reuse": is_reuse,
            "ciphertext_count": len(lines),
        }

        if is_reuse:
            # XOR all pairs to find probable keystream bytes
            ct_bytes = [bytes.fromhex(l) for l in lines[:4]]
            xored_pairs = []
            for i in range(len(ct_bytes)):
                for j in range(i + 1, len(ct_bytes)):
                    xored = bytes(a ^ b for a, b in zip(ct_bytes[i], ct_bytes[j]))
                    xored_pairs.append(xored.hex())
            result_data["xor_pairs"] = xored_pairs[:4]

        return NodeResult(status=NodeStatus.SUCCESS, data=result_data)



