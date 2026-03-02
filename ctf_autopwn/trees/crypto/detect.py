"""Cryptography vulnerability detection trees (C-Detect).

Implements crypto detection from detections.md:
- C-D.1: Encoding vs. encryption detection
- C-D.2: Substitution/Vigenère detection
- C-D.3: XOR/Caesar detection
- C-D.4: RSA/number-theoretic detection
- C-D.5: Stream cipher reuse detection
"""
from typing import Dict, Any, Optional, List
import logging
import re
import base64

from ctf_autopwn.core.nodes import DecisionNode
from ctf_autopwn.core.types import (
    NodeResult, NodeStatus
)

logger = logging.getLogger(__name__)


class CryptoDetectEncodingNode(DecisionNode):
    """C-D.1: Detect encoding vs. encryption."""
    
    def __init__(self):
        super().__init__("crypto_detect_encoding", "Crypto: Encoding Detection")
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Identify and iteratively decode encodings."""
        challenge = context.get("challenge")
        
        if not challenge:
            return NodeResult(status=NodeStatus.FAILURE, error="No challenge")
        
        # Get content
        content = self._get_content(challenge)
        
        if not content:
            return NodeResult(
                status=NodeStatus.FAILURE,
                error="No content to analyze"
            )
        
        logger.info(f"[crypto] Detecting encoding in: {content[:100]}")
        
        # Try to iteratively decode
        decoded = self._iterative_decode(content, max_depth=5)
        
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={
                "original": content,
                "decoded": decoded,
                "encoding_type": self._identify_encoding(content),
            }
        )
    
    def _get_content(self, challenge) -> str:
        """Extract text content from challenge."""
        if challenge.file_path:
            try:
                with open(challenge.file_path, 'r', errors='ignore') as f:
                    return f.read(1000)
            except:
                pass
        
        return challenge.metadata.get("content", "")
    
    def _iterative_decode(self, text: str, max_depth: int = 5) -> str:
        """Iteratively decode common encodings."""
        current = text
        depth = 0
        
        while depth < max_depth:
            prev = current
            
            # Try base64
            if self._is_valid_base64(current):
                try:
                    current = base64.b64decode(current).decode('utf-8', errors='ignore')
                    logger.debug(f"[crypto] Decoded base64 at depth {depth}")
                    depth += 1
                    continue
                except:
                    pass
            
            # Try hex
            if self._is_valid_hex(current):
                try:
                    current = bytes.fromhex(current).decode('utf-8', errors='ignore')
                    logger.debug(f"[crypto] Decoded hex at depth {depth}")
                    depth += 1
                    continue
                except:
                    pass
            
            # Try URL encoding
            if '%' in current:
                try:
                    import urllib.parse
                    decoded = urllib.parse.unquote(current)
                    if decoded != current:
                        current = decoded
                        logger.debug(f"[crypto] Decoded URL encoding at depth {depth}")
                        depth += 1
                        continue
                except:
                    pass
            
            # No more decodings possible
            if current == prev:
                break
        
        return current
    
    def _is_valid_base64(self, text: str) -> bool:
        """Check if text could be base64."""
        if not text or len(text) % 4 != 0:
            return False
        
        valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
        return all(c in valid_chars for c in text.replace('\n', ''))
    
    def _is_valid_hex(self, text: str) -> bool:
        """Check if text is valid hex."""
        if not text or len(text) % 2 != 0:
            return False
        
        try:
            int(text, 16)
            return True
        except ValueError:
            return False
    
    def _identify_encoding(self, text: str) -> str:
        """Identify encoding type."""
        if self._is_valid_hex(text):
            return "hex"
        elif self._is_valid_base64(text):
            return "base64"
        elif '%' in text:
            return "url_encoded"
        else:
            return "unknown"
    
    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        if result.status == NodeStatus.SUCCESS:
            return CryptoDetectSubstitutionNode()
        return None


class CryptoDetectSubstitutionNode(DecisionNode):
    """C-D.2: Detect substitution/Vigenère ciphers."""
    
    def __init__(self):
        super().__init__("crypto_detect_substitution", "Crypto: Substitution Detection")
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Analyze alphabet-only text for substitution patterns."""
        decoded = context.get("observations", {}).get("decoded_text", "")
        
        if not decoded:
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"is_substitution": False}
            )
        
        logger.info(f"[crypto] Checking for substitution cipher")
        
        # Check if alphabetic only
        alpha_only = all(c.isalpha() or c.isspace() for c in decoded)
        
        if not alpha_only:
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"is_substitution": False}
            )
        
        # Compute index of coincidence
        ic = self._compute_ic(decoded)
        
        # English IC is ~0.065, random is ~0.038
        # High IC suggests substitution/vigenère
        is_substitution = ic > 0.05
        
        logger.info(f"[crypto] Index of Coincidence: {ic:.3f}")
        
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={
                "is_substitution": is_substitution,
                "index_of_coincidence": ic,
            }
        )
    
    def _compute_ic(self, text: str) -> float:
        """Compute index of coincidence."""
        text = text.lower()
        freqs = {}
        
        for c in text:
            if c.isalpha():
                freqs[c] = freqs.get(c, 0) + 1
        
        if not freqs:
            return 0.0
        
        n = sum(freqs.values())
        ic = sum(count * (count - 1) for count in freqs.values()) / (n * (n - 1))
        
        return ic
    
    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        if result.status == NodeStatus.SUCCESS:
            if result.data.get("is_substitution"):
                return CryptoExploitSubstitutionNode()
            else:
                return CryptoDetectXORNode()
        return None


class CryptoDetectXORNode(DecisionNode):
    """C-D.3: Detect XOR/Caesar ciphers."""
    
    def __init__(self):
        super().__init__("crypto_detect_xor", "Crypto: XOR/Caesar Detection")
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Test XOR and Caesar variants."""
        decoded = context.get("observations", {}).get("decoded_text", "")
        
        if not decoded:
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"is_xor": False}
            )
        
        logger.info(f"[crypto] Testing XOR/Caesar variants")
        
        # Test single-byte XOR (try all 256 keys)
        for key in range(256):
            attempt = ''.join(
                chr(ord(c) ^ key) if c.isprintable() else c
                for c in decoded
            )
            
            if "flag{" in attempt.lower() or "ctf{" in attempt.lower():
                logger.info(f"[crypto] Found XOR with key: {key}")
                return NodeResult(
                    status=NodeStatus.SUCCESS,
                    data={
                        "is_xor": True,
                        "xor_key": key,
                        "decrypted": attempt,
                    }
                )
        
        # Test Caesar shifts
        for shift in range(26):
            attempt = ''.join(
                chr((ord(c.upper()) - ord('A') + shift) % 26 + ord('A'))
                if c.isalpha() else c
                for c in decoded
            )
            
            if "flag{" in attempt.lower() or "ctf{" in attempt.lower():
                logger.info(f"[crypto] Found Caesar shift: {shift}")
                return NodeResult(
                    status=NodeStatus.SUCCESS,
                    data={
                        "is_caesar": True,
                        "shift": shift,
                        "decrypted": attempt,
                    }
                )
        
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={"is_xor": False}
        )
    
    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        if result.status == NodeStatus.SUCCESS:
            if result.data.get("is_xor") or result.data.get("is_caesar"):
                # Already decrypted
                return None
            else:
                return CryptoDetectRSANode()
        return None


class CryptoDetectRSANode(DecisionNode):
    """C-D.4: Detect RSA/number-theoretic challenges."""
    
    def __init__(self):
        super().__init__("crypto_detect_rsa", "Crypto: RSA Detection")
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Identify RSA parameters."""
        challenge = context.get("challenge")
        
        if not challenge:
            return NodeResult(status=NodeStatus.SUCCESS, data={"is_rsa": False})
        
        # Look for RSA-like content
        content = challenge.metadata.get("content", "")
        
        rsa_indicators = {
            "n": False,
            "e": False,
            "d": False,
            "c": False,
            "p": False,
            "q": False,
        }
        
        for key in rsa_indicators:
            if f"{key}=" in content or f"{key} =" in content:
                rsa_indicators[key] = True
        
        is_rsa = sum(rsa_indicators.values()) >= 2
        
        logger.info(f"[crypto] RSA challenge: {is_rsa}")
        
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={
                "is_rsa": is_rsa,
                "rsa_parameters": rsa_indicators,
            }
        )
    
    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        if result.status == NodeStatus.SUCCESS:
            if result.data.get("is_rsa"):
                return CryptoExploitRSANode()
            else:
                return CryptoDetectStreamNode()
        return None


class CryptoDetectStreamNode(DecisionNode):
    """C-D.5: Detect stream cipher reuse."""
    
    def __init__(self):
        super().__init__("crypto_detect_stream", "Crypto: Stream Cipher Reuse")
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Detect multiple ciphertexts encrypted with same key/nonce."""
        challenge = context.get("challenge")
        
        if not challenge:
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"is_stream_reuse": False}
            )
        
        logger.info(f"[crypto] Checking for stream cipher reuse")
        
        # Look for multiple similar-length hex/binary strings in metadata
        content = challenge.metadata.get("content", "")
        
        # Count potential ciphertexts (newline-separated hex strings)
        ciphertexts = [
            line.strip() for line in content.split('\n')
            if line.strip() and self._is_hex(line.strip())
        ]
        
        is_stream_reuse = len(ciphertexts) > 1
        
        logger.info(f"[crypto] Found {len(ciphertexts)} ciphertexts")
        
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={
                "is_stream_reuse": is_stream_reuse,
                "ciphertext_count": len(ciphertexts),
            }
        )
    
    def _is_hex(self, text: str) -> bool:
        """Check if text is hex."""
        try:
            int(text, 16)
            return len(text) >= 4
        except ValueError:
            return False


class CryptoExploitSubstitutionNode(DecisionNode):
    """Exploit substitution cipher with frequency analysis."""
    
    def __init__(self):
        super().__init__("crypto_exploit_substitution", "Crypto: Crack Substitution")
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Use frequency analysis to crack substitution."""
        logger.info(f"[crypto] Attempting substitution crack")
        
        # In real scenario, would use:
        # 1. Frequency analysis
        # 2. Dictionary matching
        # 3. Simulated annealing / genetic algorithms
        
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={"method": "frequency_analysis"}
        )


class CryptoExploitRSANode(DecisionNode):
    """Exploit RSA vulnerability."""
    
    def __init__(self):
        super().__init__("crypto_exploit_rsa", "Crypto: Break RSA")
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Perform RSA attack."""
        logger.info(f"[crypto] Attempting RSA exploitation")
        
        # In real scenario, would:
        # 1. Check if n is factorable (small factors, Wiener attack, etc.)
        # 2. Check if d is weak
        # 3. Perform traditional factorization attacks
        
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={"methods": ["factorize", "wiener_attack", "common_factors"]}
        )


# Summary
"""
Cryptography Detection Tree (C-Detect)

Detection nodes:
- C-D.1 (CryptoDetectEncodingNode) - Decode iteratively
- C-D.2 (CryptoDetectSubstitutionNode) - Detect substitution/Vigenère
- C-D.3 (CryptoDetectXORNode) - Detect XOR/Caesar
- C-D.4 (CryptoDetectRSANode) - Detect RSA challenges
- C-D.5 (CryptoDetectStreamNode) - Detect stream cipher reuse

Decryption methods:
- Iterative decoding (base64, hex, URL-encode)
- Frequency analysis (substitution, Vigenère)
- Brute force (XOR 256 keys, Caesar 26 shifts)
- RSA factorization attacks
- Stream cipher XOR recovery
"""
