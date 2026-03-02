"""Asset discovery and classification tree (D-0).

Classifies challenges into: web service, pwn/binary, crypto, forensics/misc.
This is the entry point that routes to specialized detection trees.
"""
from typing import Dict, Any, Optional
import logging

from ctf_autopwn.core.nodes import DecisionNode
from ctf_autopwn.core.types import (
    NodeResult, NodeStatus, ChallengeDescriptor, ChallengeType
)
from ctf_autopwn.adapters.file_adapter import FileTypeAdapter

logger = logging.getLogger(__name__)


class AssetClassifyNetworkNode(DecisionNode):
    """D-0.1: Is it a network endpoint?
    
    Check if the challenge is a URL or host:port pair.
    """
    
    def __init__(self):
        super().__init__("asset_classify_network", "Asset: Network Endpoint?")
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Check if challenge is a network endpoint."""
        challenge = context.get("challenge")
        
        if not challenge:
            return NodeResult(
                status=NodeStatus.FAILURE,
                error="No challenge descriptor"
            )
        
        # Check if it's a URL or host:port
        is_network = False
        if challenge.url:
            # URL is a network endpoint
            is_network = True
            logger.info(f"[asset] Network endpoint detected: {challenge.url}")
        
        if is_network:
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={
                    "asset_type": ChallengeType.WEB,
                    "endpoint": challenge.url or challenge.metadata.get("host"),
                }
            )
        else:
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"asset_type": None},
                next_node="asset_classify_binary"
            )
    
    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        if result.data.get("asset_type") == ChallengeType.WEB:
            return AssetClassifyConfirmNode(ChallengeType.WEB)
        return AssetClassifyBinaryNode()


class AssetClassifyBinaryNode(DecisionNode):
    """D-0.2: Is it a binary file?
    
    Run 'file' command to detect ELF/PE binaries.
    """
    
    def __init__(self):
        super().__init__("asset_classify_binary", "Asset: Binary File?")
        self.file_adapter = FileTypeAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Check if challenge is a binary file."""
        challenge = context.get("challenge")
        
        if not challenge or not challenge.file_path:
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"asset_type": None},
                next_node="asset_classify_container"
            )
        
        try:
            result = self.file_adapter.run(challenge.file_path, {})
            file_type = result.get("type", "").lower()
            
            logger.debug(f"[asset] File type: {file_type}")
            
            # Check for binary indicators
            if "elf" in file_type or "pe" in file_type or "executable" in file_type:
                logger.info(f"[asset] Binary detected: {challenge.file_path}")
                return NodeResult(
                    status=NodeStatus.SUCCESS,
                    data={"asset_type": ChallengeType.PWN}
                )
            else:
                return NodeResult(
                    status=NodeStatus.SUCCESS,
                    data={"asset_type": None},
                    next_node="asset_classify_container"
                )
        
        except Exception as e:
            logger.warning(f"[asset] File type detection failed: {str(e)}")
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"asset_type": None},
                next_node="asset_classify_container"
            )
    
    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        if result.data.get("asset_type") == ChallengeType.PWN:
            return AssetClassifyConfirmNode(ChallengeType.PWN)
        return AssetClassifyContainerNode()


class AssetClassifyContainerNode(DecisionNode):
    """D-0.3: Is it a container of other files?
    
    Detect zip, tar, PCAP, disk images, etc.
    """
    
    def __init__(self):
        super().__init__("asset_classify_container", "Asset: Container File?")
        self.file_adapter = FileTypeAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Check if challenge is a container file."""
        challenge = context.get("challenge")
        
        if not challenge or not challenge.file_path:
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"asset_type": None},
                next_node="asset_classify_crypto"
            )
        
        try:
            result = self.file_adapter.run(challenge.file_path, {})
            file_type = result.get("type", "").lower()
            
            logger.debug(f"[asset] File type: {file_type}")
            
            # Check for container indicators
            container_types = ["zip", "tar", "gzip", "pcap", "disk image", 
                             "bzip2", "xz", "rar", "7z", "iso"]
            
            for ctype in container_types:
                if ctype in file_type:
                    logger.info(f"[asset] Container detected: {ctype}")
                    return NodeResult(
                        status=NodeStatus.SUCCESS,
                        data={"asset_type": ChallengeType.FORENSICS}
                    )
            
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"asset_type": None},
                next_node="asset_classify_crypto"
            )
        
        except Exception as e:
            logger.warning(f"[asset] Container detection failed: {str(e)}")
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"asset_type": None},
                next_node="asset_classify_crypto"
            )
    
    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        if result.data.get("asset_type") == ChallengeType.FORENSICS:
            return AssetClassifyConfirmNode(ChallengeType.FORENSICS)
        return AssetClassifyCryptoNode()


class AssetClassifyCryptoNode(DecisionNode):
    """D-0.4: Is it textual crypto?
    
    Check for ASCII text with high entropy or cipher patterns.
    """
    
    def __init__(self):
        super().__init__("asset_classify_crypto", "Asset: Crypto Text?")
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Check if challenge is crypto text."""
        challenge = context.get("challenge")
        
        # Try to read file content if it's a file
        content = None
        if challenge and challenge.file_path:
            try:
                with open(challenge.file_path, 'r', errors='ignore') as f:
                    content = f.read(1000)  # First 1000 chars
            except:
                pass
        
        # Or use metadata
        if not content and challenge:
            content = challenge.metadata.get("content", "")
        
        if not content:
            logger.info("[asset] No content to analyze, defaulting to MISC")
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"asset_type": ChallengeType.MISC}
            )
        
        # Analyze content
        is_crypto = self._analyze_crypto_indicators(content)
        
        if is_crypto:
            logger.info("[asset] Crypto text detected")
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"asset_type": ChallengeType.CRYPTO}
            )
        else:
            logger.info("[asset] Defaulting to MISC")
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"asset_type": ChallengeType.MISC}
            )
    
    def _analyze_crypto_indicators(self, text: str) -> bool:
        """Check for crypto indicators: high entropy, cipher patterns."""
        if not text:
            return False
        
        # Check for clear encodings/patterns
        patterns = {
            "hex": all(c in "0123456789abcdefABCDEF " for c in text[:100]),
            "base64": all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/= \n" for c in text[:100]),
            "alphabetic_only": all(c.isalpha() or c.isspace() for c in text[:100]),
        }
        
        # High entropy check (simplified)
        unique_chars = len(set(text[:100].lower()))
        high_entropy = unique_chars > 20
        
        return any(patterns.values()) or high_entropy
    
    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        if result.data.get("asset_type") == ChallengeType.CRYPTO:
            return AssetClassifyConfirmNode(ChallengeType.CRYPTO)
        return AssetClassifyConfirmNode(ChallengeType.MISC)


class AssetClassifyConfirmNode(DecisionNode):
    """Final node that confirms classification and updates context."""
    
    def __init__(self, asset_type: ChallengeType):
        super().__init__(
            f"asset_classify_confirm_{asset_type.value}",
            f"Confirm: {asset_type.value.upper()}"
        )
        self.asset_type = asset_type
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Confirm and store classification."""
        challenge = context.get("challenge")
        
        # Update challenge type if not already set
        if challenge and challenge.type == ChallengeType.MISC:
            challenge.type = self.asset_type
        
        context["observations"]["asset_type"] = self.asset_type
        
        logger.info(f"[asset] CLASSIFIED as: {self.asset_type.value}")
        
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={
                "asset_type": self.asset_type,
                "ready_for_detection": True,
            }
        )


# Summary
"""
Asset Classification Tree (D-0)

Entry point for all challenges. Routes based on:
1. D-0.1 - Network endpoint? → WEB
2. D-0.2 - Binary file? → PWN
3. D-0.3 - Container (zip/tar/pcap)? → FORENSICS
4. D-0.4 - Crypto text? → CRYPTO
5. Default → MISC

Classification stored in context for use by specialized detection trees.
"""
