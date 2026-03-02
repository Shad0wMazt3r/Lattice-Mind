"""MVP: Integrated end-to-end CTF challenge solver.

Demonstrates autonomous vulnerability detection and exploitation
across all challenge categories using integrated decision trees.
"""
import logging
from typing import Optional, Dict, Any

from ctf_autopwn.core.types import ChallengeDescriptor, ChallengeType
from ctf_autopwn.core.orchestrator import Orchestrator
from ctf_autopwn.core.flag_recognizer import get_flag_recognizer

# Import all detection tree entry points
from ctf_autopwn.trees.asset.classify import AssetClassifyNetworkNode
from ctf_autopwn.trees.web.recon import WebReconProbeNode
from ctf_autopwn.trees.pwn.detect import PwnDetectMetadataNode
from ctf_autopwn.trees.crypto.detect import CryptoDetectEncodingNode
from ctf_autopwn.trees.forensics.detect import ForensicsDetectArtifactNode

logger = logging.getLogger(__name__)


class MVPSolver:
    """MVP solver that chains asset classification to specialized detection trees."""
    
    def __init__(self):
        self.orchestrator = Orchestrator()
        self.flag_recognizer = get_flag_recognizer()
    
    def solve(self, challenge: ChallengeDescriptor) -> Optional[str]:
        """Solve a challenge autonomously.
        
        Steps:
        1. Classify asset type (web, binary, crypto, forensics)
        2. Route to appropriate detection tree
        3. Run detection nodes to identify vulnerabilities
        4. Monitor for flag detection throughout
        
        Args:
            challenge: ChallengeDescriptor with challenge metadata
        
        Returns:
            Flag if found, None otherwise
        """
        logger.info(f"\n{'='*70}")
        logger.info(f"[MVP] Starting autonomous challenge solve")
        logger.info(f"{'='*70}")
        
        # Set challenge in orchestrator
        self.orchestrator.set_challenge(challenge)
        
        # Step 1: Asset classification
        logger.info("\n[Step 1] Classifying asset type...")
        asset_type = self._classify_asset(challenge)
        
        if not asset_type:
            logger.error("[MVP] Asset classification failed")
            return None
        
        logger.info(f"[Step 1] Classified as: {asset_type}")
        
        # Check if flag found during classification
        flag = self.orchestrator.execution_context.get("flag_found")
        if flag:
            logger.info(f"[MVP] Flag found during classification: {flag}")
            return flag
        
        # Step 2: Route to appropriate detection tree
        logger.info(f"\n[Step 2] Running detection tree for {asset_type}...")
        flag = self._run_detection_tree(asset_type, challenge)
        
        if flag:
            logger.info(f"[MVP] Flag found: {flag}")
            return flag
        
        logger.warning("[MVP] No flag found after detection trees")
        return None
    
    def _classify_asset(self, challenge: ChallengeDescriptor) -> Optional[ChallengeType]:
        """Run asset classification tree (D-0)."""
        try:
            root_node = AssetClassifyNetworkNode()
            flag = self.orchestrator.run_tree(root_node)
            
            # Get classified asset type
            asset_type = self.orchestrator.execution_context.get("observations", {}).get("asset_type")
            
            return asset_type
        
        except Exception as e:
            logger.error(f"[asset] Classification failed: {str(e)}")
            return None
    
    def _run_detection_tree(self, asset_type: ChallengeType, challenge: ChallengeDescriptor) -> Optional[str]:
        """Route to specialized detection tree based on asset type."""
        
        try:
            if asset_type == ChallengeType.WEB:
                logger.info("[detection] Running WEB vulnerability detection...")
                return self._detect_web_vulns(challenge)
            
            elif asset_type == ChallengeType.PWN:
                logger.info("[detection] Running BINARY exploitation detection...")
                return self._detect_binary_vulns(challenge)
            
            elif asset_type == ChallengeType.CRYPTO:
                logger.info("[detection] Running CRYPTO detection...")
                return self._detect_crypto_vulns(challenge)
            
            elif asset_type == ChallengeType.FORENSICS:
                logger.info("[detection] Running FORENSICS detection...")
                return self._detect_forensics(challenge)
            
            else:
                logger.warning(f"[detection] No tree for asset type: {asset_type}")
                return None
        
        except Exception as e:
            logger.error(f"[detection] Tree execution failed: {str(e)}")
            return None
    
    def _detect_web_vulns(self, challenge: ChallengeDescriptor) -> Optional[str]:
        """Run web vulnerability detection (W-Recon as entry point)."""
        try:
            # Use WebReconProbeNode as entry point to web detection tree
            root_node = WebReconProbeNode()
            flag = self.orchestrator.run_tree(root_node)
            
            return flag or self.orchestrator.execution_context.get("flag_found")
        
        except Exception as e:
            logger.error(f"[web] Detection failed: {str(e)}")
            return None
    
    def _detect_binary_vulns(self, challenge: ChallengeDescriptor) -> Optional[str]:
        """Run binary exploitation detection (P-Detect)."""
        try:
            # Use PwnDetectMetadataNode as entry point to binary detection tree
            root_node = PwnDetectMetadataNode()
            flag = self.orchestrator.run_tree(root_node)
            
            return flag or self.orchestrator.execution_context.get("flag_found")
        
        except Exception as e:
            logger.error(f"[pwn] Detection failed: {str(e)}")
            return None
    
    def _detect_crypto_vulns(self, challenge: ChallengeDescriptor) -> Optional[str]:
        """Run cryptography detection (C-Detect)."""
        try:
            # Use CryptoDetectEncodingNode as entry point to crypto detection tree
            root_node = CryptoDetectEncodingNode()
            flag = self.orchestrator.run_tree(root_node)
            
            return flag or self.orchestrator.execution_context.get("flag_found")
        
        except Exception as e:
            logger.error(f"[crypto] Detection failed: {str(e)}")
            return None
    
    def _detect_forensics(self, challenge: ChallengeDescriptor) -> Optional[str]:
        """Run forensics/steganography detection (F-Detect)."""
        try:
            # Use ForensicsDetectArtifactNode as entry point to forensics detection tree
            root_node = ForensicsDetectArtifactNode()
            flag = self.orchestrator.run_tree(root_node)
            
            return flag or self.orchestrator.execution_context.get("flag_found")
        
        except Exception as e:
            logger.error(f"[forensics] Detection failed: {str(e)}")
            return None


def main():
    """Example MVP usage."""
    import sys
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(name)s - %(levelname)s - %(message)s'
    )
    
    # Example 1: Web challenge
    web_challenge = ChallengeDescriptor(
        id="ctf_001",
        name="SQL Injection Challenge",
        type=ChallengeType.WEB,
        url="http://vulnerable-app.com/search",
        description="Find the flag by exploiting SQL injection"
    )
    
    # Example 2: Binary challenge
    binary_challenge = ChallengeDescriptor(
        id="ctf_002",
        name="Buffer Overflow Challenge",
        type=ChallengeType.PWN,
        file_path="/tmp/pwn_binary",
        description="Exploit stack overflow to leak flag"
    )
    
    # Example 3: Crypto challenge
    crypto_challenge = ChallengeDescriptor(
        id="ctf_003",
        name="Cipher Challenge",
        type=ChallengeType.CRYPTO,
        metadata={"content": "HELLO_FLAG_HERE_ENCRYPTED"},
        description="Decrypt the message"
    )
    
    # Example 4: Forensics challenge
    forensics_challenge = ChallengeDescriptor(
        id="ctf_004",
        name="Steganography Challenge",
        type=ChallengeType.FORENSICS,
        file_path="/tmp/image.png",
        description="Extract hidden flag from image"
    )
    
    # Run MVP solver
    solver = MVPSolver()
    
    print("\n" + "="*70)
    print("CTF AUTOPWN - AUTONOMOUS EXPLOITATION FRAMEWORK MVP")
    print("="*70)
    
    challenges = [
        ("Web", web_challenge),
        ("Binary", binary_challenge),
        ("Crypto", crypto_challenge),
        ("Forensics", forensics_challenge),
    ]
    
    for name, challenge in challenges:
        print(f"\n[MVP] Attempting {name} challenge: {challenge.name}")
        print("-" * 70)
        
        flag = solver.solve(challenge)
        
        if flag:
            print(f"\n✓ SUCCESS: Flag found: {flag}")
        else:
            print(f"\n✗ No flag found (would continue with human-in-the-loop)")
        
        print("=" * 70)


if __name__ == "__main__":
    main()
