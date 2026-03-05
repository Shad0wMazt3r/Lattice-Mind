#!/usr/bin/env python
"""Simple example demonstrating Lattice Mind usage.

Run with: python example_usage.py
"""

import logging
from lattice_mind.mvp import MVPSolver
from lattice_mind.core.types import ChallengeDescriptor, ChallengeType

# Configure logging to see what's happening
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

def example_1_web_challenge():
    """Example 1: Solve a web challenge."""
    logger.info("\n" + "="*70)
    logger.info("EXAMPLE 1: Web Challenge (SQLi)")
    logger.info("="*70)
    
    solver = MVPSolver()
    
    challenge = ChallengeDescriptor(
        type=ChallengeType.WEB,
        name="SQL Injection Challenge",
        url="http://vulnerable-app.local/search",
        metadata={
            "description": "Find the flag by exploiting SQL injection"
        }
    )
    
    logger.info(f"Challenge: {challenge.name}")
    logger.info(f"Target: {challenge.url}")
    
    # In a real scenario, this would run against an actual vulnerable app
    flag = solver.solve(challenge)
    
    if flag:
        logger.info(f"✓ Flag found: {flag}")
    else:
        logger.info("⚠ No flag found (would need real vulnerable app)")

def example_2_binary_challenge():
    """Example 2: Analyze a binary."""
    logger.info("\n" + "="*70)
    logger.info("EXAMPLE 2: Binary Challenge")
    logger.info("="*70)
    
    solver = MVPSolver()
    
    challenge = ChallengeDescriptor(
        type=ChallengeType.PWN,
        name="Binary Exploitation",
        file_path="/tmp/vulnerable_binary",
        metadata={
            "description": "Exploit a stack buffer overflow"
        }
    )
    
    logger.info(f"Challenge: {challenge.name}")
    logger.info(f"Binary: {challenge.file_path}")
    
    # Would analyze binary and attempt exploitation
    flag = solver.solve(challenge)
    
    if flag:
        logger.info(f"✓ Flag found: {flag}")
    else:
        logger.info("⚠ No flag found (would need real binary)")

def example_3_crypto_challenge():
    """Example 3: Solve a crypto challenge."""
    logger.info("\n" + "="*70)
    logger.info("EXAMPLE 3: Crypto Challenge")
    logger.info("="*70)
    
    solver = MVPSolver()
    
    challenge = ChallengeDescriptor(
        type=ChallengeType.CRYPTO,
        name="Caesar Cipher",
        metadata={
            "content": "URYYBJBEYQ"  # ROT13 encoded
        }
    )
    
    logger.info(f"Challenge: {challenge.name}")
    logger.info(f"Content: {challenge.metadata.get('content')}")
    
    # Would detect and break the cipher
    flag = solver.solve(challenge)
    
    if flag:
        logger.info(f"✓ Flag found: {flag}")
    else:
        logger.info("⚠ No flag found")

def example_4_forensics_challenge():
    """Example 4: Extract from forensics artifact."""
    logger.info("\n" + "="*70)
    logger.info("EXAMPLE 4: Forensics Challenge")
    logger.info("="*70)
    
    solver = MVPSolver()
    
    challenge = ChallengeDescriptor(
        type=ChallengeType.FORENSICS,
        name="Image Steganography",
        file_path="/tmp/image.png",
        metadata={
            "description": "Hidden flag in image using LSB steganography"
        }
    )
    
    logger.info(f"Challenge: {challenge.name}")
    logger.info(f"File: {challenge.file_path}")
    
    # Would extract stego data
    flag = solver.solve(challenge)
    
    if flag:
        logger.info(f"✓ Flag found: {flag}")
    else:
        logger.info("⚠ No flag found (would need real forensics artifact)")

def example_5_direct_node_execution():
    """Example 5: Run a specific detection node directly."""
    logger.info("\n" + "="*70)
    logger.info("EXAMPLE 5: Direct Node Execution")
    logger.info("="*70)
    
    from lattice_mind.core.orchestrator import Orchestrator
    from lattice_mind.trees.asset.classify import AssetClassifyNetworkNode
    
    # Create orchestrator
    orchestrator = Orchestrator()
    
    # Create challenge
    challenge = ChallengeDescriptor(
        type=ChallengeType.WEB,
        name="Direct Node Test",
        url="http://test.local/",
    )
    
    # Set challenge
    orchestrator.set_challenge(challenge)
    
    logger.info(f"Challenge set: {challenge.name}")
    logger.info(f"URL: {challenge.url}")
    
    # Run asset classification tree
    root_node = AssetClassifyNetworkNode()
    logger.info(f"Running node: {root_node.name}")
    
    flag = orchestrator.run_tree(root_node)
    
    logger.info(f"Execution context: {orchestrator.execution_context['observations']}")

def main():
    """Run all examples."""
    logger.info("\n" + "="*70)
    logger.info("LATTICE MIND - USAGE EXAMPLES")
    logger.info("="*70)
    logger.info("\nNote: These examples show API usage.")
    logger.info("To test against real vulnerabilities, you would need:")
    logger.info("  - Actual vulnerable web applications")
    logger.info("  - Real binary files with exploitable bugs")
    logger.info("  - Actual CTF challenge files")
    
    # Run examples
    example_1_web_challenge()
    example_2_binary_challenge()
    example_3_crypto_challenge()
    example_4_forensics_challenge()
    example_5_direct_node_execution()
    
    logger.info("\n" + "="*70)
    logger.info("EXAMPLES COMPLETE")
    logger.info("="*70)
    logger.info("\nTo test against real challenges:")
    logger.info("  1. Set up a vulnerable web app (DVWA, WebGoat)")
    logger.info("  2. Modify challenge URLs to point to your app")
    logger.info("  3. Run solver and watch it autonomously detect vulns")
    logger.info("\nFramework is ready for integration testing!")

if __name__ == "__main__":
    main()
