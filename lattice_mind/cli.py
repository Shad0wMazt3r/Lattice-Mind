"""CLI entry point for Lattice Mind."""
import logging
import sys
from pathlib import Path

from lattice_mind import (
    ChallengeDescriptor,
    ChallengeType,
    get_orchestrator,
    get_flag_recognizer,
)
from lattice_mind.core.nodes import SimpleNode

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def main():
    """Main CLI entry point."""
    logger.info("Lattice Mind Toolkit v0.1.0")
    
    if len(sys.argv) < 2:
        print_usage()
        return
    
    command = sys.argv[1]
    
    if command == "test":
        run_test()
    elif command == "solve":
        if len(sys.argv) < 3:
            print("Usage: Lattice-Mind solve <challenge_type> [url|file]")
            return
        solve_challenge(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
    else:
        print(f"Unknown command: {command}")
        print_usage()


def print_usage():
    """Print usage information."""
    print("""
Lattice Mind - Autonomous CTF Solver

Usage:
  Lattice-Mind test              Run test/demo
  Lattice-Mind solve <type> [url|file]  Solve a challenge
  
Challenge types:
  web, pwn, crypto, forensics, steganography, reverse_engineering, osint, network, misc
""")


def run_test():
    """Run a simple test of the framework."""
    logger.info("Running framework test...")
    
    # Create a test challenge
    challenge = ChallengeDescriptor(
        type=ChallengeType.WEB,
        name="Test Web Challenge",
        url="http://example.com",
        flag_format="flag{...}",
    )
    
    # Get orchestrator and set challenge
    orchestrator = get_orchestrator()
    orchestrator.set_challenge(challenge)
    
    # Create a simple test node
    test_node = SimpleNode("test_1", "Test Node")
    
    # Run the tree
    flag = orchestrator.run_tree(test_node)
    
    # Print results
    execution_log = orchestrator.get_execution_log()
    print(f"\nTest Results:")
    print(f"  Challenge: {challenge.name}")
    print(f"  Flag Found: {flag}")
    print(f"  Tree History: {execution_log['tree_history']}")


def solve_challenge(challenge_type_str: str, target: str):
    """Solve a challenge of the given type.
    
    Args:
        challenge_type_str: Challenge type (e.g., "web", "pwn")
        target: URL or file path
    """
    logger.info(f"Solving {challenge_type_str} challenge: {target}")
    
    # Determine challenge type
    try:
        challenge_type = ChallengeType(challenge_type_str.lower())
    except ValueError:
        print(f"Invalid challenge type: {challenge_type_str}")
        return
    
    # Create challenge descriptor
    if target.startswith("http://") or target.startswith("https://"):
        challenge = ChallengeDescriptor(
            type=challenge_type,
            url=target,
            name=target,
        )
    else:
        # Treat as file
        file_path = Path(target)
        if not file_path.exists():
            print(f"File not found: {target}")
            return
        
        challenge = ChallengeDescriptor(
            type=challenge_type,
            file_path=str(file_path.absolute()),
            name=file_path.name,
        )
    
    # Get orchestrator and run (placeholder - no trees defined yet)
    orchestrator = get_orchestrator()
    orchestrator.set_challenge(challenge)
    
    print(f"Challenge set: {challenge}")
    print("Note: Decision trees not yet implemented for this category")


if __name__ == "__main__":
    main()
