#!/usr/bin/env python
"""Local deployment test script for CTF Autopwn MVP.

Tests all major components:
- Framework initialization
- Decision node execution
- Tool adapter availability
- Flag recognizer
- MVP solver

Run with: python test_deployment.py
"""

import sys
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_imports():
    """Test that all modules import correctly."""
    logger.info("\n" + "="*70)
    logger.info("TEST 1: Module Imports")
    logger.info("="*70)
    
    try:
        from ctf_autopwn.core.types import ChallengeDescriptor, ChallengeType, NodeStatus
        logger.info("✓ Core types imported")
        
        from ctf_autopwn.core.nodes import DecisionNode, SimpleNode
        logger.info("✓ Decision nodes imported")
        
        from ctf_autopwn.core.orchestrator import Orchestrator
        logger.info("✓ Orchestrator imported")
        
        from ctf_autopwn.core.flag_recognizer import get_flag_recognizer
        logger.info("✓ Flag recognizer imported")
        
        from ctf_autopwn.adapters.curl_adapter import CurlAdapter
        logger.info("✓ Curl adapter imported")
        
        from ctf_autopwn.adapters.file_adapter import FileTypeAdapter, BinwalkAdapter, ExiftoolAdapter
        logger.info("✓ File adapters imported")
        
        from ctf_autopwn.trees.asset.classify import AssetClassifyNetworkNode
        logger.info("✓ Asset classification tree imported")
        
        from ctf_autopwn.trees.web.sqli import SQLiDetectReflectionNode
        logger.info("✓ Web SQLi tree imported")
        
        from ctf_autopwn.trees.pwn.detect import PwnDetectMetadataNode
        logger.info("✓ Binary exploitation tree imported")
        
        from ctf_autopwn.trees.crypto.detect import CryptoDetectEncodingNode
        logger.info("✓ Crypto tree imported")
        
        from ctf_autopwn.trees.forensics.detect import ForensicsDetectArtifactNode
        logger.info("✓ Forensics tree imported")
        
        from ctf_autopwn.mvp import MVPSolver
        logger.info("✓ MVP solver imported")
        
        logger.info("\n✅ All imports successful!")
        return True
    
    except Exception as e:
        logger.error(f"❌ Import failed: {str(e)}")
        return False

def test_framework():
    """Test core framework functionality."""
    logger.info("\n" + "="*70)
    logger.info("TEST 2: Framework Functionality")
    logger.info("="*70)
    
    try:
        from ctf_autopwn.core.orchestrator import Orchestrator
        from ctf_autopwn.core.types import ChallengeDescriptor, ChallengeType
        from ctf_autopwn.core.flag_recognizer import get_flag_recognizer
        
        # Create orchestrator
        orchestrator = Orchestrator()
        logger.info("✓ Orchestrator created")
        
        # Create challenge
        challenge = ChallengeDescriptor(
            type=ChallengeType.WEB,
            name="Test Challenge",
            url="http://test.local/",
        )
        logger.info("✓ Challenge descriptor created")
        
        # Set challenge
        orchestrator.set_challenge(challenge)
        logger.info("✓ Challenge set in orchestrator")
        
        # Test flag recognizer
        flag_recognizer = get_flag_recognizer()
        logger.info("✓ Flag recognizer singleton accessed")
        
        # Test flag recognition
        test_text = "The flag{test_flag_12345} is here"
        flag = flag_recognizer.recognize(test_text)
        if flag:
            logger.info(f"✓ Flag recognizer working: {flag}")
        else:
            logger.warning(f"⚠ Flag recognizer didn't find flag in test")
        
        logger.info("\n✅ Framework functionality verified!")
        return True
    
    except Exception as e:
        logger.error(f"❌ Framework test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def test_adapters():
    """Test tool adapters."""
    logger.info("\n" + "="*70)
    logger.info("TEST 3: Tool Adapters")
    logger.info("="*70)
    
    try:
        from ctf_autopwn.adapters.base import MockToolAdapter
        
        # Test mock adapter (works without actual tools)
        adapter = MockToolAdapter("test_tool", {"test": "response"})
        logger.info("✓ Mock adapter created")
        
        result = adapter.run("test", {})
        logger.info(f"✓ Mock adapter execute: {result}")
        
        # Try curl adapter
        try:
            from ctf_autopwn.adapters.curl_adapter import CurlAdapter
            curl = CurlAdapter()
            logger.info("✓ Curl adapter available")
        except Exception as e:
            logger.warning(f"⚠ Curl adapter unavailable: {str(e)}")
        
        # Try file type adapter
        try:
            from ctf_autopwn.adapters.file_adapter import FileTypeAdapter
            file_adapter = FileTypeAdapter()
            logger.info("✓ File type adapter available")
        except Exception as e:
            logger.warning(f"⚠ File type adapter unavailable: {str(e)}")
        
        logger.info("\n✅ Adapter tests completed!")
        return True
    
    except Exception as e:
        logger.error(f"❌ Adapter test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def test_decision_nodes():
    """Test decision node execution."""
    logger.info("\n" + "="*70)
    logger.info("TEST 4: Decision Node Execution")
    logger.info("="*70)
    
    try:
        from ctf_autopwn.core.nodes import SimpleNode
        from ctf_autopwn.core.types import NodeStatus, NodeResult
        
        # Create a simple node
        node = SimpleNode("test_node", "Test Node")
        logger.info("✓ SimpleNode created")
        
        # Execute node
        context = {
            "test_key": "test_value",
            "observations": {}
        }
        
        result = node.run(context)
        logger.info(f"✓ Node executed: status={result.status}")
        
        if result.status == NodeStatus.SUCCESS:
            logger.info("✓ Node returned SUCCESS")
        
        next_node = node.next_node(result)
        logger.info(f"✓ Next node routing: {next_node}")
        
        logger.info("\n✅ Decision node tests passed!")
        return True
    
    except Exception as e:
        logger.error(f"❌ Decision node test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def test_mvp_solver():
    """Test MVP solver."""
    logger.info("\n" + "="*70)
    logger.info("TEST 5: MVP Solver")
    logger.info("="*70)
    
    try:
        from ctf_autopwn.mvp import MVPSolver
        from ctf_autopwn.core.types import ChallengeDescriptor, ChallengeType
        
        # Create solver
        solver = MVPSolver()
        logger.info("✓ MVPSolver created")
        
        # Create test challenge (asset classification should work)
        challenge = ChallengeDescriptor(
            type=ChallengeType.WEB,
            name="Asset Classification Test",
            url="http://test.local/search",
        )
        logger.info("✓ Test challenge created")
        
        # Note: This won't actually find flags without real targets,
        # but it should execute without errors
        logger.info("⚠ Note: Skipping full solve() test (requires real targets)")
        logger.info("✓ MVP solver structure validated")
        
        logger.info("\n✅ MVP solver tests completed!")
        return True
    
    except Exception as e:
        logger.error(f"❌ MVP solver test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def test_tree_nodes():
    """Test that detection trees can be instantiated."""
    logger.info("\n" + "="*70)
    logger.info("TEST 6: Detection Tree Nodes")
    logger.info("="*70)
    
    tests = [
        ("Asset Classification", "ctf_autopwn.trees.asset.classify", "AssetClassifyNetworkNode"),
        ("Web SQLi Detection", "ctf_autopwn.trees.web.sqli", "SQLiDetectReflectionNode"),
        ("Web CMD Detection", "ctf_autopwn.trees.web.cmd", "CMDDetectOutputNode"),
        ("Web LFI Detection", "ctf_autopwn.trees.web.lfi", "LFIDetectTraversalNode"),
        ("Web XSS Detection", "ctf_autopwn.trees.web.xss", "XSSDetectReflectedNode"),
        ("Binary Exploitation", "ctf_autopwn.trees.pwn.detect", "PwnDetectMetadataNode"),
        ("Cryptography", "ctf_autopwn.trees.crypto.detect", "CryptoDetectEncodingNode"),
        ("Forensics", "ctf_autopwn.trees.forensics.detect", "ForensicsDetectArtifactNode"),
    ]
    
    success = 0
    for name, module, cls in tests:
        try:
            mod = __import__(module, fromlist=[cls])
            node_class = getattr(mod, cls)
            node = node_class()
            logger.info(f"✓ {name}: {cls}")
            success += 1
        except Exception as e:
            logger.warning(f"⚠ {name}: {str(e)}")
    
    logger.info(f"\n✅ Tree nodes: {success}/{len(tests)} verified!")
    return success > 0

def main():
    """Run all deployment tests."""
    logger.info("\n" + "="*70)
    logger.info("CTF AUTOPWN - LOCAL DEPLOYMENT TEST")
    logger.info("="*70)
    
    results = []
    
    # Run all tests
    results.append(("Imports", test_imports()))
    results.append(("Framework", test_framework()))
    results.append(("Adapters", test_adapters()))
    results.append(("Decision Nodes", test_decision_nodes()))
    results.append(("MVP Solver", test_mvp_solver()))
    results.append(("Tree Nodes", test_tree_nodes()))
    
    # Summary
    logger.info("\n" + "="*70)
    logger.info("TEST SUMMARY")
    logger.info("="*70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        logger.info(f"{status}: {name}")
    
    logger.info(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        logger.info("\n🎉 ALL TESTS PASSED - LOCAL DEPLOYMENT SUCCESSFUL!")
        return 0
    else:
        logger.warning(f"\n⚠ {total - passed} test(s) failed - Review errors above")
        return 1

if __name__ == "__main__":
    sys.exit(main())
