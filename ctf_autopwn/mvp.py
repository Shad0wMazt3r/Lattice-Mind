"""MVP: Integrated end-to-end CTF challenge solver.

Demonstrates autonomous vulnerability detection and exploitation
across all challenge categories using integrated decision trees.
"""
import logging
from typing import Optional, Dict, Any

from ctf_autopwn.core.types import ChallengeDescriptor, ChallengeType
from ctf_autopwn.core.orchestrator import Orchestrator
from ctf_autopwn.core.flag_recognizer import get_flag_recognizer

from ctf_autopwn.core.tree_loader import get_tree_registry
from ctf_autopwn.core.confidence import ConfidencePool
from ctf_autopwn.core.executor import TreeExecutor

# ... (imports)

from ctf_autopwn.trees.asset.classify import AssetClassifyNetworkNode
from ctf_autopwn.trees.web.recon import WebReconProbeNode
from ctf_autopwn.trees.web.sqli import SQLiDetectReflectionNode
from ctf_autopwn.trees.web.lfi import LFIDetectTraversalNode
from ctf_autopwn.trees.web.xss import XSSDetectReflectedNode
from ctf_autopwn.trees.web.cmd import CMDDetectOutputNode
from ctf_autopwn.trees.web.additional import AuthBypassDetectNode
from ctf_autopwn.trees.pwn.detect import PwnDetectMetadataNode
from ctf_autopwn.trees.crypto.detect import CryptoDetectEncodingNode
from ctf_autopwn.trees.forensics.detect import ForensicsDetectArtifactNode

logger = logging.getLogger(__name__)

class MVPSolver:
    """MVP solver that chains asset classification to specialized detection trees."""
    
    def __init__(self):
        self.orchestrator = Orchestrator()
        self.flag_recognizer = get_flag_recognizer()
        self.registry = get_tree_registry()
        # Load trees from default locations
        import pathlib
        base_path = pathlib.Path(__file__).parent / "trees" / "yaml"
        self.registry.load_from_directory(str(base_path))
        
        self.confidence_pool = ConfidencePool()
        self.executor = TreeExecutor(self.confidence_pool)

    def solve(self, challenge: ChallengeDescriptor) -> Optional[str]:
        """Solve a challenge autonomously.
        
        Steps:
        1. Classify asset type (web, binary, crypto, forensics)
        2. Evaluate and run declarative YAML trees
        3. Fallback to legacy Python trees if needed
        4. Monitor for flag detection throughout
        """
        logger.info(f"\n{'='*70}")
        logger.info(f"[MVP] Starting autonomous challenge solve")
        logger.info(f"{'='*70}")
        
        # Set challenge in orchestrator and executor
        self.orchestrator.set_challenge(challenge)
        self.confidence_pool.clear()
        
        # Step 1: Asset classification
        logger.info("\n[Step 1] Classifying asset type...")
        asset_type = self._classify_asset(challenge)
        
        if not asset_type:
            logger.error("[MVP] Asset classification failed")
            # Continue anyway with generic web if URL present
            if challenge.url:
                asset_type = ChallengeType.WEB
            else:
                return None
        
        logger.info(f"[Step 1] Classified as: {asset_type}")
        
        # Step 2: Run Declarative Trees
        logger.info("\n[Step 2] Executing declarative decision trees...")

        # Run initial recon first so observations are populated before YAML
        # confidence seeds are evaluated. Without this all seeds return 0 and
        # every YAML tree is skipped.
        if asset_type == ChallengeType.WEB:
            try:
                self.orchestrator.run_tree(WebReconProbeNode())
            except Exception as e:
                logger.warning(f"[MVP] Web recon pre-pass failed: {e}")

        
        # Set up progress callback for executor to match orchestrator flow
        if self.orchestrator._progress_callback:
            self.executor.set_progress_callback(self.orchestrator._progress_callback)

        # Build context for expression evaluation
        context = self.orchestrator.execution_context
        obs = context["observations"]

        # Translate legacy recon keys to YAML-expected names.
        # WebReconProbeNode writes "technologies" (dict) and "directories" (list of dicts);
        # YAML confidence seeds reference tech_stack, found_paths, params.
        if obs.get("technologies") and not obs.get("tech_stack"):
            raw_tech = [v.lower() for v in obs["technologies"].values() if v]
            # Expand server strings to known tech tokens so seeds like
            # "'jsp' in context.tech_stack" fire correctly.
            # e.g. "apache-coyote/1.1" → also add "jsp", "java"
            expanded = list(raw_tech)
            for t in raw_tech:
                if "coyote" in t or "tomcat" in t:
                    expanded += ["jsp", "java"]
                if "php" in t:
                    expanded.append("php")
                if "asp" in t or "iis" in t:
                    expanded += ["asp", "aspx"]
                if "nginx" in t or "apache" in t:
                    expanded.append("apache")
            obs["tech_stack"] = list(dict.fromkeys(expanded))  # dedupe, preserve order
        if obs.get("directories") and not obs.get("found_paths"):
            # Normalise to leading-slash format so seeds like "'/admin' in context.found_paths" match.
            obs["found_paths"] = ["/" + d["path"].lstrip("/") for d in obs["directories"] if d.get("path")]
        if obs.get("potential_params") and not obs.get("params"):
            obs["params"] = obs["potential_params"]
        obs.setdefault("tech_stack", [])
        obs.setdefault("found_paths", [])
        obs.setdefault("params", [])

        # Mirror to top-level context so ExpressionEvaluator can resolve
        # "context.found_paths" (seeds use top-level keys, not nested observations).
        context["tech_stack"] = obs["tech_stack"]
        context["found_paths"] = obs["found_paths"]
        context["params"] = obs["params"]
        
        # Find applicable trees
        candidate_trees = []
        for tree in self.registry.list_trees():
            if not tree.enabled: continue
            
            # Check applies_when
            from ctf_autopwn.core.expressions import ExpressionEvaluator
            evaluator = ExpressionEvaluator(context)
            if all(evaluator.evaluate(cond) for cond in tree.applies_when):
                candidate_trees.append(tree)
        
        logger.info(f"[MVP] Found {len(candidate_trees)} applicable declarative trees")
        
        # Execute each tree (this could be parallelized)
        import asyncio
        for tree in candidate_trees:
            # We need to bridge sync solve() with async executor
            flag = asyncio.run(self.executor.execute_tree(tree, context))
            if flag:
                return flag

        # Step 3: Fallback to Legacy Trees
        logger.info("\n[Step 3] Running legacy detection trees...")
        flag = self._run_detection_tree(asset_type, challenge)
        
        if flag:
            return flag
        
        return self.orchestrator.execution_context.get("flag_found")
    
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
        """Run web vulnerability detection, then dispatch exploitation trees."""
        try:
            # Phase 1: Recon (probe + dir scan + vuln analysis)
            # Skip if the Step 2 pre-pass already populated observations.
            observations = self.orchestrator.execution_context.get("observations", {})
            if not observations.get("directories"):
                root_node = WebReconProbeNode()
                flag = self.orchestrator.run_tree(root_node)
                if flag:
                    return flag
                observations = self.orchestrator.execution_context.get("observations", {})

            # Phase 2: Read candidates written by WebReconAnalyzeVulnsNode
            vuln_candidates = observations.get("vuln_candidates", {})

            if not vuln_candidates:
                logger.warning("[web] No vulnerability candidates identified — stopping")
                return self.orchestrator.execution_context.get("flag_found")

            logger.info(f"[web] Phase 2 — dispatching trees for: {list(vuln_candidates.keys())}")

            # Phase 3: Dispatch exploitation trees per candidate
            for vuln_type, evidence in vuln_candidates.items():
                flag = self._dispatch_web_exploit(vuln_type, evidence, challenge)
                if flag:
                    return flag

            return self.orchestrator.execution_context.get("flag_found")

        except Exception as e:
            logger.error(f"[web] Detection failed: {str(e)}")
            return None

    def _dispatch_web_exploit(
        self, vuln_type: str, evidence: list, challenge: ChallengeDescriptor
    ) -> Optional[str]:
        """Run the exploitation tree for a single vuln type."""
        ctx = self.orchestrator.execution_context
        logger.info(f"[web] Running {vuln_type} tree (evidence={evidence})")

        # Pin all exploitation trees as branches of the analysis node in the UI tree
        self.orchestrator.set_branch_parent("web_recon_analyze_vulns")

        try:
            if vuln_type == "auth_bypass":
                return self.orchestrator.run_tree(AuthBypassDetectNode())

            if vuln_type == "sql_injection":
                # evidence entries are either "parameter" (generic) or param names
                params = [e for e in evidence if e != "parameter"] or ["id", "page", "query"]
                for param in params[:3]:
                    ctx["target_param"] = {"name": param, "endpoint": challenge.url}
                    flag = self.orchestrator.run_tree(SQLiDetectReflectionNode())
                    if flag:
                        return flag
                return None

            if vuln_type == "lfi":
                for entry in evidence[:3]:
                    if entry == "parameter":
                        test_params = ["file", "path", "include", "page"]
                    else:
                        # entry is a directory path containing upload/file
                        test_params = ["file"]
                        challenge_url_orig = challenge.url
                        challenge.url = f"{challenge.url.rstrip('/')}/{entry}"
                    for param in test_params:
                        ctx["target_param"] = {"name": param, "endpoint": challenge.url}
                        flag = self.orchestrator.run_tree(LFIDetectTraversalNode())
                        if flag:
                            return flag
                    if entry != "parameter":
                        challenge.url = challenge_url_orig
                return None

            if vuln_type == "xss":
                obs = ctx.get("observations", {})
                params = list(obs.get("potential_params", [])) or ["search", "q", "query", "name"]
                for param in params[:3]:
                    ctx["target_param"] = {"name": param, "endpoint": challenge.url}
                    flag = self.orchestrator.run_tree(XSSDetectReflectedNode())
                    if flag:
                        return flag
                return None

            if vuln_type == "command_injection":
                for param in evidence[:3]:
                    if param == "parameter":
                        continue
                    ctx["target_param"] = {"name": param, "endpoint": challenge.url}
                    flag = self.orchestrator.run_tree(CMDDetectOutputNode())
                    if flag:
                        return flag
                return None

        except Exception as e:
            logger.error(f"[web] {vuln_type} dispatch error: {str(e)}")

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
