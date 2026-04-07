"""MVP: Integrated end-to-end CTF challenge solver.

Demonstrates autonomous vulnerability detection and exploitation
across all challenge categories using integrated decision trees.

NOTE: This implementation uses separate Orchestrator (Python trees) and
TreeExecutor (YAML trees). For new code, consider using UnifiedTreeOrchestrator
from lattice_mind.core.unified_orchestrator which provides a single interface
for both Python and YAML trees with shared SignalBus and ConfidencePool.
"""
import logging
from typing import List, Optional

from lattice_mind.core.types import ChallengeDescriptor, ChallengeType
from lattice_mind.core.orchestrator import Orchestrator
from lattice_mind.core.flag_recognizer import get_flag_recognizer

from lattice_mind.core.tree_loader import get_tree_registry
from lattice_mind.core.confidence import ConfidencePool
from lattice_mind.core.executor import TreeExecutor
from lattice_mind.web.strategy_memory import (
    endpoint_pattern_from_url,
    host_fingerprint_from_url,
    record_strategy_outcomes,
)

# ... (imports)

from lattice_mind.trees.asset.classify import AssetClassifyNetworkNode
from lattice_mind.trees.web.recon import WebReconProbeNode

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

    def solve(
        self,
        challenge: ChallengeDescriptor,
        *,
        selected_tree_ids: Optional[List[str]] = None,
        run_id: Optional[str] = None,
    ) -> Optional[str]:
        """Solve a challenge autonomously.
        
        Steps:
        1. Classify asset type (web, binary, crypto, forensics)
        2. Evaluate and run declarative YAML trees
        3. Monitor for flag detection throughout
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
        if run_id:
            context["run_id"] = run_id
        # Merge MCP-managed session cookies (set via API) for YAML / executor probes
        if run_id:
            try:
                from lattice_mind.core.session_store import get_session_store

                sess = get_session_store().get(run_id)
                if sess and sess.cookies:
                    base = obs.get("session_cookies")
                    base = dict(base) if isinstance(base, dict) else {}
                    merged = dict(base)
                    merged.update(sess.cookies)
                    obs["session_cookies"] = merged
            except Exception as e:
                logger.warning("[MVP] session cookie merge failed: %s", e)

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
                if "werkzeug" in t or "flask" in t:
                    expanded += ["python", "flask", "jinja2"]
                elif "python" in t:
                    expanded.append("python")
                if "django" in t:
                    expanded += ["python", "django"]
                if "ruby" in t or "rails" in t:
                    expanded += ["ruby", "rails"]
            obs["tech_stack"] = list(dict.fromkeys(expanded))  # dedupe, preserve order
        if obs.get("directories") and not obs.get("found_paths"):
            # Normalise to leading-slash format so seeds like "'/admin' in context.found_paths" match.
            obs["found_paths"] = ["/" + d["path"].lstrip("/") for d in obs["directories"] if d.get("path")]
        if obs.get("potential_params") and not obs.get("params"):
            obs["params"] = obs["potential_params"]
        obs.setdefault("tech_stack", [])
        obs.setdefault("found_paths", [])
        obs.setdefault("params", [])
        obs.setdefault("request_candidates", [])
        obs.setdefault("form_reviews", [])
        obs.setdefault("crawl_graph", [])
        obs.setdefault("crawl_stats", {})

        # Mirror to top-level context so ExpressionEvaluator can resolve
        # "context.found_paths" (seeds use top-level keys, not nested observations).
        context["tech_stack"] = obs["tech_stack"]
        context["found_paths"] = obs["found_paths"]
        context["params"] = obs["params"]
        
        # Find applicable trees
        candidate_trees = []
        for tree in self.registry.list_trees():
            if not tree.enabled:
                continue

            # Check applies_when
            from lattice_mind.core.expressions import ExpressionEvaluator

            evaluator = ExpressionEvaluator(context)
            if all(evaluator.evaluate(cond) for cond in tree.applies_when):
                # Evaluate seeds to get initial confidence
                self.executor.evaluate_seeds(tree, context)
                candidate_trees.append(tree)

        execution_plan: dict = {
            "mode": "full",
            "ordered_tree_ids": [t.id for t in candidate_trees],
            "skipped_not_applicable": [],
            "dependency_warnings": [],
        }

        if selected_tree_ids is not None:
            sel_set = set(selected_tree_ids)
            id_to_candidate = {t.id: t for t in candidate_trees}
            skipped_na = [tid for tid in selected_tree_ids if tid not in id_to_candidate]
            from lattice_mind.core.tree_catalog import validate_tree_dependencies

            dep_graph = {t.id: t.depends_on for t in self.registry.list_trees()}
            dep_res = validate_tree_dependencies(
                [tid for tid in selected_tree_ids if tid in id_to_candidate],
                dep_graph,
            )
            ordered = [tid for tid in dep_res.ordered_ids if tid in id_to_candidate]
            candidate_trees = [id_to_candidate[tid] for tid in ordered if tid in id_to_candidate]
            warnings = [f"DEPENDENCY_MISSING:{a}_needs_{b}" for a, b in dep_res.missing_dependencies]
            if dep_res.cycle:
                warnings.append("DEPENDENCY_CYCLE")
            execution_plan = {
                "mode": "selected",
                "ordered_tree_ids": [t.id for t in candidate_trees],
                "skipped_not_applicable": skipped_na,
                "dependency_warnings": warnings,
            }
            logger.info(
                "[MVP] Selected-tree mode: running %s trees (skipped_not_applicable=%s)",
                len(candidate_trees),
                skipped_na,
            )
        
        # Sort candidate trees by initial confidence score (highest first)
        candidate_trees.sort(
            key=lambda t: self.confidence_pool.get_tree_confidence(t.id).score, 
            reverse=True
        )

        logger.info(f"[MVP] Found {len(candidate_trees)} declarative trees to execute")
        for t in candidate_trees:
            score = self.confidence_pool.get_tree_confidence(t.id).score
            logger.info(f"  - {t.id} (initial confidence: {score:.2f})")
        
        # Execute trees by repeatedly picking the highest-confidence unexecuted tree
        # (scores may change after each run, e.g. detection boosts on the active tree).
        id_to_tree = {t.id: t for t in candidate_trees}
        remaining = set(id_to_tree.keys())
        tie_rank = {t.id: i for i, t in enumerate(candidate_trees)}

        import asyncio

        def _next_tree_id() -> str:
            return max(
                remaining,
                key=lambda tid: (
                    self.confidence_pool.get_tree_confidence(tid).score,
                    -tie_rank[tid],
                ),
            )

        while remaining:
            tid = _next_tree_id()
            tree = id_to_tree[tid]
            remaining.remove(tid)
            current_score = self.confidence_pool.get_tree_confidence(tree.id).score
            logger.info(f"\n[MVP] Executing tree: {tree.id} (confidence: {current_score:.2f})")

            flag = asyncio.run(self.executor.execute_tree(tree, context))
            if flag:
                self._record_strategy_memory(context, challenge, flag)
                context["execution_plan"] = execution_plan
                return flag

        self._record_strategy_memory(
            context,
            challenge,
            self.orchestrator.execution_context.get("flag_found"),
        )
        context["execution_plan"] = execution_plan
        return self.orchestrator.execution_context.get("flag_found")

    def _record_strategy_memory(
        self,
        context: dict,
        challenge: ChallengeDescriptor,
        found_flag: Optional[str],
    ) -> None:
        obs = context.get("observations", {})
        outcomes_raw = obs.get("strategy_outcomes") or []
        outcomes = []
        chall_type = challenge.type.value if challenge and challenge.type else "web"
        for row in outcomes_raw:
            if not isinstance(row, dict):
                continue
            mk = row.get("mutation_kind")
            if not mk or mk == "baseline":
                continue
            url = str(row.get("request_url") or challenge.url or "")
            outcomes.append(
                {
                    "challenge_type": chall_type,
                    "host_fingerprint": str(row.get("host_fingerprint") or host_fingerprint_from_url(url)),
                    "endpoint_pattern": str(row.get("endpoint_pattern") or endpoint_pattern_from_url(url)),
                    "mutation_kind": str(mk),
                    "meaningful_delta": bool(row.get("meaningful_delta")),
                    "strong_candidate": bool(row.get("strong_candidate")),
                    "led_to_flag": bool(found_flag),
                    "notes": str(row.get("notes") or "")[:200],
                }
            )
        if outcomes:
            try:
                count = record_strategy_outcomes(outcomes)
                obs["strategy_memory_updates"] = count
            except Exception as e:
                logger.warning("[MVP] strategy memory write failed: %s", e)
    
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
    print("LATTICE MIND - AUTONOMOUS EXPLOITATION FRAMEWORK MVP")
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
