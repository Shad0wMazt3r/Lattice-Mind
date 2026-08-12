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


def normalize_recon_context(context: dict) -> None:
    """Normalize Python recon observations into the YAML expression contract."""
    obs = context.setdefault("observations", {})

    if obs.get("technologies") and not obs.get("tech_stack"):
        technologies = obs["technologies"]
        if isinstance(technologies, dict):
            raw_tech = [str(v).lower() for v in technologies.values() if v]
        else:
            raw_tech = [str(v).lower() for v in technologies if v]
        expanded = list(raw_tech)
        for tech in raw_tech:
            if "coyote" in tech or "tomcat" in tech:
                expanded += ["jsp", "java"]
            if "php" in tech:
                expanded.append("php")
            if "asp" in tech or "iis" in tech:
                expanded += ["asp", "aspx"]
            if "nginx" in tech or "apache" in tech:
                expanded.append("apache")
            if "werkzeug" in tech or "flask" in tech:
                expanded += ["python", "flask", "jinja2"]
            elif "python" in tech:
                expanded.append("python")
            if "django" in tech:
                expanded += ["python", "django"]
            if "ruby" in tech or "rails" in tech:
                expanded += ["ruby", "rails"]
        obs["tech_stack"] = list(dict.fromkeys(expanded))

    directory_records = obs.get("directories") or []
    raw_paths = [
        *(obs.get("found_paths") or []),
        *(obs.get("crawled_endpoints") or []),
        *directory_records,
    ]
    normalized_paths = []
    for item in raw_paths:
        path = item.get("path") if isinstance(item, dict) else item
        if not path:
            continue
        path = "/" + str(path).split("?", 1)[0].lstrip("/")
        if path not in normalized_paths:
            normalized_paths.append(path)
    obs["found_paths"] = normalized_paths

    params = [*(obs.get("params") or []), *(obs.get("potential_params") or [])]
    obs["params"] = list(dict.fromkeys(str(p) for p in params if p))
    obs.setdefault("tech_stack", [])
    obs.setdefault("request_candidates", [])
    obs.setdefault("form_reviews", [])
    obs.setdefault("crawl_graph", [])
    obs.setdefault("crawl_stats", {})

    context["tech_stack"] = obs["tech_stack"]
    context["found_paths"] = obs["found_paths"]
    context["params"] = obs["params"]

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
        # Ensure no stale HITL hints/overrides leak across runs.
        from lattice_mind.core.human_loop import get_human_loop_manager

        human_loop = get_human_loop_manager()
        human_loop.clear()
        human_loop.begin_run(run_id)
        
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
                from lattice_mind.core.session_epoch import get_session_epoch_manager

                sess = get_session_epoch_manager().read(run_id)
                if sess and sess.cookies:
                    base = obs.get("session_cookies")
                    base = dict(base) if isinstance(base, dict) else {}
                    merged = dict(base)
                    merged.update(sess.cookies)
                    obs["session_cookies"] = merged
            except Exception as e:
                raise RuntimeError(f"session cookie merge failed: {e}") from e

        normalize_recon_context(context)
        
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
        
        # Full scans are confidence-ranked. Explicit selections already carry a
        # dependency-safe topological order and must preserve it.
        if selected_tree_ids is None:
            candidate_trees.sort(
                key=lambda t: self.confidence_pool.get_tree_confidence(t.id).score,
                reverse=True,
            )

        logger.info(f"[MVP] Found {len(candidate_trees)} declarative trees to execute")
        for t in candidate_trees:
            score = self.confidence_pool.get_tree_confidence(t.id).score
            logger.info(f"  - {t.id} (initial confidence: {score:.2f})")
        
        # Full scans dynamically re-rank after every tree. Selected scans execute
        # the dependency-safe order calculated above.
        id_to_tree = {t.id: t for t in candidate_trees}
        remaining = set(id_to_tree.keys())
        selected_order = [t.id for t in candidate_trees]
        tie_rank = {t.id: i for i, t in enumerate(candidate_trees)}

        import asyncio

        async def _normalize_exec_result(v):
            if asyncio.iscoroutine(v):
                return await v
            return v

        def _next_tree_id() -> str:
            return max(
                remaining,
                key=lambda tid: (
                    self.confidence_pool.get_tree_confidence(tid).score,
                    -tie_rank[tid],
                ),
            )

        while remaining:
            tid = (
                next(t for t in selected_order if t in remaining)
                if selected_tree_ids is not None
                else _next_tree_id()
            )
            tree = id_to_tree[tid]
            remaining.remove(tid)
            current_score = self.confidence_pool.get_tree_confidence(tree.id).score
            logger.info(f"\n[MVP] Executing tree: {tree.id} (confidence: {current_score:.2f})")

            raw_result = self.executor.execute_tree(tree, context)
            normalized = _normalize_exec_result(raw_result)
            try:
                flag = asyncio.run(normalized)
            finally:
                # Unit-test runners may mock asyncio.run. Explicitly close a
                # never-awaited wrapper so those tests do not leak coroutines.
                if getattr(normalized, "cr_frame", None) is not None:
                    normalized.close()
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
        name="SQL Injection Challenge",
        type=ChallengeType.WEB,
        url="http://vulnerable-app.com/search",
        metadata={"description": "Find the flag by exploiting SQL injection"},
    )
    
    # Example 2: Binary challenge
    binary_challenge = ChallengeDescriptor(
        name="Buffer Overflow Challenge",
        type=ChallengeType.PWN,
        file_path="/tmp/pwn_binary",
        metadata={"description": "Exploit stack overflow to leak flag"},
    )
    
    # Example 3: Crypto challenge
    crypto_challenge = ChallengeDescriptor(
        name="Cipher Challenge",
        type=ChallengeType.CRYPTO,
        metadata={"content": "HELLO_FLAG_HERE_ENCRYPTED"},
    )
    
    # Example 4: Forensics challenge
    forensics_challenge = ChallengeDescriptor(
        name="Steganography Challenge",
        type=ChallengeType.FORENSICS,
        file_path="/tmp/image.png",
        metadata={"description": "Extract hidden flag from image"},
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
