"""Runtime executor for YAML-based decision trees."""
import asyncio
import logging
import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from ctf_autopwn.core.types import ChallengeDescriptor, NodeStatus
from ctf_autopwn.core.tree_loader import DecisionTree, DetectionPath, ExploitationPath, DetectionStep, ExploitationStep
from ctf_autopwn.core.confidence import ConfidencePool
from ctf_autopwn.core.expressions import ExpressionEvaluator, evaluate_condition
from ctf_autopwn.core.flag_recognizer import get_flag_recognizer

logger = logging.getLogger(__name__)


class SignalBus:
    """Tracks emitted signals during detection phase."""
    def __init__(self):
        self.signals: Set[str] = set()

    def emit(self, tree_id: str, signal_name: str):
        full_signal = f"{tree_id}:{signal_name}"
        self.signals.add(full_signal)
        return full_signal

    def has_signal(self, tree_id: str, signal_name: str) -> bool:
        return f"{tree_id}:{signal_name}" in self.signals


class TreeExecutor:
    """Executes declarative decision trees."""

    def __init__(self, confidence_pool: ConfidencePool):
        self.confidence_pool = confidence_pool
        self.signal_bus = SignalBus()
        self.captures: Dict[str, Any] = {}
        self.flag_recognizer = get_flag_recognizer()
        self._progress_callback = None

    def set_progress_callback(self, callback):
        self._progress_callback = callback

    async def execute_tree(self, tree: DecisionTree, context: Dict[str, Any]):
        """Run full tree lifecycle: Seeds -> Detection -> Exploitation."""
        
        # 1. Seeds
        evaluator = ExpressionEvaluator(context)
        for seed in tree.confidence_seeds:
            try:
                if evaluator.evaluate(seed.condition):
                    self.confidence_pool.apply_boost(tree.id, seed.boost, seed.label, phase="seed")
            except Exception as e:
                logger.error(f"Error evaluating seed in {tree.id}: {e}")

        # 2. Detection Phase
        current_conf = self.confidence_pool.get_tree_confidence(tree.id).score
        if current_conf < tree.min_confidence:
            logger.info(f"Skipping detection for {tree.id}: confidence {current_conf:.2f} < {tree.min_confidence}")
            return None

        detection_tasks = []
        for path in tree.detection_paths:
            if current_conf >= path.min_confidence:
                detection_tasks.append(self._run_detection_path(tree, path, context))
        
        if detection_tasks:
            await asyncio.gather(*detection_tasks)

        # 3. Exploitation Phase
        self.confidence_pool.freeze()
        
        # Filter exploit paths whose signals were emitted
        valid_exploits = [
            p for p in tree.exploitation_paths 
            if self.signal_bus.has_signal(tree.id, p.requires_signal)
        ]
        
        # Execute exploitation paths sequentially
        for exploit in valid_exploits:
            flag = await self._run_exploitation_path(tree, exploit, context)
            if flag and tree.stop_on_flag:
                return flag
        
        return None

    async def _run_detection_path(self, tree: DecisionTree, path: DetectionPath, context: Dict[str, Any]):
        """Run steps in a detection path sequentially."""
        logger.info(f"Running detection path: {tree.id}/{path.id}")
        
        for step in path.steps:
            results = await self._run_step(tree, step, context)
            
            # results is a list of response dicts (one per payload)
            for result in results:
                # Process signals
                for sig_def in step.signals:
                    matched = False
                    if "match" in sig_def and isinstance(sig_def["match"], str):
                        # Simple regex match in response.body
                        body = result.get("body", "")
                        if re.search(sig_def["match"], body, re.IGNORECASE):
                            matched = True
                    elif "match" in sig_def and isinstance(sig_def["match"], dict):
                        # Mini-language condition
                        cond = sig_def["match"].get("condition")
                        if cond:
                            # Build local context for evaluation
                            local_ctx = context.copy()
                            local_ctx["response"] = result
                            local_ctx["response_time"] = result.get("response_time", 0)
                            if evaluate_condition(cond, local_ctx):
                                matched = True
                    
                    if matched:
                        on_match = sig_def.get("on_match", {})
                        boost = on_match.get("confidence_boost", 0.0)
                        if boost:
                            self.confidence_pool.apply_boost(tree.id, boost, f"match:{step.id}", phase="detection")
                        
                        signal_name = on_match.get("emit")
                        if signal_name:
                            self.signal_bus.emit(tree.id, signal_name)
                            # Record the parameter that worked
                            if result.get("injected_param"):
                                context["vulnerable_param"] = result["injected_param"]

            # Handle step flow (success/failure)
            # Simplified: always continue for now
            pass

    async def _run_exploitation_path(self, tree: DecisionTree, path: ExploitationPath, context: Dict[str, Any]):
        """Run steps in an exploitation path sequentially."""
        logger.info(f"Running exploitation path: {tree.id}/{path.id}")
        
        for step in path.steps:
            results = await self._run_step(tree, step, context)
            
            for result in results:
                # Handle captures
                for cap_def in step.capture:
                    pattern = cap_def.get("pattern")
                    as_key = cap_def.get("as")
                    if pattern and as_key:
                        body = result.get("body", "")
                        m = re.search(pattern, body)
                        if m:
                            val = m.group(1) if m.groups() else m.group(0)
                            self.captures[as_key] = val
                            context.setdefault("captures", {})[as_key] = val
                
                # Check for flag in body
                body = result.get("body", "")
                flag = self.flag_recognizer.recognize(body)
                if flag:
                    return flag
        return None

    async def _run_step(self, tree: DecisionTree, step: Any, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Execute a single step action, possibly with multiple payloads."""
        from ctf_autopwn.adapters.curl_adapter import CurlAdapter
        
        action = step.action
        params = step.params
        
        payloads = params.get("payloads", [])
        if "payload" in params:
            payloads.append(params["payload"])
        if not payloads:
            payloads = [None]
            
        inject_into = params.get("inject_into", "none")
        url = context.get("challenge", {}).url
        
        # Determine target parameters
        target_params = []
        if inject_into == "all_params":
            target_params = context.get("observations", {}).get("params", ["id", "query", "user"])
        elif inject_into == "vulnerable_param":
            v = context.get("vulnerable_param")
            target_params = [v] if v else ["id"]
        else:
            target_params = [None]

        self._emit_progress("node_start", tree.id, step.id)
        
        results = []
        adapter = CurlAdapter()
        
        for p in payloads:
            for param in target_params:
                start_time = time.time()
                
                # Build request params
                req_params = {}
                if param and p:
                    # Template replacement in payload if needed
                    final_p = p
                    if "{{" in str(p):
                        # Simple jinja-like replacement
                        for k, v in self.captures.items():
                            final_p = final_p.replace("{{ captures." + k + " }}", str(v))
                    req_params[param] = final_p
                
                # Run the probe
                try:
                    # Note: CurlAdapter is synchronous in this codebase
                    resp = adapter.run(url, req_params)
                    elapsed = (time.time() - start_time) * 1000
                    resp["response_time"] = elapsed
                    resp["injected_param"] = param
                    resp["injected_payload"] = p
                    results.append(resp)
                except Exception as e:
                    logger.error(f"Step execution failed: {e}")
        
        self._emit_progress("node_end", tree.id, step.id, status="success")
        return results

    def _emit_progress(self, event: str, tree_id: str, node_id: str, status: Optional[str] = None):
        if self._progress_callback:
            self._progress_callback({
                "event": event,
                "node_id": f"{tree_id}:{node_id}",
                "node_name": node_id,
                "status": status,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
