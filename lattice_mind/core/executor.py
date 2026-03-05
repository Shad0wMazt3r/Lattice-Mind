"""Runtime executor for YAML-based decision trees."""
import asyncio
import logging
import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from lattice_mind.core.types import ChallengeDescriptor, NodeStatus
from lattice_mind.core.tree_loader import DecisionTree, DetectionPath, ExploitationPath, DetectionStep, ExploitationStep
from lattice_mind.core.confidence import ConfidencePool
from lattice_mind.core.expressions import ExpressionEvaluator, evaluate_condition
from lattice_mind.core.flag_recognizer import get_flag_recognizer

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

    def evaluate_seeds(self, tree: DecisionTree, context: Dict[str, Any]):
        """Evaluate confidence seeds for a tree to set initial confidence."""
        self.confidence_pool.frozen = False
        evaluator = ExpressionEvaluator(context)
        for seed in tree.confidence_seeds:
            try:
                if evaluator.evaluate(seed.condition):
                    self.confidence_pool.apply_boost(tree.id, seed.boost, seed.label, phase="seed")
            except Exception as e:
                logger.error(f"Error evaluating seed in {tree.id}: {e}")

    async def execute_tree(self, tree: DecisionTree, context: Dict[str, Any]):
        """Run full tree lifecycle: Seeds -> Detection -> Exploitation."""
        
        # Reset per-run state so stale captures/signals from a prior tree
        # execution can never leak into this run.
        self.captures.clear()
        self.signal_bus = SignalBus()

        # 1. Seeds — always evaluate seeds even if pool was frozen by a prior tree
        self.evaluate_seeds(tree, context)

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
            self._emit_progress("node_start", tree.id, step.id)
            results = await self._run_step(tree, step, context)
            
            # results is a list of response dicts (one per payload)
            any_matched = False
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
                            # Expose comparison responses if present in result
                            if "true_response" in result:
                                local_ctx["true_response"] = result["true_response"]
                            if "false_response" in result:
                                local_ctx["false_response"] = result["false_response"]
                            try:
                                if evaluate_condition(cond, local_ctx):
                                    matched = True
                            except Exception:
                                pass  # Missing variables → condition not met
                    
                    if matched:
                        any_matched = True
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
            status = "success" if any_matched else "failure"
            self._emit_progress("node_end", tree.id, step.id, status=status)

    async def _run_exploitation_path(self, tree: DecisionTree, path: ExploitationPath, context: Dict[str, Any]):
        """Run steps in an exploitation path sequentially."""
        logger.info(f"Running exploitation path: {tree.id}/{path.id}")
        
        for step in path.steps:
            self._emit_progress("node_start", tree.id, step.id)
            results = await self._run_step(tree, step, context)
            
            step_success = False
            found_flag = None
            
            for result in results:
                body = result.get("body", "")
                payload = result.get("injected_payload", "")
                logger.info(f"[exploit] param={result.get('injected_param')} payload={str(payload)[:80]} status={result.get('status')} body_len={len(body)} body={body[:300]!r}")

                # Handle captures
                for cap_def in step.capture:
                    pattern = cap_def.get("pattern")
                    as_key = cap_def.get("as")
                    if pattern and as_key:
                        m = re.search(pattern, body)
                        if m:
                            val = m.group(1) if m.groups() else m.group(0)
                            self.captures[as_key] = val
                            context.setdefault("captures", {})[as_key] = val
                            step_success = True

                self._emit_progress(
                    "exploit_result",
                    tree.id,
                    step.id,
                    status=result.get("status"),
                    data={
                        "param": result.get("injected_param"),
                        "payload_preview": str(payload)[:120],
                        "body_preview": body[:400],
                        "captures": context.get("captures", {}),
                        "status": result.get("status"),
                    },
                )

                # Check for flag in body
                flag = self.flag_recognizer.recognize(body)
                if flag:
                    logger.info(f"[exploit] FLAG FOUND: {flag}")
                    self.captures["flag_value"] = flag
                    context.setdefault("captures", {})["flag_value"] = flag
                    context["flag_found"] = flag
                    found_flag = flag
                    step_success = True
                    break
                
                # Fallback: check capture named "flag_value"
                captured = self.captures.get("flag_value", "")
                if captured and self.flag_recognizer.recognize(captured):
                    logger.info(f"[exploit] FLAG via capture: {captured}")
                    context.setdefault("captures", {})["flag_value"] = captured
                    context["flag_found"] = captured
                    found_flag = captured
                    step_success = True
                    break
            
            status = "success" if step_success else "failure"
            if found_flag:
                self._emit_progress(
                    "flag_found",
                    tree.id,
                    step.id,
                    status=status,
                    data={"flag": found_flag, "param": results[0].get("injected_param") if results else None},
                )
                self._emit_progress("node_end", tree.id, step.id, status=status)
                return found_flag
            
            self._emit_progress("node_end", tree.id, step.id, status=status)
            
        return None

    async def _run_step(self, tree: DecisionTree, step: Any, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Execute a single step action, possibly with multiple payloads."""
        from lattice_mind.adapters.curl_adapter import RequestsAdapter
        
        action = step.action
        params = step.params
        
        payloads = params.get("payloads", [])
        if "payload" in params:
            payloads.append(params["payload"])
        
        # Handle boolean-comparison pattern: true_payload vs false_payload
        true_payload = params.get("true_payload")
        false_payload = params.get("false_payload")
        if true_payload is not None and false_payload is not None:
            return await self._run_comparison_step(tree, step, context, true_payload, false_payload)
        
        if not payloads:
            payloads = [None]
            
        inject_into = params.get("inject_into", "none")
        challenge = context.get("challenge")
        url = challenge.url if challenge else ""
        
        # Determine target parameters
        obs = context.get("observations", {})
        target_params = []
        if inject_into == "all_params":
            discovered = obs.get("params") or obs.get("potential_params") or []
            target_params = discovered if discovered else ["id", "query", "name", "user"]
        elif inject_into == "vulnerable_param":
            v = context.get("vulnerable_param")
            target_params = [v] if v else ["id"]
        else:
            target_params = [None]

        # Determine form submission targets: [(url, method), ...]
        probe_targets = []
        forms = obs.get("forms", [])
        if inject_into != "none" and forms:
            for f in forms[:2]:  # at most 2 forms
                probe_targets.append((f.get("action", url), f.get("method", "GET").upper()))
        # Always include a plain GET to the challenge URL as fallback
        if not probe_targets or not any(m == "GET" for _, m in probe_targets):
            probe_targets.append((url, "GET"))

        results = []
        adapter = RequestsAdapter()
        
        for p in payloads:
            for param in target_params:
                for probe_url, http_method in probe_targets:
                    start_time = time.time()
                    
                    if param and p is not None:
                        final_p = str(p)
                        for k, v in self.captures.items():
                            final_p = final_p.replace("{{ captures." + k + " }}", str(v))
                        req_args: Dict[str, Any] = {"follow_redirects": True}
                        if http_method == "POST":
                            req_args["method"] = "POST"
                            req_args["data"] = {param: final_p}
                        else:
                            req_args["params"] = {param: final_p}
                    else:
                        req_args = {"follow_redirects": True}
                    
                    try:
                        resp = adapter.run(probe_url, req_args)
                        elapsed = (time.time() - start_time) * 1000
                        resp["response_time"] = elapsed
                        resp["injected_param"] = param
                        resp["injected_payload"] = p
                        results.append(resp)
                    except Exception as e:
                        logger.error(f"Step execution failed: {e}")
        
        return results

    async def _run_comparison_step(self, tree: DecisionTree, step: Any, context: Dict[str, Any],
                                    true_payload: str, false_payload: str) -> List[Dict[str, Any]]:
        """Run two requests (true/false payloads) and return a synthetic comparison result."""
        from lattice_mind.adapters.curl_adapter import RequestsAdapter
        adapter = RequestsAdapter()
        params = step.params
        inject_into = params.get("inject_into", "none")
        challenge = context.get("challenge")
        url = challenge.url if challenge else ""
        obs = context.get("observations", {})

        if inject_into == "all_params":
            discovered = obs.get("params") or obs.get("potential_params") or []
            target_params = discovered if discovered else ["id"]
        elif inject_into == "vulnerable_param":
            v = context.get("vulnerable_param")
            target_params = [v] if v else ["id"]
        else:
            target_params = [None]

        forms = obs.get("forms", [])
        probe_targets = [(f.get("action", url), f.get("method", "GET").upper()) for f in forms[:2]]
        if not probe_targets:
            probe_targets = [(url, "GET")]

        results = []
        for param in target_params:
            for probe_url, http_method in probe_targets:
                try:
                    def _build_args(payload):
                        args: Dict[str, Any] = {"follow_redirects": True}
                        if param:
                            if http_method == "POST":
                                args["method"] = "POST"
                                args["data"] = {param: payload}
                            else:
                                args["params"] = {param: payload}
                        return args

                    true_resp = adapter.run(probe_url, _build_args(true_payload))
                    false_resp = adapter.run(probe_url, _build_args(false_payload))

                    # Synthetic result carries both for signal condition evaluation
                    synthetic = {
                        "body": true_resp.get("body", ""),
                        "status": true_resp.get("status"),
                        "response_time": 0,
                        "injected_param": param,
                        "injected_payload": f"true={true_payload} / false={false_payload}",
                        "true_response": true_resp,
                        "false_response": false_resp,
                    }
                    results.append(synthetic)
                except Exception as e:
                    logger.error(f"Comparison step failed: {e}")

        return results

    def _emit_progress(self, event: str, tree_id: str, node_id: str, status: Optional[str] = None,
                       data: Optional[Dict[str, Any]] = None):
        if self._progress_callback:
            payload = {
                "event": event,
                "node_id": f"{tree_id}:{node_id}",
                "node_name": node_id,
                "status": status,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            if data:
                payload["data"] = self._sanitize_data(data)
            self._progress_callback(payload)

    @staticmethod
    def _sanitize_data(data: Dict[str, Any]) -> Dict[str, Any]:
        sanitized: Dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, str):
                sanitized[key] = value[:400]
            elif isinstance(value, dict):
                sanitized[key] = {k: str(v)[:200] for k, v in value.items()}
            elif isinstance(value, list):
                sanitized[key] = [str(v)[:200] for v in value]
            else:
                sanitized[key] = value
        return sanitized
