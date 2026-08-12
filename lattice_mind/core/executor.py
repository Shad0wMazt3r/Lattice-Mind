"""Runtime executor for YAML-based decision trees."""
import asyncio
import base64
import enum
import logging
import os
import re
import shlex
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin

from lattice_mind.core.types import ChallengeDescriptor, NodeStatus
from lattice_mind.core.tree_loader import DecisionTree, DetectionPath, ExploitationPath, DetectionStep, ExploitationStep
from lattice_mind.core.confidence import ConfidencePool
from lattice_mind.core.expressions import ExpressionEvaluator, evaluate_condition
from lattice_mind.core.flag_recognizer import get_flag_recognizer
from lattice_mind.core.request_reconstruction import RequestReconstructionEngine
from lattice_mind.web.request_models import (
    HTTPRequestSpec,
    apply_param_payload,
    clone_http_request_spec,
    record_from_adapter_response,
    request_spec_for_challenge_url,
    spec_to_adapter_args,
    normalize_request_url,
)
from lattice_mind.web.request_builder import (
    filter_probe_specs_by_candidate_filter,
    merge_session_cookies_from_context,
    resolve_probe_base_specs,
    target_params_for_selector,
)
from lattice_mind.web.request_mutator import PlannedVariant, plan_mutation_variants
from lattice_mind.web.response_diff import (
    attach_response_deltas_to_mutation_batch,
    compute_response_delta,
    delta_summary,
)
from lattice_mind.web.evidence import max_severity, score_response_delta
from lattice_mind.web.strategy_memory import (
    endpoint_pattern_from_url,
    host_fingerprint_from_url,
    rank_mutation_families,
)

logger = logging.getLogger(__name__)

_COMMAND_TEMPLATE_FIELDS = {
    "file_path",
    "ciphertext",
    "c1",
    "n1",
    "c2",
    "n2",
    "c3",
    "n3",
    "e",
    "n",
    "c",
    "detected_offset",
    "detected_keysizes",
}


class UnsupportedTreeAction(RuntimeError):
    """A declarative step requests behavior the executor cannot faithfully run."""


class StepExecutionError(RuntimeError):
    """Every attempted operation for a declarative step failed."""


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


def _attach_evidence_for_result(
    result: Dict[str, Any],
    tree: DecisionTree,
    step: Any,
    context: Dict[str, Any],
) -> None:
    delta = result.get("response_delta")
    if not delta:
        return
    recs = score_response_delta(
        delta,
        tree_id=tree.id,
        step_id=getattr(step, "id", None),
        mutation_kind=result.get("mutation_kind"),
        baseline_id=result.get("baseline_id"),
        mutation_id=result.get("mutation_id"),
    )
    if not recs:
        return
    payload = [r.to_jsonable() for r in recs]
    result["evidence_records"] = payload
    result["evidence_max_severity"] = max_severity(recs)
    context.setdefault("evidence_records", []).extend(payload)


class TreeExecutor:
    """Executes declarative decision trees."""

    def __init__(self, confidence_pool: ConfidencePool):
        self.confidence_pool = confidence_pool
        self.signal_bus = SignalBus()
        self.captures: Dict[str, Any] = {}
        self.flag_recognizer = get_flag_recognizer()
        self.request_reconstructor = RequestReconstructionEngine()
        self._signal_regex_cache: Dict[str, re.Pattern[str]] = {}
        self._progress_callback = None
        self._last_learning_hints: List[Dict[str, Any]] = []

    def consume_learning_hints(self) -> List[Dict[str, Any]]:
        out = list(self._last_learning_hints)
        self._last_learning_hints = []
        return out

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

    def _template_values(self, context: Dict[str, Any]) -> Dict[str, Any]:
        challenge = context.get("challenge")
        values: Dict[str, Any] = {}
        if challenge is not None:
            values.update(
                {
                    "file_path": getattr(challenge, "file_path", None),
                    "url": getattr(challenge, "url", None),
                }
            )
            metadata = getattr(challenge, "metadata", None)
            if isinstance(metadata, dict):
                values.update(metadata)
        values.update(context.get("observations") or {})
        values.update(context.get("captures") or {})
        values.update(self.captures)
        values.update(
            {
                key: value
                for key, value in context.items()
                if key not in {"challenge", "observations", "captures"}
                and not isinstance(value, (dict, set))
            }
        )
        return values

    def _interpolate(self, raw: Any, context: Dict[str, Any]) -> Any:
        if not isinstance(raw, str) or "{" not in raw:
            return raw
        values = self._template_values(context)
        result = raw
        for field in set(re.findall(r"(?<![\\{])\{([A-Za-z_][A-Za-z0-9_]*)\}", raw)):
            if field not in values or values[field] is None:
                raise StepExecutionError(f"missing template value {field!r}")
            result = result.replace("{" + field + "}", str(values[field]))
        for key, value in self.captures.items():
            result = result.replace("{{ captures." + key + " }}", str(value))
        return result

    def _command_interpolate(self, raw: str, context: Dict[str, Any]) -> str:
        values = self._template_values(context)
        command = raw
        fields = set(re.findall(r"(?<![\\{])\{([A-Za-z_][A-Za-z0-9_]*)\}", raw))
        for field in fields & _COMMAND_TEMPLATE_FIELDS:
            if field not in values or values[field] is None:
                raise StepExecutionError(f"missing command template value {field!r}")
            value = str(values[field])
            if field == "file_path":
                # Python snippets in the corpus use open('{file_path}').
                # Replace that quoted literal as Python data before applying
                # shell quoting to the remaining command-argument occurrences.
                quoted_pattern = re.compile(
                    r"(['\"])\{file_path\}([^'\"]*)\1"
                )
                command = quoted_pattern.sub(
                    lambda match: (
                        "__import__('base64').b64decode('"
                        + base64.b64encode(
                            (value + match.group(2)).encode("utf-8")
                        ).decode("ascii")
                        + "').decode('utf-8')"
                    ),
                    command,
                )
                # list2cmdline follows CreateProcess quoting, not cmd.exe
                # metacharacter rules. shell=True uses cmd.exe on Windows, so
                # force a quoted token even when the path has no whitespace.
                value = f'"{value}"' if os.name == "nt" else shlex.quote(value)
            elif not re.fullmatch(r"[0-9, .+\-\[\]]+", value):
                raise StepExecutionError(
                    f"unsafe non-numeric command template value {field!r}"
                )
            command = command.replace("{" + field + "}", value)

        # Legacy double-brace fields are permitted only when their resolved
        # values can be safely represented as a shell token.
        for field in set(
            re.findall(r"\{\{(?:context\.)?([A-Za-z_][A-Za-z0-9_]*)\}\}", raw)
        ):
            if field not in values or values[field] is None:
                raise StepExecutionError(f"missing command template value {field!r}")
            value = str(values[field])
            if field in {"memory_dump_file", "file_path"}:
                rendered = f'"{value}"' if os.name == "nt" else shlex.quote(value)
            elif field == "pid" and re.fullmatch(r"\d+", value):
                rendered = value
            elif field == "os_profile" and re.fullmatch(r"[A-Za-z0-9_.-]+", value):
                rendered = value
            else:
                raise StepExecutionError(
                    f"unsafe command template value {field!r}"
                )
            command = command.replace("{{context." + field + "}}", rendered)
            command = command.replace("{{" + field + "}}", rendered)
        return command

    async def _run_exec_command_step(
        self, step: Any, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        commands = step.params.get("commands")
        if commands is None:
            commands = [step.params.get("command")]
        if not isinstance(commands, list) or not all(
            isinstance(command, str) and command.strip() for command in commands
        ):
            raise StepExecutionError("exec_command requires command or commands")

        challenge = context.get("challenge")
        file_path = getattr(challenge, "file_path", None) if challenge else None
        cwd = None
        if file_path:
            parent = Path(str(file_path)).expanduser().resolve().parent
            cwd = str(parent) if parent.exists() else None

        results: List[Dict[str, Any]] = []
        for raw_command in commands:
            command = self._command_interpolate(raw_command, context)

            def _execute() -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    command,
                    shell=True,
                    cwd=cwd,
                    capture_output=True,
                    text=True,
                    timeout=float(step.params.get("timeout", 30)),
                )

            try:
                completed = await asyncio.to_thread(_execute)
                output = completed.stdout + completed.stderr
                results.append(
                    {
                        "status": completed.returncode,
                        "body": output,
                        "headers": {},
                        "error": (
                            output.strip()
                            if completed.returncode in {126, 127}
                            else None
                        ),
                        "command_failed": completed.returncode != 0,
                        "command": command,
                    }
                )
            except subprocess.TimeoutExpired as exc:
                stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
                stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
                results.append(
                    {
                        "status": None,
                        "body": stdout + stderr,
                        "headers": {},
                        "error": f"command timed out after {exc.timeout}s",
                        "command": command,
                    }
                )
        if results and all(result.get("error") for result in results):
            raise StepExecutionError(
                f"all commands failed for step {getattr(step, 'id', '')}: "
                f"{results[0].get('error')}"
            )
        return results

    def _apply_step_request_params(
        self,
        spec: HTTPRequestSpec,
        params: Dict[str, Any],
        payload: Any,
        context: Dict[str, Any],
    ) -> HTTPRequestSpec:
        out = clone_http_request_spec(spec)
        method = params.get("method")
        if method:
            out.method = str(method).upper()

        path = params.get("path")
        if path:
            out.url = urljoin(out.url, str(self._interpolate(path, context)))

        raw_headers = params.get("headers") or {}
        if raw_headers:
            headers = dict(out.headers or {})
            headers.update(
                {
                    str(name): str(self._interpolate(value, context))
                    for name, value in raw_headers.items()
                }
            )
            lowered = {name.lower() for name in headers}
            if "content-length" in lowered and "transfer-encoding" in lowered:
                raise UnsupportedTreeAction(
                    "raw HTTP boundary control requires a transport-specific adapter"
                )
            out.headers = headers

        if "body" in params:
            out.raw_body = self._interpolate(params["body"], context)
            out.json_body = None
            out.body_params = None
            out.body_param_pairs = None

        inject_into = str(params.get("inject_into", "none"))
        if payload is None or inject_into in {"none", "all_params", "vulnerable_param"}:
            return out

        final_payload = str(self._interpolate(payload, context))
        if inject_into == "path":
            out.url = urljoin(out.url, final_payload)
        elif inject_into == "header":
            name = str(params.get("header_name") or "X-Lattice-Payload")
            headers = dict(out.headers or {})
            headers[name] = final_payload
            out.headers = headers
        elif inject_into == "cookie":
            cookies = dict(out.cookies or {})
            if "=" in final_payload and not final_payload.rstrip().endswith("="):
                name, value = final_payload.split("=", 1)
                cookies[name] = value
            elif cookies:
                first_name = next(iter(cookies))
                cookies[first_name] = final_payload
            else:
                cookies["session"] = final_payload
            out.cookies = cookies
        else:
            raise UnsupportedTreeAction(
                f"unsupported inject_into mode {inject_into!r}"
            )
        return out

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
                        body = str(result.get("body", ""))[:200_000]
                        if self._safe_signal_search(sig_def["match"], body):
                            matched = True
                    elif "match" in sig_def and isinstance(sig_def["match"], dict):
                        # Mini-language condition
                        cond = sig_def["match"].get("condition")
                        if cond:
                            local_ctx = context.copy()
                            er = result.get("evidence_records") or []
                            evidence = {
                                "max_severity": result.get("evidence_max_severity") or "",
                                "top_reason": (er[0].get("reason") if er else "")[:500],
                                "count": len(er),
                            }
                            extra_roots: Dict[str, Any] = {
                                "response": result,
                                "variant_response": result,
                                "response_time": result.get("response_time", 0),
                                "response_delta": result.get("response_delta") or {},
                                "evidence_max_severity": result.get("evidence_max_severity") or "",
                                "baseline_response": result.get("baseline_response") or {},
                                "evidence": evidence,
                                "request": result.get("request_spec") or {},
                            }
                            if "true_response" in result:
                                extra_roots["true_response"] = result["true_response"]
                            if "false_response" in result:
                                extra_roots["false_response"] = result["false_response"]
                            try:
                                if evaluate_condition(cond, local_ctx, extra_roots=extra_roots):
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
            end_data = None
            if any(r.get("evidence_records") for r in results):
                end_data = {
                    "delta_summaries": [
                        delta_summary(r["response_delta"])[:120]
                        for r in results
                        if r.get("response_delta")
                    ][:8],
                }
            self._emit_progress("node_end", tree.id, step.id, status=status, data=end_data)

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
                            safe_val = self._sanitize_capture_value(val)
                            self.captures[as_key] = safe_val
                            context.setdefault("captures", {})[as_key] = safe_val
                            step_success = True

                er = result.get("evidence_records") or []
                top_reason = (er[0].get("reason") or "")[:250] if er else ""
                ds = (
                    delta_summary(result["response_delta"])
                    if result.get("response_delta")
                    else ""
                )
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
                        "delta_summary": ds[:300],
                        "evidence_top_reason": top_reason,
                        "evidence_max_severity": result.get("evidence_max_severity") or "",
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
        from lattice_mind.trees.web.client_decode import decode_client_side
        
        action = step.action
        params = step.params

        if action == "client_decode":
            obs = context.get("observations", {})
            body = obs.get("http_response", {}).get("body", "")
            if not body:
                challenge = context.get("challenge")
                url = challenge.url if challenge else ""
                if url:
                    try:
                        adapter = RequestsAdapter()
                        resp = adapter.run(url, {"follow_redirects": True})
                        body = resp.get("body", "")
                        obs.setdefault("http_response", resp)
                    except Exception as e:
                        logger.error(f"Client decode fetch failed: {e}")
                        body = ""

            decoded = decode_client_side(body or "")
            return [{
                "status": 200,
                "body": "\n".join(decoded),
                "decoded_candidates": decoded,
                "response_time": 0,
                "injected_param": None,
                "injected_payload": None,
            }]

        if action == "exec_command":
            return await self._run_exec_command_step(step, context)
        if action not in {"http_probe", "http_request"}:
            raise UnsupportedTreeAction(
                f"unsupported tree action {action!r} in step {step.id!r}"
            )
        
        payloads = list(params.get("payloads", []))
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

        request_source = params.get("request_source")
        candidate_filter = params.get("candidate_filter")
        if inject_into == "none":
            probe_specs = [
                merge_session_cookies_from_context(
                    request_spec_for_challenge_url(url), context
                )
            ]
        else:
            probe_specs = resolve_probe_base_specs(context, url, request_source)
        probe_specs = filter_probe_specs_by_candidate_filter(
            probe_specs, context, candidate_filter
        )

        mutation_families = params.get("mutation_families") or []
        use_mutations = bool(mutation_families)
        mutation_budget = params.get("mutation_budget")
        mv = params.get("max_variants")
        if mv is not None:
            try:
                n = int(mv)
                mb = dict(mutation_budget) if isinstance(mutation_budget, dict) else {}
                if "max_per_family" not in mb:
                    mb["max_per_family"] = 8
                mb["max_total_variants"] = n
                mutation_budget = mb
            except (TypeError, ValueError):
                pass

        results = []
        adapter = RequestsAdapter()

        for p in payloads:
            for param in target_params:
                for base_spec in probe_specs:
                    inj = self._apply_step_request_params(
                        base_spec, params, p, context
                    )
                    if param and p is not None:
                        inj = apply_param_payload(
                            inj, param, self._interpolate(p, context)
                        )

                    if use_mutations:
                        base_req_view = {
                            "method": inj.method,
                            "url": inj.url,
                            "query_params": inj.query_params,
                            "query_param_pairs": inj.query_param_pairs,
                            "body_params": inj.body_params,
                            "body_param_pairs": inj.body_param_pairs,
                        }
                        ctype = getattr(challenge, "type", None)
                        if isinstance(ctype, enum.Enum):
                            chall_type = str(ctype.value).lower()
                        else:
                            chall_type = (str(ctype).lower() if ctype else "web")
                        host_fp = host_fingerprint_from_url(inj.url or url)
                        ep_pat = endpoint_pattern_from_url(inj.url or url)
                        ranked_families, hints = rank_mutation_families(
                            mutation_families,
                            challenge_type=chall_type,
                            host_fingerprint=host_fp,
                            endpoint_pattern=ep_pat,
                            request_spec=base_req_view,
                        )
                        if hints:
                            obs.setdefault("applied_strategy_hints", []).extend(hints[:3])
                            self._last_learning_hints.extend(hints[:3])

                        tsel = params.get("target_selector", "all_inputs")
                        mtargets = target_params_for_selector(tsel, context, inj)
                        planned = plan_mutation_variants(inj, ranked_families, mtargets, mutation_budget)
                        baseline_id = str(uuid.uuid4())
                    else:
                        planned = [
                            PlannedVariant(
                                clone_http_request_spec(inj),
                                "baseline",
                                "No structural mutations",
                                is_baseline=True,
                            )
                        ]
                        baseline_id = None

                    batch: List[Dict[str, Any]] = []
                    for pv in planned:
                        run_spec = pv.spec
                        run_id = context.get("run_id")
                        if run_id:
                            from lattice_mind.core.request_lifecycle import (
                                get_request_lifecycle_manager,
                            )

                            run_spec = get_request_lifecycle_manager().intercept_before_send(
                                str(run_id),
                                tree.id,
                                getattr(step, "id", ""),
                                run_spec,
                            )
                        start_time = time.time()
                        mutation_id: Optional[str] = None
                        if use_mutations and not pv.is_baseline:
                            mutation_id = str(uuid.uuid4())

                        try:
                            req_args = spec_to_adapter_args(run_spec)
                            req_args = self.request_reconstructor.reconstruct(req_args)
                            target_base, _ = normalize_request_url(run_spec.url)
                            resp = await asyncio.to_thread(
                                adapter.run, target_base, req_args
                            )
                            elapsed = (time.time() - start_time) * 1000
                            resp["response_time"] = elapsed
                            resp["injected_param"] = param
                            resp["injected_payload"] = p
                            rec = record_from_adapter_response(
                                run_spec,
                                resp,
                                elapsed,
                                resp.get("redirect_chain"),
                                mutation_id=mutation_id if use_mutations else None,
                                baseline_id=baseline_id if use_mutations else None,
                            )
                            resp["request_spec"] = rec.request_spec
                            resp["mutation_kind"] = pv.mutation_kind
                            resp["mutation_reason"] = pv.mutation_reason
                            resp["baseline_id"] = baseline_id
                            resp["mutation_id"] = mutation_id
                            batch.append(resp)
                            if resp.get("error"):
                                context.setdefault("scan_errors", []).append(
                                    {
                                        "tree_id": tree.id,
                                        "step_id": getattr(step, "id", ""),
                                        "url": target_base,
                                        "error": str(resp["error"]),
                                    }
                                )
                        except Exception as e:
                            logger.error(f"Step execution failed: {e}")
                            context.setdefault("scan_errors", []).append(
                                {
                                    "tree_id": tree.id,
                                    "step_id": getattr(step, "id", ""),
                                    "url": getattr(run_spec, "url", ""),
                                    "error": str(e),
                                }
                            )

                    if use_mutations and batch:
                        attach_response_deltas_to_mutation_batch(batch)
                        base = batch[0]
                        slim_base = {
                            "status": base.get("status"),
                            "body": base.get("body", ""),
                            "headers": base.get("headers") or {},
                            "response_time": base.get("response_time", 0),
                            "redirect_chain": base.get("redirect_chain") or [],
                        }
                        for row in batch:
                            row["baseline_response"] = slim_base
                        for row in batch[1:]:
                            _attach_evidence_for_result(row, tree, step, context)
                            req = row.get("request_spec") or {}
                            req_url = str(req.get("url") or inj.url or url)
                            obs.setdefault("strategy_outcomes", []).append(
                                {
                                    "challenge_type": chall_type,
                                    "host_fingerprint": host_fingerprint_from_url(req_url),
                                    "endpoint_pattern": endpoint_pattern_from_url(req_url),
                                    "request_url": req_url,
                                    "mutation_kind": row.get("mutation_kind"),
                                    "meaningful_delta": bool(row.get("response_delta")),
                                    "strong_candidate": (row.get("evidence_max_severity") in ("high", "medium")),
                                    "led_to_flag": False,
                                    "notes": str(row.get("mutation_reason") or "")[:200],
                                }
                            )
                    results.extend(batch)

        if results and all(result.get("error") for result in results):
            raise StepExecutionError(
                f"all requests failed for {tree.id}/{getattr(step, 'id', '')}: "
                f"{results[0].get('error')}"
            )
        if not results:
            errors = context.get("scan_errors") or []
            detail = errors[-1]["error"] if errors else "no request variants were produced"
            raise StepExecutionError(
                f"step {tree.id}/{getattr(step, 'id', '')} did not execute: {detail}"
            )
        return results

    def _safe_signal_search(self, pattern: str, body: str) -> bool:
        try:
            compiled = self._signal_regex_cache.get(pattern)
            if compiled is None:
                compiled = re.compile(pattern, re.IGNORECASE)
                self._signal_regex_cache[pattern] = compiled
            return compiled.search(body) is not None
        except re.error:
            logger.warning("Invalid signal regex: %r", pattern)
            return False

    @staticmethod
    def _sanitize_capture_value(value: Any) -> str:
        text = str(value)
        text = text.replace("\r", "").replace("\n", "")
        if len(text) > 2048:
            return text[:2048]
        return text

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

        if inject_into == "none":
            probe_specs = [
                merge_session_cookies_from_context(
                    request_spec_for_challenge_url(url), context
                )
            ]
        else:
            probe_specs = resolve_probe_base_specs(context, url, params.get("request_source"))
        probe_specs = filter_probe_specs_by_candidate_filter(
            probe_specs, context, params.get("candidate_filter")
        )

        results = []
        for param in target_params:
            for base_spec in probe_specs:
                try:
                    base_spec = self._apply_step_request_params(
                        base_spec, params, None, context
                    )
                    if param:
                        true_spec = apply_param_payload(
                            base_spec, param, self._interpolate(true_payload, context)
                        )
                        false_spec = apply_param_payload(
                            base_spec, param, self._interpolate(false_payload, context)
                        )
                    else:
                        true_spec = clone_http_request_spec(base_spec)
                        false_spec = clone_http_request_spec(base_spec)
                    run_id = context.get("run_id")
                    if run_id:
                        from lattice_mind.core.request_lifecycle import (
                            get_request_lifecycle_manager,
                        )

                        rlm = get_request_lifecycle_manager()
                        true_spec = rlm.intercept_before_send(
                            str(run_id), tree.id, getattr(step, "id", ""), true_spec
                        )
                        false_spec = rlm.intercept_before_send(
                            str(run_id), tree.id, getattr(step, "id", ""), false_spec
                        )
                    ra_t = spec_to_adapter_args(true_spec)
                    tb_t, _ = normalize_request_url(true_spec.url)
                    t0 = time.time()
                    true_resp = await asyncio.to_thread(adapter.run, tb_t, ra_t)
                    true_resp["response_time"] = float(
                        true_resp.get("response_time") or ((time.time() - t0) * 1000)
                    )
                    ra_f = spec_to_adapter_args(false_spec)
                    tb_f, _ = normalize_request_url(false_spec.url)
                    t1 = time.time()
                    false_resp = await asyncio.to_thread(adapter.run, tb_f, ra_f)
                    false_resp["response_time"] = float(
                        false_resp.get("response_time") or ((time.time() - t1) * 1000)
                    )
                    response_error = true_resp.get("error") or false_resp.get("error")
                    if response_error:
                        context.setdefault("scan_errors", []).append(
                            {
                                "tree_id": tree.id,
                                "step_id": getattr(step, "id", ""),
                                "url": tb_t,
                                "error": str(response_error),
                            }
                        )
                        continue

                    rec = record_from_adapter_response(
                        true_spec,
                        true_resp,
                        float(true_resp.get("response_time") or 0.0),
                        true_resp.get("redirect_chain"),
                    )
                    cmp_delta = compute_response_delta(false_resp, true_resp)
                    synthetic = {
                        "body": true_resp.get("body", ""),
                        "status": true_resp.get("status"),
                        "response_time": true_resp.get("response_time", 0),
                        "injected_param": param,
                        "injected_payload": f"true={true_payload} / false={false_payload}",
                        "true_response": true_resp,
                        "false_response": false_resp,
                        "request_spec": rec.request_spec,
                        "response_delta": cmp_delta,
                        "mutation_kind": "boolean_compare",
                        "baseline_response": {
                            "status": false_resp.get("status"),
                            "body": false_resp.get("body", ""),
                            "headers": false_resp.get("headers") or {},
                            "response_time": false_resp.get("response_time", 0),
                            "redirect_chain": false_resp.get("redirect_chain") or [],
                        },
                    }
                    _attach_evidence_for_result(synthetic, tree, step, context)
                    results.append(synthetic)
                except Exception as e:
                    logger.error(f"Comparison step failed: {e}")
                    context.setdefault("scan_errors", []).append(
                        {
                            "tree_id": tree.id,
                            "step_id": getattr(step, "id", ""),
                            "url": getattr(base_spec, "url", url),
                            "error": str(e),
                        }
                    )

        if not results:
            errors = context.get("scan_errors") or []
            detail = errors[-1]["error"] if errors else "no request pair was produced"
            raise StepExecutionError(
                f"comparison step {tree.id}/{getattr(step, 'id', '')} did not execute: {detail}"
            )

        return results

    def _emit_progress(self, event: str, tree_id: str, node_id: str, status: Optional[str] = None,
                       data: Optional[Dict[str, Any]] = None):
        if self._progress_callback:
            payload = {
                "event": event,
                "node_id": f"{tree_id}:{node_id}",
                "node_name": node_id,
                "status": status,
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            }
            if data:
                payload["data"] = self._sanitize_data(data)
            self._progress_callback(payload)

    @staticmethod
    def _sanitize_data(data: Dict[str, Any]) -> Dict[str, Any]:
        def _one(value: Any, depth: int = 0) -> Any:
            if depth > 4:
                return "<truncated>"
            if isinstance(value, str):
                return value[:400]
            if isinstance(value, (int, float, bool)) or value is None:
                return value
            if isinstance(value, dict):
                return {
                    str(k): _one(v, depth + 1)
                    for k, v in list(value.items())[:40]
                }
            if isinstance(value, list):
                return [_one(v, depth + 1) for v in value[:25]]
            return str(value)[:200]

        sanitized: Dict[str, Any] = {}
        for key, value in data.items():
            sanitized[key] = _one(value, 0)
        return sanitized
