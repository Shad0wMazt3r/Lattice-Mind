"""Executor tests to validate YAML exploitation flow."""

import asyncio
import copy
import os
import subprocess
import sys
from types import SimpleNamespace

import lattice_mind.adapters.curl_adapter as curl_module
import pytest
from lattice_mind.core.confidence import ConfidencePool
from lattice_mind.core.executor import (
    StepExecutionError,
    TreeExecutor,
    UnsupportedTreeAction,
)
from lattice_mind.core.tree_loader import DetectionPath, DetectionStep, ExploitationPath, ExploitationStep
from lattice_mind.web.request_models import request_spec_from_jsonable, spec_to_adapter_args
from lattice_mind.core.request_reconstruction import RequestReconstructionEngine


class FakeRequestsAdapter:
    def __init__(self, *args, **kwargs):
        pass

    def run(self, target: str, args: dict):
        return {
            "status": 200,
            "headers": {},
            "body": "Welcome picoCTF{flag_value} from the server!",
            "error": None,
            "response_time": 10,
            "injected_param": next(iter(args.get("params", args.get("data", {}))), None),
            "injected_payload": args.get("params") or args.get("data"),
        }


def test_request_reconstruction_preserves_structured_form_data():
    request = RequestReconstructionEngine().reconstruct(
        {"data": {"user": "alice"}, "headers": {}}
    )

    assert request["data"] == {"user": "alice"}
    assert "Content-Length" not in request["headers"]


def test_executor_detects_flag(monkeypatch):
    monkeypatch.setattr(curl_module, "RequestsAdapter", FakeRequestsAdapter)

    executor = TreeExecutor(ConfidencePool())
    tree = SimpleNamespace(id="executor-test")
    step = ExploitationStep(
        id="read_flag",
        action="http_probe",
        params={
            "inject_into": "all_params",
            "payloads": ["flag"],
        },
        capture=[{"pattern": r"picoCTF\{([^}]+)\}", "as": "flag_value"}],
    )
    path = ExploitationPath(
        id="ssti",
        name="SSTI",
        requires_signal="ssti_confirmed",
        technique="ssti",
        steps=[step],
    )

    executor.signal_bus.emit(tree.id, "ssti_confirmed")

    context = {
        "challenge": SimpleNamespace(url="http://example.com"),
        "observations": {
            "forms": [{"action": "http://example.com", "method": "GET"}],
            "params": ["content"],
        },
    }

    flag = asyncio.run(executor._run_exploitation_path(tree, path, context))

    assert flag == "picoCTF{flag_value}"
    assert context["flag_found"] == flag
    assert context["captures"]["flag_value"] == flag


def test_executor_attaches_request_spec_and_replays(monkeypatch):
    calls = []

    class RecordingAdapter:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, target: str, args: dict):
            calls.append((target, dict(args)))
            merged = args.get("params") or args.get("data") or {}
            return {
                "status": 200,
                "headers": {},
                "body": "ok",
                "error": None,
                "redirect_chain": [],
                "injected_param": next(iter(merged), None) if isinstance(merged, dict) and merged else None,
                "injected_payload": merged,
            }

    monkeypatch.setattr(curl_module, "RequestsAdapter", RecordingAdapter)

    executor = TreeExecutor(ConfidencePool())
    tree = SimpleNamespace(id="executor-spec")
    step = ExploitationStep(
        id="probe",
        action="http_request",
        params={
            "inject_into": "all_params",
            "payloads": ["p1"],
        },
    )

    context = {
        "challenge": SimpleNamespace(url="http://example.com"),
        "observations": {
            "forms": [
                {
                    "action": "http://example.com",
                    "method": "GET",
                    "enctype": "application/x-www-form-urlencoded",
                    "id": None,
                    "fields": [],
                }
            ],
            "params": ["q"],
        },
    }

    async def _run():
        return await executor._run_step(tree, step, context)

    results = asyncio.run(_run())
    assert results and "request_spec" in results[0]
    rs = results[0]["request_spec"]
    assert rs["method"] == "GET"
    replay = spec_to_adapter_args(request_spec_from_jsonable(rs))
    assert replay["params"].get("q") == "p1"
    assert calls and calls[0][0] == "http://example.com"


def test_executor_mutations_baseline_first_and_metadata(monkeypatch):
    calls = []

    class RecordingAdapter:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, target: str, args: dict):
            calls.append((target, copy.deepcopy(args)))
            return {
                "status": 200,
                "headers": {},
                "body": "ok",
                "error": None,
                "redirect_chain": [],
            }

    monkeypatch.setattr(curl_module, "RequestsAdapter", RecordingAdapter)

    executor = TreeExecutor(ConfidencePool())
    tree = SimpleNamespace(id="mut-meta")
    step = ExploitationStep(
        id="probe",
        action="http_probe",
        params={
            "inject_into": "all_params",
            "payloads": ["x"],
            "mutation_families": ["param_duplicate"],
            "target_selector": "all_inputs",
            "mutation_budget": {"max_total_variants": 8, "max_per_family": 8},
        },
    )
    context = {
        "challenge": SimpleNamespace(url="http://example.com/page"),
        "observations": {"params": ["id"]},
    }

    async def _run():
        return await executor._run_step(tree, step, context)

    results = asyncio.run(_run())
    assert len(results) >= 2
    bid = results[0]["baseline_id"]
    assert bid
    assert results[0]["mutation_id"] is None
    assert results[0]["mutation_kind"] == "baseline"
    assert results[1]["baseline_id"] == bid
    assert results[1]["mutation_id"]
    assert results[1]["mutation_kind"] == "param_duplicate"
    dup_call = next(c for c in calls if isinstance(c[1].get("params"), list))
    assert dup_call[1]["params"].count(("id", "x")) == 2


def test_executor_body_drop_post_removes_form_body(monkeypatch):
    calls = []

    class RecordingAdapter:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, target: str, args: dict):
            calls.append((target, copy.deepcopy(args)))
            return {
                "status": 200,
                "headers": {},
                "body": "",
                "error": None,
                "redirect_chain": [],
            }

    monkeypatch.setattr(curl_module, "RequestsAdapter", RecordingAdapter)

    executor = TreeExecutor(ConfidencePool())
    tree = SimpleNamespace(id="mut-body")
    step = ExploitationStep(
        id="probe",
        action="http_probe",
        params={
            "inject_into": "all_params",
            "payloads": ["1"],
            "mutation_families": ["body_drop"],
            "target_selector": "all_inputs",
            "mutation_budget": {"max_total_variants": 8, "max_per_family": 8},
        },
    )
    context = {
        "challenge": SimpleNamespace(url="http://example.com"),
        "observations": {
            "forms": [
                {
                    "action": "http://example.com/post",
                    "method": "POST",
                    "enctype": "application/x-www-form-urlencoded",
                    "fields": [
                        {"name": "otp", "value": "9"},
                        {"name": "token", "value": "t"},
                    ],
                }
            ],
            "params": ["otp"],
        },
    }

    async def _run():
        return await executor._run_step(tree, step, context)

    results = asyncio.run(_run())
    drop_i = next(i for i, r in enumerate(results) if r.get("mutation_kind") == "body_drop")
    assert results[drop_i]["baseline_id"]
    _, args = calls[drop_i]
    assert args.get("method") == "POST"
    assert args.get("data") is None


def test_executor_method_flip_sends_get_with_merged_query(monkeypatch):
    calls = []

    class RecordingAdapter:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, target: str, args: dict):
            calls.append((target, copy.deepcopy(args)))
            return {
                "status": 200,
                "headers": {},
                "body": "",
                "error": None,
                "redirect_chain": [],
            }

    monkeypatch.setattr(curl_module, "RequestsAdapter", RecordingAdapter)

    executor = TreeExecutor(ConfidencePool())
    tree = SimpleNamespace(id="mut-flip")
    step = ExploitationStep(
        id="probe",
        action="http_probe",
        params={
            "inject_into": "all_params",
            "payloads": ["v"],
            "mutation_families": ["method_flip"],
            "target_selector": "all_inputs",
            "mutation_budget": {"max_total_variants": 8, "max_per_family": 8},
        },
    )
    context = {
        "challenge": SimpleNamespace(url="http://example.com"),
        "observations": {
            "forms": [
                {
                    "action": "http://example.com/do",
                    "method": "POST",
                    "enctype": "application/x-www-form-urlencoded",
                    "fields": [
                        {"name": "id", "value": "1"},
                    ],
                }
            ],
            "params": ["id"],
        },
    }

    async def _run():
        return await executor._run_step(tree, step, context)

    results = asyncio.run(_run())
    flip_i = next(i for i, r in enumerate(results) if r.get("mutation_kind") == "method_flip")
    _, args = calls[flip_i]
    assert args.get("method") == "GET"
    assert "data" not in args or args.get("data") is None
    assert isinstance(args.get("params"), list)
    assert ("id", "v") in args["params"]


def test_detection_path_condition_response_delta_emits_signal(monkeypatch):
    ctr = [0]

    class FakeAdapter:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, target: str, args: dict):
            ctr[0] += 1
            if ctr[0] == 1:
                return {
                    "status": 200,
                    "body": "ok",
                    "headers": {},
                    "error": None,
                    "redirect_chain": [],
                }
            return {
                "status": 500,
                "body": "nope",
                "headers": {},
                "error": None,
                "redirect_chain": [],
            }

    monkeypatch.setattr(curl_module, "RequestsAdapter", FakeAdapter)

    executor = TreeExecutor(ConfidencePool())
    tree = SimpleNamespace(id="delta_sig")
    step = DetectionStep(
        id="mut",
        action="http_probe",
        params={
            "inject_into": "all_params",
            "payloads": ["v"],
            "mutation_families": ["param_remove"],
            "target_selector": "all_inputs",
            "mutation_budget": {"max_total_variants": 4, "max_per_family": 4},
        },
        signals=[
            {
                "match": {"condition": "response_delta.status_changed"},
                "on_match": {"confidence_boost": 0.4, "emit": "flow_change"},
            }
        ],
    )
    path = DetectionPath(id="p", name="P", description="", steps=[step], min_confidence=0.01)

    context = {
        "challenge": SimpleNamespace(url="http://example.com/"),
        "observations": {
            "params": ["a"],
            "forms": [
                {
                    "action": "http://example.com/page",
                    "method": "GET",
                    "fields": [
                        {"name": "a", "value": "1"},
                        {"name": "b", "value": "2"},
                    ],
                }
            ],
        },
    }

    async def _run():
        await executor._run_detection_path(tree, path, context)

    asyncio.run(_run())
    assert executor.signal_bus.has_signal("delta_sig", "flow_change")
    assert ctr[0] >= 2


def test_executor_max_variants_limits_mutation_count(monkeypatch):
    class RecordingAdapter:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, target: str, args: dict):
            return {
                "status": 200,
                "body": "",
                "headers": {},
                "error": None,
                "redirect_chain": [],
            }

    monkeypatch.setattr(curl_module, "RequestsAdapter", RecordingAdapter)

    executor = TreeExecutor(ConfidencePool())
    tree = SimpleNamespace(id="maxv")
    step = ExploitationStep(
        id="probe",
        action="http_probe",
        params={
            "inject_into": "all_params",
            "payloads": ["x"],
            "mutation_families": ["param_remove", "value_empty"],
            "target_selector": "all_inputs",
            "max_variants": 1,
        },
        capture=[],
    )
    context = {
        "challenge": SimpleNamespace(url="http://example.com/"),
        "observations": {
            "params": ["a"],
            "forms": [
                {
                    "action": "http://example.com/p",
                    "method": "GET",
                    "fields": [
                        {"name": "a", "value": "1"},
                        {"name": "b", "value": "2"},
                    ],
                }
            ],
        },
    }

    async def _run():
        return await executor._run_step(tree, step, context)

    results = asyncio.run(_run())
    assert len(results) == 2


def test_executor_applies_strategy_ranking(monkeypatch):
    calls = []

    class RecordingAdapter:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, target: str, args: dict):
            calls.append((target, copy.deepcopy(args)))
            return {
                "status": 200,
                "headers": {},
                "body": "",
                "error": None,
                "redirect_chain": [],
            }

    monkeypatch.setattr(curl_module, "RequestsAdapter", RecordingAdapter)
    import lattice_mind.core.executor as exmod

    monkeypatch.setattr(
        exmod,
        "rank_mutation_families",
        lambda families, **kwargs: (["value_empty", "param_remove"], [{"mutation_kind": "value_empty"}]),
    )

    executor = TreeExecutor(ConfidencePool())
    tree = SimpleNamespace(id="ranked")
    step = ExploitationStep(
        id="probe",
        action="http_probe",
        params={
            "inject_into": "all_params",
            "payloads": ["x"],
            "mutation_families": ["param_remove", "value_empty"],
            "target_selector": "all_inputs",
            "max_variants": 2,
        },
        capture=[],
    )
    context = {
        "challenge": SimpleNamespace(url="http://example.com/", type="web"),
        "observations": {
            "forms": [{"action": "http://example.com/p", "method": "GET", "fields": [{"name": "otp", "value": "1"}]}],
            "params": ["otp"],
        },
    }

    async def _run():
        return await executor._run_step(tree, step, context)

    results = asyncio.run(_run())
    assert any(r.get("mutation_kind") == "value_empty" for r in results)
    assert context["observations"].get("applied_strategy_hints")


def test_http_request_step_applies_declared_request_fields(monkeypatch):
    calls = []

    class RecordingAdapter:
        def run(self, target: str, args: dict):
            calls.append((target, copy.deepcopy(args)))
            return {
                "status": 200,
                "headers": {},
                "body": "ok",
                "error": None,
                "redirect_chain": [],
            }

    monkeypatch.setattr(curl_module, "RequestsAdapter", RecordingAdapter)
    executor = TreeExecutor(ConfidencePool())
    tree = SimpleNamespace(id="declared-request")
    step = DetectionStep(
        id="raw-post",
        action="http_request",
        params={
            "method": "POST",
            "path": "/submit",
            "headers": {"X-Probe": "lattice"},
            "body": "mode=check",
            "inject_into": "none",
        },
        signals=[],
    )
    context = {
        "challenge": SimpleNamespace(url="http://example.com/start"),
        "observations": {},
    }

    results = asyncio.run(executor._run_step(tree, step, context))

    assert results[0]["request_spec"]["url"] == "http://example.com/submit"
    assert len(calls) == 1
    target, args = calls[0]
    assert target == "http://example.com/submit"
    assert args["method"] == "POST"
    assert args["headers"]["X-Probe"] == "lattice"
    assert args["headers"]["Content-Length"] == "10"
    assert args["data"] == b"mode=check"


def test_executor_rejects_unsupported_actions_instead_of_sending_http(monkeypatch):
    class FailIfConstructed:
        def __init__(self):
            raise AssertionError("an unsupported action must not become HTTP traffic")

    monkeypatch.setattr(curl_module, "RequestsAdapter", FailIfConstructed)
    executor = TreeExecutor(ConfidencePool())
    step = DetectionStep(id="blind", action="blind_extract", params={}, signals=[])

    with pytest.raises(UnsupportedTreeAction, match="blind_extract"):
        asyncio.run(
            executor._run_step(
                SimpleNamespace(id="unsupported"),
                step,
                {"challenge": SimpleNamespace(url="http://example.com")},
            )
        )


def test_executor_surfaces_adapter_failures(monkeypatch):
    class FailingAdapter:
        def run(self, target: str, args: dict):
            return {
                "status": None,
                "headers": {},
                "body": "",
                "error": "connection refused",
                "redirect_chain": [],
            }

    monkeypatch.setattr(curl_module, "RequestsAdapter", FailingAdapter)
    executor = TreeExecutor(ConfidencePool())
    tree = SimpleNamespace(id="network-failure")
    step = DetectionStep(
        id="probe",
        action="http_probe",
        params={"inject_into": "none"},
        signals=[],
    )
    context = {
        "challenge": SimpleNamespace(url="http://127.0.0.1:1"),
        "observations": {},
    }

    with pytest.raises(StepExecutionError, match="connection refused"):
        asyncio.run(executor._run_step(tree, step, context))

    assert context["scan_errors"][0]["error"] == "connection refused"


def test_command_interpolation_preserves_python_braces_and_quotes_file_path(tmp_path):
    challenge_file = tmp_path / "odd name's sample.txt"
    challenge_file.write_text("SAFE_CONTENT", encoding="utf-8")
    executor = TreeExecutor(ConfidencePool())
    executable = subprocess.list2cmdline([sys.executable])
    raw = (
        executable
        + ' -c "data=open(\'{file_path}\').read(); '
        + "print(f'VALUE_{data}')\""
    )

    command = executor._command_interpolate(
        raw,
        {"challenge": SimpleNamespace(file_path=str(challenge_file), metadata={})},
    )
    completed = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "VALUE_SAFE_CONTENT"
    assert "{data}" in command


@pytest.mark.skipif(os.name != "nt", reason="cmd.exe quoting regression")
def test_command_interpolation_quotes_windows_shell_metacharacters(tmp_path):
    executor = TreeExecutor(ConfidencePool())
    hostile_path = str(tmp_path / "sample&whoami&.bin")
    executable = subprocess.list2cmdline([sys.executable])
    raw = executable + ' -c "import sys; print(sys.argv[1])" {file_path}'

    command = executor._command_interpolate(
        raw,
        {"challenge": SimpleNamespace(file_path=hostile_path, metadata={})},
    )
    completed = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == hostile_path
