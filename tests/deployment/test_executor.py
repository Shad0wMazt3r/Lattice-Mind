"""Executor tests to validate YAML exploitation flow."""

import asyncio
from types import SimpleNamespace

import lattice_mind.adapters.curl_adapter as curl_module
from lattice_mind.core.confidence import ConfidencePool
from lattice_mind.core.executor import TreeExecutor
from lattice_mind.core.tree_loader import ExploitationPath, ExploitationStep


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
