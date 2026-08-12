"""Deterministic, real-HTTP integration coverage for the primary solver path."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import shutil
from threading import Thread
from urllib.parse import parse_qs, urlsplit

import pytest

from lattice_mind.adapters.curl_adapter import CurlAdapter
from lattice_mind.core.adapter_types import HttpDataKeys
from lattice_mind.core.tree_loader import DecisionTree, TreeRegistry
from lattice_mind.core.types import ChallengeDescriptor, ChallengeType
from lattice_mind.mvp import MVPSolver


class _VulnerableHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - stdlib HTTP handler API
        value = parse_qs(urlsplit(self.path).query).get("id", [""])[0]
        status = 200
        if "extractvalue" in value:
            body = "database result: flag{local_pipeline_verified}"
        elif "'" in value:
            status = 500
            body = "SQL syntax error near quote"
        else:
            body = (
                '<form action="/" method="get">'
                '<input name="id" value="1">'
                "</form>"
            )
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_args):
        pass


def _local_sqli_tree() -> DecisionTree:
    return DecisionTree(
        {
            "id": "local_sqli",
            "name": "Local SQLi integration",
            "category": "web",
            "min_confidence": 0.1,
            "confidence_seeds": [
                {
                    "if": "'id' in context.params",
                    "boost": 0.5,
                    "label": "recon found id",
                }
            ],
            "detection": {
                "paths": [
                    {
                        "id": "detect",
                        "name": "Detect",
                        "steps": [
                            {
                                "id": "quote",
                                "action": "http_probe",
                                "with": {
                                    "inject_into": "all_params",
                                    "payload": "'",
                                },
                                "signals": [
                                    {
                                        "match": "SQL syntax",
                                        "on_match": {"emit": "sqli_confirmed"},
                                    }
                                ],
                            }
                        ],
                    }
                ]
            },
            "exploitation": {
                "stop_on_flag": True,
                "paths": [
                    {
                        "id": "exploit",
                        "name": "Exploit",
                        "requires_signal": "sqli_confirmed",
                        "technique": "error_based",
                        "steps": [
                            {
                                "id": "extract",
                                "action": "http_probe",
                                "with": {
                                    "inject_into": "vulnerable_param",
                                    "payload": "' AND extractvalue(1,flag)--",
                                },
                            }
                        ],
                    }
                ]
            },
        }
    )


def test_mvp_solver_recon_detect_exploit_over_real_local_http():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _VulnerableHandler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        tree = _local_sqli_tree()
        registry = TreeRegistry()
        registry.trees[tree.id] = tree

        solver = MVPSolver()
        solver.registry = registry
        result = solver.solve(
            ChallengeDescriptor(
                type=ChallengeType.WEB,
                name="Local integration",
                url=f"http://127.0.0.1:{server.server_port}/",
            ),
            selected_tree_ids=[tree.id],
        )

        assert result == "flag{local_pipeline_verified}"
        observations = solver.orchestrator.execution_context["observations"]
        assert "id" in observations["params"]
        assert solver.orchestrator.execution_context["vulnerable_param"] == "id"
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


def test_curl_fallback_preserves_real_subprocess_body():
    if not shutil.which("curl"):
        pytest.skip("curl executable is not installed")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _VulnerableHandler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        result = CurlAdapter().run(
            f"http://127.0.0.1:{server.server_port}/", {}
        )
        assert result.get(HttpDataKeys.STATUS_CODE) == 200
        assert '<input name="id"' in result.get(HttpDataKeys.BODY)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
