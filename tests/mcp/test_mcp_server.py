"""Tests for MCP server tool dispatch."""

import json

from lattice_mind.mcp.server import LatticeMindMCPServer


class _FakeResponse:
    def __init__(self, status_code=200, data=None, text=""):
        self.status_code = status_code
        self._data = data
        self.text = text
        self.content = b"" if data is None else json.dumps(data).encode("utf-8")

    def json(self):
        if self._data is None:
            raise ValueError("No json")
        return self._data


def test_tools_list_contains_submit_scan():
    server = LatticeMindMCPServer(base_url="http://example.com")
    response = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert response is not None
    tools = response["result"]["tools"]
    names = {tool["name"] for tool in tools}
    assert "submit_scan" in names
    assert "get_run_status" in names
    assert "list_scan_trees" in names
    assert "run_selected_trees" in names
    assert "set_scan_session" in names
    assert "tail_run_events" in names
    assert "get_tree_execution_trace" in names
    assert "retry_failed_node" in names
    assert "explain_confidence" in names
    assert "export_attack_notebook" in names


def test_submit_scan_tool_call_success(monkeypatch):
    captured = {}

    def fake_request(method, url, headers, json, timeout):
        captured["method"] = method
        captured["url"] = url
        captured["headers"] = headers
        captured["json"] = json
        captured["timeout"] = timeout
        return _FakeResponse(data={"run_id": "abc-123", "status": "queued"})

    monkeypatch.setattr("lattice_mind.mcp.server.requests.request", fake_request)
    server = LatticeMindMCPServer(base_url="http://engine.local", token="secret", timeout=5)
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "submit_scan",
                "arguments": {"challenge_type": "web", "url": "http://target.local"},
            },
        }
    )

    assert response is not None
    assert response["result"]["isError"] is False
    assert captured["method"] == "POST"
    assert captured["url"] == "http://engine.local/solve"
    assert captured["headers"]["Authorization"] == "Bearer secret"
    assert captured["json"]["challenge_type"] == "web"


def test_unknown_tool_returns_tool_error():
    server = LatticeMindMCPServer(base_url="http://example.com")
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "does_not_exist", "arguments": {}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is True
    assert "Unknown tool" in response["result"]["content"][0]["text"]


def test_api_error_returns_tool_error(monkeypatch):
    def fake_request(method, url, headers, json, timeout):
        return _FakeResponse(status_code=500, data={"detail": "boom"}, text="boom")

    monkeypatch.setattr("lattice_mind.mcp.server.requests.request", fake_request)
    server = LatticeMindMCPServer(base_url="http://engine.local")
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "health_check", "arguments": {}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is True
    assert "API request failed" in response["result"]["content"][0]["text"]


def test_missing_required_argument_returns_error():
    server = LatticeMindMCPServer(base_url="http://example.com")
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "get_run_status", "arguments": {}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is True
    assert "Invalid tool arguments" in response["result"]["content"][0]["text"]


def test_unknown_method_returns_jsonrpc_error():
    server = LatticeMindMCPServer(base_url="http://example.com")
    response = server.handle_request({"jsonrpc": "2.0", "id": 6, "method": "prompts/list"})
    assert response is not None
    assert response["error"]["code"] == -32601


def test_list_scan_trees_get(monkeypatch):
    def fake_request(method, url, headers, json, timeout):
        assert method == "GET"
        assert "/scan-trees" in url
        return _FakeResponse(data={"trees": [], "groups": []})

    monkeypatch.setattr("lattice_mind.mcp.server.requests.request", fake_request)
    server = LatticeMindMCPServer(base_url="http://engine.local")
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "list_scan_trees",
                "arguments": {"category": "web", "include_disabled": False},
            },
        }
    )
    assert response["result"]["isError"] is False


def test_run_selected_trees_posts_solve(monkeypatch):
    def fake_request(method, url, headers, json, timeout):
        assert method == "POST"
        assert url.endswith("/solve")
        assert json.get("selected_tree_ids") == ["a"]
        return _FakeResponse(data={"run_id": "r1", "status": "queued"})

    monkeypatch.setattr("lattice_mind.mcp.server.requests.request", fake_request)
    server = LatticeMindMCPServer(base_url="http://engine.local")
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {
                "name": "run_selected_trees",
                "arguments": {
                    "challenge_type": "web",
                    "url": "http://t",
                    "selected_tree_ids": ["a"],
                },
            },
        }
    )
    assert response["result"]["isError"] is False


def test_new_operator_tools_routes(monkeypatch):
    calls = []

    def fake_request(method, url, headers, json, timeout):
        calls.append((method, url, json))
        return _FakeResponse(data={"ok": True})

    monkeypatch.setattr("lattice_mind.mcp.server.requests.request", fake_request)
    server = LatticeMindMCPServer(base_url="http://engine.local")

    for name, args in [
        ("tail_run_events", {"run_id": "r1", "since_seq": 5, "limit": 10}),
        ("get_tree_execution_trace", {"run_id": "r1", "tree_id": "web_eval_injection"}),
        ("retry_failed_node", {"run_id": "r1", "node_id": "n1", "override_timeout": 12}),
        ("explain_confidence", {"run_id": "r1"}),
        ("export_attack_notebook", {"run_id": "r1"}),
    ]:
        response = server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 90,
                "method": "tools/call",
                "params": {"name": name, "arguments": args},
            }
        )
        assert response["result"]["isError"] is False

    assert any("/runs/r1/events" in u for _, u, _ in calls)
    assert any("/runs/r1/trees/" in u for _, u, _ in calls)
    assert any("/runs/r1/nodes/" in u for _, u, _ in calls)
    assert any("/runs/r1/confidence/explain" in u for _, u, _ in calls)
    assert any("/runs/r1/export/notebook" in u for _, u, _ in calls)

