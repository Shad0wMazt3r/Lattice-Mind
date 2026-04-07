"""Minimal stdio MCP server for the Lattice Mind engine API."""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, Optional
from urllib.parse import quote

import requests


class MCPRequestError(RuntimeError):
    """Raised when Lattice Mind API requests fail."""


class LatticeMindMCPServer:
    """Model Context Protocol server exposing Lattice Mind engine operations."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        token: Optional[str] = None,
        timeout: Optional[float] = None,
    ):
        self.base_url = (base_url or os.environ.get("LATTICE_MIND_API_BASE_URL", "http://127.0.0.1:8000")).rstrip("/")
        self.token = token if token is not None else os.environ.get("LATTICE_MIND_MCP_TOKEN")
        raw_timeout = timeout if timeout is not None else os.environ.get("LATTICE_MIND_MCP_TIMEOUT", "30")
        self.timeout = float(raw_timeout)

    @staticmethod
    def _tool_definitions() -> list[Dict[str, Any]]:
        return [
            {
                "name": "health_check",
                "description": "Check if the Lattice Mind API server is healthy.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "auth_login",
                "description": (
                    "Authenticate and obtain a fresh JWT token. Use this to recover "
                    "from 'Invalid or expired token' errors without leaving the agent session."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "username": {"type": "string"},
                        "password": {"type": "string"},
                    },
                    "required": ["username", "password"],
                },
            },
            {
                "name": "submit_scan",
                "description": "Queue a solver run (scan + decision-tree execution).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "challenge_type": {"type": "string"},
                        "url": {"type": "string"},
                        "file_path": {"type": "string"},
                        "flag_format": {"type": "string"},
                        "metadata": {"type": "object"},
                    },
                    "required": ["challenge_type"],
                },
            },
            {
                "name": "wait_for_run",
                "description": (
                    "Poll a run until it reaches a terminal state (success, completed, error) "
                    "then return a summary. Avoids writing external polling loops."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "run_id": {"type": "string"},
                        "timeout_seconds": {
                            "type": "integer",
                            "description": "Max seconds to wait (default 300).",
                            "minimum": 5,
                            "maximum": 600,
                        },
                        "poll_interval_seconds": {
                            "type": "integer",
                            "description": "Seconds between polls (default 3).",
                            "minimum": 1,
                            "maximum": 30,
                        },
                    },
                    "required": ["run_id"],
                },
            },
            {
                "name": "get_run_summary",
                "description": (
                    "Return a concise summary of a run: status, flag (if found), and error "
                    "(if any). Much smaller than get_run_status — use this to check results."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {"run_id": {"type": "string"}},
                    "required": ["run_id"],
                },
            },
            {
                "name": "get_run_status",
                "description": "Get full run status including every scan/tree step and observation. Prefer get_run_summary unless you need the detailed step log.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"run_id": {"type": "string"}},
                    "required": ["run_id"],
                },
            },
            {
                "name": "list_runs",
                "description": "List recent runs from the Lattice Mind engine.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 200}},
                },
            },
            {
                "name": "list_rules",
                "description": "List loaded decision-tree rules in the engine.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "get_rule",
                "description": "Get full details for a specific decision-tree rule.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"rule_id": {"type": "string"}},
                    "required": ["rule_id"],
                },
            },
            {
                "name": "list_scan_trees",
                "description": (
                    "List available YAML scan trees with metadata for targeted execution "
                    "(ids, tags, category, estimated duration, dependencies)."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "category": {"type": "string"},
                        "challenge_type": {"type": "string"},
                        "include_disabled": {"type": "boolean"},
                    },
                },
            },
            {
                "name": "run_selected_trees",
                "description": (
                    "Queue a solver run that executes only the selected YAML tree IDs and/or groups. "
                    "Same as submit_scan plus tree_selection / selected_tree_ids."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "challenge_type": {"type": "string"},
                        "url": {"type": "string"},
                        "file_path": {"type": "string"},
                        "flag_format": {"type": "string"},
                        "metadata": {"type": "object"},
                        "selected_tree_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "tree_selection": {
                            "type": "object",
                            "description": "Optional ids, groups[], exclude_ids[] per tree catalog API.",
                        },
                        "include_disabled_trees": {"type": "boolean"},
                    },
                    "required": ["challenge_type"],
                },
            },
            {
                "name": "set_scan_session",
                "description": (
                    "Set or merge HTTP cookies for a run (run-scoped session). "
                    "Cookies apply to subsequent HTTP probes for that run_id."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "run_id": {"type": "string"},
                        "cookies": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string"},
                                    "value": {"type": "string"},
                                },
                                "required": ["name", "value"],
                            },
                        },
                        "replace": {"type": "boolean"},
                        "ttl_seconds": {"type": "integer", "minimum": 1, "maximum": 86400},
                    },
                    "required": ["run_id", "cookies"],
                },
            },
            {
                "name": "get_scan_session",
                "description": "Inspect cookies stored for a run (values redacted unless include_values is true).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "run_id": {"type": "string"},
                        "include_values": {"type": "boolean"},
                    },
                    "required": ["run_id"],
                },
            },
            {
                "name": "rotate_scan_session",
                "description": "Atomically replace session cookies for a run; optional expected_version for optimistic locking.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "run_id": {"type": "string"},
                        "cookies": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string"},
                                    "value": {"type": "string"},
                                },
                                "required": ["name", "value"],
                            },
                        },
                        "expected_version": {"type": "integer"},
                        "ttl_seconds": {"type": "integer", "minimum": 1, "maximum": 86400},
                    },
                    "required": ["run_id", "cookies"],
                },
            },
            {
                "name": "enable_request_interception",
                "description": (
                    "Arm interception for the next matching HTTP request in a run. "
                    "Agent polls then submits a mutation to resume."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "run_id": {"type": "string"},
                        "match": {
                            "type": "object",
                            "description": "Optional tree_id, step_id, url_contains, method",
                        },
                        "mode": {"type": "string", "enum": ["first", "all"]},
                        "ttl_seconds": {"type": "integer", "minimum": 1, "maximum": 3600},
                    },
                    "required": ["run_id", "match"],
                },
            },
            {
                "name": "poll_interception",
                "description": "Poll a pending intercepted HTTP request for mutation.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"interception_id": {"type": "string"}},
                    "required": ["interception_id"],
                },
            },
            {
                "name": "submit_request_mutation",
                "description": "Submit patch.set mutations for a paused request and resume the scan thread.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "interception_id": {"type": "string"},
                        "request_id": {"type": "string"},
                        "mutation": {"type": "object"},
                        "note": {"type": "string"},
                    },
                    "required": ["interception_id", "request_id", "mutation"],
                },
            },
            {
                "name": "list_mutation_history",
                "description": "List mutation audit records for a run.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "run_id": {"type": "string"},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                    },
                    "required": ["run_id"],
                },
            },
        ]

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _request(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None) -> Any:
        url = f"{self.base_url}{path}"
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=self._headers(),
                json=payload,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise MCPRequestError(f"Failed to reach Lattice Mind API at {url}: {exc}") from exc

        if response.status_code >= 400:
            detail = response.text
            try:
                detail = response.json()
            except ValueError:
                pass
            raise MCPRequestError(f"API request failed ({response.status_code}) for {path}: {detail}")

        if not response.content:
            return {}

        try:
            return response.json()
        except ValueError:
            return {"raw": response.text}

    def _call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        if name == "health_check":
            return self._request("GET", "/health")
        if name == "auth_login":
            result = self._request("POST", "/auth/login", {
                "username": arguments["username"],
                "password": arguments["password"],
            })
            result["note"] = (
                "Store this token and include it as 'Authorization: Bearer <token>' "
                "in future MCP requests."
            )
            return result
        if name == "submit_scan":
            payload = {
                "name": arguments.get("name", "Untitled Challenge"),
                "challenge_type": arguments["challenge_type"],
                "url": arguments.get("url"),
                "file_path": arguments.get("file_path"),
                "flag_format": arguments.get("flag_format", "flag{"),
                "metadata": arguments.get("metadata", {}),
            }
            return self._request("POST", "/solve", payload)
        if name == "wait_for_run":
            import time
            run_id = arguments["run_id"]
            timeout = int(arguments.get("timeout_seconds", 300))
            interval = int(arguments.get("poll_interval_seconds", 3))
            terminal = {"success", "completed", "error"}
            deadline = time.monotonic() + timeout
            while True:
                data = self._request("GET", f"/runs/{run_id}")
                if data.get("status") in terminal:
                    return self._run_summary(data)
                if time.monotonic() >= deadline:
                    return {
                        "run_id": run_id,
                        "status": data.get("status"),
                        "flag": None,
                        "error": f"Timed out after {timeout}s — run still in state '{data.get('status')}'",
                    }
                time.sleep(interval)
        if name == "get_run_summary":
            data = self._request("GET", f"/runs/{arguments['run_id']}")
            return self._run_summary(data)
        if name == "get_run_status":
            run_id = arguments["run_id"]
            return self._request("GET", f"/runs/{run_id}")
        if name == "list_runs":
            limit = int(arguments.get("limit", 50))
            return self._request("GET", f"/runs?limit={limit}")
        if name == "list_rules":
            return self._request("GET", "/rules")
        if name == "get_rule":
            rule_id = arguments["rule_id"]
            return self._request("GET", f"/rules/{rule_id}")
        if name == "list_scan_trees":
            q = []
            if arguments.get("category"):
                q.append(f"category={quote(str(arguments['category']), safe='')}")
            if arguments.get("challenge_type"):
                q.append(
                    "challenge_type="
                    + quote(str(arguments["challenge_type"]), safe="")
                )
            if arguments.get("include_disabled"):
                q.append("include_disabled=true")
            path = "/scan-trees"
            if q:
                path += "?" + "&".join(q)
            return self._request("GET", path)
        if name == "run_selected_trees":
            payload = {
                "name": arguments.get("name", "Untitled Challenge"),
                "challenge_type": arguments["challenge_type"],
                "url": arguments.get("url"),
                "file_path": arguments.get("file_path"),
                "flag_format": arguments.get("flag_format", "flag{"),
                "metadata": arguments.get("metadata", {}),
                "selected_tree_ids": arguments.get("selected_tree_ids"),
                "tree_selection": arguments.get("tree_selection"),
                "include_disabled_trees": bool(arguments.get("include_disabled_trees")),
            }
            return self._request("POST", "/solve", payload)
        if name == "set_scan_session":
            run_id = arguments["run_id"]
            body = {
                "cookies": arguments["cookies"],
                "replace": bool(arguments.get("replace")),
                "ttl_seconds": arguments.get("ttl_seconds"),
            }
            return self._request("POST", f"/runs/{run_id}/session", body)
        if name == "get_scan_session":
            run_id = arguments["run_id"]
            iv = arguments.get("include_values", False)
            return self._request(
                "GET",
                f"/runs/{run_id}/session?include_values={'true' if iv else 'false'}",
            )
        if name == "rotate_scan_session":
            run_id = arguments["run_id"]
            body = {
                "cookies": arguments["cookies"],
                "expected_version": arguments.get("expected_version"),
                "ttl_seconds": arguments.get("ttl_seconds"),
            }
            return self._request("POST", f"/runs/{run_id}/session/rotate", body)
        if name == "enable_request_interception":
            run_id = arguments["run_id"]
            body = {
                "match": arguments["match"],
                "mode": arguments.get("mode", "first"),
                "ttl_seconds": arguments.get("ttl_seconds"),
            }
            return self._request("POST", f"/runs/{run_id}/interception", body)
        if name == "poll_interception":
            iid = arguments["interception_id"]
            return self._request("GET", f"/interception/{iid}")
        if name == "submit_request_mutation":
            iid = arguments["interception_id"]
            body = {
                "request_id": arguments["request_id"],
                "mutation": arguments["mutation"],
                "note": arguments.get("note"),
            }
            return self._request("POST", f"/interception/{iid}/mutate", body)
        if name == "list_mutation_history":
            run_id = arguments["run_id"]
            limit = int(arguments.get("limit", 100))
            return self._request("GET", f"/runs/{run_id}/mutations?limit={limit}")
        raise MCPRequestError(f"Unknown tool: {name}")

    @staticmethod
    def _run_summary(data: Dict[str, Any]) -> Dict[str, Any]:
        challenge = data.get("challenge") or {}
        return {
            "run_id": data.get("run_id"),
            "status": data.get("status"),
            "flag": data.get("flag"),
            "error": data.get("error"),
            "challenge": challenge.get("name", ""),
            "started_at": data.get("started_at"),
            "finished_at": data.get("finished_at"),
        }

    def _ok(self, request_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    def _error(self, request_id: Any, code: int, message: str) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}

    def handle_request(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        method = request.get("method")
        request_id = request.get("id")
        params = request.get("params", {})

        if method == "notifications/initialized":
            return None

        if method == "initialize":
            return self._ok(
                request_id,
                {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": "lattice-mind-mcp", "version": "0.1.0"},
                    "capabilities": {"tools": {}},
                },
            )

        if method == "tools/list":
            return self._ok(request_id, {"tools": self._tool_definitions()})

        if method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments", {})
            try:
                payload = self._call_tool(name, arguments)
                return self._ok(
                    request_id,
                    {"content": [{"type": "text", "text": json.dumps(payload, indent=2)}], "isError": False},
                )
            except (KeyError, ValueError) as exc:
                return self._ok(
                    request_id,
                    {"content": [{"type": "text", "text": f"Invalid tool arguments: {exc}"}], "isError": True},
                )
            except MCPRequestError as exc:
                return self._ok(request_id, {"content": [{"type": "text", "text": str(exc)}], "isError": True})

        return self._error(request_id, -32601, f"Method not found: {method}")

    @staticmethod
    def _read_message() -> Optional[Dict[str, Any]]:
        headers: Dict[str, str] = {}
        while True:
            line = sys.stdin.buffer.readline()
            if not line:
                return None
            if line in (b"\r\n", b"\n"):
                break
            key, _, value = line.decode("utf-8").partition(":")
            headers[key.strip().lower()] = value.strip()

        content_length = int(headers.get("content-length", "0"))
        if content_length <= 0:
            return None
        body = sys.stdin.buffer.read(content_length)
        if not body:
            return None
        return json.loads(body.decode("utf-8"))

    @staticmethod
    def _write_message(payload: Dict[str, Any]):
        encoded = json.dumps(payload).encode("utf-8")
        sys.stdout.buffer.write(f"Content-Length: {len(encoded)}\r\n\r\n".encode("utf-8"))
        sys.stdout.buffer.write(encoded)
        sys.stdout.buffer.flush()

    def serve(self):
        while True:
            request = self._read_message()
            if request is None:
                return
            response = self.handle_request(request)
            if response is not None:
                self._write_message(response)


def main():
    """Run the MCP server over stdio."""
    LatticeMindMCPServer().serve()


if __name__ == "__main__":
    main()

