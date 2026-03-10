"""Minimal stdio MCP server for the Lattice Mind engine API."""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, Optional

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
                "name": "get_run_status",
                "description": "Get full run status including scan/tree steps and observations.",
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
        raise MCPRequestError(f"Unknown tool: {name}")

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

