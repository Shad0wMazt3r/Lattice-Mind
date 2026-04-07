"""Structured errors for MCP tools (agent-recoverable hints)."""

from __future__ import annotations

from typing import Any, Dict, Optional


def tool_error(
    code: str,
    message: str,
    *,
    recoverable: bool = True,
    suggested_next_tool: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return a JSON-serializable error payload for MCP tool responses."""
    out: Dict[str, Any] = {
        "ok": False,
        "error": {
            "code": code,
            "message": message,
            "recoverable": recoverable,
        },
    }
    if suggested_next_tool:
        out["error"]["suggested_next_tool"] = suggested_next_tool
    if details:
        out["error"]["details"] = details
    return out
