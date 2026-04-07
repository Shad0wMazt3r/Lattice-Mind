# MCP Server Reference

> Covers: `mcp/server.py` — stdio MCP, 9 tools, dispatch, validation gaps

---

## Overview

The MCP server is the **primary interface for LLM agents**. The agent never calls adapters, the executor, or the solver directly — everything goes through these 9 tools. The engine handles all automated scanning; the agent uses these tools to:

1. Submit a challenge and get a `run_id`
2. Optionally inject session cookies or select specific YAML trees before the scan runs
3. Poll for results or wait for completion
4. Augment in-flight requests via mutation tools (planned — see `07_known_bugs.md` Feature 2)
5. Answer HITL escalation questions if the engine gets stuck

Two transport modes expose the same 9 tools:

| Transport | Location | Auth |
|-----------|----------|------|
| **stdio** (primary) | `mcp/server.py` | Token passed in `auth_login` tool; stored on instance |
| **HTTP** (`POST /mcp`) | `api/server.py` | Bearer header; middleware bypassed (Bug 20) |

Framing: JSON-RPC 2.0 with LSP `Content-Length: N\r\n\r\n` headers (stdio only).

---

## Startup & Configuration

```python
# mcp/server.py
class LatticeMineMCPServer:
    def __init__(self):
        self.base_url = os.environ.get("LATTICE_MIND_API_BASE_URL", "http://localhost:8000")
        self.timeout  = float(os.environ.get("LATTICE_MIND_MCP_TIMEOUT", "30"))
        # BUG: invalid env string for timeout raises ValueError at server init — crash before any tools run
        self.token: Optional[str] = None
```

---

## Tool Definitions

All 9 tools are defined in `_tool_definitions()` as JSON Schema objects. These are what the LLM agent sees.

### 1. `health_check`
- **Purpose:** Verify API is up
- **Inputs:** none
- **Returns:** `{status, version}`

### 2. `auth_login`
- **Purpose:** Get JWT token; must be called before all other tools
- **Inputs:** `{username: str, password: str}`
- **Returns:** `{token: str, role: str}`
- **Side effect:** stores `token` on the MCP server instance

### 3. `submit_scan`
- **Purpose:** Queue a solver run
- **Inputs:**
  ```json
  {
    "challenge_type": "web|pwn|crypto|forensics|...",
    "url": "optional str",
    "file_path": "optional str",
    "name": "optional str",
    "flag_format": "optional str (default flag{...})",
    "selected_tree_ids": "optional list[str]"
  }
  ```
- **Returns:** `{run_id: str}`

### 4. `wait_for_run`
- **Purpose:** Poll until run finishes
- **Inputs:**
  ```json
  {
    "run_id": "str",
    "timeout_seconds": "int (default 300)",     // BUG 21: not clamped in MCP layer
    "poll_interval_seconds": "int (default 3)"  // BUG 21: not clamped in MCP layer
  }
  ```
- **Returns:** final run state dict
- **Known issue (Bug 21):** `int(arguments.get("timeout_seconds", 300))` — value of 0 → infinite loop; value of 86400 → blocks MCP process for 24h. REST API clamps TTL but MCP layer does not.

### 5. `get_run_summary`
- **Purpose:** Compact result (flag, status, timestamps only)
- **Inputs:** `{run_id: str}`
- **Returns:** `{run_id, status, flag, started_at, finished_at, duration_seconds}`

### 6. `get_run_status`
- **Purpose:** Full run data including all steps
- **Inputs:** `{run_id: str}`
- **Returns:** full run dict including `steps` array (can be 200+ entries)
- **Known issue (Bug 22):** No `max_steps` or pagination. Long runs return the full steps array, consuming the agent's entire context window with event data.

### 7. `list_runs`
- **Purpose:** Recent runs (up to 200)
- **Inputs:** `{limit: int (default 50, max 200)}`
- **Returns:** array of run summaries

### 8. `list_rules`
- **Purpose:** All loaded YAML trees
- **Inputs:** none
- **Returns:** array of `{id, name, category, version, applies_when}`

### 9. `get_rule`
- **Purpose:** Full tree definition by ID
- **Inputs:** `{rule_id: str}`
- **Returns:** full YAML tree as parsed dict
- **Note:** `rule_id` is interpolated into URL path — unusual characters go through REST path handling

---

## Dispatch & Validation

```python
def _call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
    if name == "auth_login":
        result = self._request("POST", "/auth/login", {
            "username": arguments["username"],   # KeyError if missing
            "password": arguments["password"],
        })
        self.token = result.get("token")
        return result

    if name == "wait_for_run":
        run_id   = arguments["run_id"]
        timeout  = int(arguments.get("timeout_seconds", 300))   # no clamp
        interval = int(arguments.get("poll_interval_seconds", 3))
        # polling loop — blocks MCP process thread
        ...
```

**Validation model:** arguments are plain dicts. Required fields enforced by `KeyError` → caught in `handle_request` → returned as user message. JSON Schema in `_tool_definitions()` is advisory to the LLM only — not programmatically enforced.

---

## Error Handling

```python
def handle_request(self, request: Dict) -> Dict:
    try:
        result = self._call_tool(name, arguments)
        return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [...]}}
    except KeyError as e:
        return error_response(f"Missing required argument: {e}")
    except (ValueError, TypeError) as e:
        return error_response(f"Invalid argument: {e}")
    except Exception as e:
        return error_response(str(e))   # BUG 23: raw Python exception string to agent
```

**Bug 23:** The agent receives strings like `AttributeError: 'NoneType' object has no attribute 'type'`. It cannot distinguish transient vs permanent errors, so it may retry indefinitely.

---

## HTTP Transport (`_request`)

```python
def _request(self, method: str, path: str, body: Optional[Dict] = None) -> Any:
    headers = {"Content-Type": "application/json"}
    if self.token:
        headers["Authorization"] = f"Bearer {self.token}"
    response = requests.request(
        method,
        f"{self.base_url}{path}",
        json=body,
        headers=headers,
        timeout=self.timeout,
    )
    response.raise_for_status()
    return response.json()
```

All MCP tools are thin wrappers over the REST API. The MCP server is a client to `api/server.py`. It does not call adapters or the solver directly.

---

## stdio Read Loop

```python
def run(self) -> None:
    while True:
        # Read Content-Length header
        header = sys.stdin.buffer.readline()
        length = int(header.split(b":")[1].strip())
        sys.stdin.buffer.readline()   # blank line
        body = sys.stdin.buffer.read(length)
        request = json.loads(body)
        response = self.handle_request(request)
        # Write Content-Length + response
        encoded = json.dumps(response).encode()
        sys.stdout.buffer.write(f"Content-Length: {len(encoded)}\r\n\r\n".encode())
        sys.stdout.buffer.write(encoded)
        sys.stdout.buffer.flush()
```

No concurrent handling — each request is processed synchronously before the next is read.

---

## Adding a New MCP Tool

1. Add JSON Schema entry to `_tool_definitions()` with `name`, `description`, `inputSchema`
2. Add dispatch branch in `_call_tool()` with argument extraction and `_request()` call
3. Ensure the REST API has the corresponding endpoint
4. Add input clamping/validation in `_call_tool()` (do not rely on JSON Schema alone)
5. Write agent-in-the-loop test: simulate LLM calling the tool with hostile or missing arguments

---

## Known Issues Summary

| Bug | Severity | Detail |
|-----|----------|--------|
| Bug 20 | High | `/mcp` endpoint fully public — middleware bypassed |
| Bug 21 | High | `wait_for_run` timeout/interval unclamped — infinite loop or 24h block possible |
| Bug 22 | Medium | `get_run_status` returns full unbounded steps array — context window bloat |
| Bug 23 | Medium | Raw Python exception strings returned to agent — no structured error codes |
