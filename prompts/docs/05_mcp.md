# MCP Server Reference

> Covers: `mcp/server.py` — stdio MCP, tool catalog, dispatch, validation gaps

---

## Overview

The MCP server is the **primary interface for LLM agents**. The agent never calls adapters, the executor, or the solver directly — everything goes through MCP tools. The engine handles all automated scanning; the agent uses these tools to:

1. Submit a challenge and get a `run_id`
2. Optionally inject session cookies or select specific YAML trees before the scan runs
3. Poll for results or wait for completion
4. Augment in-flight requests via mutation tools (planned — see `07_known_bugs.md` Feature 2)
5. Answer HITL escalation questions if the engine gets stuck

Two transport modes expose the same toolset:

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

Tools are defined in `_tool_definitions()` as JSON Schema objects. These are what the LLM agent sees.

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
    "timeout_seconds": "int (default 300, clamped 1–600)",
    "poll_interval_seconds": "int (default 3, clamped 1–30)"
  }
  ```
- **Returns:** final run state dict

### 5. `get_run_summary`
- **Purpose:** Compact result (flag, status, timestamps only)
- **Inputs:** `{run_id: str}`
- **Returns:** `{run_id, status, flag, started_at, finished_at, duration_seconds}`

### 6. `get_run_status`
- **Purpose:** Full run data including all steps
- **Inputs:** `{run_id: str, max_steps: int (default 50, max 500)}`
- **Returns:** full run dict with `steps[-max_steps:]` and `total_steps` count. Use `get_run_summary` unless you need the step log.

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

### Additional operator tools
- `tail_run_events` — incremental event tailing with `since_seq`
- `get_tree_execution_trace` — tree-scoped event history
- `retry_failed_node` — queue operator retry requests for active runs
- `explain_confidence` — ranked confidence + decision receipts
- `export_attack_notebook` — markdown export for replay/reporting

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
        timeout  = max(1, min(600, int(arguments.get("timeout_seconds", 300))))
        interval = max(1, min(30,  int(arguments.get("poll_interval_seconds", 3))))
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
        return error_response(str(e))   # some paths still return raw exception strings (Bug 23, partial)
```

**Bug 23 (partial):** Common error paths include an `error_code` field (`"invalid_arguments"`, `"request_failed"`). Uncommon exception paths still return raw Python strings. See `07_known_bugs.md`.

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

## Open Issues

| Bug | Severity | Detail |
|-----|----------|--------|
| Bug 23 | Medium | Some error paths still return raw Python exception strings (partial fix) |
