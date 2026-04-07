# Known Bugs & Audit Ledger

> Terse reference for all 25 bugs identified in the Security & Reliability Audit.  
> Severity: Critical > High > Medium > Low  
> Sprint column maps to the phased fix plan.

---

## Quick Index by Category

| Category | Bugs |
|----------|------|
| YAML Parsing & Logic | 1, 2, 3, 4, 5, 6, 7 |
| HTTP Adapter & Network | 8, 9, 10, 11, 12, 13, 14 |
| Session & State Integrity | 15, 16, 17, 18, 19 |
| MCP / Agent Interface | 20, 21, 22, 23, 24, 25 |

---

## YAML Parsing & Logic

| # | Title | File | Line(s) | Severity | Sprint |
|---|-------|------|---------|----------|--------|
| 1 | **ReDoS via YAML-controlled signal regex** | `core/executor.py` | ~172–176 | Critical | 1 |
| 2 | **Silent duplicate tree ID overwrite** | `core/tree_loader.py` | ~156–159 | High | 1 |
| 3 | **Missing key validation → KeyError crash on load** | `core/tree_loader.py` | ~64–92 | High | 3 |
| 4 | **Integer vs string type coercion in expressions** | `core/expressions.py` | ~107–121 | Medium | 3 |
| 5 | **Circular `requires_signal` → polling starvation** | `core/executor.py` | exploitation phase | High | 1 (DAG) |
| 6 | **`{{ captures.KEY }}` injection from attacker response** | `core/executor.py` | ~422–426 | High | 3 |
| 7 | **`asyncio.run()` inside `asyncio.to_thread()` → crash** | `mvp.py` | ~246–254 | Critical | 1 |

### Details

**Bug 1 — ReDoS**  
`re.search(sig_def["match"], body, re.IGNORECASE)` — YAML-controlled regex on full response body. Crafted pattern like `(a+)+$` + long body = exponential backtracking. Fix: compile all regexes at tree load time; use `re.compile(...).match` with `timeout` param (Python 3.11+) or wrap in `signal.alarm`.

**Bug 2 — Duplicate ID**  
`registry[tree.id] = tree` — second tree silently replaces first. No log, no error. Fix: check before insert; log warning and keep first (or quarantine both).

**Bug 3 — Schema validation**  
`confidence_seeds` parsed as `s["if"]` / `s["boost"]` / `s["label"]`. YAML format in `research_yaml.md` uses these keys but executor's internal schema expects `condition`. Mismatch → `KeyError`. Fix: Pydantic model for `DecisionTree` with field aliases.

**Bug 4 — Type coercion**  
`context.observations.port == '80'` fails silently when `port` is `int(80)`. Enum auto-unwrap works but int/str mismatches are not handled. Fix: normalize context values or document that comparisons must account for type.

**Bug 5 — Circular dependency**  
Tree A exploitation requires signal X (only emitted by Tree B). Tree B exploitation requires signal Y (only emitted by Tree A). Neither fires; solver runs to timeout silently. Fix: DAGValidator at load time using Kahn's algorithm.

**Bug 6 — Capture injection**  
`captures["table_name"]` inserted verbatim into next payload. If target returns `table_name` as `users\r\nX-Injected: evil`, the substitution injects into the subsequent HTTP request. Fix: strip control chars + enforce max length on capture values before storage.

**Bug 7 — asyncio.run in thread**  
`asyncio.run(executor.execute_tree(...))` called inside `asyncio.to_thread()` worker. Python 3.10+ raises `RuntimeError: This event loop is already running`. Fix: restructure `MVPSolver.solve()` as `async def` and `await executor.execute_tree(...)` directly, or use `loop.run_until_complete()` after getting the running loop.

---

## HTTP Adapter & Network

| # | Title | File | Severity | Sprint |
|---|-------|------|----------|--------|
| 8 | **Query params not percent-encoded** | `adapters/curl_adapter.py` | High | 1 |
| 9 | **SNI mismatch on IP-targeted HTTPS** | `adapters/curl_adapter.py` | Medium | 3 |
| 10 | **CRLF injection via unsanitized header values** | `core/executor.py` | High | 2 |
| 11 | **Multipart boundary collision after capture substitution** | `adapters/curl_adapter.py` | Medium | 3 |
| 12 | **Shared `/tmp/ffuf_output.json` — cross-run data mixing** | `adapters/ffuf_adapter.py` | Critical | 1 |
| 13 | **`SimplePortScanAdapter` total timeout unbounded** | `adapters/nmap_adapter.py` | High | 3 |
| 14 | **`file.filename` path traversal in upload** | `api/server.py` | Critical | 1 |

### Details

**Bug 8 — Encoding**  
Manual `f"{k}={v}"` query string building. `&`, `=`, unicode in values corrupt the request. Fix: `urllib.parse.urlencode(params)`.

**Bug 9 — SNI**  
`requests` sends target hostname as SNI. For `https://10.0.0.1/api`, the IP is the SNI value — rejected by strict TLS servers. Fix: expose `server_hostname` in `RequestsAdapter`; use `urllib3.HTTPSConnectionPool` with explicit `server_hostname`.

**Bug 10 — CRLF**  
YAML step header `{X-Custom: "foo\r\nSet-Cookie: evil=1"}` passes directly to `requests`. `requests` ≥2.26 rejects some but behavior varies. Fix: `RequestReconstructionEngine._sanitize_headers()` strips `\r` and `\n` from all header names/values before dispatch.

**Bug 11 — Multipart boundary**  
After `{{ captures.KEY }}` substitution, if the substituted value contains the multipart boundary string, the server's parser misparses the body. Fix: post-substitution check for boundary collision; regenerate boundary if collision detected.

**Bug 12 — Shared temp file** (Critical)  
`FFUFAdapter.OUTPUT_FILE = "/tmp/ffuf_output.json"` is a class constant. Concurrent runs overwrite each other's results. Fix: `fd, path = tempfile.mkstemp(suffix=".json")` in `run()`; delete in `finally`.

**Bug 13 — Unbounded port scan**  
`for port in ports: execute_command(["nc", "-zv", "-w", "2", target, str(port)])` — each call has `self.timeout` (60s) but the loop has no aggregate deadline. Fix: add `max_total_seconds` parameter; track wall-clock time and break when exceeded.

**Bug 14 — Path traversal** (Critical)  
`dest = UPLOAD_DIR / file.filename` — `file.filename = "../../etc/passwd"` writes outside intended directory. Fix: `safe_name = pathlib.Path(file.filename).name; dest = UPLOAD_DIR / safe_name`.

---

## Session & State Integrity

| # | Title | File | Severity | Sprint |
|---|-------|------|----------|--------|
| 15 | **Human loop hints/overrides persist across runs** | `core/human_loop.py` / `mvp.py` | High | 1 |
| 16 | **Cookie merge failure swallowed silently** | `mvp.py` | High | 2 |
| 17 | **`FlagRecognizer.has_flag()` mutates state as side effect** | `core/flag_recognizer.py` | Medium | 1 |
| 18 | **`requests.Session` accumulates target-set cookies** | `adapters/curl_adapter.py` | High | 2 |
| 19 | **`NodeStatus.FAILED` / `FAILURE` identity confusion** | `core/types.py` | Medium | 3 |

### Details

**Bug 15 — HITL state leakage**  
`MVPSolver.solve()` calls `orchestrator.set_challenge()` (resets flag recognizer + confidence pool) but never calls `get_human_loop_manager().clear()`. Hints/overrides from run N silently bias run N+1. Fix: call `get_human_loop_manager().clear()` at the start of `solve()`.

**Bug 16 — Silent cookie failure**  
```python
try:
    session_store.get_cookies(run_id) → merged into context
except Exception:
    logger.warning(...)   # solver continues without cookies; agent believes they were applied
```
Fix: surface the exception as a run-level error or pre-validate that the session store is reachable before starting solve.

**Bug 17 — has_flag side effect**  
`has_flag(text)` calls `recognize(text)` which appends to `found_flags`. Calling `has_flag()` for a read-only check permanently records the flag. Fix: add `_probe(text)` that runs patterns without modifying state; `has_flag()` calls `_probe()`; `recognize()` calls `_probe()` then appends if match found.

**Bug 18 — Session cookie leak**  
Target sends `Set-Cookie: session=evil`. `requests.Session` stores it. Next request in the same `RequestsAdapter` instance replays it. If the adapter is reused (e.g., shared in a legacy Python tree), attacker cookies persist across steps. Fix: create fresh `requests.Session()` per step, not per adapter; or call `self._session.cookies.clear()` after each response.

**Bug 19 — Enum identity**  
`NodeStatus.FAILED` and `NodeStatus.FAILURE` both have `.value == "failure"`. `result.status is NodeStatus.FAILURE` is `False` when status is `NodeStatus.FAILED` (different object). Equality `==` works; identity `is` does not. Fix: remove `FAILED` alias; migrate all call sites to `FAILURE`.

---

## MCP / Agent Interface

| # | Title | File | Severity | Sprint |
|---|-------|------|----------|--------|
| 20 | **`/mcp` endpoint fully public** | `api/server.py` | High | 2 |
| 21 | **`wait_for_run` timeout unclamped** | `mcp/server.py` | High | 2 |
| 22 | **`get_run_status` returns unbounded steps array** | `mcp/server.py` | Medium | 3 |
| 23 | **Opaque exception strings to agent** | `api/server.py` / `mcp/server.py` | Medium | 3 |
| 24 | **`reset-password` no minimum password length** | `api/server.py` | Medium | 3 |
| 25 | **`mvp.py:main()` passes unknown kwargs to `ChallengeDescriptor`** | `mvp.py` | Low | 3 |

### Details

**Bug 20 — Public MCP**  
`/mcp` in `_PUBLIC_PATHS` → auth middleware bypassed. `tools/list` and `initialize` work without any token. `tools/call` for non-`auth_login` tools has a manual Bearer check inside the handler, but `tools/list` and `initialize` are unauthenticated to any HTTP caller. Fix: remove `/mcp` from `_PUBLIC_PATHS`; handle the `initialize` handshake inside the `/mcp` handler with relaxed auth.

**Bug 21 — Unbounded wait**  
`timeout_seconds=0` → `while True` loop. `timeout_seconds=86400` → blocks the MCP process thread for 24h. Fix: clamp `timeout_seconds` to `[1, 600]` and `poll_interval_seconds` to `[1, 30]` at the start of `_call_tool` for `wait_for_run`.

**Bug 22 — Context bloat**  
`get_run_status` returns the full `steps` array. A 200-step run returns ~50KB+ of JSON. An LLM agent calling this after a long scan consumes its context window with event log noise. Fix: add `max_steps: int = 50` parameter; return the last N steps + a count.

**Bug 23 — Opaque errors**  
`except Exception as e: return error(str(e))` — raw Python exception messages (`AttributeError`, `KeyError`) are returned to the agent with no structured error code. The agent cannot distinguish transient from permanent errors. Fix: introduce `LatticeError(code, message)` exception hierarchy; map to error codes like `"run_not_found"`, `"solver_busy"`, `"invalid_challenge_type"`.

**Bug 24 — Weak password on reset**  
`POST /auth/reset-password` accepts any `new_password` string, including 1 character. `POST /auth/change-password` enforces `min_length=8`. Fix: add `Field(min_length=8)` to `new_password` in the reset endpoint's Pydantic model.

**Bug 25 — TypeError in demo code**  
`mvp.py:main()` constructs `ChallengeDescriptor(id="ctf_001", description="...")`. `ChallengeDescriptor` has no `id` or `description` fields. Running the CLI's demo path raises `TypeError`. Fix: remove the unknown kwargs from the `main()` example.
