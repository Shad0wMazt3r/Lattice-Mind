# REST API Reference

> Covers: `api/server.py` — FastAPI app, auth, routes, SQLite schema, WebSocket, MCP HTTP endpoint

---

## Stack

| Component | Detail |
|-----------|--------|
| Framework | FastAPI (async) |
| Auth | JWT (HS256) + bcrypt via `python-jose` + `passlib` |
| DB | SQLite at `/data/runs.db` (via raw `sqlite3`, not ORM) |
| Static files | `frontend/` mounted at `/static/` |
| WS | `fastapi.websockets` — per run_id |
| Entrypoint | `Lattice-Mind-api` → `lattice_mind.api.server:main` → `uvicorn` on port 8000 |

---

## Authentication

### JWT

- Secret auto-generated once on first start; persisted in `settings` table as `jwt_secret`
- Algorithm: HS256
- Default lifetime: 24h (configurable via `LATTICE_MIND_TOKEN_HOURS` env var)
- First registered user → `admin` role; all subsequent → `operator`

### Middleware

```python
_PUBLIC_PATHS = {
    "/", "/health", "/mcp",           # BUG 20: /mcp is fully public
    "/auth/login", "/auth/register",
    "/auth/forgot-password", "/auth/reset-password",
    "/docs", "/openapi.json", "/redoc",
}

@app.middleware("http")
async def _auth_middleware(request, call_next):
    if path in _PUBLIC_PATHS or path.startswith("/static/") or path.startswith("/ws/"):
        return await call_next(request)
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer ") or not _decode_token(auth[7:]):
        return JSONResponse(401, {"detail": "Not authenticated"})
    return await call_next(request)
```

**Bug 20:** `/mcp` in `_PUBLIC_PATHS` means the entire auth middleware is bypassed for MCP requests. Tool-level auth only fires for `tools/call` with non-`auth_login` tool names. `tools/list` and `initialize` are fully unauthenticated.

---

## Auth Routes

| Method | Path | Body | Notes |
|--------|------|------|-------|
| POST | `/auth/register` | `{username, password(min 8)}` | First → admin |
| POST | `/auth/login` | `{username, password}` | Returns `{token, role}` |
| POST | `/auth/change-password` | `{current_password, new_password(min 8)}` | Requires Bearer |
| POST | `/auth/forgot-password` | `{email}` | Sends reset email via mailpit |
| POST | `/auth/reset-password` | `{token, new_password}` | **Bug 24: no min_length** |

---

## Solver Routes

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/solve` | ✓ | Submit challenge → returns `{run_id}` |
| GET | `/runs` | ✓ | List last 50 runs |
| GET | `/runs/{run_id}` | ✓ | Full run detail; supports 8-char prefix |
| POST | `/runs/{run_id}/rerun` | ✓ | Clone config and re-run |
| POST | `/upload` | ✓ | Upload file → returns server path |
| POST | `/runs/{run_id}/session` | ✓ | Set/replace session cookies for run |

### POST /solve — SolveRequest

```python
class SolveRequest(BaseModel):
    challenge_type: ChallengeType
    name: Optional[str]
    url: Optional[str]
    file_path: Optional[str]
    flag_format: str = "flag{...}"
    metadata: Dict[str, Any] = {}
    selected_tree_ids: Optional[List[str]] = None   # selective YAML tree execution
```

Returns: `{run_id: str}`. Solver runs in background via `asyncio.create_task`.

### Run status lifecycle

`queued` → `running` → `success` | `completed` | `error`

### POST /upload — file upload

```python
dest = UPLOAD_DIR / file.filename   # BUG 14: no path sanitization
```

**Bug 14 (Critical):** `file.filename` containing `../` can write outside `UPLOAD_DIR`. Fix: `pathlib.Path(file.filename).name`.

### POST /runs/{run_id}/session — SetRunSessionRequest

```python
class CookieInputModel(BaseModel):
    name: str = Field(max_length=256)
    value: str = Field(max_length=8192)

class SetRunSessionRequest(BaseModel):
    cookies: List[CookieInputModel]
    replace: bool = False
    ttl_seconds: Optional[int] = Field(default=None, ge=1, le=86400)
```

Delegates to `get_session_store().create_or_update(...)`.

---

## Rules Routes

| Method | Path | Description |
|--------|------|-------------|
| GET | `/rules` | List all loaded YAML trees |
| GET | `/rules/{rule_id}` | Full tree definition |
| POST | `/rules/reload` | Hot-reload trees from disk |

---

## Other Routes

| Method | Path | Description |
|--------|------|-------------|
| GET/PUT | `/settings` | Feature flags (`dir_scan_enabled`) |
| GET | `/hitl/pending` | Pending HITL questions (polled by frontend every 2s) |
| POST | `/hitl/{id}/answer` | Submit human answer; `payload: dict` — no field validation |
| POST | `/crypto/solve` | Standalone crypto decoder; `payload: dict` — no field validation |
| GET | `/health` | `{status: "ok"}` — unauthenticated |

---

## Solver Execution — Concurrency Model

```python
solver_lock = asyncio.Lock()   # serializes solver runs globally

async def _run_solver_task(run_id, descriptor, selected_tree_ids):
    async with solver_lock:
        solver.orchestrator.set_progress_callback(progress_callback)
        flag, log = await asyncio.to_thread(
            _execute_solver, descriptor, run_id, selected_tree_ids
        )
    # solver_lock released; next queued run can start
```

Key points:
- Only one solver run executes at a time (`solver_lock`)
- Progress callback injected inside the lock (prevents concurrent runs overwriting each other's callback)
- `asyncio.to_thread()` runs the synchronous `MVPSolver.solve()` in a thread pool
- **Bug 7:** inside that thread, `MVPSolver.solve()` calls `asyncio.run()` for each YAML tree — this fails on Python 3.10+ because a loop is already running

---

## SQLite Schema (`/data/runs.db`)

### runs

| Column | Type | Notes |
|--------|------|-------|
| `run_id` | TEXT PK | UUID |
| `status` | TEXT | queued/running/success/completed/error |
| `challenge` | TEXT | JSON-serialized ChallengeDescriptor |
| `steps` | TEXT | JSON array of progress events |
| `flag` | TEXT | nullable |
| `error` | TEXT | nullable |
| `log` | TEXT | JSON array |
| `observations` | TEXT | JSON dict |
| `confidence` | TEXT | JSON dict of tree_id → score |
| `started_at` | TEXT | ISO timestamp |
| `finished_at` | TEXT | ISO timestamp nullable |
| `created_at` | TEXT | ISO timestamp |
| `updated_at` | TEXT | ISO timestamp |

### users

| Column | Type |
|--------|------|
| `username` | TEXT PK |
| `hashed_password` | TEXT |
| `role` | TEXT (admin/operator) |
| `email` | TEXT nullable |
| `created_at` | TEXT |

### settings

| Column | Type |
|--------|------|
| `key` | TEXT PK |
| `value` | TEXT |

Stored keys: `jwt_secret`, `dir_scan_enabled`, etc.

---

## WebSocket

**Path:** `WS /ws/{run_id}?token=<jwt>`

- Auth: `token` query param (JWT); middleware skips `/ws/` paths; WS handler validates manually
- On connect: sends `init` message with full run state
- During run: broadcasts `step` and `update` events as progress callback fires
- Frontend subscribes on VIEW and reconnects automatically on disconnect

### Message types

```json
{"type": "init",   "run": {...}}
{"type": "step",   "event": {...}}   // progress event dict
{"type": "update", "run": {...}}     // partial run state
```

---

## MCP over HTTP

**Path:** `POST /mcp`  
**Auth:** Protected by auth middleware; only `initialize` and `tools/call` with `auth_login` are allowed unauthenticated inside handler logic.

```python
@app.post("/mcp")
async def mcp_rpc(request: Request):
    body = await request.json()
    method = body.get("method")
    params = body.get("params", {})

    if method == "tools/call":
        tool_name = params.get("name")
        if tool_name != "auth_login":
            # Check Bearer header manually
            if not valid_bearer:
                return _ok({"isError": True, "text": "Invalid token..."})
        result = await _mcp_dispatch(tool_name, arguments)
        return _ok({"content": [{"type": "text", "text": json.dumps(result)}]})
    # initialize and auth_login are the only unauthenticated MCP actions
```

Error handling:
- `HTTPException` → formatted error message (no structured code)
- `KeyError`, `ValueError` → "Invalid arguments: ..."
- All other `Exception` → `str(exc)` verbatim to agent (Bug 23)

---

## Known Issues Summary

| Bug | Severity | Route / Module |
|-----|----------|---------------|
| Bug 14: path traversal in upload | Critical | `POST /upload` |
| Bug 24: no min_length on reset-password | Medium | `POST /auth/reset-password` |
| Bug 23: opaque exception strings to agent | Medium | MCP dispatch handler |
| Run status includes `degraded_success` | Info | solver execution status lifecycle |
