from __future__ import annotations

import asyncio
import base64 as _b64
import json
import logging
import os
import pathlib
import re as _re
import secrets as _secrets
import shutil
import smtplib
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from email.message import EmailMessage
from typing import Any, Dict, List, Optional, Tuple

from fastapi import (
    FastAPI,
    File,
    HTTPException,
    Request,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse, JSONResponse
from jose import JWTError
from jose import jwt as _jwt
from passlib.context import CryptContext
from pydantic import BaseModel, ConfigDict, Field

from lattice_mind.core.types import ChallengeDescriptor, ChallengeType
from lattice_mind.mvp import MVPSolver

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.utcnow().isoformat() + "Z"


# ── Auth ─────────────────────────────────────────────────────────────────────
_ALGORITHM = "HS256"
_TOKEN_HOURS = int(os.environ.get("LATTICE_MIND_TOKEN_HOURS", "24"))
_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY: str = ""  # populated after _init_db()


def _hash_pw(pw: str) -> str:
    return _pwd_ctx.hash(pw)


def _verify_pw(plain: str, hashed: str) -> bool:
    return _pwd_ctx.verify(plain, hashed)


def _make_token(data: dict) -> str:
    from datetime import timedelta

    payload = {**data, "exp": datetime.utcnow() + timedelta(hours=_TOKEN_HOURS)}
    return _jwt.encode(payload, SECRET_KEY, algorithm=_ALGORITHM)


def _decode_token(token: str) -> Optional[dict]:
    try:
        return _jwt.decode(token, SECRET_KEY, algorithms=[_ALGORITHM])
    except Exception:
        return None


def _send_email(to_email: str, subject: str, content: str):
    import smtplib
    from email.message import EmailMessage

    msg = EmailMessage()
    msg.set_content(content)
    msg["Subject"] = subject
    msg["From"] = "noreply@latticemind.local"
    msg["To"] = to_email
    try:
        host = os.environ.get("SMTP_HOST", "mailpit")
        port = int(os.environ.get("SMTP_PORT", "1025"))
        with smtplib.SMTP(host, port) as server:
            server.send_message(msg)
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {e}")


# ── WebSocket Management ─────────────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, run_id: str):
        await websocket.accept()
        if run_id not in self.active_connections:
            self.active_connections[run_id] = []
        self.active_connections[run_id].append(websocket)

    def disconnect(self, websocket: WebSocket, run_id: str):
        if run_id in self.active_connections:
            try:
                self.active_connections[run_id].remove(websocket)
            except ValueError:
                pass
            if not self.active_connections[run_id]:
                del self.active_connections[run_id]

    async def broadcast(self, run_id: str, message: Any):
        if run_id in self.active_connections:
            encoded_message = jsonable_encoder(message)
            for connection in self.active_connections[run_id]:
                try:
                    await connection.send_json(encoded_message)
                except Exception:
                    pass


manager = ConnectionManager()

# ── SQLite persistence ────────────────────────────────────────────────────────
DB_PATH = os.environ.get("LATTICE_MIND_DB", "/data/runs.db")


def _db_connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def _db():
    conn = _db_connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _init_db():
    with _db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS runs (
                run_id       TEXT PRIMARY KEY,
                status       TEXT NOT NULL DEFAULT 'queued',
                challenge    TEXT NOT NULL,
                steps        TEXT NOT NULL DEFAULT '[]',
                flag         TEXT,
                error        TEXT,
                log          TEXT,
                observations TEXT,
                started_at   TEXT,
                finished_at  TEXT,
                created_at   TEXT NOT NULL,
                updated_at   TEXT NOT NULL
            )
        """)
        # migrate existing DBs that lack the observations column
        try:
            conn.execute("ALTER TABLE runs ADD COLUMN observations TEXT")
        except Exception:
            pass
        try:
            conn.execute("ALTER TABLE runs ADD COLUMN confidence TEXT")
        except Exception:
            pass
        # settings table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        # seed default if missing
        conn.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES ('dir_scan_enabled', 'false')"
        )
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username        TEXT PRIMARY KEY,
                hashed_password TEXT NOT NULL,
                role            TEXT NOT NULL DEFAULT 'operator',
                email           TEXT UNIQUE,
                created_at      TEXT NOT NULL
            )
        """)
        try:
            conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
        except Exception:
            pass
        conn.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES ('secret_key', ?)",
            (_secrets.token_hex(32),),
        )


def _load_settings():
    """Load persisted settings into FEATURE_FLAGS on startup."""
    from lattice_mind.config import FEATURE_FLAGS

    with _db() as conn:
        row = conn.execute(
            "SELECT value FROM settings WHERE key='dir_scan_enabled'"
        ).fetchone()
        if row:
            FEATURE_FLAGS.dir_scan_enabled = row["value"].lower() == "true"


def _get_secret_key() -> str:
    with _db() as conn:
        row = conn.execute(
            "SELECT value FROM settings WHERE key='secret_key'"
        ).fetchone()
    return row["value"] if row else _secrets.token_hex(32)


def _db_get_user(username: str) -> Optional[dict]:
    with _db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
    return dict(row) if row else None


def _db_get_user_by_email(email: str) -> Optional[dict]:
    with _db() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    return dict(row) if row else None


def _db_user_count() -> int:
    with _db() as conn:
        return conn.execute("SELECT COUNT(*) as cnt FROM users").fetchone()["cnt"]


def _db_create_user(
    username: str, password: str, email: str = None, role: str = "operator"
) -> dict:
    hashed = _hash_pw(password)
    with _db() as conn:
        conn.execute(
            "INSERT INTO users (username, hashed_password, role, email, created_at) VALUES (?,?,?,?,?)",
            (username, hashed, role, email, _now()),
        )
    return {"username": username, "role": role, "email": email}


def _seed_admin():
    """Create default admin account if no users exist yet."""
    if _db_user_count() > 0:
        return
    admin_user = os.environ.get("LATTICE_MIND_ADMIN_USER", "admin")
    admin_pass = os.environ.get("LATTICE_MIND_ADMIN_PASS", "admin")
    admin_email = os.environ.get("LATTICE_MIND_ADMIN_EMAIL", "admin@latticemind.local")
    _db_create_user(admin_user, admin_pass, admin_email, "admin")
    logger.info("Seeded default admin user: %s", admin_user)


def _db_save(state: RunState):
    """Upsert a RunState to SQLite."""
    d = state.to_dict()
    with _db() as conn:
        conn.execute(
            """
            INSERT INTO runs
                (run_id, status, challenge, steps, flag, error, log, observations, confidence,
                 started_at, finished_at, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(run_id) DO UPDATE SET
                status       = excluded.status,
                steps        = excluded.steps,
                flag         = excluded.flag,
                error        = excluded.error,
                log          = excluded.log,
                observations = excluded.observations,
                confidence   = excluded.confidence,
                started_at   = excluded.started_at,
                finished_at  = excluded.finished_at,
                updated_at   = excluded.updated_at
        """,
            (
                d["run_id"],
                d["status"],
                json.dumps(d["challenge"]),
                json.dumps(d["steps"]),
                d["flag"],
                d["error"],
                json.dumps(d["log"]) if d["log"] else None,
                json.dumps(d["observations"]) if d["observations"] else None,
                json.dumps(d["confidence"]) if d["confidence"] else None,
                d["started_at"],
                d["finished_at"],
                d["created_at"],
                d["updated_at"],
            ),
        )


def _db_load(run_id: str) -> Optional[Dict[str, Any]]:
    """Load a run row by full or partial UUID prefix."""
    with _db() as conn:
        # exact match first
        row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if not row:
            # prefix match (supports 8-char dashboard IDs)
            row = conn.execute(
                "SELECT * FROM runs WHERE run_id LIKE ?", (run_id + "%",)
            ).fetchone()
    if not row:
        return None
    d = dict(row)
    d["challenge"] = json.loads(d["challenge"])
    d["steps"] = json.loads(d["steps"])
    d["log"] = json.loads(d["log"]) if d["log"] else None
    d["observations"] = json.loads(d["observations"]) if d["observations"] else None
    d["confidence"] = json.loads(d["confidence"]) if d.get("confidence") else None
    return d


def _db_list(limit: int = 50) -> List[Dict[str, Any]]:
    with _db() as conn:
        rows = conn.execute(
            "SELECT run_id, status, flag, error, created_at, finished_at, challenge "
            "FROM runs ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    out = []
    for row in rows:
        d = dict(row)
        d["challenge"] = json.loads(d["challenge"])
        out.append(d)
    return out


app = FastAPI(
    title="Lattice Mind API",
    description="REST API + web UI for the autonomous CTF solver",
    version="0.1.0",
)

_PUBLIC_PATHS = {
    "/",
    "/health",
    "/mcp",
    "/auth/login",
    "/auth/register",
    "/auth/forgot-password",
    "/auth/reset-password",
    "/docs",
    "/openapi.json",
    "/redoc",
}


@app.middleware("http")
async def _auth_middleware(request: Request, call_next):
    path = request.url.path
    if path.startswith("/static/") or path.startswith("/ws/") or path in _PUBLIC_PATHS:
        return await call_next(request)
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"detail": "Not authenticated"})
    if not _decode_token(auth[7:]):
        return JSONResponse(
            status_code=401, content={"detail": "Invalid or expired token"}
        )
    return await call_next(request)


_init_db()  # ensure schema exists at import time
_load_settings()  # restore persisted feature flags
SECRET_KEY = _get_secret_key()  # load or create persistent JWT secret
# _seed_admin()  # seed default admin if no users

solver = MVPSolver()
solver_lock = asyncio.Lock()


@dataclass
class RunState:
    run_id: str
    challenge: Dict[str, Any]
    status: str = "queued"
    steps: List[Dict[str, Any]] = field(default_factory=list)
    flag: Optional[str] = None
    error: Optional[str] = None
    log: Optional[Dict[str, Any]] = None
    observations: Optional[Dict[str, Any]] = None
    confidence: Optional[Dict[str, float]] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "run_id": self.run_id,
                "status": self.status,
                "steps": list(self.steps),
                "flag": self.flag,
                "error": self.error,
                "log": self.log,
                "observations": self.observations,
                "confidence": self.confidence,
                "challenge": self.challenge,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
            }

    def add_step(self, event: Dict[str, Any]):
        with self._lock:
            payload = dict(event)
            payload["step"] = len(self.steps) + 1
            self.steps.append(payload)
            self.updated_at = _now()
        _db_save(self)
        # Broadcast via WebSocket
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.run_coroutine_threadsafe(
                    manager.broadcast(self.run_id, {"type": "step", "data": payload}),
                    loop,
                )
        except Exception:
            pass

    def update(self, **kwargs):
        with self._lock:
            for key, value in kwargs.items():
                setattr(self, key, value)
            self.updated_at = _now()
        _db_save(self)
        # Broadcast via WebSocket
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.run_coroutine_threadsafe(
                    manager.broadcast(
                        self.run_id, {"type": "update", "data": self.to_dict()}
                    ),
                    loop,
                )
        except Exception:
            pass


_runs: Dict[str, RunState] = {}
_runs_lock = threading.Lock()
_tasks: Dict[str, asyncio.Task] = {}


def _register_run(state: RunState):
    with _runs_lock:
        _runs[state.run_id] = state
    _db_save(state)  # write initial queued row immediately


def get_run_state(run_id: str) -> Optional[RunState]:
    with _runs_lock:
        state = _runs.get(run_id)
    if state:
        return state
    # Not in memory — try to reconstruct from DB (covers post-restart lookups)
    row = _db_load(run_id)
    if not row:
        return None
    state = RunState(
        run_id=row["run_id"],
        challenge=row["challenge"],
        status=row["status"],
        steps=row["steps"],
        flag=row["flag"],
        error=row["error"],
        log=row["log"],
        observations=row["observations"],
        confidence=row.get("confidence"),
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )
    return state


class SolveRequest(BaseModel):
    """Incoming payload for solver requests."""

    model_config = ConfigDict(populate_by_name=True)

    name: str = Field(default="Untitled Challenge", max_length=256)
    challenge_type: ChallengeType = ChallengeType.WEB
    url: Optional[str] = None
    file_path: Optional[str] = None
    flag_format: str = Field(default="flag{")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SolveSubmissionResponse(BaseModel):
    """Response returned when a run is queued."""

    run_id: str
    status: str


class RunStatusResponse(BaseModel):
    """Detailed run status for polling clients."""

    run_id: str
    status: str
    steps: List[Dict[str, Any]]
    flag: Optional[str] = None
    error: Optional[str] = None
    log: Optional[Dict[str, Any]] = None
    observations: Optional[Dict[str, Any]] = None
    confidence: Optional[Dict[str, float]] = None
    challenge: Dict[str, Any]
    started_at: Optional[str] = None
    finished_at: Optional[str] = None


# ── Auth endpoints ───────────────────────────────────────────────────────────
class AuthRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    password: str
    email: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str
    must_change_password: bool = False


@app.post("/auth/login", response_model=TokenResponse)
async def auth_login(payload: AuthRequest):
    user = _db_get_user(payload.username)
    if not user or not _verify_pw(payload.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = _make_token({"sub": user["username"], "role": user["role"]})

    return TokenResponse(
        access_token=token,
        username=user["username"],
        role=user["role"],
    )


@app.post("/auth/register", response_model=TokenResponse)
async def auth_register(payload: RegisterRequest):
    if len(payload.username) < 2 or len(payload.password) < 6:
        raise HTTPException(
            status_code=422, detail="Username ≥ 2 chars and password ≥ 6 chars required"
        )
    if _db_get_user(payload.username):
        raise HTTPException(status_code=409, detail="Username already exists")
    if _db_get_user_by_email(payload.email):
        raise HTTPException(status_code=409, detail="Email already exists")
    role = "admin" if _db_user_count() == 0 else "operator"
    user = _db_create_user(payload.username, payload.password, payload.email, role)
    token = _make_token({"sub": user["username"], "role": user["role"]})
    return TokenResponse(
        access_token=token, username=user["username"], role=user["role"]
    )


class ForgotPasswordRequest(BaseModel):
    email: str


@app.post("/auth/forgot-password")
async def auth_forgot_password(payload: ForgotPasswordRequest):
    user = _db_get_user_by_email(payload.email)
    if user:
        token = base64.b64encode(urllib.parse.quote(payload.email).encode()).decode()
        reset_link = f"/#reset={token}"
        _send_email(
            payload.email,
            "Password Reset",
            f"Please use this link to reset your password: {reset_link}",
        )
    return {"detail": "If that email exists, a reset link was sent."}


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


@app.post("/auth/reset-password")
async def auth_reset_password(payload: ResetPasswordRequest):
    try:
        email = urllib.parse.unquote(base64.b64decode(payload.token).decode())
    except:
        raise HTTPException(status_code=400, detail="Invalid token")

    user = _db_get_user_by_email(email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    hashed = _hash_pw(payload.new_password)
    with _db() as conn:
        conn.execute(
            "UPDATE users SET hashed_password = ? WHERE email = ?", (hashed, email)
        )
    return {"detail": "Password reset successfully"}


@app.get("/auth/me")
async def auth_me(request: Request):
    auth = request.headers.get("Authorization", "")
    payload = _decode_token(auth[7:]) if auth.startswith("Bearer ") else None
    if not payload:
        raise HTTPException(status_code=401, detail="Not authenticated")

    username = payload.get("sub")
    user = _db_get_user(username)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return {
        "username": username,
        "role": user["role"],
        "must_change_password": False,
    }


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@app.post("/auth/change-password")
async def auth_change_password(request: Request, payload: ChangePasswordRequest):
    auth = request.headers.get("Authorization", "")
    token_payload = _decode_token(auth[7:]) if auth.startswith("Bearer ") else None
    if not token_payload:
        raise HTTPException(status_code=401, detail="Not authenticated")

    username = token_payload.get("sub")
    user = _db_get_user(username)
    if not user or not _verify_pw(payload.current_password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid current password")

    if len(payload.new_password) < 6:
        raise HTTPException(
            status_code=400, detail="New password must be at least 6 characters"
        )

    hashed = _hash_pw(payload.new_password)
    with _db() as conn:
        conn.execute(
            "UPDATE users SET hashed_password = ? WHERE username = ?",
            (hashed, username),
        )
    return {"detail": "Password changed successfully"}


@app.get("/rules")
async def list_rules():
    """List all loaded YAML decision trees."""
    return [
        {
            "id": t.id,
            "name": t.name,
            "category": t.category,
            "version": t.version,
            "enabled": t.enabled,
            "description": t.description,
            "detection_paths": len(t.detection_paths),
            "exploitation_paths": len(t.exploitation_paths),
        }
        for t in solver.registry.list_trees()
    ]


@app.get("/rules/{rule_id}")
async def get_rule(rule_id: str):
    """Get full definition of a specific rule."""
    tree = solver.registry.get_tree(rule_id)
    if not tree:
        raise HTTPException(status_code=404, detail="Rule not found")
    return tree


@app.post("/rules/reload")
async def reload_rules():
    """Rescan the YAML trees directory and hot-reload rules."""
    import pathlib

    base_path = pathlib.Path(solver.__file__).parent / "trees" / "yaml"
    solver.registry.load_from_directory(str(base_path))
    return {"status": "ok", "count": len(solver.registry.list_trees())}


@app.get("/settings")
async def get_settings():
    """Return current feature flag settings."""
    from lattice_mind.config import FEATURE_FLAGS

    return {"dir_scan_enabled": FEATURE_FLAGS.dir_scan_enabled}


@app.put("/settings")
async def put_settings(payload: dict):
    """Update feature flag settings and persist to DB."""
    from lattice_mind.config import FEATURE_FLAGS

    changed = {}
    if "dir_scan_enabled" in payload:
        val = bool(payload["dir_scan_enabled"])
        FEATURE_FLAGS.dir_scan_enabled = val
        with _db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES ('dir_scan_enabled', ?)",
                ("true" if val else "false",),
            )
        changed["dir_scan_enabled"] = val
    return {
        "updated": changed,
        "settings": {"dir_scan_enabled": FEATURE_FLAGS.dir_scan_enabled},
    }


async def patch_rule(rule_id: str, payload: dict):
    """Enable or disable a specific rule."""
    tree = solver.registry.get_tree(rule_id)
    if not tree:
        raise HTTPException(status_code=404, detail="Rule not found")
    if "enabled" in payload:
        tree.enabled = bool(payload["enabled"])
    return {"id": tree.id, "enabled": tree.enabled}


from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from lattice_mind.mcp.server import LatticeMindMCPServer

BASE_DIR = pathlib.Path(__file__).parent.parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"


@app.get("/mcp")
async def mcp_info():
    """MCP server discovery / health endpoint."""
    return {
        "name": "lattice-mind-mcp",
        "version": "0.1.0",
        "protocol": "2024-11-05",
        "transport": "http",
        "tools": [t["name"] for t in LatticeMindMCPServer._tool_definitions()],
    }


async def _mcp_dispatch(name: str, arguments: Dict[str, Any]) -> Any:
    """Call server functions directly — no HTTP roundtrip, no deadlock."""
    if name == "health_check":
        return await healthcheck()

    if name == "submit_scan":
        payload = SolveRequest(
            name=arguments.get("name", "Untitled Challenge"),
            challenge_type=arguments["challenge_type"],
            url=arguments.get("url"),
            file_path=arguments.get("file_path"),
            flag_format=arguments.get("flag_format", "flag{"),
            metadata=arguments.get("metadata", {}),
        )
        result = await solve_challenge(payload)
        return result.model_dump()

    if name == "get_run_status":
        result = await get_run_status(arguments["run_id"])
        return result.model_dump() if hasattr(result, "model_dump") else dict(result)

    if name == "list_runs":
        return await list_runs(limit=int(arguments.get("limit", 50)))

    if name == "list_rules":
        return await list_rules()

    if name == "get_rule":
        return await get_rule(arguments["rule_id"])

    raise ValueError(f"Unknown tool: {name}")


@app.post("/mcp")
async def mcp_rpc(request: Request):
    """Handle MCP JSON-RPC over HTTP — dispatches to server functions directly."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content={"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}},
        )

    method = body.get("method")
    req_id = body.get("id")
    params = body.get("params") or {}

    def _ok(result: Any) -> JSONResponse:
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": result})

    def _err(code: int, msg: str) -> JSONResponse:
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": msg}})

    # Notifications have no id and expect no response body
    if req_id is None and method != "initialize":
        return Response(status_code=202)

    if method == "initialize":
        return _ok({
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "lattice-mind-mcp", "version": "0.1.0"},
            "capabilities": {"tools": {}},
        })

    if method == "tools/list":
        return _ok({"tools": LatticeMindMCPServer._tool_definitions()})

    if method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments") or {}
        try:
            result = await _mcp_dispatch(tool_name, arguments)
            return _ok({"content": [{"type": "text", "text": json.dumps(result, indent=2)}], "isError": False})
        except HTTPException as exc:
            return _ok({"content": [{"type": "text", "text": f"Error {exc.status_code}: {exc.detail}"}], "isError": True})
        except (KeyError, ValueError) as exc:
            return _ok({"content": [{"type": "text", "text": f"Invalid arguments: {exc}"}], "isError": True})
        except Exception as exc:
            return _ok({"content": [{"type": "text", "text": str(exc)}], "isError": True})

    return _err(-32601, f"Method not found: {method}")


@app.websocket("/ws/{run_id}")
async def websocket_endpoint(websocket: WebSocket, run_id: str, token: str = ""):
    if not _decode_token(token):
        await websocket.close(code=4001)
        return
    await manager.connect(websocket, run_id)
    try:
        state = get_run_state(run_id)
        if state:
            await websocket.send_json({"type": "init", "data": state.to_dict()})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, run_id)
    except Exception:
        manager.disconnect(websocket, run_id)


app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/")
async def read_index():
    return FileResponse(str(FRONTEND_DIR / "index.html"))


@app.get("/health")
async def healthcheck() -> Dict[str, str]:
    """Simple health endpoint for readiness probes."""
    return {"status": "ok"}


@app.get("/challenge-types")
async def challenge_types() -> Dict[str, List[str]]:
    """Expose available challenge types for clients."""
    return {
        "challenge_types": [challenge_type.value for challenge_type in ChallengeType]
    }


@app.post("/solve", response_model=SolveSubmissionResponse)
async def solve_challenge(payload: SolveRequest) -> SolveSubmissionResponse:
    """Queue a solver run and return a run identifier for polling."""
    descriptor = ChallengeDescriptor(
        type=payload.challenge_type,
        name=payload.name,
        url=payload.url,
        file_path=payload.file_path,
        flag_format=payload.flag_format,
        metadata=dict(payload.metadata),
    )

    run_id = str(uuid.uuid4())
    challenge_snapshot = _serialize_challenge(descriptor)
    state = RunState(run_id=run_id, challenge=challenge_snapshot or {})
    _register_run(state)
    _start_solver_task(run_id, descriptor)
    return SolveSubmissionResponse(run_id=run_id, status=state.status)


@app.get("/runs", response_model=List[Dict[str, Any]])
async def list_runs(limit: int = 50) -> List[Dict[str, Any]]:
    """Return the most recent runs (persisted across restarts)."""
    return _db_list(limit=limit)


@app.get("/runs/{run_id}", response_model=RunStatusResponse)
async def get_run_status(run_id: str) -> RunStatusResponse:
    """Fetch the current state of a solver run."""
    state = get_run_state(run_id)
    if not state:
        raise HTTPException(status_code=404, detail="Run not found")
    return RunStatusResponse(**state.to_dict())


def _start_solver_task(run_id: str, descriptor: ChallengeDescriptor):
    task = asyncio.create_task(_run_solver(run_id, descriptor))
    _tasks[run_id] = task


async def _run_solver(run_id: str, descriptor: ChallengeDescriptor):
    state = get_run_state(run_id)
    if not state:
        return

    state.update(status="running", started_at=_now())

    def progress_callback(event: Dict[str, Any]):
        state.add_step(event)

    try:
        async with solver_lock:
            # Set callback inside the lock so concurrent queued runs can't
            # overwrite each other's callback before execution starts.
            solver.orchestrator.set_progress_callback(progress_callback)
            try:
                flag, log = await asyncio.to_thread(_execute_solver, descriptor)
            finally:
                solver.orchestrator.clear_progress_callback()
        serialized_log = _serialize_log(log)
        observations = jsonable_encoder(
            solver.orchestrator.execution_context.get("observations", {})
        )
        confidence = solver.confidence_pool.get_scores()
        state.update(
            flag=flag,
            log=serialized_log,
            observations=observations,
            confidence=confidence,
            status="success" if flag else "completed",
            finished_at=_now(),
        )
    except Exception as exc:  # pragma: no cover - defensive guard
        logger.exception("Solver execution failed")
        state.update(status="error", error=str(exc), finished_at=_now())
    finally:
        _tasks.pop(run_id, None)


def _execute_solver(
    challenge: ChallengeDescriptor,
) -> Tuple[Optional[str], Dict[str, Any]]:
    """Run MVPSolver synchronously for use inside asyncio executors."""
    flag = solver.solve(challenge)
    log = solver.orchestrator.get_execution_log()
    return flag, log


def _serialize_log(log: Dict[str, Any]) -> Dict[str, Any]:
    """Convert orchestrator logs into JSON-serializable data."""
    challenge = log.get("challenge")
    observations = log.get("observations", {})

    return {
        "challenge": _serialize_challenge(challenge),
        "tree_history": list(log.get("tree_history", [])),
        "observations": jsonable_encoder(observations),
        "flag_found": log.get("flag_found"),
    }


def _serialize_challenge(
    challenge: Optional[ChallengeDescriptor],
) -> Optional[Dict[str, Any]]:
    """Convert ChallengeDescriptor objects to JSON."""
    if not challenge:
        return None

    return {
        "name": challenge.name,
        "type": challenge.type.value if challenge.type else None,
        "url": challenge.url,
        "file_path": challenge.file_path,
        "flag_format": challenge.flag_format,
        "metadata": jsonable_encoder(challenge.metadata),
    }


UPLOAD_DIR = pathlib.Path("/tmp/lattice-mind-uploads")


@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """Save uploaded file and return its server path."""
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    dest = UPLOAD_DIR / f"{uuid.uuid4().hex}_{file.filename}"
    with dest.open("wb") as f:
        shutil.copyfileobj(file.file, f)
    return {"path": str(dest), "filename": file.filename}


@app.post("/runs/{run_id}/rerun", response_model=SolveSubmissionResponse)
async def rerun_challenge(run_id: str):
    """Clone an existing run's challenge and start a new run."""
    state = get_run_state(run_id)
    if not state:
        raise HTTPException(status_code=404, detail="Run not found")
    ch = state.challenge
    descriptor = ChallengeDescriptor(
        type=ChallengeType(ch.get("type", "web")),
        name=ch.get("name", "Rerun"),
        url=ch.get("url"),
        file_path=ch.get("file_path"),
        flag_format=ch.get("flag_format", "flag{"),
        metadata=ch.get("metadata", {}),
    )
    new_id = str(uuid.uuid4())
    new_state = RunState(
        run_id=new_id, challenge=_serialize_challenge(descriptor) or {}
    )
    _register_run(new_state)
    _start_solver_task(new_id, descriptor)
    return SolveSubmissionResponse(run_id=new_id, status=new_state.status)


@app.get("/hitl/pending")
async def hitl_pending():
    """Return pending human-in-the-loop questions."""
    from lattice_mind.core.human_loop import get_human_loop_manager

    mgr = get_human_loop_manager()
    return {"questions": mgr.get_pending()}


@app.post("/hitl/{question_id}/answer")
async def hitl_answer(question_id: str, payload: dict):
    """Submit an answer to a pending HITL question."""
    from lattice_mind.core.human_loop import get_human_loop_manager

    mgr = get_human_loop_manager()
    answer = payload.get("answer", "")
    ok = mgr.answer(question_id, answer)
    if not ok:
        raise HTTPException(
            status_code=404, detail="Question not found or already answered"
        )
    return {"ok": True}


@app.post("/crypto/solve")
async def crypto_solve(payload: dict):
    """
    Auto-solve common crypto challenges.
    payload: {type, text, params:{shift, key, n, e, c, p, q}}
    """
    text = payload.get("text", "").strip()
    ctype = payload.get("type", "auto")
    params = payload.get("params", {})
    results = []
    flag_pattern = _re.compile(
        r"flag\{[^}]+\}|ctf\{[^}]+\}|HTB\{[^}]+\}", _re.IGNORECASE
    )

    def add(method, output, note=""):
        flag = flag_pattern.search(str(output))
        results.append(
            {
                "method": method,
                "output": str(output)[:2000],
                "note": note,
                "flag": flag.group(0) if flag else None,
            }
        )

    if ctype in ("auto", "base64"):
        try:
            add("base64_decode", _b64.b64decode(text).decode("utf-8", errors="replace"))
        except Exception as ex:
            if ctype == "base64":
                add("base64_decode", f"Error: {ex}")

    if ctype in ("auto", "hex"):
        try:
            stripped = text.replace(" ", "").replace("\n", "")
            add("hex_decode", bytes.fromhex(stripped).decode("utf-8", errors="replace"))
        except Exception as ex:
            if ctype == "hex":
                add("hex_decode", f"Error: {ex}")

    if ctype in ("auto", "url"):
        import urllib.parse

        add("url_decode", urllib.parse.unquote(text))

    if ctype in ("auto", "caesar", "rot13"):
        shift = int(params.get("shift", 13)) if ctype != "auto" else None
        shifts = [shift] if shift is not None else range(26)
        for s in shifts:
            out = "".join(
                (
                    chr((ord(c) - ord("A") + s) % 26 + ord("A"))
                    if c.isupper()
                    else (
                        chr((ord(c) - ord("a") + s) % 26 + ord("a"))
                        if c.islower()
                        else c
                    )
                )
                for c in text
            )
            add(f"caesar_{s}", out, f"ROT{s}")
            if flag_pattern.search(out):
                break

    if ctype in ("auto", "xor"):
        key_param = params.get("key")
        if key_param is not None:
            key_bytes = (
                key_param.encode()
                if isinstance(key_param, str)
                else bytes([int(key_param)])
            )
            raw = text.encode("latin-1", errors="replace")
            xored = bytes(
                raw[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(raw))
            )
            add("xor_key", xored.decode("utf-8", errors="replace"))
        else:
            raw = text.encode("latin-1", errors="replace")
            best = []
            for k in range(256):
                out_bytes = bytes(b ^ k for b in raw)
                out_str = out_bytes.decode("utf-8", errors="replace")
                score = sum(
                    {"e": 13, "t": 9, "a": 8, "o": 8, "i": 7, "n": 7, "s": 6}.get(
                        c.lower(), 0
                    )
                    for c in out_str
                )
                best.append((score, k, out_str))
            best.sort(reverse=True)
            for score, k, out_str in best[:5]:
                add(f"xor_0x{k:02x}", out_str, f"key=0x{k:02x}")
                if flag_pattern.search(out_str):
                    break

    if ctype in ("auto", "binary"):
        try:
            clean = text.replace(" ", "")
            if all(c in "01" for c in clean) and len(clean) % 8 == 0:
                out = "".join(
                    chr(int(clean[i : i + 8], 2)) for i in range(0, len(clean), 8)
                )
                add("binary_decode", out)
        except Exception:
            pass

    if ctype in ("auto", "morse"):
        morse = {
            ".-": "A",
            "-...": "B",
            "-.-.": "C",
            "-..": "D",
            ".": "E",
            "..-.": "F",
            "--.": "G",
            "....": "H",
            "..": "I",
            ".---": "J",
            "-.-": "K",
            ".-..": "L",
            "--": "M",
            "-.": "N",
            "---": "O",
            ".--.": "P",
            "--.-": "Q",
            ".-.": "R",
            "...": "S",
            "-": "T",
            "..-": "U",
            "...-": "V",
            ".--": "W",
            "-..-": "X",
            "-.--": "Y",
            "--..": "Z",
            "-----": "0",
            ".----": "1",
            "..---": "2",
            "...--": "3",
            "....-": "4",
            ".....": "5",
            "-....": "6",
            "--...": "7",
            "---..": "8",
            "----.": "9",
        }
        try:
            decoded = " ".join(morse.get(w, "?") for w in text.strip().split())
            add("morse_decode", decoded)
        except Exception:
            pass

    if ctype == "rsa":
        try:
            n = int(params.get("n", 0))
            e = int(params.get("e", 65537))
            c = int(params.get("c", 0))
            if params.get("p") and params.get("q"):
                p, q = int(params["p"]), int(params["q"])
                phi = (p - 1) * (q - 1)
                d = pow(e, -1, phi)
                m = pow(c, d, n)
                length = (m.bit_length() + 7) // 8
                add(
                    "rsa_pq_decrypt",
                    m.to_bytes(length, "big").decode("utf-8", errors="replace"),
                )
            elif params.get("d"):
                d = int(params["d"])
                m = pow(c, d, n)
                length = (m.bit_length() + 7) // 8
                add(
                    "rsa_known_d",
                    m.to_bytes(length, "big").decode("utf-8", errors="replace"),
                )
            else:
                add("rsa_no_key", "Need p,q or d to decrypt. Try factoring n.")
        except Exception as ex:
            add("rsa_error", str(ex))

    found_flags = [r["flag"] for r in results if r["flag"]]
    return {"results": results, "flag": found_flags[0] if found_flags else None}


def main():
    """Run a development server via `python -m lattice_mind.api.server`."""
    import uvicorn

    uvicorn.run("lattice_mind.api.server:app", host="0.0.0.0", port=8000, reload=False)
