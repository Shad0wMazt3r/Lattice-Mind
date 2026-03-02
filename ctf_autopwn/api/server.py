"""FastAPI server exposing the CTF Autopwn solver along with a simple UI."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field

from ctf_autopwn.mvp import MVPSolver
from ctf_autopwn.core.types import ChallengeDescriptor, ChallengeType

logger = logging.getLogger(__name__)

# ── SQLite persistence ────────────────────────────────────────────────────────
DB_PATH = os.environ.get("AUTOPWN_DB", "/data/runs.db")

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
                run_id      TEXT PRIMARY KEY,
                status      TEXT NOT NULL DEFAULT 'queued',
                challenge   TEXT NOT NULL,
                steps       TEXT NOT NULL DEFAULT '[]',
                flag        TEXT,
                error       TEXT,
                log         TEXT,
                started_at  TEXT,
                finished_at TEXT,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            )
        """)

def _db_save(state: RunState):
    """Upsert a RunState to SQLite."""
    d = state.to_dict()
    with _db() as conn:
        conn.execute("""
            INSERT INTO runs
                (run_id, status, challenge, steps, flag, error, log,
                 started_at, finished_at, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(run_id) DO UPDATE SET
                status      = excluded.status,
                steps       = excluded.steps,
                flag        = excluded.flag,
                error       = excluded.error,
                log         = excluded.log,
                started_at  = excluded.started_at,
                finished_at = excluded.finished_at,
                updated_at  = excluded.updated_at
        """, (
            d["run_id"], d["status"],
            json.dumps(d["challenge"]),
            json.dumps(d["steps"]),
            d["flag"], d["error"],
            json.dumps(d["log"]) if d["log"] else None,
            d["started_at"], d["finished_at"],
            d["created_at"], d["updated_at"],
        ))

def _db_load(run_id: str) -> Optional[Dict[str, Any]]:
    """Load a run row by full or partial UUID prefix."""
    with _db() as conn:
        # exact match first
        row = conn.execute(
            "SELECT * FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if not row:
            # prefix match (supports 8-char dashboard IDs)
            row = conn.execute(
                "SELECT * FROM runs WHERE run_id LIKE ?", (run_id + "%",)
            ).fetchone()
    if not row:
        return None
    d = dict(row)
    d["challenge"] = json.loads(d["challenge"])
    d["steps"]     = json.loads(d["steps"])
    d["log"]       = json.loads(d["log"]) if d["log"] else None
    return d

def _db_list(limit: int = 50) -> List[Dict[str, Any]]:
    with _db() as conn:
        rows = conn.execute(
            "SELECT run_id, status, flag, error, created_at, finished_at, challenge "
            "FROM runs ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    out = []
    for row in rows:
        d = dict(row)
        d["challenge"] = json.loads(d["challenge"])
        out.append(d)
    return out

app = FastAPI(
    title="CTF Autopwn API",
    description="REST API + web UI for the autonomous CTF solver",
    version="0.1.0",
)

_init_db()  # ensure schema exists at import time

solver = MVPSolver()
solver_lock = asyncio.Lock()


def _now() -> str:
    return datetime.utcnow().isoformat() + "Z"


@dataclass
class RunState:
    run_id: str
    challenge: Dict[str, Any]
    status: str = "queued"
    steps: List[Dict[str, Any]] = field(default_factory=list)
    flag: Optional[str] = None
    error: Optional[str] = None
    log: Optional[Dict[str, Any]] = None
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

    def update(self, **kwargs):
        with self._lock:
            for key, value in kwargs.items():
                setattr(self, key, value)
            self.updated_at = _now()
        _db_save(self)


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
    challenge: Dict[str, Any]
    started_at: Optional[str] = None
    finished_at: Optional[str] = None


@app.get("/health")
async def healthcheck() -> Dict[str, str]:
    """Simple health endpoint for readiness probes."""
    return {"status": "ok"}


@app.get("/")
async def frontend() -> HTMLResponse:
    """Serve the lightweight dashboard."""
    return HTMLResponse(content=FRONTEND_HTML)


@app.get("/challenge-types")
async def challenge_types() -> Dict[str, List[str]]:
    """Expose available challenge types for clients."""
    return {"challenge_types": [challenge_type.value for challenge_type in ChallengeType]}


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

    solver.orchestrator.set_progress_callback(progress_callback)

    try:
        async with solver_lock:
            flag, log = await asyncio.to_thread(_execute_solver, descriptor)
        serialized_log = _serialize_log(log)
        state.update(
            flag=flag,
            log=serialized_log,
            status="success" if flag else "completed",
            finished_at=_now(),
        )
    except Exception as exc:  # pragma: no cover - defensive guard
        logger.exception("Solver execution failed")
        state.update(status="error", error=str(exc), finished_at=_now())
    finally:
        solver.orchestrator.clear_progress_callback()
        _tasks.pop(run_id, None)


def _execute_solver(challenge: ChallengeDescriptor) -> Tuple[Optional[str], Dict[str, Any]]:
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


def _serialize_challenge(challenge: Optional[ChallengeDescriptor]) -> Optional[Dict[str, Any]]:
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


def main():
    """Run a development server via `python -m ctf_autopwn.api.server`."""
    import uvicorn

    uvicorn.run("ctf_autopwn.api.server:app", host="0.0.0.0", port=8000, reload=False)


FRONTEND_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>CTF Autopwn // CYBER DASHBOARD</title>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&family=Inter:wght@300;400;600&display=swap" rel="stylesheet"/>
  <style>
    /* ── CSS custom properties ── */
    :root {
      --cyan:   #00fff0;
      --magenta:#ff2d78;
      --purple: #9d4edd;
      --yellow: #ffe600;
      --green:  #39ff14;
      --bg:     #020510;
      --surface:#070d1e;
      --card:   rgba(0,255,240,.04);
      --border: rgba(0,255,240,.12);
      --text:   #c8d6f0;
      --dim:    #4a5878;
      --font-mono: "Share Tech Mono", monospace;
      --font-hud:  "Orbitron", sans-serif;
      --font-body: "Inter", sans-serif;
    }

    /* ── reset ── */
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    /* ── scanline overlay ── */
    body::before {
      content: "";
      position: fixed; inset: 0;
      background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0,0,0,.18) 2px,
        rgba(0,0,0,.18) 4px
      );
      pointer-events: none;
      z-index: 9999;
    }

    body {
      font-family: var(--font-body);
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      overflow-x: hidden;
    }

    /* ── animated grid background ── */
    .grid-bg {
      position: fixed; inset: 0;
      background-image:
        linear-gradient(rgba(0,255,240,.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,255,240,.03) 1px, transparent 1px);
      background-size: 48px 48px;
      animation: grid-drift 30s linear infinite;
      z-index: 0;
    }
    @keyframes grid-drift {
      from { background-position: 0 0; }
      to   { background-position: 0 48px; }
    }

    /* ── glow blobs ── */
    .blob {
      position: fixed;
      border-radius: 50%;
      filter: blur(120px);
      opacity: .22;
      pointer-events: none;
      z-index: 0;
    }
    .blob-1 { width:600px; height:600px; top:-200px; left:-100px; background:var(--purple); }
    .blob-2 { width:500px; height:500px; bottom:-150px; right:-100px; background:var(--cyan); }
    .blob-3 { width:400px; height:400px; top:40%; left:50%; transform:translate(-50%,-50%); background:var(--magenta); }

    /* ── layout ── */
    .shell {
      position: relative;
      z-index: 1;
      max-width: 1280px;
      margin: 0 auto;
      padding: 1.5rem 2rem 4rem;
    }

    /* ── header ── */
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 1.2rem 0 2rem;
      border-bottom: 1px solid var(--border);
      margin-bottom: 2rem;
      flex-wrap: wrap;
      gap: 1rem;
    }
    .logo {
      font-family: var(--font-hud);
      font-size: 1.6rem;
      font-weight: 900;
      letter-spacing: .12em;
      text-transform: uppercase;
      background: linear-gradient(120deg, var(--cyan), var(--magenta));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      text-shadow: none;
      position: relative;
    }
    .logo::after {
      content: attr(data-text);
      position: absolute; inset: 0;
      background: linear-gradient(120deg, var(--cyan), var(--magenta));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      filter: blur(12px);
      opacity: .6;
      z-index: -1;
    }
    .header-meta {
      font-family: var(--font-mono);
      font-size: .78rem;
      color: var(--dim);
      display: flex;
      gap: 1.5rem;
      align-items: center;
      flex-wrap: wrap;
    }
    .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: .4rem; }
    .dot.online { background: var(--green); box-shadow: 0 0 8px var(--green); animation: pulse 2s infinite; }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }

    /* ── two-column grid ── */
    .main-grid {
      display: grid;
      grid-template-columns: 420px 1fr;
      gap: 1.5rem;
      align-items: start;
    }
    @media (max-width: 900px) {
      .main-grid { grid-template-columns: 1fr; }
    }

    /* ── panel (card) ── */
    .panel {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.5rem;
      backdrop-filter: blur(24px);
      position: relative;
      overflow: hidden;
    }
    .panel::before {
      content: "";
      position: absolute; top: 0; left: 0; right: 0;
      height: 2px;
      background: linear-gradient(90deg, transparent, var(--cyan), transparent);
    }
    .panel-title {
      font-family: var(--font-hud);
      font-size: .7rem;
      letter-spacing: .2em;
      text-transform: uppercase;
      color: var(--cyan);
      margin-bottom: 1.25rem;
      display: flex;
      align-items: center;
      gap: .6rem;
    }
    .panel-title svg { flex-shrink: 0; }

    /* ── form ── */
    .field { margin-bottom: 1.1rem; }
    .field label {
      display: block;
      font-family: var(--font-mono);
      font-size: .72rem;
      letter-spacing: .15em;
      text-transform: uppercase;
      color: var(--dim);
      margin-bottom: .45rem;
    }
    .field input,
    .field select,
    .field textarea {
      width: 100%;
      background: rgba(0,255,240,.03);
      border: 1px solid rgba(0,255,240,.15);
      border-radius: 8px;
      padding: .7rem .9rem;
      font-size: .92rem;
      font-family: var(--font-mono);
      color: var(--text);
      outline: none;
      transition: border-color .2s, background .2s, box-shadow .2s;
    }
    .field input:focus,
    .field select:focus,
    .field textarea:focus {
      border-color: var(--cyan);
      background: rgba(0,255,240,.06);
      box-shadow: 0 0 0 3px rgba(0,255,240,.1), inset 0 0 12px rgba(0,255,240,.04);
    }
    .field textarea { min-height: 80px; resize: vertical; }
    .field select option { background: #0e1526; }

    /* ── run button ── */
    .btn-run {
      width: 100%;
      margin-top: .5rem;
      padding: .9rem 1.5rem;
      font-family: var(--font-hud);
      font-size: .85rem;
      font-weight: 700;
      letter-spacing: .2em;
      text-transform: uppercase;
      color: #000;
      background: linear-gradient(120deg, var(--cyan) 0%, var(--purple) 100%);
      border: none;
      border-radius: 8px;
      cursor: pointer;
      position: relative;
      overflow: hidden;
      transition: transform .15s, box-shadow .15s;
    }
    .btn-run::after {
      content: "";
      position: absolute; inset: 0;
      background: linear-gradient(120deg, var(--magenta), var(--cyan));
      opacity: 0;
      transition: opacity .3s;
    }
    .btn-run:hover { transform: translateY(-2px); box-shadow: 0 0 30px rgba(0,255,240,.35); }
    .btn-run:hover::after { opacity: 1; }
    .btn-run span { position: relative; z-index: 1; }
    .btn-run:disabled { opacity: .5; cursor: not-allowed; transform: none; }

    /* ── right column ── */
    .right-col { display: flex; flex-direction: column; gap: 1.25rem; }

    /* ── stat row ── */
    .stat-row {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: .75rem;
    }
    @media (max-width: 700px) {
      .stat-row { grid-template-columns: repeat(2, 1fr); }
    }
    .stat-card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1rem;
      position: relative;
      overflow: hidden;
    }
    .stat-card::before {
      content: "";
      position: absolute; top: 0; left: 0; right: 0;
      height: 2px;
    }
    .stat-card.cyan::before  { background: linear-gradient(90deg, transparent, var(--cyan), transparent); }
    .stat-card.magenta::before { background: linear-gradient(90deg, transparent, var(--magenta), transparent); }
    .stat-card.purple::before { background: linear-gradient(90deg, transparent, var(--purple), transparent); }
    .stat-card.green::before  { background: linear-gradient(90deg, transparent, var(--green), transparent); }
    .stat-label {
      font-family: var(--font-mono);
      font-size: .65rem;
      letter-spacing: .18em;
      text-transform: uppercase;
      color: var(--dim);
      margin-bottom: .4rem;
    }
    .stat-value {
      font-family: var(--font-hud);
      font-size: 1.5rem;
      font-weight: 700;
      line-height: 1;
    }
    .stat-card.cyan   .stat-value { color: var(--cyan); text-shadow: 0 0 12px var(--cyan); }
    .stat-card.magenta .stat-value { color: var(--magenta); text-shadow: 0 0 12px var(--magenta); }
    .stat-card.purple .stat-value { color: var(--purple); text-shadow: 0 0 12px var(--purple); }
    .stat-card.green  .stat-value { color: var(--green); text-shadow: 0 0 12px var(--green); }

    /* ── progress bar ── */
    .prog-wrap { margin-bottom: .5rem; }
    .prog-label {
      font-family: var(--font-mono);
      font-size: .72rem;
      color: var(--dim);
      display: flex;
      justify-content: space-between;
      margin-bottom: .4rem;
    }
    .prog-track {
      height: 6px;
      background: rgba(255,255,255,.06);
      border-radius: 999px;
      overflow: hidden;
    }
    .prog-fill {
      height: 100%;
      width: 0%;
      background: linear-gradient(90deg, var(--cyan), var(--purple));
      border-radius: inherit;
      transition: width .4s ease;
      box-shadow: 0 0 10px var(--cyan);
    }

    /* ── badge ── */
    .badge {
      display: inline-flex;
      align-items: center;
      gap: .35rem;
      padding: .28rem .7rem;
      border-radius: 999px;
      font-family: var(--font-hud);
      font-size: .65rem;
      letter-spacing: .12em;
      text-transform: uppercase;
      font-weight: 700;
      border: 1px solid;
    }
    .badge.idle    { color: var(--dim);     border-color: var(--dim);     background: rgba(74,88,120,.12); }
    .badge.queued  { color: var(--yellow);  border-color: var(--yellow);  background: rgba(255,230,0,.08); }
    .badge.running { color: var(--cyan);    border-color: var(--cyan);    background: rgba(0,255,240,.08); animation: blink-border 1s ease-in-out infinite; }
    .badge.success { color: var(--green);   border-color: var(--green);   background: rgba(57,255,20,.08); }
    .badge.completed { color: var(--purple); border-color: var(--purple); background: rgba(157,78,221,.08); }
    .badge.error   { color: var(--magenta); border-color: var(--magenta); background: rgba(255,45,120,.08); }
    @keyframes blink-border { 0%,100%{opacity:1} 50%{opacity:.5} }

    /* ── flag panel ── */
    .flag-panel {
      display: none;
      background: rgba(57,255,20,.06);
      border: 1px solid rgba(57,255,20,.3);
      border-radius: 10px;
      padding: 1.25rem 1.5rem;
      position: relative;
      overflow: hidden;
    }
    .flag-panel::before {
      content: "";
      position: absolute; top: 0; left: 0; right: 0;
      height: 2px;
      background: linear-gradient(90deg, transparent, var(--green), transparent);
    }
    .flag-panel.visible { display: block; }
    .flag-label {
      font-family: var(--font-hud);
      font-size: .65rem;
      letter-spacing: .2em;
      text-transform: uppercase;
      color: var(--green);
      margin-bottom: .5rem;
    }
    .flag-value {
      font-family: var(--font-mono);
      font-size: 1.1rem;
      color: var(--green);
      text-shadow: 0 0 16px var(--green);
      word-break: break-all;
    }

    /* ── error panel ── */
    .error-panel {
      display: none;
      background: rgba(255,45,120,.05);
      border: 1px solid rgba(255,45,120,.25);
      border-radius: 10px;
      padding: 1rem 1.25rem;
    }
    .error-panel.visible { display: block; }
    .error-title {
      font-family: var(--font-hud);
      font-size: .65rem;
      letter-spacing: .2em;
      text-transform: uppercase;
      color: var(--magenta);
      margin-bottom: .4rem;
    }
    .error-body {
      font-family: var(--font-mono);
      font-size: .85rem;
      color: #ff88aa;
    }

    /* ── timeline ── */
    .timeline-list {
      list-style: none;
      max-height: 280px;
      overflow-y: auto;
      padding-right: .25rem;
    }
    .timeline-list::-webkit-scrollbar { width: 4px; }
    .timeline-list::-webkit-scrollbar-track { background: transparent; }
    .timeline-list::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

    .tl-item {
      display: grid;
      grid-template-columns: 16px 1fr auto;
      gap: .5rem .75rem;
      align-items: start;
      padding: .6rem 0;
      border-bottom: 1px solid rgba(255,255,255,.04);
      font-family: var(--font-mono);
      font-size: .8rem;
    }
    .tl-item:last-child { border-bottom: none; }
    .tl-dot {
      width: 8px; height: 8px;
      border-radius: 50%;
      margin-top: .25rem;
      flex-shrink: 0;
    }
    .tl-dot.node_start { background: var(--cyan); box-shadow: 0 0 6px var(--cyan); }
    .tl-dot.node_end   { background: var(--green); box-shadow: 0 0 6px var(--green); }
    .tl-dot.flag_found { background: var(--yellow); box-shadow: 0 0 6px var(--yellow); }
    .tl-dot.default    { background: var(--dim); }
    .tl-node { color: var(--text); font-size: .82rem; }
    .tl-node .tl-sub { font-size: .7rem; color: var(--dim); margin-top: .1rem; }
    .tl-status { font-size: .68rem; color: var(--dim); white-space: nowrap; margin-top: .25rem; }
    .tl-status.success  { color: var(--green); }
    .tl-status.failure  { color: var(--magenta); }
    .tl-status.flag_found { color: var(--yellow); }

    /* ── JSON output ── */
    .json-out {
      font-family: var(--font-mono);
      font-size: .78rem;
      line-height: 1.6;
      background: rgba(0,0,0,.4);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1rem 1.25rem;
      max-height: 320px;
      overflow-y: auto;
      color: #7ecfff;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .json-out::-webkit-scrollbar { width: 4px; }
    .json-out::-webkit-scrollbar-track { background: transparent; }
    .json-out::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

    /* ── section header ── */
    .sec-hdr {
      font-family: var(--font-hud);
      font-size: .68rem;
      letter-spacing: .2em;
      text-transform: uppercase;
      color: var(--dim);
      padding-bottom: .6rem;
      border-bottom: 1px solid var(--border);
      margin-bottom: 1rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .sec-hdr span { font-size: .64rem; }

    /* ── run-id label ── */
    .run-id-label {
      font-family: var(--font-mono);
      font-size: .72rem;
      color: var(--dim);
      margin-top: .3rem;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .run-id-label strong { color: var(--cyan); }

    /* ── empty state ── */
    .empty-state {
      text-align: center;
      padding: 2rem 1rem;
      color: var(--dim);
      font-family: var(--font-mono);
      font-size: .82rem;
    }
  </style>
</head>
<body>
<div class="grid-bg"></div>
<div class="blob blob-1"></div>
<div class="blob blob-2"></div>
<div class="blob blob-3"></div>

<div class="shell">
  <!-- HEADER -->
  <header>
    <div class="logo" data-text="CTF AUTOPWN">CTF AUTOPWN</div>
    <div class="header-meta">
      <span><span class="dot online"></span>SYSTEM ONLINE</span>
      <span id="apiHealth" style="color:var(--dim)">CHECKING API…</span>
      <span id="clockEl" style="font-size:.72rem"></span>
    </div>
  </header>

  <!-- MAIN GRID -->
  <div class="main-grid">

    <!-- LEFT: Mission config -->
    <div class="panel">
      <div class="panel-title">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
        Mission Config
      </div>

      <form id="solveForm" autocomplete="off">
        <div class="field">
          <label>Challenge Name</label>
          <input id="challengeName" type="text" value="Demo Challenge" spellcheck="false"/>
        </div>
        <div class="field">
          <label>Challenge Type</label>
          <select id="challengeType"></select>
        </div>
        <div class="field">
          <label>Target URL</label>
          <input id="challengeUrl" type="text" placeholder="http://target.local:8080" spellcheck="false"/>
        </div>
        <div class="field">
          <label>Artifact Path</label>
          <input id="filePath" type="text" placeholder="/path/to/binary" spellcheck="false"/>
        </div>
        <div class="field">
          <label>Flag Format</label>
          <input id="flagFormat" type="text" value="flag{" spellcheck="false"/>
        </div>
        <div class="field">
          <label>Metadata JSON</label>
          <textarea id="metadata" placeholder='{"description": "CTF challenge"}' spellcheck="false"></textarea>
        </div>
        <button class="btn-run" type="submit" id="submitBtn"><span>▶ EXECUTE AUTOPWN</span></button>
      </form>

      <!-- status + badge -->
      <div style="margin-top:1.25rem; display:flex; align-items:center; gap:.75rem; flex-wrap:wrap;">
        <span id="resultBadge" class="badge idle">IDLE</span>
        <div class="run-id-label" id="runIdDisplay">No active run</div>
      </div>
    </div>

    <!-- RIGHT: live dashboard -->
    <div class="right-col">

      <!-- STAT ROW -->
      <div class="stat-row">
        <div class="stat-card cyan">
          <div class="stat-label">Nodes Run</div>
          <div class="stat-value" id="statNodes">—</div>
        </div>
        <div class="stat-card magenta">
          <div class="stat-label">Errors</div>
          <div class="stat-value" id="statErrors">—</div>
        </div>
        <div class="stat-card purple">
          <div class="stat-label">Duration</div>
          <div class="stat-value" id="statDuration">—</div>
        </div>
        <div class="stat-card green">
          <div class="stat-label">Flag Status</div>
          <div class="stat-value" id="statFlag">—</div>
        </div>
      </div>

      <!-- PROGRESS -->
      <div class="panel">
        <div class="panel-title">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
          Execution Progress
        </div>
        <div class="prog-wrap">
          <div class="prog-label">
            <span id="progLabel">Awaiting run…</span>
            <span id="progPct">0%</span>
          </div>
          <div class="prog-track">
            <div class="prog-fill" id="progressFill"></div>
          </div>
        </div>
      </div>

      <!-- FLAG -->
      <div class="flag-panel" id="flagPanel">
        <div class="flag-label">⚡ Flag Captured</div>
        <div class="flag-value" id="flagValue"></div>
      </div>

      <!-- ERROR -->
      <div class="error-panel" id="errorPanel">
        <div class="error-title">⚠ Error / Diagnostic</div>
        <div class="error-body" id="errorBody"></div>
      </div>

      <!-- EXECUTION TIMELINE -->
      <div class="panel">
        <div class="sec-hdr">
          <span>Execution Timeline</span>
          <span id="stepCount">0 events</span>
        </div>
        <ul class="timeline-list" id="timelineList">
          <li class="empty-state">No events yet — submit a challenge to begin.</li>
        </ul>
      </div>

      <!-- OBSERVATIONS / JSON LOG -->
      <div class="panel">
        <div class="sec-hdr">
          <span>Solver Output &amp; Observations</span>
        </div>
        <div class="json-out" id="jsonOut">Awaiting run data…</div>
      </div>

    </div><!-- /right-col -->
  </div><!-- /main-grid -->
</div><!-- /shell -->

<script>
/* ── utilities ── */
const $ = id => document.getElementById(id);
const delay = ms => new Promise(r => setTimeout(r, ms));

function formatDuration(startISO, endISO) {
  if (!startISO) return "—";
  const ms = new Date(endISO || new Date()) - new Date(startISO);
  if (ms < 1000) return ms + "ms";
  return (ms / 1000).toFixed(1) + "s";
}

function hlJson(obj) {
  const str = JSON.stringify(obj, null, 2);
  return str
    .replace(/("([^"]+)"\s*:)/g, '<span style="color:#9d4edd">$1</span>')
    .replace(/:\s*"([^"]*)"/g, ': <span style="color:#00fff0">"$1"</span>')
    .replace(/:\s*(\d+(\.\d+)?)/g, ': <span style="color:#ffe600">$1</span>')
    .replace(/:\s*(true|false|null)/g, ': <span style="color:#ff2d78">$1</span>');
}

/* ── clock ── */
setInterval(() => {
  $("clockEl").textContent = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";
}, 1000);

/* ── health check ── */
async function checkHealth() {
  try {
    const r = await fetch("/health");
    const d = await r.json();
    $("apiHealth").textContent = d.status === "ok" ? "API ● LIVE" : "API ✕ DOWN";
    $("apiHealth").style.color = d.status === "ok" ? "var(--green)" : "var(--magenta)";
  } catch {
    $("apiHealth").textContent = "API ✕ UNREACHABLE";
    $("apiHealth").style.color = "var(--magenta)";
  }
}
checkHealth();
setInterval(checkHealth, 15000);

/* ── populate challenge types ── */
const CHALLENGE_TYPES = ["web","pwn","crypto","forensics","steganography","reverse_engineering","osint","network","misc"];
const typeSelect = $("challengeType");
CHALLENGE_TYPES.forEach(t => {
  const o = document.createElement("option");
  o.value = t;
  o.textContent = t.replaceAll("_", " ").toUpperCase();
  typeSelect.appendChild(o);
});
typeSelect.value = "web";

/* ── state ── */
let stopPolling = false;
let runStartTime = null;
let durationTimer = null;

/* ── reset UI ── */
function resetUI() {
  $("progressFill").style.width = "0%";
  $("progLabel").textContent = "Awaiting run…";
  $("progPct").textContent = "0%";
  $("timelineList").innerHTML = '<li class="empty-state">No events yet — submit a challenge to begin.</li>';
  $("jsonOut").innerHTML = "Awaiting run data…";
  $("flagPanel").classList.remove("visible");
  $("errorPanel").classList.remove("visible");
  $("flagValue").textContent = "";
  $("resultBadge").className = "badge idle";
  $("resultBadge").textContent = "IDLE";
  $("runIdDisplay").innerHTML = "No active run";
  $("statNodes").textContent = "—";
  $("statErrors").textContent = "—";
  $("statDuration").textContent = "—";
  $("statFlag").textContent = "—";
  $("stepCount").textContent = "0 events";
  clearInterval(durationTimer);
}

/* ── render timeline ── */
function renderTimeline(steps) {
  if (!steps.length) {
    $("timelineList").innerHTML = '<li class="empty-state">No events yet.</li>';
    return;
  }
  const recent = steps.slice(-40).reverse();
  $("timelineList").innerHTML = recent.map(step => {
    const dotClass = ["node_start","node_end","flag_found"].includes(step.event) ? step.event : "default";
    const sLabel = (step.status || step.event).toLowerCase();
    const ts = step.timestamp ? step.timestamp.slice(11,19) : "";
    const dataKeys = step.data_keys ? `<div class="tl-sub">data: ${step.data_keys.join(", ")}</div>` : "";
    return `<li class="tl-item">
      <div style="display:flex;align-items:flex-start;padding-top:.25rem">
        <span class="tl-dot ${dotClass}"></span>
      </div>
      <div class="tl-node">
        ${step.node_name || step.event}
        ${dataKeys}
      </div>
      <div class="tl-status ${sLabel}">${ts ? ts + " · " : ""}${sLabel.toUpperCase()}</div>
    </li>`;
  }).join("");
  $("stepCount").textContent = steps.length + " events";
}

/* ── update entire run view ── */
function updateRunUI(run) {
  const TERMINAL = ["success","completed","error"];

  /* badge */
  $("resultBadge").className = "badge " + run.status;
  $("resultBadge").textContent = run.status.toUpperCase();

  /* run id */
  $("runIdDisplay").innerHTML = `RUN <strong>${run.run_id.slice(0,8)}…</strong>`;

  /* progress */
  const endedNodes = run.steps.filter(s => s.event === "node_end").length;
  const pct = TERMINAL.includes(run.status) ? 100 : Math.min(96, endedNodes * 7);
  $("progressFill").style.width = pct + "%";
  $("progPct").textContent = pct + "%";
  $("progLabel").textContent = run.status === "running"
    ? `Running — ${endedNodes} node(s) complete`
    : run.status === "queued"
    ? "Queued, waiting for worker…"
    : run.status.charAt(0).toUpperCase() + run.status.slice(1);

  /* stats */
  $("statNodes").textContent = endedNodes;
  $("statErrors").textContent = run.error ? "1" : "0";
  $("statDuration").textContent = formatDuration(run.started_at, run.finished_at);
  $("statFlag").textContent = run.flag ? "YES" : (TERMINAL.includes(run.status) ? "NO" : "…");

  /* flag */
  if (run.flag) {
    $("flagPanel").classList.add("visible");
    $("flagValue").textContent = run.flag;
  }

  /* errors */
  if (run.error) {
    $("errorPanel").classList.add("visible");
    $("errorBody").textContent = run.error;
  } else {
    $("errorPanel").classList.remove("visible");
  }

  /* timeline */
  renderTimeline(run.steps);

  /* json output */
  const outObj = run.log || { challenge: run.challenge, status: run.status, steps_count: run.steps.length };
  $("jsonOut").innerHTML = hlJson(outObj);

  return TERMINAL.includes(run.status);
}

/* ── polling loop ── */
async function pollRun(runId) {
  stopPolling = false;
  runStartTime = Date.now();
  durationTimer = setInterval(() => {
    $("statDuration").textContent = ((Date.now() - runStartTime) / 1000).toFixed(1) + "s";
  }, 200);

  while (!stopPolling) {
    try {
      const r = await fetch(`/runs/${runId}`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const data = await r.json();
      const done = updateRunUI(data);
      if (done) {
        clearInterval(durationTimer);
        $("statDuration").textContent = formatDuration(data.started_at, data.finished_at);
        break;
      }
    } catch (err) {
      $("resultBadge").className = "badge error";
      $("resultBadge").textContent = "POLL ERROR";
      $("errorPanel").classList.add("visible");
      $("errorBody").textContent = "Polling error: " + err.message;
      clearInterval(durationTimer);
      break;
    }
    await delay(800);
  }
}

/* ── form submit ── */
$("solveForm").addEventListener("submit", async e => {
  e.preventDefault();
  stopPolling = true;
  await delay(50);
  resetUI();

  const metaRaw = $("metadata").value.trim();
  let metadata = {};
  if (metaRaw) {
    try { metadata = JSON.parse(metaRaw); }
    catch { $("errorPanel").classList.add("visible"); $("errorBody").textContent = "Metadata must be valid JSON."; return; }
  }

  const payload = {
    name: $("challengeName").value || "Untitled Challenge",
    challenge_type: typeSelect.value,
    url: $("challengeUrl").value || null,
    file_path: $("filePath").value || null,
    flag_format: $("flagFormat").value || "flag{",
    metadata,
  };

  $("submitBtn").disabled = true;
  $("resultBadge").className = "badge queued";
  $("resultBadge").textContent = "SUBMITTING…";

  try {
    const r = await fetch("/solve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!r.ok) throw new Error(await r.text() || `HTTP ${r.status}`);

    const data = await r.json();
    $("resultBadge").className = "badge queued";
    $("resultBadge").textContent = "QUEUED";
    $("runIdDisplay").innerHTML = `RUN <strong>${data.run_id.slice(0,8)}…</strong>`;
    pollRun(data.run_id);
  } catch (err) {
    $("resultBadge").className = "badge error";
    $("resultBadge").textContent = "ERROR";
    $("errorPanel").classList.add("visible");
    $("errorBody").textContent = err.message;
  } finally {
    $("submitBtn").disabled = false;
  }
});
</script>
</body>
</html>
"""


__all__ = ["app", "main"]
