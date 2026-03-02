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

def _db_save(state: RunState):
    """Upsert a RunState to SQLite."""
    d = state.to_dict()
    with _db() as conn:
        conn.execute("""
            INSERT INTO runs
                (run_id, status, challenge, steps, flag, error, log, observations,
                 started_at, finished_at, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(run_id) DO UPDATE SET
                status       = excluded.status,
                steps        = excluded.steps,
                flag         = excluded.flag,
                error        = excluded.error,
                log          = excluded.log,
                observations = excluded.observations,
                started_at   = excluded.started_at,
                finished_at  = excluded.finished_at,
                updated_at   = excluded.updated_at
        """, (
            d["run_id"], d["status"],
            json.dumps(d["challenge"]),
            json.dumps(d["steps"]),
            d["flag"], d["error"],
            json.dumps(d["log"]) if d["log"] else None,
            json.dumps(d["observations"]) if d["observations"] else None,
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
    d["challenge"]    = json.loads(d["challenge"])
    d["steps"]        = json.loads(d["steps"])
    d["log"]          = json.loads(d["log"]) if d["log"] else None
    d["observations"] = json.loads(d["observations"]) if d["observations"] else None
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
    observations: Optional[Dict[str, Any]] = None
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
        observations=row["observations"],
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
        observations = jsonable_encoder(
            solver.orchestrator.execution_context.get("observations", {})
        )
        state.update(
            flag=flag,
            log=serialized_log,
            observations=observations,
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
    :root {
      --cyan:#00fff0; --magenta:#ff2d78; --purple:#9d4edd;
      --yellow:#ffe600; --green:#39ff14; --orange:#ff9500;
      --bg:#020510; --surface:#070d1e; --card:rgba(0,255,240,.04);
      --border:rgba(0,255,240,.12); --text:#c8d6f0; --dim:#4a5878;
      --font-mono:"Share Tech Mono",monospace;
      --font-hud:"Orbitron",sans-serif;
      --font-body:"Inter",sans-serif;
    }
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body::before{content:"";position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.15) 2px,rgba(0,0,0,.15) 4px);pointer-events:none;z-index:9999}
    body{font-family:var(--font-body);background:var(--bg);color:var(--text);min-height:100vh;overflow-x:hidden}
    .grid-bg{position:fixed;inset:0;background-image:linear-gradient(rgba(0,255,240,.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,255,240,.03) 1px,transparent 1px);background-size:48px 48px;animation:grid-drift 30s linear infinite;z-index:0}
    @keyframes grid-drift{from{background-position:0 0}to{background-position:0 48px}}
    .blob{position:fixed;border-radius:50%;filter:blur(120px);opacity:.2;pointer-events:none;z-index:0}
    .blob-1{width:600px;height:600px;top:-200px;left:-100px;background:var(--purple)}
    .blob-2{width:500px;height:500px;bottom:-150px;right:-100px;background:var(--cyan)}
    .blob-3{width:400px;height:400px;top:40%;left:50%;transform:translate(-50%,-50%);background:var(--magenta)}
    .shell{position:relative;z-index:1;max-width:1440px;margin:0 auto;padding:1.5rem 2rem 4rem}

    /* header */
    header{display:flex;align-items:center;justify-content:space-between;padding:1.2rem 0 2rem;border-bottom:1px solid var(--border);margin-bottom:2rem;flex-wrap:wrap;gap:1rem}
    .logo{font-family:var(--font-hud);font-size:1.6rem;font-weight:900;letter-spacing:.12em;text-transform:uppercase;background:linear-gradient(120deg,var(--cyan),var(--magenta));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
    .header-meta{font-family:var(--font-mono);font-size:.78rem;color:var(--dim);display:flex;gap:1.5rem;align-items:center;flex-wrap:wrap}
    .dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:.4rem}
    .dot.online{background:var(--green);box-shadow:0 0 8px var(--green);animation:pulse 2s infinite}
    @keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}

    /* layout */
    .main-grid{display:grid;grid-template-columns:380px 1fr;gap:1.5rem;align-items:start}
    @media(max-width:960px){.main-grid{grid-template-columns:1fr}}

    /* panel */
    .panel{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.5rem;backdrop-filter:blur(24px);position:relative;overflow:hidden}
    .panel::before{content:"";position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--cyan),transparent)}
    .panel.accent-magenta::before{background:linear-gradient(90deg,transparent,var(--magenta),transparent)}
    .panel.accent-purple::before{background:linear-gradient(90deg,transparent,var(--purple),transparent)}
    .panel.accent-green::before{background:linear-gradient(90deg,transparent,var(--green),transparent)}
    .panel.accent-orange::before{background:linear-gradient(90deg,transparent,var(--orange),transparent)}
    .panel-title{font-family:var(--font-hud);font-size:.68rem;letter-spacing:.2em;text-transform:uppercase;color:var(--cyan);margin-bottom:1.25rem;display:flex;align-items:center;gap:.6rem}
    .panel-title.mg{color:var(--magenta)}.panel-title.pu{color:var(--purple)}.panel-title.gr{color:var(--green)}.panel-title.or{color:var(--orange)}

    /* form */
    .field{margin-bottom:1.1rem}
    .field label{display:block;font-family:var(--font-mono);font-size:.7rem;letter-spacing:.15em;text-transform:uppercase;color:var(--dim);margin-bottom:.4rem}
    .field input,.field select,.field textarea{width:100%;background:rgba(0,255,240,.03);border:1px solid rgba(0,255,240,.15);border-radius:8px;padding:.65rem .85rem;font-size:.9rem;font-family:var(--font-mono);color:var(--text);outline:none;transition:border-color .2s,background .2s,box-shadow .2s}
    .field input:focus,.field select:focus,.field textarea:focus{border-color:var(--cyan);background:rgba(0,255,240,.06);box-shadow:0 0 0 3px rgba(0,255,240,.1)}
    .field textarea{min-height:70px;resize:vertical}
    .field select option{background:#0e1526}
    .btn-run{width:100%;margin-top:.5rem;padding:.85rem 1.5rem;font-family:var(--font-hud);font-size:.82rem;font-weight:700;letter-spacing:.2em;text-transform:uppercase;color:#000;background:linear-gradient(120deg,var(--cyan) 0%,var(--purple) 100%);border:none;border-radius:8px;cursor:pointer;position:relative;overflow:hidden;transition:transform .15s,box-shadow .15s}
    .btn-run:hover{transform:translateY(-2px);box-shadow:0 0 30px rgba(0,255,240,.35)}
    .btn-run:disabled{opacity:.5;cursor:not-allowed;transform:none}

    /* right col */
    .right-col{display:flex;flex-direction:column;gap:1.25rem}

    /* stats */
    .stat-row{display:grid;grid-template-columns:repeat(4,1fr);gap:.75rem}
    @media(max-width:700px){.stat-row{grid-template-columns:repeat(2,1fr)}}
    .stat-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1rem;position:relative;overflow:hidden}
    .stat-card::before{content:"";position:absolute;top:0;left:0;right:0;height:2px}
    .stat-card.cy::before{background:linear-gradient(90deg,transparent,var(--cyan),transparent)}
    .stat-card.mg::before{background:linear-gradient(90deg,transparent,var(--magenta),transparent)}
    .stat-card.pu::before{background:linear-gradient(90deg,transparent,var(--purple),transparent)}
    .stat-card.gr::before{background:linear-gradient(90deg,transparent,var(--green),transparent)}
    .stat-label{font-family:var(--font-mono);font-size:.63rem;letter-spacing:.18em;text-transform:uppercase;color:var(--dim);margin-bottom:.4rem}
    .stat-value{font-family:var(--font-hud);font-size:1.5rem;font-weight:700;line-height:1}
    .stat-card.cy .stat-value{color:var(--cyan);text-shadow:0 0 12px var(--cyan)}
    .stat-card.mg .stat-value{color:var(--magenta);text-shadow:0 0 12px var(--magenta)}
    .stat-card.pu .stat-value{color:var(--purple);text-shadow:0 0 12px var(--purple)}
    .stat-card.gr .stat-value{color:var(--green);text-shadow:0 0 12px var(--green)}

    /* progress */
    .prog-label{font-family:var(--font-mono);font-size:.72rem;color:var(--dim);display:flex;justify-content:space-between;margin-bottom:.4rem}
    .prog-track{height:6px;background:rgba(255,255,255,.06);border-radius:999px;overflow:hidden}
    .prog-fill{height:100%;width:0%;background:linear-gradient(90deg,var(--cyan),var(--purple));border-radius:inherit;transition:width .4s ease;box-shadow:0 0 10px var(--cyan)}

    /* badge */
    .badge{display:inline-flex;align-items:center;gap:.35rem;padding:.26rem .65rem;border-radius:999px;font-family:var(--font-hud);font-size:.63rem;letter-spacing:.12em;text-transform:uppercase;font-weight:700;border:1px solid}
    .badge.idle{color:var(--dim);border-color:var(--dim);background:rgba(74,88,120,.12)}
    .badge.queued{color:var(--yellow);border-color:var(--yellow);background:rgba(255,230,0,.08)}
    .badge.running{color:var(--cyan);border-color:var(--cyan);background:rgba(0,255,240,.08);animation:blink-bd 1s ease-in-out infinite}
    .badge.success{color:var(--green);border-color:var(--green);background:rgba(57,255,20,.08)}
    .badge.completed{color:var(--purple);border-color:var(--purple);background:rgba(157,78,221,.08)}
    .badge.error{color:var(--magenta);border-color:var(--magenta);background:rgba(255,45,120,.08)}
    @keyframes blink-bd{0%,100%{opacity:1}50%{opacity:.5}}

    /* flag */
    .flag-panel{display:none;background:rgba(57,255,20,.06);border:1px solid rgba(57,255,20,.3);border-radius:10px;padding:1.2rem 1.5rem;position:relative}
    .flag-panel::before{content:"";position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--green),transparent)}
    .flag-panel.visible{display:block}
    .flag-label{font-family:var(--font-hud);font-size:.63rem;letter-spacing:.2em;text-transform:uppercase;color:var(--green);margin-bottom:.5rem}
    .flag-value{font-family:var(--font-mono);font-size:1.05rem;color:var(--green);text-shadow:0 0 16px var(--green);word-break:break-all}

    /* error */
    .error-panel{display:none;background:rgba(255,45,120,.05);border:1px solid rgba(255,45,120,.25);border-radius:10px;padding:1rem 1.25rem}
    .error-panel.visible{display:block}
    .error-title{font-family:var(--font-hud);font-size:.63rem;letter-spacing:.2em;text-transform:uppercase;color:var(--magenta);margin-bottom:.4rem}
    .error-body{font-family:var(--font-mono);font-size:.82rem;color:#ff88aa}

    /*  EXECUTION TREE  */
    .tree-wrap{max-height:520px;overflow-y:auto;padding-right:.25rem}
    .tree-wrap::-webkit-scrollbar{width:4px}
    .tree-wrap::-webkit-scrollbar-track{background:transparent}
    .tree-wrap::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}

    .tree-nodes{display:flex;flex-direction:column;gap:0;position:relative}

    .tree-node{display:grid;grid-template-columns:28px 1fr;gap:.5rem;position:relative}
    /* connector line */
    .tree-node:not(:last-child) .tc-line{position:absolute;left:13px;top:28px;bottom:-8px;width:1px;background:var(--border)}

    .tc-dot-wrap{display:flex;flex-direction:column;align-items:center;padding-top:8px}
    .tc-dot{width:14px;height:14px;border-radius:50%;flex-shrink:0;border:2px solid;transition:box-shadow .3s}
    .tc-dot.start    {background:rgba(0,255,240,.15);border-color:var(--cyan)}
    .tc-dot.success  {background:rgba(57,255,20,.2);border-color:var(--green);box-shadow:0 0 8px var(--green)}
    .tc-dot.failure  {background:rgba(255,45,120,.2);border-color:var(--magenta);box-shadow:0 0 8px var(--magenta)}
    .tc-dot.flag_found{background:rgba(255,230,0,.25);border-color:var(--yellow);box-shadow:0 0 10px var(--yellow)}
    .tc-dot.running  {background:rgba(0,255,240,.1);border-color:var(--cyan);animation:spin-glow 1.2s linear infinite}
    @keyframes spin-glow{0%{box-shadow:0 0 4px var(--cyan)}50%{box-shadow:0 0 14px var(--cyan)}100%{box-shadow:0 0 4px var(--cyan)}}

    .tc-card{background:rgba(0,0,0,.35);border:1px solid var(--border);border-radius:8px;padding:.65rem .85rem;margin-bottom:8px;cursor:pointer;transition:border-color .2s,background .2s}
    .tc-card:hover{border-color:rgba(0,255,240,.3);background:rgba(0,255,240,.04)}
    .tc-card.tc-success{border-left:2px solid var(--green)}
    .tc-card.tc-failure{border-left:2px solid var(--magenta)}
    .tc-card.tc-flag_found{border-left:2px solid var(--yellow);background:rgba(255,230,0,.04)}
    .tc-card.tc-running{border-left:2px solid var(--cyan)}

    .tc-header{display:flex;justify-content:space-between;align-items:center;gap:.5rem}
    .tc-name{font-family:var(--font-mono);font-size:.8rem;color:var(--text);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .tc-meta{font-family:var(--font-mono);font-size:.66rem;color:var(--dim);white-space:nowrap;display:flex;align-items:center;gap:.4rem}
    .tc-status-dot{width:6px;height:6px;border-radius:50%;flex-shrink:0}
    .tc-status-dot.success{background:var(--green)}.tc-status-dot.failure{background:var(--magenta)}.tc-status-dot.running{background:var(--cyan)}.tc-status-dot.flag_found{background:var(--yellow)}

    .tc-outputs{display:none;margin-top:.6rem;border-top:1px solid rgba(255,255,255,.06);padding-top:.6rem}
    .tc-outputs.open{display:block}
    .tc-kv{display:grid;grid-template-columns:auto 1fr;gap:.2rem .6rem;font-family:var(--font-mono);font-size:.72rem}
    .tc-k{color:var(--purple);white-space:nowrap}.tc-v{color:#7ecfff;word-break:break-all}
    .tc-error{font-family:var(--font-mono);font-size:.72rem;color:var(--magenta);margin-top:.35rem}

    /*  DISCOVERIES  */
    .disc-grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
    @media(max-width:700px){.disc-grid{grid-template-columns:1fr}}
    .disc-section{}
    .disc-title{font-family:var(--font-hud);font-size:.62rem;letter-spacing:.2em;text-transform:uppercase;color:var(--dim);margin-bottom:.6rem;padding-bottom:.4rem;border-bottom:1px solid var(--border)}
    .disc-list{list-style:none;display:flex;flex-direction:column;gap:.35rem;max-height:160px;overflow-y:auto}
    .disc-list::-webkit-scrollbar{width:3px}
    .disc-list::-webkit-scrollbar-thumb{background:var(--border)}
    .disc-item{font-family:var(--font-mono);font-size:.75rem;display:flex;align-items:baseline;gap:.4rem}
    .disc-item .di-bullet{font-size:.6rem;flex-shrink:0}
    .disc-item.service   .di-bullet{color:var(--cyan)}
    .disc-item.directory .di-bullet{color:var(--purple)}
    .disc-item.param     .di-bullet{color:var(--yellow)}
    .disc-item.vuln      .di-bullet{color:var(--magenta)}
    .disc-item.attack    .di-bullet{color:var(--orange)}
    .disc-item .di-label{color:var(--text);word-break:break-all}
    .disc-item .di-sub{color:var(--dim);font-size:.68rem}
    .disc-empty{font-family:var(--font-mono);font-size:.75rem;color:var(--dim);padding:.4rem 0}

    /* run-id */
    .run-id-label{font-family:var(--font-mono);font-size:.7rem;color:var(--dim);margin-top:.3rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .run-id-label strong{color:var(--cyan)}
    .empty-state{text-align:center;padding:2rem 1rem;color:var(--dim);font-family:var(--font-mono);font-size:.82rem}

    /* tabs */
    .tabs{display:flex;gap:.5rem;margin-bottom:1rem;flex-wrap:wrap}
    .tab{font-family:var(--font-hud);font-size:.62rem;letter-spacing:.15em;text-transform:uppercase;padding:.3rem .8rem;border-radius:6px;border:1px solid var(--border);background:transparent;color:var(--dim);cursor:pointer;transition:all .15s}
    .tab:hover{border-color:var(--cyan);color:var(--cyan)}
    .tab.active{border-color:var(--cyan);color:var(--cyan);background:rgba(0,255,240,.08)}
  </style>
</head>
<body>
<div class="grid-bg"></div>
<div class="blob blob-1"></div><div class="blob blob-2"></div><div class="blob blob-3"></div>

<div class="shell">
  <header>
    <div class="logo">CTF AUTOPWN</div>
    <div class="header-meta">
      <span><span class="dot online"></span>SYSTEM ONLINE</span>
      <span id="apiHealth" style="color:var(--dim)">CHECKING API</span>
      <span id="clockEl"></span>
    </div>
  </header>

  <div class="main-grid">
    <!-- LEFT: mission config -->
    <div class="panel">
      <div class="panel-title">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
        Mission Config
      </div>
      <form id="solveForm" autocomplete="off">
        <div class="field"><label>Challenge Name</label><input id="challengeName" type="text" value="Demo Challenge" spellcheck="false"/></div>
        <div class="field"><label>Challenge Type</label><select id="challengeType"></select></div>
        <div class="field"><label>Target URL</label><input id="challengeUrl" type="text" placeholder="http://target.local:8080" spellcheck="false"/></div>
        <div class="field"><label>Artifact Path</label><input id="filePath" type="text" placeholder="/path/to/binary" spellcheck="false"/></div>
        <div class="field"><label>Flag Format</label><input id="flagFormat" type="text" value="flag{" spellcheck="false"/></div>
        <div class="field"><label>Metadata JSON</label><textarea id="metadata" placeholder='{"description":"CTF challenge"}' spellcheck="false"></textarea></div>
        <button class="btn-run" type="submit" id="submitBtn"> EXECUTE AUTOPWN</button>
      </form>
      <div style="margin-top:1.25rem;display:flex;align-items:center;gap:.75rem;flex-wrap:wrap">
        <span id="resultBadge" class="badge idle">IDLE</span>
        <div class="run-id-label" id="runIdDisplay">No active run</div>
      </div>
    </div>

    <!-- RIGHT: live dashboard -->
    <div class="right-col">

      <!-- stats -->
      <div class="stat-row">
        <div class="stat-card cy"><div class="stat-label">Nodes Run</div><div class="stat-value" id="statNodes"></div></div>
        <div class="stat-card mg"><div class="stat-label">Errors</div><div class="stat-value" id="statErrors"></div></div>
        <div class="stat-card pu"><div class="stat-label">Duration</div><div class="stat-value" id="statDuration"></div></div>
        <div class="stat-card gr"><div class="stat-label">Flag</div><div class="stat-value" id="statFlag"></div></div>
      </div>

      <!-- progress -->
      <div class="panel">
        <div class="panel-title"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>Execution Progress</div>
        <div class="prog-label"><span id="progLabel">Awaiting run</span><span id="progPct">0%</span></div>
        <div class="prog-track"><div class="prog-fill" id="progressFill"></div></div>
      </div>

      <!-- flag -->
      <div class="flag-panel" id="flagPanel">
        <div class="flag-label"> Flag Captured</div>
        <div class="flag-value" id="flagValue"></div>
      </div>

      <!-- error -->
      <div class="error-panel" id="errorPanel">
        <div class="error-title"> Error / Diagnostic</div>
        <div class="error-body" id="errorBody"></div>
      </div>

      <!-- EXECUTION TREE + DISCOVERIES (tabbed) -->
      <div class="panel accent-purple">
        <div class="tabs">
          <button class="tab active" onclick="showTab('tree',this)">Execution Tree</button>
          <button class="tab" onclick="showTab('discoveries',this)">Discoveries</button>
          <button class="tab" onclick="showTab('attacks',this)">Attacks Tried</button>
          <button class="tab" onclick="showTab('raw',this)">Raw Output</button>
        </div>

        <!-- tab: tree -->
        <div id="tab-tree">
          <div class="panel-title pu">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><line x1="12" y1="2" x2="12" y2="9"/><line x1="12" y1="15" x2="12" y2="22"/><line x1="2" y1="12" x2="9" y2="12"/><line x1="15" y1="12" x2="22" y2="12"/></svg>
            Decision Tree Execution
            <span style="margin-left:auto;font-size:.62rem;color:var(--dim)" id="treeNodeCount">0 nodes</span>
          </div>
          <div class="tree-wrap">
            <div class="tree-nodes" id="treeNodes">
              <div class="empty-state">No execution yet  submit a challenge to see the tree.</div>
            </div>
          </div>
        </div>

        <!-- tab: discoveries -->
        <div id="tab-discoveries" style="display:none">
          <div class="panel-title or">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            Discovered Assets &amp; Services
          </div>
          <div class="disc-grid" id="discGrid">
            <div class="empty-state" style="grid-column:1/-1">No discoveries yet.</div>
          </div>
        </div>

        <!-- tab: attacks -->
        <div id="tab-attacks" style="display:none">
          <div class="panel-title mg">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            Attacks Attempted
          </div>
          <ul class="disc-list" id="attacksList">
            <li class="disc-empty">No attacks recorded yet.</li>
          </ul>
        </div>

        <!-- tab: raw -->
        <div id="tab-raw" style="display:none">
          <div class="panel-title" style="color:var(--dim)">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
            Raw Solver Output
          </div>
          <div class="json-out" id="jsonOut" style="font-family:var(--font-mono);font-size:.76rem;line-height:1.6;background:rgba(0,0,0,.4);border:1px solid var(--border);border-radius:8px;padding:1rem;max-height:400px;overflow-y:auto;color:#7ecfff;white-space:pre-wrap;word-break:break-all">Awaiting run data</div>
        </div>
      </div><!-- /tabbed panel -->

    </div><!-- /right-col -->
  </div><!-- /main-grid -->
</div><!-- /shell -->

<script>
const $ = id => document.getElementById(id);
const delay = ms => new Promise(r => setTimeout(r, ms));

/*  clock  */
setInterval(() => {
  $("clockEl").textContent = new Date().toISOString().replace("T"," ").slice(0,19)+" UTC";
}, 1000);

/*  health  */
async function checkHealth() {
  try {
    const r = await fetch("/health");
    const d = await r.json();
    $("apiHealth").textContent = d.status==="ok" ? "API  LIVE" : "API  DOWN";
    $("apiHealth").style.color = d.status==="ok" ? "var(--green)" : "var(--magenta)";
  } catch { $("apiHealth").textContent="API  UNREACHABLE"; $("apiHealth").style.color="var(--magenta)"; }
}
checkHealth(); setInterval(checkHealth, 15000);

/*  challenge types  */
const TYPES = ["web","pwn","crypto","forensics","steganography","reverse_engineering","osint","network","misc"];
TYPES.forEach(t => {
  const o = document.createElement("option");
  o.value = t; o.textContent = t.replaceAll("_"," ").toUpperCase();
  $("challengeType").appendChild(o);
});
$("challengeType").value = "web";

/*  tabs  */
function showTab(name, btn) {
  ["tree","discoveries","attacks","raw"].forEach(t => {
    $("tab-"+t).style.display = t===name ? "" : "none";
  });
  document.querySelectorAll(".tab").forEach(b => b.classList.remove("active"));
  btn.classList.add("active");
}

/*  node category helpers  */
const NODE_ICONS = {
  asset: "", web: "�", pwn: "", crypto: "",
  forensics: "", steg: "", recon: "", exploit: "",
  default: ""
};
function nodeIcon(id) {
  const pfx = (id||"").split("_")[0].toLowerCase();
  return NODE_ICONS[pfx] || NODE_ICONS.default;
}
function nodeCategory(id) {
  const pfx = (id||"").split("_")[0].toLowerCase();
  const map = { asset:"asset", web:"web", pwn:"pwn", crypto:"crypto",
                forensics:"forensics", sqli:"web", lfi:"web", xss:"web",
                buffer:"pwn", format:"pwn", rop:"pwn", rsa:"crypto",
                steg:"forensics" };
  return map[pfx] || "default";
}

/*  format duration  */
function fmtDur(start, end) {
  if (!start) return "";
  const ms = new Date(end||new Date()) - new Date(start);
  return ms < 1000 ? ms+"ms" : (ms/1000).toFixed(1)+"s";
}

/*  highlight JSON  */
function hlJson(obj) {
  const s = JSON.stringify(obj, null, 2);
  return s
    .replace(/("([^"]+)"\s*:)/g,'<span style="color:#9d4edd">$1</span>')
    .replace(/:\s*"([^"]*)"/g,': <span style="color:#00fff0">"$1"</span>')
    .replace(/:\s*(\d+(\.\d+)?)/g,': <span style="color:#ffe600">$1</span>')
    .replace(/:\s*(true|false|null)/g,': <span style="color:#ff2d78">$1</span>');
}

/*  state  */
let stopPolling = false, durationTimer = null, runStartTime = null;
// node map: node_id  { start_event, end_event, el }
let nodeMap = {};

/*  reset UI  */
function resetUI() {
  $("progressFill").style.width="0%";
  $("progLabel").textContent="Awaiting run"; $("progPct").textContent="0%";
  $("treeNodes").innerHTML='<div class="empty-state">No execution yet.</div>';
  $("treeNodeCount").textContent="0 nodes";
  $("jsonOut").innerHTML="Awaiting run data";
  $("flagPanel").classList.remove("visible");
  $("errorPanel").classList.remove("visible");
  $("flagValue").textContent="";
  $("resultBadge").className="badge idle"; $("resultBadge").textContent="IDLE";
  $("runIdDisplay").innerHTML="No active run";
  $("statNodes").textContent=""; $("statErrors").textContent="";
  $("statDuration").textContent="—"; $("statFlag").textContent="";
  $("discGrid").innerHTML='<div class="empty-state" style="grid-column:1/-1">No discoveries yet.</div>';
  $("attacksList").innerHTML='<li class="disc-empty">No attacks recorded yet.</li>';
  clearInterval(durationTimer);
  nodeMap = {};
}

/*  build / update a tree node card  */
function upsertTreeNode(step) {
  const key = step.node_id;
  const isStart = step.event === "node_start";
  const isEnd   = step.event === "node_end";
  const isFlag  = step.event === "flag_found";

  if (isStart && !nodeMap[key]) {
    // create card
    const wrapper = document.createElement("div");
    wrapper.className = "tree-node";
    wrapper.dataset.nodeId = key;

    const dotWrap = document.createElement("div");
    dotWrap.className = "tc-dot-wrap";
    const dot = document.createElement("div");
    dot.className = "tc-dot running";
    const line = document.createElement("div");
    line.className = "tc-line";
    dotWrap.appendChild(dot); dotWrap.appendChild(line);

    const card = document.createElement("div");
    card.className = "tc-card tc-running";

    const hdr = document.createElement("div");
    hdr.className = "tc-header";
    const nm = document.createElement("div");
    nm.className = "tc-name";
    nm.textContent = nodeIcon(key)+" "+step.node_name;
    const meta = document.createElement("div");
    meta.className = "tc-meta";
    const sdot = document.createElement("div");
    sdot.className = "tc-status-dot running";
    const ts = document.createElement("span");
    ts.textContent = (step.timestamp||"").slice(11,19);
    meta.appendChild(sdot); meta.appendChild(ts);
    hdr.appendChild(nm); hdr.appendChild(meta);

    const outputs = document.createElement("div");
    outputs.className = "tc-outputs";

    card.appendChild(hdr); card.appendChild(outputs);

    // toggle outputs on click
    card.addEventListener("click", () => outputs.classList.toggle("open"));

    wrapper.appendChild(dotWrap); wrapper.appendChild(card);

    // remove empty state
    const empty = $("treeNodes").querySelector(".empty-state");
    if (empty) empty.remove();

    $("treeNodes").appendChild(wrapper);
    nodeMap[key] = { dot, card, outputs, sdot, wrapper };

    // scroll to bottom
    const wrap = $("treeNodes").parentElement;
    wrap.scrollTop = wrap.scrollHeight;
  }

  if ((isEnd || isFlag) && nodeMap[key]) {
    const { dot, card, outputs, sdot } = nodeMap[key];
    const st = isFlag ? "flag_found" : (step.status||"success");

    dot.className = "tc-dot "+st;
    sdot.className = "tc-status-dot "+st;
    card.className = "tc-card tc-"+st;

    // render outputs
    if (step.data && Object.keys(step.data).length) {
      const kv = document.createElement("div");
      kv.className = "tc-kv";
      for (const [k, v] of Object.entries(step.data)) {
        if (k === "asset_type" || k === "ready_for_detection") continue;
        const kEl = document.createElement("div"); kEl.className="tc-k"; kEl.textContent=k+":";
        const vEl = document.createElement("div"); vEl.className="tc-v";
        vEl.textContent = typeof v === "object" ? JSON.stringify(v).slice(0,200) : String(v).slice(0,200);
        kv.appendChild(kEl); kv.appendChild(vEl);
      }
      outputs.appendChild(kv);
      // auto-open on flag
      if (isFlag) outputs.classList.add("open");
    }
    if (step.error) {
      const err = document.createElement("div");
      err.className = "tc-error"; err.textContent = " "+step.error;
      outputs.appendChild(err); outputs.classList.add("open");
    }
  }
}

/*  render discoveries from observations  */
function renderDiscoveries(obs) {
  if (!obs) return;
  const sections = [];

  // Services / asset type
  if (obs.asset_type) {
    sections.push({ title:"Asset Classification", cls:"service", icon:"",
      items:[{ label: obs.asset_type, sub:"" }] });
  }

  // HTTP recon
  if (obs.http_responses) {
    const items = Object.entries(obs.http_responses).slice(0,20).map(([u,v]) =>
      ({ label: u, sub: v.status_code ? "HTTP "+v.status_code : "" }));
    if (items.length) sections.push({ title:"HTTP Probes", cls:"service", icon:"", items });
  }

  // Directories
  const dirs = obs.directories || [];
  if (dirs.length) {
    sections.push({ title:"Directories Found ("+dirs.length+")", cls:"directory", icon:"",
      items: dirs.slice(0,30).map(d => ({ label: d.path||d, sub: d.status?"HTTP "+d.status:"" })) });
  }

  // Parameters
  const params = obs.potential_params || [];
  if (params.length) {
    sections.push({ title:"Potential Parameters", cls:"param", icon:"",
      items: params.slice(0,20).map(p => ({ label: typeof p==="object"?p.name||JSON.stringify(p):p, sub:"" })) });
  }

  // Vuln candidates
  const vc = obs.vuln_candidates || obs.vulnerability_candidates || {};
  const vcItems = [];
  for (const [type, locs] of Object.entries(vc)) {
    if (Array.isArray(locs) && locs.length) vcItems.push({ label: type.toUpperCase(), sub: locs.length+" location(s)" });
    else if (locs) vcItems.push({ label: type.toUpperCase(), sub:"detected" });
  }
  if (vcItems.length) sections.push({ title:"Vulnerability Candidates", cls:"vuln", icon:"", items:vcItems });

  if (!sections.length) {
    $("discGrid").innerHTML = '<div class="empty-state" style="grid-column:1/-1">No discoveries recorded.</div>';
    return;
  }

  $("discGrid").innerHTML = sections.map(sec => `
    <div class="disc-section">
      <div class="disc-title">${sec.title}</div>
      <ul class="disc-list">
        ${sec.items.map(it => `
          <li class="disc-item ${sec.cls}">
            <span class="di-bullet">${sec.icon}</span>
            <span>
              <span class="di-label">${it.label}</span>
              ${it.sub ? `<span class="di-sub">  ${it.sub}</span>` : ""}
            </span>
          </li>`).join("")}
      </ul>
    </div>
  `).join("");
}

/*  render attacks from steps  */
function renderAttacks(steps) {
  const attackPrefixes = ["sqli","lfi","xss","buffer","format","rop","rsa","heap","auth","exploit","inject"];
  const attacks = steps.filter(s =>
    s.event === "node_end" &&
    attackPrefixes.some(p => (s.node_id||"").toLowerCase().includes(p))
  );
  if (!attacks.length) {
    $("attacksList").innerHTML = '<li class="disc-empty">No exploit nodes executed yet.</li>';
    return;
  }
  $("attacksList").innerHTML = attacks.map(a => {
    const st = a.status || "unknown";
    const color = st==="success" ? "var(--green)" : st==="failure" ? "var(--magenta)" : "var(--dim)";
    const outputs = a.data ? Object.entries(a.data).slice(0,3).map(([k,v])=>`${k}: ${String(v).slice(0,80)}`).join("  ") : "";
    return `<li class="disc-item attack">
      <span class="di-bullet" style="color:${color}"></span>
      <span>
        <span class="di-label">${a.node_name||a.node_id}</span>
        <span class="di-sub">  ${st.toUpperCase()}${outputs?"  "+outputs:""}</span>
      </span>
    </li>`;
  }).join("");
}

/*  update full run UI  */
function updateRunUI(run) {
  const TERMINAL = ["success","completed","error"];

  $("resultBadge").className="badge "+run.status;
  $("resultBadge").textContent=run.status.toUpperCase();
  $("runIdDisplay").innerHTML=`RUN <strong>${run.run_id.slice(0,8)}</strong>`;

  const endedNodes = run.steps.filter(s=>s.event==="node_end").length;
  const pct = TERMINAL.includes(run.status) ? 100 : Math.min(96, endedNodes*7);
  $("progressFill").style.width=pct+"%"; $("progPct").textContent=pct+"%";
  $("progLabel").textContent = run.status==="running"
    ? `Running  ${endedNodes} node(s) complete`
    : run.status==="queued" ? "Queued, waiting for worker"
    : run.status.charAt(0).toUpperCase()+run.status.slice(1);

  $("statNodes").textContent=endedNodes;
  $("statErrors").textContent=run.error?"1":"0";
  $("statDuration").textContent=fmtDur(run.started_at, run.finished_at);
  $("statFlag").textContent=run.flag?"YES":(TERMINAL.includes(run.status)?"NO":"");
  $("treeNodeCount").textContent=endedNodes+" nodes";

  // flag
  if (run.flag) { $("flagPanel").classList.add("visible"); $("flagValue").textContent=run.flag; }
  // error
  if (run.error) { $("errorPanel").classList.add("visible"); $("errorBody").textContent=run.error; }
  else $("errorPanel").classList.remove("visible");

  // update tree for new steps
  run.steps.forEach(s => {
    if (["node_start","node_end","flag_found"].includes(s.event)) upsertTreeNode(s);
  });

  // discoveries + attacks on terminal
  if (TERMINAL.includes(run.status)) {
    renderDiscoveries(run.observations);
    renderAttacks(run.steps);
  }

  // raw output
  const outObj = run.log || { status:run.status, steps:run.steps.length };
  $("jsonOut").innerHTML = hlJson(outObj);

  return TERMINAL.includes(run.status);
}

/*  polling  */
async function pollRun(runId) {
  stopPolling = false;
  runStartTime = Date.now();
  durationTimer = setInterval(() => {
    $("statDuration").textContent = ((Date.now()-runStartTime)/1000).toFixed(1)+"s";
  }, 200);

  while (!stopPolling) {
    try {
      const r = await fetch(`/runs/${runId}`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const data = await r.json();
      const done = updateRunUI(data);
      if (done) {
        clearInterval(durationTimer);
        $("statDuration").textContent=fmtDur(data.started_at,data.finished_at);
        break;
      }
    } catch(err) {
      $("resultBadge").className="badge error"; $("resultBadge").textContent="POLL ERROR";
      $("errorPanel").classList.add("visible"); $("errorBody").textContent="Polling error: "+err.message;
      clearInterval(durationTimer); break;
    }
    await delay(800);
  }
}

/*  form submit  */
$("solveForm").addEventListener("submit", async e => {
  e.preventDefault();
  stopPolling = true;
  await delay(50);
  resetUI();

  let metadata = {};
  const metaRaw = $("metadata").value.trim();
  if (metaRaw) {
    try { metadata = JSON.parse(metaRaw); }
    catch { $("errorPanel").classList.add("visible"); $("errorBody").textContent="Metadata must be valid JSON."; return; }
  }

  const payload = {
    name: $("challengeName").value||"Untitled",
    challenge_type: $("challengeType").value,
    url: $("challengeUrl").value||null,
    file_path: $("filePath").value||null,
    flag_format: $("flagFormat").value||"flag{",
    metadata,
  };

  $("submitBtn").disabled=true;
  $("resultBadge").className="badge queued"; $("resultBadge").textContent="SUBMITTING";

  try {
    const r = await fetch("/solve", {
      method:"POST", headers:{"Content-Type":"application/json"},
      body:JSON.stringify(payload),
    });
    if (!r.ok) throw new Error(await r.text()||"HTTP "+r.status);
    const data = await r.json();
    $("resultBadge").className="badge queued"; $("resultBadge").textContent="QUEUED";
    $("runIdDisplay").innerHTML=`RUN <strong>${data.run_id.slice(0,8)}</strong>`;
    pollRun(data.run_id);
  } catch(err) {
    $("resultBadge").className="badge error"; $("resultBadge").textContent="ERROR";
    $("errorPanel").classList.add("visible"); $("errorBody").textContent=err.message;
  } finally {
    $("submitBtn").disabled=false;
  }
});
</script>
</body>
</html>
"""

__all__ = ["app", "main"]
