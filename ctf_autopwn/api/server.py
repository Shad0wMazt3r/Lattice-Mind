"""FastAPI server exposing the CTF Autopwn solver along with a simple UI."""
from __future__ import annotations

import asyncio
import logging
import threading
import uuid
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

app = FastAPI(
    title="CTF Autopwn API",
    description="REST API + web UI for the autonomous CTF solver",
    version="0.1.0",
)

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

    def update(self, **kwargs):
        with self._lock:
            for key, value in kwargs.items():
                setattr(self, key, value)
            self.updated_at = _now()


_runs: Dict[str, RunState] = {}
_runs_lock = threading.Lock()
_tasks: Dict[str, asyncio.Task] = {}

def _register_run(state: RunState):
    with _runs_lock:
        _runs[state.run_id] = state


def get_run_state(run_id: str) -> Optional[RunState]:
    with _runs_lock:
        return _runs.get(run_id)


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
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>CTF Autopwn Dashboard</title>
  <style>
    :root {
      font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: #f5f5f5;
      background-color: #0b0d17;
    }
    body {
      margin: 0;
      min-height: 100vh;
      background: radial-gradient(circle at top, #1c2238, #05060d 60%);
      padding: 2rem;
      display: flex;
      justify-content: center;
    }
    .app {
      width: min(1080px, 100%);
      background: rgba(12, 16, 32, 0.92);
      border: 1px solid rgba(255, 255, 255, 0.05);
      border-radius: 20px;
      padding: 2.5rem;
      box-shadow: 0 25px 60px rgba(0, 0, 0, 0.55);
      backdrop-filter: blur(24px);
    }
    h1 {
      font-size: 2rem;
      margin-bottom: 0.35rem;
    }
    p {
      color: #98a0c2;
      margin-top: 0;
      margin-bottom: 2rem;
    }
    form {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 1.25rem;
      margin-bottom: 1.5rem;
    }
    label {
      font-size: 0.9rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: #8ba1c7;
      margin-bottom: 0.4rem;
      display: block;
    }
    input, select, textarea {
      width: 100%;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 12px;
      padding: 0.85rem 1rem;
      font-size: 1rem;
      color: #f5f5f5;
      transition: border 0.2s ease, background 0.2s ease;
    }
    input:focus, select:focus, textarea:focus {
      outline: none;
      border-color: #4db5ff;
      background: rgba(77, 181, 255, 0.08);
    }
    textarea {
      min-height: 120px;
      resize: vertical;
    }
    button {
      grid-column: 1 / -1;
      background: linear-gradient(120deg, #4db5ff, #845ef7);
      border: none;
      border-radius: 16px;
      padding: 1rem 1.5rem;
      font-size: 1rem;
      font-weight: 600;
      color: white;
      cursor: pointer;
      transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    button:hover {
      transform: translateY(-2px);
      box-shadow: 0 15px 30px rgba(77, 181, 255, 0.25);
    }
    .status-grid {
      display: grid;
      gap: 1rem;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      margin-bottom: 1.5rem;
    }
    .status-card {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid rgba(255, 255, 255, 0.05);
      border-radius: 16px;
      padding: 1.25rem;
    }
    .status-card h3 {
      margin-top: 0;
      margin-bottom: 0.5rem;
      font-size: 1rem;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      color: #8ba1c7;
    }
    .progress-bar {
      position: relative;
      height: 12px;
      background: rgba(255, 255, 255, 0.08);
      border-radius: 999px;
      overflow: hidden;
      margin-bottom: 0.5rem;
    }
    .progress-fill {
      position: absolute;
      top: 0;
      left: 0;
      bottom: 0;
      width: 0%;
      background: linear-gradient(120deg, #4db5ff, #845ef7);
      border-radius: inherit;
      transition: width 0.3s ease;
    }
    .timeline {
      margin: 0;
      padding: 0;
      list-style: none;
      max-height: 220px;
      overflow-y: auto;
    }
    .timeline li {
      padding: 0.6rem 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      display: flex;
      flex-direction: column;
      gap: 0.2rem;
    }
    .timeline li:last-child {
      border-bottom: none;
    }
    .timeline .meta {
      font-size: 0.8rem;
      color: #7f8cb2;
      display: flex;
      justify-content: space-between;
      gap: 1rem;
    }
    pre {
      background: rgba(5, 6, 13, 0.8);
      border-radius: 16px;
      padding: 1.25rem;
      overflow-x: auto;
      border: 1px solid rgba(255, 255, 255, 0.05);
      font-size: 0.95rem;
      line-height: 1.5;
    }
    .badge {
      padding: 0.35rem 0.65rem;
      border-radius: 999px;
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      display: inline-block;
    }
    .badge.success {
      background: rgba(77, 255, 182, 0.15);
      color: #4dffb6;
    }
    .badge.pending {
      background: rgba(255, 195, 77, 0.15);
      color: #ffc34d;
    }
    .badge.error {
      background: rgba(255, 99, 132, 0.15);
      color: #ff6384;
    }
    .flag {
      font-weight: 600;
      color: #4dffb6;
      word-break: break-all;
    }
    .section-title {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-top: 2rem;
      margin-bottom: 0.5rem;
    }
    .hidden {
      display: none;
    }
  </style>
</head>
<body>
  <div class="app">
    <h1>CTF Autopwn</h1>
    <p>Submit challenge metadata and monitor solver progress in realtime.</p>
    <form id="solveForm">
      <div>
        <label for="challengeName">Challenge Name</label>
        <input id="challengeName" type="text" value="Demo Challenge" />
      </div>
      <div>
        <label for="challengeType">Challenge Type</label>
        <select id="challengeType"></select>
      </div>
      <div>
        <label for="challengeUrl">Target URL</label>
        <input id="challengeUrl" type="text" placeholder="http://target.local" />
      </div>
      <div>
        <label for="filePath">Artifact Path</label>
        <input id="filePath" type="text" placeholder="/path/to/binary" />
      </div>
      <div>
        <label for="flagFormat">Flag Format</label>
        <input id="flagFormat" type="text" value="flag{" />
      </div>
      <div style="grid-column: 1 / -1;">
        <label for="metadata">Metadata JSON</label>
        <textarea id="metadata" placeholder='{"description": "Example metadata"}'></textarea>
      </div>
      <button type="submit">Run Autopwn</button>
    </form>

    <div class="status-grid">
      <div class="status-card">
        <h3>Run Status</h3>
        <div id="status" style="min-height:1.25rem;color:#94a9ff;">Waiting for submission...</div>
        <div style="margin-top:0.5rem;">
          <span id="resultBadge" class="badge pending">Pending</span>
        </div>
      </div>
      <div class="status-card">
        <h3>Progress</h3>
        <div class="progress-bar">
          <div id="progressFill" class="progress-fill"></div>
        </div>
        <div id="progressSummary" style="font-size:0.9rem;color:#98a0c2;">No steps yet.</div>
      </div>
    </div>

    <div class="section-title">
      <h3>Execution Timeline</h3>
      <span style="font-size:0.85rem;color:#7f8cb2;">Last 20 events</span>
    </div>
    <ul id="progressList" class="timeline">
      <li>No activity yet.</li>
    </ul>

    <div class="section-title">
      <h3>Errors & Diagnostics</h3>
    </div>
    <div id="errorPanel" class="status-card hidden" style="background:rgba(255,99,132,0.08); border-color:rgba(255,99,132,0.2);">
      <strong style="color:#ff788f;">No errors reported.</strong>
    </div>

    <div class="section-title">
      <h3>Latest Output</h3>
    </div>
    <div id="flagDisplay" class="flag"></div>
    <pre id="resultOutput">Submit a challenge to view execution details.</pre>
  </div>
  <script>
    const challengeTypes = ["web","pwn","crypto","forensics","steganography","reverse_engineering","osint","network","misc"];
    const typeSelect = document.getElementById("challengeType");
    const statusEl = document.getElementById("status");
    const resultOutput = document.getElementById("resultOutput");
    const flagDisplay = document.getElementById("flagDisplay");
    const resultBadge = document.getElementById("resultBadge");
    const progressFill = document.getElementById("progressFill");
    const progressSummary = document.getElementById("progressSummary");
    const progressList = document.getElementById("progressList");
    const errorPanel = document.getElementById("errorPanel");

    let activeRunId = null;
    let stopPolling = false;

    const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

    challengeTypes.forEach((type) => {
      const option = document.createElement("option");
      option.value = type;
      option.textContent = type.replaceAll("_", " ").toUpperCase();
      typeSelect.appendChild(option);
    });
    typeSelect.value = "web";

    function resetUI() {
      progressFill.style.width = "0%";
      progressSummary.textContent = "No steps yet.";
      progressList.innerHTML = "<li>No activity yet.</li>";
      flagDisplay.textContent = "";
      resultOutput.textContent = "Awaiting run data...";
      errorPanel.classList.add("hidden");
      resultBadge.textContent = "Pending";
      resultBadge.className = "badge pending";
    }

    function renderTimeline(steps) {
      if (!steps.length) {
        progressList.innerHTML = "<li>No activity yet.</li>";
        return;
      }
      const recent = steps.slice(-20).reverse();
      progressList.innerHTML = recent.map((step) => {
        const statusLabel = step.status ? step.status.toUpperCase() : step.event.toUpperCase();
        return `
          <li>
            <div>${step.node_name || step.event}</div>
            <div class="meta">
              <span>${statusLabel}</span>
              <span>${step.timestamp || ""}</span>
            </div>
          </li>
        `;
      }).join("");
    }

    function updateRunUI(run) {
      const terminalStatuses = ["success", "completed", "error"];
      statusEl.textContent = `Run ${run.run_id} — ${run.status}`;
      resultBadge.textContent = run.status.toUpperCase();
      resultBadge.className = `badge ${run.status === "success" ? "success" : run.status === "error" ? "error" : "pending"}`;

      const completedSteps = run.steps.filter((step) => step.event === "node_end").length;
      const percent = Math.min(100, completedSteps * 8);
      progressFill.style.width = `${percent}%`;
      progressSummary.textContent = `${completedSteps} node(s) completed`;

      renderTimeline(run.steps);

      if (run.flag) {
        flagDisplay.textContent = run.flag;
      }

      if (run.log) {
        resultOutput.textContent = JSON.stringify(run.log, null, 2);
      }

      if (run.error) {
        errorPanel.classList.remove("hidden");
        errorPanel.innerHTML = `<strong style="color:#ff788f;">${run.error}</strong>`;
      } else if (run.status === "error") {
        errorPanel.classList.remove("hidden");
        errorPanel.innerHTML = "<strong style='color:#ff788f;'>Unknown error occurred.</strong>";
      } else {
        errorPanel.classList.add("hidden");
      }

      return terminalStatuses.includes(run.status);
    }

    async function pollRun(runId) {
      activeRunId = runId;
      stopPolling = false;

      while (!stopPolling) {
        try {
          const response = await fetch(`/runs/${runId}`);
          if (!response.ok) {
            throw new Error("Unable to fetch run status");
          }
          const data = await response.json();
          const done = updateRunUI(data);
          if (done) {
            break;
          }
        } catch (error) {
          statusEl.textContent = `Error fetching status: ${error.message}`;
          resultBadge.textContent = "Error";
          resultBadge.className = "badge error";
          break;
        }
        await delay(1200);
      }
    }

    const form = document.getElementById("solveForm");
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      stopPolling = true;
      resetUI();
      statusEl.textContent = "Submitting run...";

      let metadata = {};
      const metadataInput = document.getElementById("metadata").value.trim();
      if (metadataInput) {
        try {
          metadata = JSON.parse(metadataInput);
        } catch (error) {
          statusEl.textContent = "Metadata must be valid JSON.";
          return;
        }
      }

      const payload = {
        name: document.getElementById("challengeName").value || "Untitled Challenge",
        challenge_type: typeSelect.value,
        url: document.getElementById("challengeUrl").value || null,
        file_path: document.getElementById("filePath").value || null,
        flag_format: document.getElementById("flagFormat").value || "flag{",
        metadata
      };

      try {
        const response = await fetch("/solve", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });

        if (!response.ok) {
          const errorBody = await response.text();
          throw new Error(errorBody || "Request failed");
        }

        const data = await response.json();
        statusEl.textContent = `Run ${data.run_id} queued...`;
        resultBadge.textContent = "QUEUED";
        resultBadge.className = "badge pending";
        pollRun(data.run_id);
      } catch (error) {
        statusEl.textContent = `Error: ${error.message}`;
        resultBadge.textContent = "Error";
        resultBadge.className = "badge error";
        resultOutput.textContent = error.stack || error.message;
      }
    });
  </script>
</body>
</html>
"""


__all__ = ["app", "main"]
