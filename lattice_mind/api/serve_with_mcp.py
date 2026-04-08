"""Run the API/web UI (uvicorn). MCP is served at POST /mcp by the API itself."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from typing import List


def _build_uvicorn_cmd() -> List[str]:
    cmd = [
        "uvicorn",
        "lattice_mind.api.server:app",
        "--host",
        os.environ.get("LATTICE_MIND_HOST", "0.0.0.0"),
        "--port",
        os.environ.get("LATTICE_MIND_PORT", "8000"),
    ]
    if os.environ.get("LATTICE_MIND_RELOAD", "false").lower() == "true":
        cmd.append("--reload")
        reload_dir = os.environ.get("LATTICE_MIND_RELOAD_DIR")
        if reload_dir:
            cmd.extend(["--reload-dir", reload_dir])
        includes = os.environ.get("LATTICE_MIND_RELOAD_INCLUDE", "")
        for pattern in [item.strip() for item in includes.split(",") if item.strip()]:
            cmd.extend(["--reload-include", pattern])
    return cmd


def _terminate(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()


def main() -> None:
    if "LATTICE_MIND_API_BASE_URL" not in os.environ:
        port = os.environ.get("LATTICE_MIND_PORT", "8000")
        os.environ["LATTICE_MIND_API_BASE_URL"] = f"http://127.0.0.1:{port}"

    uvicorn_proc = subprocess.Popen(_build_uvicorn_cmd())

    should_stop = False

    def _handle_signal(signum, frame):  # type: ignore[no-untyped-def]
        nonlocal should_stop
        should_stop = True

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    exit_code = 0
    try:
        while not should_stop:
            code = uvicorn_proc.poll()
            if code is not None:
                exit_code = code
                break
            import time
            time.sleep(0.5)
    finally:
        _terminate(uvicorn_proc)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()

