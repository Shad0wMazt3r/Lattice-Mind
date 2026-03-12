# Usage Guide

Lattice Mind can be interacted with through multiple interfaces: CLI, REST API, Web Dashboard, and MCP.

## 1. Web Dashboard (Recommended)

The most intuitive way to track automation progress.

1.  Navigate to `http://localhost:8000`.
2.  Click **"New Scan"**.
3.  Enter the challenge details (URL, Type, Flag Format).
4.  Monitor the **Tree View** to see paths being explored in real-time.

---

## 2. API Interaction

The API is built with FastAPI and is the primary way to integrate Lattice Mind into other tools.

### Submit a Challenge
**Endpoint:** `POST /solve`

**Example Request (curl):**
```bash
curl -X POST http://localhost:8000/solve \
     -H "Content-Type: application/json" \
     -d '{
           "name": "Target Application",
           "challenge_type": "web",
           "url": "http://target.ctf.local:1337",
           "flag_format": "flag{.*?}"
         }'
```

---

## 3. Command Line Interface (CLI)

Use the built-in CLI for quick tasks and setup verification.

```powershell
# Get help
Lattice-Mind --help

# Check engine health
Lattice-Mind health

# List available decision trees
Lattice-Mind trees --list
```

---

## 4. MCP Server (AI Orchestration)

Lattice Mind acts as an MCP server, allowing it to be used by AI agents like Antigravity.

**Start the MCP Server:**
```powershell
Lattice-Mind-mcp
```

**Available Tools:**
*   `submit_scan`: Queue a new vulnerability scan.
*   `get_run_status`: Retrieve detailed logs and current progress of a run.
*   `list_runs`: Get a history of all recent automated tasks.
*   `get_rule`: Inspect the logic of a specific decision tree.

---

## Technical Notes

### Assumptions
*   **Network Isolation**: The engine assumes that the target is reachable from the host/container.
*   **Tool Availability**: For local installations, tools like `nmap` and `ffuf` must be in the system `PATH`.
*   **Flag Format**: Providing a `flag_format` (e.g., `CTF{.*}`) significantly increases confidence in the final result.

### Troubleshooting
*   **Logs**: Check `docker compose logs` or the console output for `uvicorn`.
*   **Persistence**: If runs are disappearing, check that `LATTICE_MIND_DB` is correctly set and writable.
