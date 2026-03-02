# CTF Autopwn - Autonomous CTF Exploitation Toolkit

A deterministic, decision-tree-based framework for autonomous vulnerability detection and exploitation in CTF challenges.

## Overview

**ctf-autopwn** is an autonomous CTF solver that:
- Analyzes challenges (web services, binaries, crypto, forensics, etc.)
- Builds a decision tree of vulnerability hypotheses
- Intelligently probes and exploits vulnerabilities
- Recovers flags without external reasoning or LLMs
- Supports human-in-the-loop interaction for edge cases

## Architecture

```
ctf_autopwn/
├── core/                    # Core framework
│   ├── types.py            # ChallengeDescriptor, VulnDescriptor, NodeResult
│   ├── nodes.py            # DecisionNode abstract base class
│   ├── orchestrator.py      # Central execution engine
│   ├── knowledge_base.py    # Vulnerability archetype registry
│   ├── flag_recognizer.py   # Global flag pattern detector
│   └── human_loop.py        # Human-in-the-loop manager
├── engines/                 # Execution engines
│   ├── detection.py         # DetectionEngine interface
│   └── exploitation.py      # ExploitationEngine interface
├── adapters/                # Tool wrappers (nmap, curl, binwalk, etc.)
├── trees/                   # Category-specific decision trees
│   ├── web/
│   ├── pwn/
│   ├── crypto/
│   ├── forensics/
│   ├── steganography/
│   ├── reverse_engineering/
│   ├── osint/
│   └── network/
├── templates/               # Exploit templates (ret2win, RSA attacks, etc.)
├── cli.py                  # Command-line interface
├── config.py               # Global configuration
└── __init__.py             # Package exports
```

## Key Components

### 1. **Orchestrator** (`core/orchestrator.py`)
Central engine that:
- Manages challenge state and execution context
- Executes decision trees
- Monitors for flag patterns globally
- Tracks execution history for reproducibility

### 2. **Decision Nodes** (`core/nodes.py`)
Abstract base class `DecisionNode` with:
- `run(context)` - Execute the node's action
- `next_node(result)` - Determine branching logic
- Implementations for detection, exploitation, and analysis steps

### 3. **Knowledge Base** (`core/knowledge_base.py`)
Stores:
- Vulnerability archetype mappings (challenge type → applicable vulns)
- Confirmed vulnerabilities per challenge
- Decision tree references and strategies

### 4. **Flag Recognizer** (`core/flag_recognizer.py`)
Global service that:
- Monitors all action outputs for flag patterns
- Configurable flag formats (e.g., `flag{...}`, `CTF{...}`)
- Terminates exploitation once flag is found

### 5. **Detection & Exploitation Engines**
Abstract interfaces for:
- **Detection Engine** - Observational actions (HTTP probes, tool calls)
- **Exploitation Engine** - State-changing actions (payload injection, ROP chains)

### 6. **Tool Adapters** (`adapters/`)
Thin wrappers normalizing outputs from:
- Network tools: `nmap`, `curl`, `ffuf`, `dirsearch`
- Binary analysis: `binwalk`, `exiftool`, `strings`, `objdump`, `gdb`
- Crypto: RSA attack libraries, Vigenère crackers
- Exploitation: `pwntools`, custom payloads

### 7. **Human-in-the-Loop Manager** (`core/human_loop.py`)
Enables:
- Asking users for hints at decision nodes
- Override flags (skip certain trees)
- Storing domain-specific knowledge

## Web Dashboard & API

- **FastAPI service** (`ctf_autopwn.api.server:app`) exposes `/health`, `/challenge-types`, and `/solve`.
- **One-file dashboard** (served from `/`) lets you submit challenge metadata, trigger the solver, and view execution logs/flags without using the CLI.
- **Thread-safe orchestration** ensures only one solver run executes at a time while still supporting concurrent HTTP requests.
- **Docker & Compose** provide a turnkey way to launch the API/UI (`docker compose up --build` binds to `localhost:8000`).

Use the API programmatically:

```bash
curl -X POST http://localhost:8000/solve ^
     -H "Content-Type: application/json" ^
     -d "{\"name\": \"demo\", \"challenge_type\": \"web\", \"url\": \"http://target\"}"
```

The response contains the flag (if any), node history, and observations captured by the orchestrator.

## Quick Start

```bash
# Install (includes FastAPI + UI deps)
pip install -e .

# Launch the FastAPI backend + web dashboard
uvicorn ctf_autopwn.api.server:app --host 0.0.0.0 --port 8000
# or simply run: ctf-autopwn-api
# open http://localhost:8000 to access the UI

# Prefer containers? bring everything up with Docker
docker compose up --build
```

The legacy CLI entry point is still available for scripted usage:

```bash
# Smoke test adapters + solver
ctf-autopwn test

# Kick off a web or pwn analysis directly from the terminal
ctf-autopwn solve web http://example.com:8080
ctf-autopwn solve pwn /path/to/binary
```

## Project Status

- **Phase 1–5** – ✅ Complete (core framework, adapters, 50 detection nodes, MVP integration, exploitation trees)
- **Phase 6** – 🔄 Integrating exploitation planners into MVPSolver routing
- **Phase 7** – ✅ FastAPI service + embedded dashboard + automated tests
- **Phase 8** – 🚧 Containerization & multi-environment deployment (initial Dockerfile/Compose shipped)

## Research & Papers

This framework is based on:
- **Pangr** - Behavior-based vulnerability detection
- **Automated Exploit Generation (AEG)** - CGC systems
- **Classical CTF techniques** - Academic and community research

See `Research Paper - CTF Toolkit.md` for detailed analysis and references.

## Requirements

- Python 3.11+
- Python packages (installed automatically via `pip install -e .`):
  - `fastapi`, `uvicorn[standard]`, `requests`
- Optional command-line tools for deeper analysis:
  - `nmap`, `curl`, `ffuf`/`dirsearch`
  - `binwalk`, `zsteg`, `exiftool`
  - `tshark`, `volatility`
  - `gdb`, `objdump`, `strings`
  - Crypto helpers (`pycryptodome`, `sympy`, etc.)

## License

MIT

---

**Built for CTF players who want autonomous exploitation. Deterministic. Rule-based. No magic.**
