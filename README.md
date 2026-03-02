# ctf-autopwn  Autonomous CTF Exploitation Toolkit

A deterministic, decision-tree-based framework for autonomous vulnerability
detection and exploitation in CTF challenges.  No LLMs. No magic. Pure rules.

---

## Table of Contents

1. [What is this?](#what-is-this)
2. [Quick Start  Docker](#quick-start--docker)
3. [Quick Start  Local](#quick-start--local)
4. [Web Dashboard](#web-dashboard)
5. [CLI Usage](#cli-usage)
6. [REST API](#rest-api)
7. [Architecture](#architecture)
8. [Decision Trees & Pipeline](#decision-trees--pipeline)
9. [Tools Bundled in Docker](#tools-bundled-in-docker)
10. [Adding a New Decision Tree](#adding-a-new-decision-tree)
11. [Testing](#testing)
12. [Research & References](#research--references)
13. [License](#license)

---

## What is this?

**ctf-autopwn** is an autonomous CTF solver that:

- Classifies challenge artifacts (web service, binary, crypto, forensics)
- Runs category-specific **detection decision trees** to identify vulnerability types
- Dispatches **exploitation decision trees** for each confirmed candidate
- Monitors every node output for flag patterns (`flag{...}`, `CTF{...}`) and halts on match
- Falls back to **human-in-the-loop** when automation is insufficient

The system is fully deterministic  every branch decision is justified by observable
evidence (HTTP response codes, header values, directory names, binary metadata, etc.).

---

## Quick Start  Docker

The easiest way to run ctf-autopwn.  Docker installs all required CTF tools
automatically (nmap, ffuf, binwalk, exiftool, etc.).

```bash
# Build and start
docker compose up --build

# Service is now available at http://localhost:8000
# SQLite run history is persisted in a named Docker volume (survives rebuilds)
```

To rebuild after code changes:

```bash
docker compose up --build -d
```

---

## Quick Start  Local

```bash
# Python 3.11+ required
pip install -e .

# Start the API + web dashboard
uvicorn ctf_autopwn.api.server:app --host 0.0.0.0 --port 8000

# Visit http://localhost:8000
```

Install optional CLI tools for deeper analysis:

```bash
# Debian/Ubuntu
sudo apt install nmap curl dirb binwalk exiftool file steghide foremost netcat-openbsd
# Install ffuf separately (Go binary)
# https://github.com/ffuf/ffuf/releases
```

---

## Web Dashboard

Open `http://localhost:8000` for a cyberpunk-themed dashboard.

**Submit a challenge:**

| Field           | Example                          | Notes                        |
|-----------------|----------------------------------|------------------------------|
| Challenge Type  | `web`                            | web / pwn / crypto / forensics |
| Name            | `Bank Login`                     | Free-form label              |
| URL             | `http://target.com:8080`         | Required for web challenges  |
| File Path       | `/tmp/binary`                    | Required for pwn/forensics   |
| Flag Format     | `flag{...}` *(default)*          | Regex hint for recognizer    |

**Dashboard panels (right side):**

- **Execution Tree**  Live flowchart of every node, click to expand outputs
- **Discoveries**  Aggregated directories, services, parameters found
- **Attacks Tried**  Exploitation nodes only, with payloads and outcomes
- **Raw Output**  Full JSON state for debugging

Past runs are stored in SQLite and browseable via `GET /runs`.

---

## CLI Usage

```bash
# Smoke-test adapters and solver
ctf-autopwn test

# Web challenge
ctf-autopwn solve web http://target.com:8080

# Binary/pwn challenge
ctf-autopwn solve pwn ./challenge_binary

# Crypto challenge
ctf-autopwn solve crypto ./cipher.txt

# Forensics/stego
ctf-autopwn solve forensics ./image.png
```

---

## REST API

### Submit a challenge

```http
POST /solve
Content-Type: application/json

{
  "name": "SQLi Bank",
  "challenge_type": "web",
  "url": "http://target.com/login",
  "flag_format": "flag{...}"
}
```

Returns immediately with a `run_id`.

### Poll run status

```http
GET /runs/{run_id}
```

```json
{
  "run_id": "abc123...",
  "status": "running",
  "flag": null,
  "steps": [...],
  "observations": {...}
}
```

### List past runs

```http
GET /runs
```

Returns the last 50 runs from SQLite.

### Health check

```http
GET /health
```

---

## Architecture

```
ctf_autopwn/
 core/
    types.py            # ChallengeDescriptor, VulnDescriptor, NodeResult
    nodes.py            # DecisionNode abstract base class
    orchestrator.py     # Central execution engine + flag scanning
    knowledge_base.py   # Vulnerability archetype registry
    flag_recognizer.py  # Global flag pattern detector (stateless)
    human_loop.py       # Human-in-the-loop interaction manager
 engines/
    detection.py        # DetectionEngine abstract interface
    exploitation.py     # ExploitationEngine abstract interface
 adapters/               # Thin tool wrappers, normalise output to dicts
    curl_adapter.py
    ffuf_adapter.py
    nmap_adapter.py
    binwalk_adapter.py
    ...
 trees/                  # Decision tree implementations
    asset/              # D-0: Asset classification
    web/                # W-Recon, SQLi, LFI, XSS, CMD, Auth Bypass, IDOR, SSRF
    pwn/                # P-Detect, buffer overflow, format string, ROP
    crypto/             # C-Detect, RSA, Vigenere, XOR
    forensics/          # F-Detect, stego, binwalk, metadata
 templates/              # Reusable exploit blueprints (ret2win, RSA attacks)
 api/
    server.py           # FastAPI app + embedded cyberpunk dashboard
 cli.py                  # ctf-autopwn entry point
 config.py               # Flag patterns, timeouts, tool paths
 mvp.py                  # MVPSolver  top-level orchestration logic
```

### Key types (`core/types.py`)

```python
@dataclass ChallengeDescriptor   # type, url, file_path, flag_format, metadata
@dataclass VulnDescriptor        # type, technique, endpoint, param, confidence
@dataclass NodeResult            # status, data, error, next_node
NodeStatus: SUCCESS | FAILURE | TIMEOUT | ASK_HUMAN | ESCALATE
```

---

## Decision Trees & Pipeline

```
User submits ChallengeDescriptor
          
          
  D-0: Asset Classification
  (network endpoint? binary? text? container?)
          │
    
   WEB                         PWN / CRYPTO / FORENSICS
                                   (specialist trees)
    
  W-Recon: HTTP Probe
       Server headers  tech detection (JSP/PHP/ASP)
       ffuf directory scan (extensions adapt to tech)
    
  W-Analyze: Vulnerability Candidates
      Rule: /admin path  auth_bypass candidate
      Rule: id/page param  sql_injection candidate
      Rule: file/path param  lfi candidate
    
  Dispatch phase (one tree per candidate):
     auth_bypass   AuthBypassDetectNode
                     (direct access + default creds + header tricks)
     sql_injection  SQLiDetectReflectionNode  BooleanNode  ErrorNode  UnionNode
                       SQLiExploitBooleanNode / SQLiExploitErrorNode
     lfi           LFIDetectTraversalNode  LFIDetectFilterNode  LFIExploitTraversalNode
     xss           XSSDetectReflectedNode  XSSDetectStoredNode  XSSExploitNode
     command_injection  CMDDetectOutputNode  CMDDetectBlindNode  CMDExploitNode
```

**Flag recognition** runs after every node  if any string value in `result.data`
matches the flag pattern, the orchestrator halts and returns the flag immediately.

---

## Tools Bundled in Docker

The Docker image installs everything automatically:

| Tool       | Purpose                                      |
|------------|----------------------------------------------|
| `curl`     | HTTP probing (web recon, vuln testing)       |
| `nmap`     | Port/service scanning                        |
| `ffuf`     | Directory/parameter fuzzing (100 threads)    |
| `dirb`     | Wordlists (`/usr/share/dirb/wordlists/`)     |
| `binwalk`  | Embedded-data extraction (forensics)         |
| `exiftool` | File metadata extraction                     |
| `steghide` | LSB steganography extraction                 |
| `foremost` | File carving                                 |
| `netcat`   | Raw TCP connections                          |
| `file`     | Magic-byte classification                    |

---

## Adding a New Decision Tree

### 1  Create the node file

```python
# ctf_autopwn/trees/web/my_vuln.py
from ctf_autopwn.core.nodes import DecisionNode
from ctf_autopwn.core.types import NodeResult, NodeStatus

class MyVulnDetectNode(DecisionNode):
    def __init__(self):
        super().__init__("my_vuln_detect", "MyVuln: Detect")

    def run(self, context):
        # Probe target, write evidence to context["observations"]
        # Return NodeResult with status + data
        ...

    def next_node(self, result):
        if result.status == NodeStatus.SUCCESS:
            return MyVulnExploitNode()
        return None
```

### 2  Wire it into `WebReconAnalyzeVulnsNode`

Add a detection rule in `trees/web/recon.py`:

```python
if any("keyword" in path for path in dir_paths):
    candidates["my_vuln"].append(path)
```

### 3  Register the dispatch in `mvp.py`

```python
if vuln_type == "my_vuln":
    return self.orchestrator.run_tree(MyVulnDetectNode())
```

### Guidelines

- All nodes inherit `DecisionNode` and implement `run()` + `next_node()`
- Write observations to `context["observations"]` so later nodes and the UI can display them
- Store string values in `result.data`  the orchestrator's FlagRecognizer scans every string
- On failure, return `NodeResult(status=NodeStatus.FAILURE, ...)`  do not raise
- Use adapters for all tool invocations; never shell out directly

---

## Testing

```bash
# Run all tests
pytest test_deployment.py test_exploitation_trees.py test_api.py -q

# With coverage
pytest --cov=ctf_autopwn test_deployment.py test_exploitation_trees.py test_api.py
```

Tests mock tool adapters  real network calls are not made during unit tests.

---

## Research & References

This framework is grounded in academic work on autonomous exploitation:

- **Pangr**  Behavior-based vulnerability detection and exploit generation
- **Automated Exploit Generation (AEG)**  CGC / DARPA Cyber Grand Challenge systems
- **Classical CTF techniques**  Community-documented TTPs for web, pwn, crypto, forensics

Full citations and algorithm descriptions: [`Research Paper - CTF Toolkit.md`](Research%20Paper%20-%20CTF%20Toolkit.md)

Technical detection specs: [`detections.md`](detections.md)

Exploitation TTPs: [`ttps.md`](ttps.md)

---

## License

MIT

---

*Deterministic. Rule-based. No magic.*
