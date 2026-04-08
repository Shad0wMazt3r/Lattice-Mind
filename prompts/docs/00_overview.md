# Lattice Mind — Overview & Pipeline

> Token-saving reference. Each section links to a deeper doc. Read only what your task needs.

---

## What It Is

An MCP (Model Context Protocol) server that gives LLM agents a complete, automated vulnerability discovery and exploitation pipeline. The engine handles all the mechanical work deterministically — the LLM agent directs and augments.

**What the engine does automatically (no LLM needed):**
- Asset classification, web recon, technology fingerprinting
- YAML-tree-driven HTTP probing, signal evaluation, confidence scoring
- Exploit payload permutation and flag capture
- Fallback Python decision trees for common vuln classes

**What the LLM agent does:**
- Submits challenges and monitors progress via MCP tools (`submit_scan`, `wait_for_run`, `get_run_status`)
- Mutates in-flight requests (headers, body, params) via `mutate_request` when the engine surfaces a promising signal
- Injects/rotates session cookies mid-scan via `set_session_cookies`
- Targets specific YAML trees via `selected_tree_ids` in `submit_scan`
- Answers HITL escalation questions when automation is insufficient

Every automated action is rule-driven and reproducible. Every LLM intervention is explicitly scoped to a `run_id` and recorded in the execution log.

**Pipeline:** recon → asset classification → confidence scoring → YAML tree detection → exploitation → flag capture → (LLM augmentation at any stage)

---

## Division of Labor

| Layer | Who controls it | Detail |
|-------|----------------|--------|
| Asset classification | Engine (automatic) | Rule-based; no agent input needed |
| Web recon / fingerprinting | Engine (automatic) | Populates context for confidence seeding |
| YAML tree selection & ranking | Engine + Agent | Agent can narrow via `selected_tree_ids`; engine ranks the rest by confidence |
| HTTP probing (detection) | Engine (automatic) | Payload loops, signal evaluation, confidence boosting |
| Request mutation | Agent (optional) | Agent calls `mutate_request` to pause, inspect, and modify a pending request |
| Session cookie injection | Agent (optional) | Agent calls `set_session_cookies` to inject or rotate tokens mid-scan |
| Exploit payload dispatch | Engine (automatic) | Ordered payload sets; `{{ captures.KEY }}` multi-step chaining |
| Flag recognition | Engine (automatic) | Regex patterns on every response |
| HITL escalation | Agent | Engine pauses; agent answers via MCP or dashboard to unblock |
| Result retrieval | Agent | `wait_for_run` / `get_run_status` MCP tools |

The key principle: **the engine eliminates the mechanical grind; the LLM agent provides context, credentials, and judgment where rules are insufficient.**

---

## Repo Layout

```
copilot/
├── lattice_mind/
│   ├── config.py              # FLAG_PATTERNS, TOOL_PATHS, TIMEOUTS, FeatureFlags
│   ├── cli.py                 # CLI: "Lattice-Mind solve / test"
│   ├── mvp.py                 # MVPSolver.solve() — top-level pipeline wiring
│   ├── api/
│   │   ├── server.py          # FastAPI REST + SQLite + WebSocket + dashboard (1479 lines)
│   │   └── serve_with_mcp.py  # Production launcher (uvicorn + signal handling)
│   ├── mcp/
│   │   └── server.py          # stdio MCP — 9 tools for AI agent integration
│   ├── core/
│   │   ├── types.py           # ChallengeDescriptor, VulnDescriptor, NodeResult, enums
│   │   ├── nodes.py           # DecisionNode ABC + SimpleNode stub
│   │   ├── orchestrator.py    # Walks Python node chains; emits progress events
│   │   ├── executor.py        # Drives YAML trees: seed→detect→exploit phases
│   │   ├── flag_recognizer.py # Global singleton regex flag detector
│   │   ├── confidence.py      # ConfidencePool — diminishing-returns scoring
│   │   ├── tree_loader.py     # YAML parser + TreeRegistry
│   │   ├── expressions.py     # Safe AST evaluator for applies_when conditions
│   │   ├── knowledge_base.py  # ChallengeType → [VulnType] archetype mappings
│   │   ├── session_store.py   # Per-run cookie/session storage
│   │   └── human_loop.py      # HITL escalation
│   ├── adapters/
│   │   ├── base.py            # ToolAdapter ABC + CommandToolAdapter
│   │   ├── curl_adapter.py    # HTTP via requests (+ curl subprocess fallback)
│   │   ├── nmap_adapter.py    # Network scanning
│   │   ├── ffuf_adapter.py    # Directory/param fuzzing
│   │   └── file_adapter.py    # File analysis (binwalk, exiftool, file)
│   ├── engines/
│   │   ├── detection.py       # DetectionEngine abstract interface
│   │   └── exploitation.py    # ExploitationEngine abstract interface
│   ├── trees/
│   │   ├── asset/classify.py  # AssetClassifyNetworkNode
│   │   ├── web/               # Legacy Python nodes: recon, sqli, lfi, xss, cmd
│   │   ├── pwn/detect.py      # Binary exploitation detection
│   │   ├── crypto/detect.py   # Crypto challenge detection
│   │   ├── forensics/detect.py
│   │   ├── exploit/           # Exploit execution nodes
│   │   └── yaml/              # 21 declarative YAML attack trees (gitignored)
│   └── templates/             # Exploit template stubs
├── frontend/
│   ├── index.html             # SPA shell (5 tabs + modals + boot screen)
│   ├── script.js              # All dashboard logic — vanilla JS (1644 lines)
│   └── style.css              # Cyberpunk dark theme
├── tests/                     # pytest suite
├── wiki/                      # Markdown documentation
├── Dockerfile                 # Production image
├── Dockerfile.dev             # Dev image (hot-reload)
├── docker-compose.yml         # Services: lattice-mind-dev, lattice-mind-api, mailpit
└── setup.py                   # Package deps + entry points
```

---

## Entry Points

| Command | Resolves To |
|---------|-------------|
| `Lattice-Mind solve` | `lattice_mind.cli:main` |
| `Lattice-Mind-api` | `lattice_mind.api.server:main` |
| `Lattice-Mind-mcp` | `lattice_mind.mcp.server:main` |
| Docker CMD | `python -m lattice_mind.api.serve_with_mcp` |

---

## End-to-End Execution Pipeline

LLM agent interaction points are marked with `◀ AGENT`.

```
LLM Agent calls submit_scan (MCP)          ◀ AGENT: challenge type, URL, optional selected_tree_ids
    │
    ▼
MVPSolver.solve()                          [mvp.py]
    │
    ├─ Step 1: Asset Classification        [AUTOMATIC]
    │    AssetClassifyNetworkNode
    │    → ChallengeType (web/pwn/crypto/forensics/…)
    │
    ├─ Step 2: Web Recon (web only)        [AUTOMATIC]
    │    WebReconProbeNode
    │    → observations: tech_stack, found_paths, params, forms, potential_vulns
    │
    ├─ Step 3: Confidence Seeding          [AUTOMATIC]
    │    Each YAML tree's applies_when + confidence_seeds evaluated against context
    │    ConfidencePool scores trees (diminishing returns)
    │    Trees sorted by score descending
    │
    ├─ Step 4: YAML Tree Dispatch          [executor.py — AUTOMATIC]
    │    For each tree (by confidence rank):
    │    - DetectionPaths (HTTP probes, signal evaluation)
    │    - If signals found → ExploitationPaths (payload × param × target loops)
    │    - FlagRecognizer watches every response
    │    - stop_on_flag=true → halt entire pipeline
    │
    │    ◀ AGENT AUGMENTATION POINTS (during this phase):
    │    - mutate_request: pause a pending request, inspect/modify headers/body/params, resume
    │    - set_session_cookies: inject or rotate auth tokens/cookies mid-scan
    │
    ├─ Step 5: Legacy Python Tree Fallback [orchestrator.py — AUTOMATIC]
    │    Web: AuthBypass → SQLi → LFI → XSS → CMDi
    │    Pwn/Crypto/Forensics: dedicated detection trees
    │
    └─ Step 6: HITL Escalation
         HumanLoopManager.ask_user()       ◀ AGENT: answer escalation question to unblock solver
         Dashboard HITL tab shows pending questions

LLM Agent calls wait_for_run / get_run_status  ◀ AGENT: poll until terminal state (success/completed/degraded_success/error)
```

---

## Two-Tier Tree System

| Tier | Location | Format | Runs When |
|------|----------|--------|-----------|
| YAML trees | `trees/yaml/` | Declarative YAML | First pass — all applicable trees by confidence rank |
| Python trees | `trees/web/`, `trees/pwn/`, etc. | Imperative `DecisionNode` chains | Fallback if YAML pass finds no flag |

---

## Key Design Patterns

| Pattern | Where | Detail |
|---------|-------|--------|
| Singleton | `FlagRecognizer`, `FeatureFlags`, `TreeRegistry` | Module-level instances shared across run |
| Callback injection | `Orchestrator.set_progress_callback()` | Server injects DB write + WS broadcast |
| Shared mutable context dict | All nodes and executor | Contains `challenge`, `observations`, `flag_found`, tree-specific state |
| Frozen pool | `ConfidencePool.freeze()` | Called before exploitation; scores locked |
| Template substitution | `{{ captures.KEY }}` in YAML payloads | Multi-step exploits (e.g. capture table → extract data) |
| Signal bus | `SignalBus` | Tracks which detection signals fired per tree; exploitation paths gate on these |
| Decision receipts | `TreeExecutor` context writes | Per-run trace of observation/inference/action/result for explainability |

---

## Infrastructure

| Item | Detail |
|------|--------|
| Python | 3.11+ required |
| Docker services | `lattice-mind-dev` (port 8000, hot-reload), `lattice-mind-api` (prod), `mailpit` (SMTP) |
| System tools in Docker | `curl`, `nmap`, `ffuf` v2.1.0, `binwalk`, `exiftool`, `steghide`, `foremost`, `dirb`, `netcat` |
| DB | SQLite at `/data/runs.db` |

---

## Deep-Dive Docs

| Topic | File |
|-------|------|
| Core types, nodes, orchestrator, confidence, expressions | `01_core.md` |
| YAML tree engine (loader, executor, schema) | `02_yaml_engine.md` |
| HTTP & tool adapters | `03_adapters.md` |
| REST API, auth, WebSocket, DB schema | `04_api.md` |
| MCP stdio server & tools | `05_mcp.md` |
| Frontend SPA | `06_frontend.md` |
| Known bugs & audit ledger | `07_known_bugs.md` |
