# YAML Tree Engine Reference

> Covers: `core/tree_loader.py`, `core/executor.py`, YAML schema, `SignalBus`, `captures` substitution

---

## YAML Tree Schema

Full annotated reference. All fields required unless marked optional.

```yaml
# ── Metadata ──────────────────────────────────────────────────
id: web_sqli                   # snake_case; unique across ALL trees
name: SQL Injection
category: web                  # web | pwn | crypto | forensics | stego | reversing
version: "1.0"
author: system                 # optional
description: >                 # optional; 1-2 sentences
  What this tree detects and how it exploits.

# ── Guard ──────────────────────────────────────────────────────
applies_when:                  # ALL conditions must be True; evaluated via expressions.py
  - "context.challenge.type == 'web'"

min_confidence: 0.10           # tree skipped if seeds don't reach this

stop_on_flag: true             # halt all paths once flag captured

# ── Confidence Seeds ───────────────────────────────────────────
# Evaluated BEFORE detection. Free (no HTTP). Boost uses diminishing returns.
# Sum should reach ~0.30–0.50 when all fire.
confidence_seeds:
  - if: "'php' in context.tech_stack"
    boost: 0.30
    label: "php_detected"

# ── Detection Paths ────────────────────────────────────────────
# Run CONCURRENTLY. Each path is a serial sequence of steps.
# Paths with min_confidence > current score are skipped.
detection_paths:
  - id: detect_error_based
    name: Error-Based Detection
    min_confidence: 0.10
    steps:
      - id: probe_single_quote
        action: http_request           # only supported action
        with:
          method: GET                  # GET | POST | PUT | etc.
          inject_into: all_params      # all_params | vulnerable_param | none
          payloads:
            - "'"
            - "''"
          headers:                     # optional dict
            Content-Type: application/json
          body: null                   # optional; for POST
        signals:
          - name: sql_error_detected
            condition: "regex:SQL syntax|mysql_fetch|ORA-[0-9]"
            on_match:
              boost: 0.50
              label: "sql_error_response"

# ── Exploitation Paths ─────────────────────────────────────────
# Run SEQUENTIALLY after detection, ordered by confidence.
# Only runs if requires_signal was emitted during detection.
exploitation_paths:
  - id: exploit_union
    name: UNION-Based Extraction
    requires_signal: "sql_error_detected"   # must match an emitted signal name exactly
    technique: union_based
    steps:
      - id: extract_flag
        action: http_request
        with:
          method: GET
          inject_into: vulnerable_param     # param identified as vulnerable in detection
          payloads:
            - "' UNION SELECT flag FROM flags-- -"
          capture:
            - name: flag_value
              regex: 'flag\{[^}]+\}'        # always include CTF\{ variant too
```

### Two schema variants

`tree_loader.py` normalizes both to `DecisionTree`:

| Schema variant | Key difference |
|---------------|----------------|
| **v1** (primary) | `action: http_request`, `with:` block, `signals[].condition: "regex:..."` |
| **v2** (legacy prompt format) | `action: http_probe`, `params:` block, `signals[].match: "string"`, `signals[].on_match.emit:` |

If you write new trees, use **v1** (matches executor primary code path). The `research_yaml.md` prompt uses v2 format — it still works but goes through normalization.

---

## tree_loader.py

### TreeRegistry

Module-level singleton (`_global_registry`). Loads all `.yaml` files from `lattice_mind/trees/yaml/` recursively.

```python
class TreeRegistry:
    def load_from_directory(self, path: str) -> int:
        # Walks dirs; calls _parse_tree() for each .yaml file
        # Returns count of successfully loaded trees
        # On error: broad except + print (structured logging missing — Bug)

    def get_tree(self, tree_id: str) -> Optional[DecisionTree]:  ...
    def get_all_trees(self) -> List[DecisionTree]: ...
    def reload(self) -> int: ...   # called by POST /rules/reload
```

### Known issues in tree_loader.py

| Issue | Detail |
|-------|--------|
| No schema validation | `confidence_seeds` parsed with `s["if"]` / `s["boost"]` — wrong key → `KeyError`; v2 uses `condition` not `if` |
| Silent duplicate ID overwrite | `registry[tree.id] = tree` with no duplicate check or warning (Bug 2) |
| Broad `except Exception` + `print` | Errors go to stdout; no structured logging |
| No DAG validation | Circular `requires_signal` chains not detected at load time (Bug 5) |

---

## executor.py — TreeExecutor

Runs a single `DecisionTree` asynchronously. Three phases: seed → detect → exploit.

```python
class TreeExecutor:
    async def execute_tree(
        self,
        tree: DecisionTree,
        context: Dict[str, Any]
    ) -> Optional[str]:
        # Returns flag string or None
```

### Phase 1: Seed

```python
for seed in tree.confidence_seeds:
    if eval_expression(seed.condition, context):   # via expressions.py
        pool.add_boost(tree.id, seed.boost, source_id=f"seed:{tree.id}:{seed.label}")
```

### Phase 2: Detection (concurrent)

```python
tasks = [_run_detection_path(path, context) for path in tree.detection_paths
         if pool.get_score(tree.id) >= path.min_confidence]
await asyncio.gather(*tasks)
```

Inside each detection path:
1. For each step → build `req_args` (method, headers, body, params)
2. Call `RequestsAdapter.run(target, req_args)` → response dict
3. Evaluate `signals` against response body/headers
4. Signal match → `signal_bus.emit(tree.id, signal_name)`, `pool.add_boost(...)`
5. `FlagRecognizer.recognize(body)` on every response

### Phase 3: Exploitation (sequential)

```python
pool.freeze()   # lock scores before exploitation
for path in exploitation_paths:
    if signal_bus.has(tree.id, path.requires_signal):
        await _run_exploitation_path(path, context)
```

Inside each exploitation path:
1. Same HTTP dispatch as detection
2. `{{ captures.KEY }}` template substitution in payloads (from `self.captures` dict)
3. `capture` block: regex applied to response → stored in `self.captures`
4. `FlagRecognizer.recognize()` on every response

### RequestsAdapter instantiation

A **new** `RequestsAdapter()` is created per executor step (line ~417). This limits session cookie leakage between steps — but the `requests.Session` inside still accumulates `Set-Cookie` responses from the target within a single step's requests (Bug 18).

### Known issues in executor.py

| Issue | Line range | Detail |
|-------|-----------|--------|
| ReDoS via YAML signal regex | ~172–176 | `re.search(sig_def["match"], body)` with no timeout (Bug 1) |
| Exception swallowed in condition eval | ~202–206 | Failures become "no match" silently |
| Template injection from captures | ~422–426 | Attacker-controlled `captures.table_name` inserted into next payloads (Bug 6) |
| Shallow `context.copy()` | ~181 | Nested dicts still shared; deep cycles in context can confuse evaluators |
| `asyncio.run()` in while loop | mvp.py:246–254 | `execute_tree` called via `asyncio.run()` inside `to_thread` — crashes Python 3.10+ (Bug 7) |

---

## SignalBus

Tracks which detection signals have fired, scoped per tree.

```python
class SignalBus:
    def emit(self, tree_id: str, signal_name: str) -> None: ...
    def has(self, tree_id: str, signal_name: str) -> bool: ...
    def get_emitted(self, tree_id: str) -> Set[str]: ...
    def reset(self) -> None: ...
```

Internally: `Dict[str, Set[str]]` — `{tree_id: {signal_name, ...}}`.

Signal namespace: fully qualified = `f"{tree_id}:{signal_name}"`. The YAML only uses the short name (`signal_name`); the `tree_id` prefix is implicit from the executing tree's ID.

**Circular dependency risk:** Tree A exploitation requires signal X, which is only ever emitted by Tree B's detection, which requires signal Y from Tree A. Neither fires. No cycle detection at runtime (static DAG validation is the fix — see `07_known_bugs.md` Bug 5).

---

## `captures` dict & `{{ }}` substitution

```python
# In executor._run_exploitation_path():
for key, pattern in step.capture.items():
    match = re.search(pattern, response_body)
    if match:
        self.captures[key] = match.group(0)

# Template substitution in payload building:
payload = payload.replace(f"{{{{ captures.{key} }}}}", value)
```

**Security note:** `captures` values come from attacker-controlled HTTP responses. If a later step's payload is `UNION SELECT {{captures.table_name}}-- -` and the attacker poisoned `table_name` with `\r\nX-Injected: evil`, the substitution propagates hostile content into the next request (Bug 6).

**Fix (planned Sprint 3):** sanitize `captures` values — strip control characters and enforce maximum length before storage.

---

## Adding New YAML Trees

1. Create `lattice_mind/trees/yaml/<category>/<name>.yaml`
2. Follow schema above; use `id` = filename stem (snake_case)
3. Ensure every `requires_signal` in exploitation exactly matches an `emit` / `name` in detection
4. Call `POST /rules/reload` or restart to load
5. No Python changes needed

### Quality checklist

- [ ] `id` globally unique
- [ ] Regex patterns in signals use single-quoted YAML strings
- [ ] Every `requires_signal` matches an emitted signal name exactly
- [ ] Seeds only reference `context.found_paths`, `context.tech_stack`, `context.params`
- [ ] At least one exploitation path with `capture` block targeting `flag\{` or `CTF\{`
- [ ] `applies_when` correctly scopes to the right challenge type
