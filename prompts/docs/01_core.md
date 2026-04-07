# Core Modules Reference

> Covers: `types.py`, `nodes.py`, `orchestrator.py`, `confidence.py`, `expressions.py`, `flag_recognizer.py`, `human_loop.py`

---

## types.py

All shared data structures. Pure dataclasses + enums — no logic.

### Enums

```python
class ChallengeType(str, Enum):
    WEB | PWN | CRYPTO | FORENSICS | STEGANOGRAPHY
    REVERSE_ENGINEERING | OSINT | NETWORK | MISC

class VulnType(str, Enum):
    # 19 types: sql_injection, lfi, rfi, xss, command_injection,
    # path_traversal, buffer_overflow, format_string, rop_chain,
    # heap_exploit, race_condition, weak_crypto, side_channel,
    # broken_auth, privilege_escalation, deserialization,
    # hidden_data, compression_bomb, polyglot_file

class NodeStatus(str, Enum):
    SUCCESS | FAILURE | FAILED  # FAILED = "failure" (alias — same value, different member)
    PENDING | SKIPPED | QUEUED | ESCALATE | ASK_HUMAN | TIMEOUT
```

**Note:** `NodeStatus` has a single `FAILURE = "failure"` member. The former `FAILED` alias has been removed — use `FAILURE` exclusively.

### Dataclasses

```python
@dataclass
class ChallengeDescriptor:
    type: ChallengeType
    name: Optional[str] = None
    url: Optional[str] = None
    file_path: Optional[str] = None
    flag_format: str = "flag{...}"
    metadata: Dict[str, Any] = field(default_factory=dict)
    # Fields: type, name, url, file_path, flag_format, metadata only

@dataclass
class VulnDescriptor:
    type: VulnType
    technique: str
    endpoint: Optional[str] = None
    param: Optional[str] = None
    confidence: float = 0.5     # 0.0–1.0 range; not enforced by the dataclass
    extra: Dict[str, Any] = field(default_factory=dict)

@dataclass
class NodeResult:
    status: NodeStatus
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    next_node: Optional[str] = None
```

---

## nodes.py

Defines the `DecisionNode` ABC that every executable unit implements.

```python
class DecisionNode(ABC):
    node_id: str
    name: str
    # Injected by orchestrator at run time:
    signal_bus: Optional[SignalBus]
    confidence_pool: Optional[ConfidencePool]
    tree_id: Optional[str]

    @abstractmethod
    def run(self, context: Dict) -> NodeResult: ...

    def next_node(self, result: NodeResult) -> Optional[str]:
        return None   # subclasses override for branching

    def emit_signal(self, signal_name: str, confidence_boost: float = 0.0): ...
    def has_signal(self, signal_name: str, tree_id: Optional[str] = None) -> bool: ...
```

`SimpleNode` is a passthrough stub for testing — returns `SUCCESS` with a message.

**State leakage risk:** `signal_bus`, `confidence_pool`, and `tree_id` are instance fields. Node instances should not be reused across runs without re-injection.

---

## orchestrator.py

Walks a linked chain of `DecisionNode` objects. Called by `MVPSolver` for Python-tree fallback (Step 5 of pipeline).

### Key methods

```python
def set_challenge(self, challenge: ChallengeDescriptor) -> None:
    # Resets execution context, clears FlagRecognizer, clears ConfidencePool

def set_progress_callback(self, cb: Callable[[Dict], None]) -> None:
    # Server injects: writes to DB + broadcasts over WebSocket

def run_tree(self, root_node: DecisionNode) -> Optional[str]:
    # Walks node chain; returns flag string or None
```

### Progress event structure

```python
{
    "event": "node_start" | "node_end" | "flag_found" | "exploit_result",
    "node_id": str,
    "node_name": str,
    "timestamp": ISO str,
    "parent_node_id": str | None,
    "status": NodeStatus,
    "error": str | None,
    "next_node": str | None,
    "data": dict  # values truncated to 300 chars
}
```

### Walk loop logic

1. Emit `node_start`
2. Call `node.run(context)`
3. Check all result data for flags via `FlagRecognizer`
4. Emit `node_end`
5. Handle terminal statuses: `FAILURE` stops branch, `TIMEOUT` logs+stops, `ASK_HUMAN` pauses for HITL
6. Move to `next_node(result)`

---

## confidence.py

`ConfidencePool` — scoring store for YAML tree dispatch.

### Score formula (diminishing returns)

```
new_score = old_score + boost * (1 - old_score)
```

For negative boosts (penalties):
```
new_score = old_score * (1 + penalty)   # penalty is negative float
```

### API

```python
class ConfidencePool:
    def add_boost(self, tree_id: str, boost: float,
                  source_id: str, label: str = "") -> float:
        # source_id = "{phase}:{tree_id}:{label}" — deduped; same source only applies once
        # Raises if pool is frozen

    def get_score(self, tree_id: str) -> float: ...

    def freeze(self) -> None:
        # Called before exploitation phase — no further boosts possible

    def clear(self) -> None: ...

    def get_all_scores(self) -> Dict[str, float]: ...
```

**Dedup:** same `source_id` can only contribute once. Prevents signal re-firing on retry loops.

**Frozen state:** `add_boost` after `freeze()` raises. Executor calls `freeze()` before looping exploitation paths to prevent detection signals mid-exploit from reordering execution.

---

## expressions.py

Safe AST evaluator — used for YAML `applies_when` guards and `confidence_seeds` conditions.

**Never calls `eval()`.** Parses with `ast.parse()` then walks nodes manually.

### Supported syntax

| Feature | Example |
|---------|---------|
| Dot access | `context.challenge.type` |
| Comparisons | `==`, `!=`, `>`, `<`, `>=`, `<=` |
| Membership | `in`, `not in` |
| Boolean | `and`, `or`, `not` |
| Functions | `len()`, `any()`, `all()` with generator expressions |
| Enum auto-unwrap | `context.challenge.type == 'web'` works without `.value` |

### Known gaps

- **No evaluation timeout:** pathological expressions can hang the executor thread
- **ReDoS via regex:** signal regex matching has no execution timeout — see `07_known_bugs.md` Bug 1

---

## flag_recognizer.py

Global singleton (`get_flag_recognizer()`). Called after every node execution and every HTTP response.

### Patterns (case-insensitive)

```
picoCTF{...}
flag{...} / FLAG{...} / ctf{...} / CTF{...}
flag(...) / FLAG(...)
FLAG=something{...} / CTF_FLAG=something{...}
```

### API

```python
class FlagRecognizer:
    found_flags: List[str]    # grows; NOT reset between calls

    def recognize(self, text: str) -> Optional[str]:
        # Appends match to found_flags — has SIDE EFFECTS even on "check" calls

    def has_flag(self, text: str) -> bool:
        return self.recognize(text) is not None   # also mutates found_flags (Bug 17)

    def clear(self) -> None:
        self.found_flags.clear()
```

**`has_flag()` is side-effect-free:** calls `_probe()` internally — does not mutate `found_flags`.

**No input size guard:** extremely large response bodies can make regex expensive.

---

## human_loop.py

`HumanLoopManager` — pause solver and ask a human for input via the dashboard HITL tab.

### API

```python
class HumanLoopManager:
    hints: Dict[str, Any]        # pre-loaded hints; cleared at start of each solve()
    overrides: Dict[str, bool]   # feature overrides; cleared at start of each solve()

    def ask_user(self, question: str, qid: str,
                 timeout: Optional[float] = None) -> Optional[str]:
        # Blocks solver thread until answer received or timeout
        # Returns None on timeout

    def answer(self, qid: str, answer: str) -> bool:
        # Called by REST endpoint POST /hitl/{id}/answer
        # Returns False if qid already timed out and was popped

    def set_hint(self, key: str, value: Any) -> None: ...
    def set_override(self, key: str, enabled: bool) -> None: ...

    def clear(self) -> None:
        # Clears hints, overrides, unblocks all waiting threads
        # MVPSolver.solve() does NOT call this — must be called manually (Bug 15)
```

### Threading model

- `ask_user` stores a `threading.Event` in `_pending[qid]`
- `answer` sets the event; `ask_user` unblocks and pops the entry
- On timeout: entry is popped after `event.wait()` returns `False`
- Late `answer()` on a timed-out `qid` returns `False` (entry already gone)

---

## mvp.py — MVPSolver

Top-level pipeline orchestrator. Called by the API when an LLM agent submits a challenge via `submit_scan` MCP tool or `POST /solve`. The agent does not call `MVPSolver` directly — it interacts exclusively through MCP tools.

```python
class MVPSolver:
    orchestrator: Orchestrator
    executor: TreeExecutor
    confidence_pool: ConfidencePool

    def solve(self, challenge: ChallengeDescriptor,
              selected_tree_ids: Optional[List[str]] = None) -> Tuple[Optional[str], List]:
        # Returns (flag_or_None, log_entries)
        # selected_tree_ids: agent can pass these via submit_scan to run only specific YAML trees
```

### Solve sequence (condensed)

```python
# 1. Reset state
orchestrator.set_challenge(challenge)     # clears FlagRecognizer, ConfidencePool
confidence_pool.clear()
get_human_loop_manager().clear()          # clears hints/overrides from prior runs

# 2. Classify asset                       [AUTOMATIC]
asset_type = _classify_asset()

# 3. Web recon (if web)                   [AUTOMATIC]
try:
    orchestrator.run_tree(WebReconProbeNode())
except Exception:
    logger.warning(...)                   # recon failure is non-fatal; solve continues

# 4. Merge session cookies (if any)
# Agent may have called set_session_cookies MCP tool before or during this run
try:
    session_store.get_cookies(run_id) → merged into context
except Exception:
    raise RuntimeError("session cookie merge failed: ...")  # surfaces to run log

# 5. YAML tree dispatch loop              [AUTOMATIC; agent can augment via mutate_request]
while remaining_trees:
    flag = asyncio.run(executor.execute_tree(tree, context))   # BUG 7 (open): crashes Python 3.10+ in async context
    if flag: return flag

# 6. Legacy Python tree fallback          [AUTOMATIC]
orchestrator.run_tree(domain_root_node)

# 7. HITL if still no flag               [AGENT answers via MCP or dashboard]
human_loop.ask_user(...)
```

**Open bug (Bug 7):** `asyncio.run()` at line 263 inside the tree execution loop. On Python 3.10+ this raises `RuntimeError: This event loop is already running` when called from a FastAPI async context. See `07_known_bugs.md`.
