# CTF Autopwn - Copilot Instructions

## Project Overview

**ctf-autopwn** is an autonomous CTF exploitation toolkit that uses **decision trees** to detect and exploit vulnerabilities across multiple challenge categories (web, binary, crypto, forensics, steganography, etc.). The system is deterministic—no LLMs, no external reasoning, just expert rules and classical analysis.

### Core Philosophy
- **Deterministic**: Rule-based, reproducible exploitation
- **Modular**: Each vulnerability type gets its own decision tree
- **Extensible**: Add new trees, adapters, and templates without core changes
- **Human-aware**: Graceful fallback to human-in-the-loop when automation is brittle

---

## Architecture & Microservices

### Core Components (Python 3.11+)

#### 1. **Orchestrator** (`core/orchestrator.py`)
- Central execution engine that manages challenge state and decision tree execution
- Tracks execution history, observations, and confirmed vulnerabilities
- Monitors outputs for flags via global `FlagRecognizer`
- Methods: `set_challenge()`, `run_tree()`, `get_execution_log()`

#### 2. **Decision Nodes** (`core/nodes.py`)
```python
class DecisionNode(ABC):
    def run(context: Dict) -> NodeResult
    def next_node(result: NodeResult) -> Optional[DecisionNode]
```
- Abstract base class for all decision tree nodes
- Implement `run()` for the node's action (detect vulnerability, exploit, probe)
- Implement `next_node()` for branching logic (if detection succeeded, try exploitation)
- All nodes operate on shared types: `ChallengeDescriptor`, `VulnDescriptor`, `NodeResult`

#### 3. **Knowledge Base** (`core/knowledge_base.py`)
- Stores vulnerability archetype mappings: `ChallengeType → [VulnType]`
- Tracks confirmed vulnerabilities per challenge session
- Provides `get_applicable_vulns()` to route challenge → relevant detection trees

#### 4. **Flag Recognizer** (`core/flag_recognizer.py`)
- Global singleton that watches all action outputs for flag patterns
- Configurable patterns in `config.py` (default: `flag{...}`, `CTF{...}`)
- Methods: `recognize()`, `recognize_all()`, `has_flag()`

#### 5. **Detection & Exploitation Engines** (`engines/`)
- **DetectionEngine**: Abstract interface for observational actions (HTTP probes, tool calls)
- **ExploitationEngine**: Abstract interface for state-changing actions (payload injection)
- Implementations per vulnerability category (web SQLi detection, ROP chain generation, etc.)

#### 6. **Human-in-the-Loop Manager** (`core/human_loop.py`)
- Manages interactive decision points when automation is insufficient
- Methods: `ask_user()`, `set_hint()`, `set_override()`
- Global singleton with interactive/non-interactive modes

#### 7. **Shared Data Types** (`core/types.py`)
```python
@dataclass ChallengeDescriptor
  type: ChallengeType (web, pwn, crypto, forensics, steganography, reverse_engineering, osint, network, misc)
  url: Optional[str]
  file_path: Optional[str]
  flag_format: str (default "flag{...}")
  metadata: Dict[str, Any]

@dataclass VulnDescriptor
  type: VulnType (sql_injection, lfi, buffer_overflow, weak_crypto, etc.)
  technique: str
  endpoint: Optional[str]
  param: Optional[str]
  confidence: float (0.0 to 1.0)
  extra: Dict[str, Any]

@dataclass NodeResult
  status: NodeStatus (success, failure, escalate, ask_human, timeout)
  data: Dict[str, Any] (result data, captured outputs)
  error: Optional[str]
  next_node: Optional[str]
```

### Tool Adapters (`adapters/`)
Thin wrappers normalizing tool outputs to structured forms (JSON dicts):
- **Network**: `NmapAdapter`, `CurlAdapter`, `FFUFAdapter`, `DirSearchAdapter`
- **Binary**: `BinwalkAdapter`, `ExiftoolAdapter`, `GdbAdapter`, `ObjdumpAdapter`
- **Crypto**: `RSAAttackAdapter`, `VigenereAdapter`
- **Exploitation**: `PwtoolsAdapter`, custom payload builders

### Decision Trees (`trees/`)
Organized by vulnerability category:
```
trees/
├── web/
│   ├── sqli.py       (SQL Injection detection/exploitation)
│   ├── lfi.py        (Local File Inclusion)
│   ├── xss.py        (Cross-Site Scripting)
│   ├── auth_bypass.py
│   └── ...
├── pwn/
│   ├── buffer_overflow.py
│   ├── format_string.py
│   ├── rop_chain.py
│   ├── heap_exploit.py
│   └── ...
├── crypto/
│   ├── weak_rsa.py
│   ├── weak_cipher.py
│   └── ...
├── forensics/
│   ├── hidden_data.py
│   └── ...
└── ...
```

Each tree is a network of `DecisionNode` implementations with decision logic:
- **Detection nodes**: Probe the target, observe responses
- **Exploitation nodes**: Inject payloads, execute exploits
- **Branch nodes**: Route to next phase based on observations

### Exploit Templates (`templates/`)
Reusable exploit blueprints:
- `ret2win.py` - Return-to-win ROP chains
- `rsa_attacks.py` - Small-e, Wiener, CRT attacks
- `format_string.py` - Format string exploitation
- `sqli_templates.py` - SQL injection payloads
- Custom template system for user-defined exploits

---

## Development Workflow

### 1. **Adding a New Decision Tree**

**Example: SQL Injection Detection Tree**

```python
# trees/web/sqli.py
from ctf_autopwn.core.nodes import DecisionNode
from ctf_autopwn.core.types import NodeResult, NodeStatus

class SQLiProbeNode(DecisionNode):
    def run(self, context: Dict) -> NodeResult:
        # 1. Extract target URL and parameters from context
        # 2. Use CurlAdapter to send SQL injection probes
        # 3. Analyze responses for SQL errors, time delays, etc.
        # 4. Return observations in NodeResult.data
        pass
    
    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        # If SQL error detected, route to exploitation node
        # Otherwise, try next detection technique
        pass

class SQLiExploitNode(DecisionNode):
    def run(self, context: Dict) -> NodeResult:
        # Execute SQLi payload using database-specific techniques
        # Flag recognizer automatically detects if flag appears in output
        pass
```

### 2. **Adding a New Tool Adapter**

```python
# adapters/nmap_adapter.py
from ctf_autopwn.adapters.base import ToolAdapter

class NmapAdapter(ToolAdapter):
    def run(self, target: str, args: Dict) -> Dict:
        # Execute: nmap -sV -O target
        # Parse nmap XML output
        # Return normalized: {"open_ports": [...], "services": [...]}
        pass
```

### 3. **Key Patterns to Follow**

- **Always use shared types** (`ChallengeDescriptor`, `VulnDescriptor`, `NodeResult`)
- **All I/O is observable** - Flag recognizer watches all text outputs
- **Fail gracefully** - If automation is brittle, escalate to `ask_human`
- **Document decisions** - Comments in decision logic help reproducibility
- **Use tool adapters** - Don't shell out directly; use normalized adapters

---

## How Things Work Together

### Challenge Execution Pipeline
```
1. User provides ChallengeDescriptor (type, url/file, flag format)
2. Orchestrator routes to Knowledge Base → get applicable VulnTypes
3. For each VulnType, select and execute Detection Tree
   a. Detection nodes probe/analyze target
   b. Outputs checked by FlagRecognizer
   c. If confirmed vulnerability, record in Knowledge Base
4. For each confirmed vulnerability, execute Exploitation Tree
   a. Exploitation nodes inject payloads
   b. FlagRecognizer monitors for flags
   c. If flag found, Orchestrator halts and returns flag
5. If automation insufficient, escalate to HumanLoopManager
```

### Context Flow
```
execution_context = {
    "challenge": ChallengeDescriptor,
    "observations": {
        "http_responses": {...},
        "tool_outputs": {...},
        "confirmed_vulns": [VulnDescriptor, ...]
    },
    "flag_found": None  # Updated by FlagRecognizer
}
```
All nodes receive and can modify this shared context.

---

## Build, Test, and Run

### Installation
```bash
# Local development
python setup.py develop

# Install dependencies
pip install -r requirements-dev.txt  # (to be created)
```

### Testing
```bash
# Run all tests
pytest tests/

# Run specific test
pytest tests/core/test_orchestrator.py

# Run with coverage
pytest --cov=ctf_autopwn tests/
```

### CLI Usage
```bash
# Test the framework
ctf-autopwn test

# Solve a web challenge
ctf-autopwn solve web http://target.com:8080

# Solve a binary
ctf-autopwn solve pwn ./binary

# Solve a crypto challenge
ctf-autopwn solve crypto "ciphertext.txt"
```

### Debug Mode
Set environment variables:
```bash
export CTF_AUTOPWN_LOG_LEVEL=DEBUG
export CTF_AUTOPWN_INTERACTIVE=1
ctf-autopwn solve web http://target.com
```

---

## Key Conventions

### Naming Conventions
- **Decision Nodes**: `<VulnType><Phase>Node` (e.g., `SQLiDetectionNode`, `BufferOverflowExploitNode`)
- **Tool Adapters**: `<ToolName>Adapter` (e.g., `NmapAdapter`, `CurlAdapter`)
- **Exploit Templates**: `<ExploitType>Template` (e.g., `Ret2WinTemplate`)
- **Decision Trees**: Module per vulnerability (e.g., `trees/web/sqli.py`)

### Code Structure
- All nodes inherit from `DecisionNode` and implement `run()` + `next_node()`
- All tool adapters inherit from base adapter and normalize outputs
- No hardcoded paths/configs; use `config.py`
- Logging via `logging` module with node IDs for traceability

### Error Handling
- Timeouts: Return `NodeResult(status=NodeStatus.TIMEOUT, ...)`
- Automation insufficient: Return `NodeResult(status=NodeStatus.ASK_HUMAN, ...)`
- False leads: Return `NodeResult(status=NodeStatus.FAILURE, ...)` and continue

### Testing
- Mock tool adapters (don't invoke real nmap, curl, etc. in unit tests)
- Test decision tree branching logic independently
- Use fixtures for ChallengeDescriptor and context
- Integration tests with real tools in sandbox environment

---

## Important File Locations

| File | Purpose |
|------|---------|
| `core/orchestrator.py` | Main execution engine |
| `core/types.py` | Shared data types (must read for understanding) |
| `core/nodes.py` | DecisionNode base class |
| `config.py` | Global configuration (flag patterns, tool paths, timeouts) |
| `core/flag_recognizer.py` | Flag detection service |
| `trees/` | Decision tree implementations per category |
| `adapters/` | Tool wrapper interfaces |
| `templates/` | Exploit blueprint templates |
| `cli.py` | Command-line entry point |

---

## Research & Background

The framework is grounded in academic work:
- **Pangr**: Behavior-based vulnerability detection
- **Automated Exploit Generation (AEG)**: CGC systems and automated patch generation
- **DARPA Cyber Grand Challenge**: Principles of autonomous exploitation

See `Research Paper - CTF Toolkit.md` for detailed citations and algorithms.

---

## Next Phases

**Phase 2**: Tool adapters + Web tree (SQLi, LFI, XSS)
**Phase 3**: Binary exploitation trees (buffer overflow, ROP, format string)
**Phase 4**: Crypto and forensics trees
**Phase 5**: Performance, test suite, documentation

---

**Remember**: This is deterministic automation. Every decision must be justifiable by rules, not reasoning. If you can't explain why a node makes a decision, add more observational probes or escalate to human-in-the-loop.
