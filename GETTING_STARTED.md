# Getting Started with CTF Autopwn

## What You've Built

A complete **autonomous CTF exploitation framework** with a solid foundation for automated vulnerability detection and exploitation.

## The 30-Second Version

- **What**: Autonomous CTF solver using decision trees
- **How**: Orchestrator runs detection/exploitation trees, flag recognizer halts on success
- **Why**: Deterministic, rule-based, no LLMs—pure expert logic
- **Status**: Phase 1 complete, ready for Phase 2

## The Next 5 Minutes

Read these in order:
1. **This file** (you're reading it)
2. **`.github/copilot-instructions.md`** (comprehensive dev guide)
3. **`README.md`** (project overview)
4. **`ctf_autopwn/core/types.py`** (data structures)

## The Next 30 Minutes

Explore the code:
```bash
# Install
python setup.py develop

# See what's there
cat ctf_autopwn/cli.py        # Entry point
cat ctf_autopwn/config.py     # Configuration
cat ctf_autopwn/core/orchestrator.py  # How it works

# Run the test
ctf-autopwn test
```

## The Next Hour

Pick a Phase 2 task and start implementing:

### Option 1: Tool Adapters
Start with the base `ToolAdapter` class in `adapters/base.py`:
- Abstract interface that all tool wrappers inherit from
- Normalize tool outputs to structured dicts
- See `.github/copilot-instructions.md` for the pattern

### Option 2: Web Vulnerability Trees
Start with a simple tree like `trees/web/sqli.py`:
- Implement `SQLiDetectionNode` - probe for SQL errors
- Implement `SQLiExploitNode` - extract data
- See `.github/copilot-instructions.md` for the pattern

### Option 3: Tool Adapters (Specific)
Implement `CurlAdapter` in `adapters/curl_adapter.py`:
- Wraps HTTP requests
- Normalizes response: `{status, headers, body}`
- Used by web trees for probing

## Key Architecture Points

### How It Works (Flow)

```
1. User provides ChallengeDescriptor (type, url/file, flag format)
2. Orchestrator.set_challenge(descriptor)
3. Orchestrator.run_tree(root_node)
   - Executes decision tree
   - Monitors all outputs via FlagRecognizer
   - Halts on flag detection
```

### Decision Trees

A decision tree is a network of `DecisionNode` implementations:

```python
class MyDetectionNode(DecisionNode):
    def run(self, context: Dict) -> NodeResult:
        # 1. Observe the target
        # 2. Return observations in NodeResult.data
        # 3. Flag recognizer checks outputs automatically
        return NodeResult(status=NodeStatus.SUCCESS, data={...})
    
    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        # Branch based on result
        if result.data.get("vulnerable"):
            return MyExploitNode(...)
        return None
```

### Shared Context

All nodes see and modify the same execution context:

```python
context = {
    "challenge": ChallengeDescriptor,
    "observations": {},
    "confirmed_vulns": [VulnDescriptor, ...],
    "flag_found": None,
}
```

### Tool Adapters

Thin wrappers that normalize outputs:

```python
class CurlAdapter(ToolAdapter):
    def run(self, url: str, args: Dict) -> Dict:
        # Execute: curl url ...args
        # Return: {status: 200, headers: {...}, body: "..."}
        pass
```

## Important Files

| File | What | Why |
|------|------|-----|
| `.github/copilot-instructions.md` | Architecture & dev guide | **Start here** |
| `ctf_autopwn/core/types.py` | All data types | Reference all types |
| `ctf_autopwn/core/orchestrator.py` | How execution works | Understand flow |
| `ctf_autopwn/core/nodes.py` | DecisionNode ABC | Create new nodes |
| `ctf_autopwn/config.py` | Global config | Paths, timeouts, patterns |
| `README.md` | Project overview | Context & research |

## Development Workflow

### To Add a New Decision Tree

1. Create `trees/category/vulnerability.py`
2. Implement detection nodes (inherit from `DecisionNode`)
3. Implement exploitation nodes
4. Register in the tree registry (TODO: create if needed)

### To Add a New Tool Adapter

1. Create `adapters/tool_adapter.py`
2. Inherit from `ToolAdapter` base class
3. Implement `run(target, args) -> Dict`
4. Normalize output to structured dict

### To Add a New Exploit Template

1. Create `templates/exploit_name.py`
2. Define template class with parameters
3. Generate payloads for specific vulnerabilities

## Common Tasks

### Debug a Node

Add logging to see what's happening:

```python
import logging
logger = logging.getLogger(__name__)

class MyNode(DecisionNode):
    def run(self, context):
        logger.debug(f"Challenge: {context['challenge']}")
        logger.debug(f"Observations so far: {context['observations']}")
        # ... do work ...
        logger.info(f"Found vulnerability: {result}")
```

Run with debug logging:
```bash
export CTF_AUTOPWN_LOG_LEVEL=DEBUG
ctf-autopwn solve web http://target.com
```

### Test a Node

Create a test file:

```python
from ctf_autopwn import ChallengeDescriptor, ChallengeType, get_orchestrator
from trees.web.sqli import SQLiDetectionNode

def test_sqli_detection():
    challenge = ChallengeDescriptor(
        type=ChallengeType.WEB,
        url="http://example.com/search?q=test",
    )
    
    orchestrator = get_orchestrator()
    orchestrator.set_challenge(challenge)
    
    node = SQLiDetectionNode("sqli_detect", "SQL Injection Detection")
    result = node.run(orchestrator.execution_context)
    
    assert result.status == NodeStatus.SUCCESS
    assert "vulnerable" in result.data
```

### Add a Flag Pattern

Edit `config.py`:

```python
FLAG_PATTERNS = [
    r"flag\{[^}]+\}",
    r"CTF\{[^}]+\}",
    r"FLAG\([^)]+\)",  # Custom pattern
]
```

## Phase 2 Checklist

- [ ] Create `adapters/base.py` with `ToolAdapter` ABC
- [ ] Implement `adapters/curl_adapter.py`
- [ ] Implement `adapters/nmap_adapter.py`
- [ ] Create `trees/web/__init__.py`
- [ ] Implement `trees/web/sqli.py` (detection + exploitation)
- [ ] Implement `trees/web/lfi.py`
- [ ] Implement `trees/web/xss.py`
- [ ] Write unit tests for adapters
- [ ] Write integration test with real target

## When You Get Stuck

1. **Read the architecture guide**: `.github/copilot-instructions.md`
2. **Check the types**: `ctf_autopwn/core/types.py`
3. **See how orchestrator works**: `ctf_autopwn/core/orchestrator.py`
4. **Look at existing nodes**: `ctf_autopwn/core/nodes.py` has `SimpleNode` as example
5. **Test in isolation**: Write a simple test for your component

## Key Principles

1. **Deterministic** - Every decision must be rule-based, not probabilistic
2. **Observable** - Probe the target to make informed decisions
3. **Modular** - Each vulnerability type is independent
4. **Graceful** - Escalate to human when automation fails
5. **Reproducible** - Execution logs explain what happened

## Remember

- The framework handles flag recognition globally—don't worry about it in nodes
- All nodes share the same execution context—use it to coordinate
- Tool adapters abstract away implementation details
- Escalate to human-in-the-loop when decisions are brittle
- Every tree is a network of nodes, not a linear sequence

---

**You're ready! Pick a Phase 2 task and start building.** 🚀
