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

## Quick Start

```bash
# Install
python setup.py install

# Run a test
ctf-autopwn test

# Solve a web challenge
ctf-autopwn solve web http://example.com:8080

# Solve a binary exploitation challenge
ctf-autopwn solve pwn /path/to/binary
```

## Project Status

**Phase 1 (Foundation)** - ✅ Complete
- Core types and data structures
- Base classes for nodes, engines, adapters
- Orchestrator framework
- CLI skeleton
- Flag recognizer
- Knowledge base
- Human-in-the-loop manager

**Phase 2** - Next
- Tool adapters (nmap, curl, binwalk, etc.)
- Web vulnerability detection trees
- Binary exploitation trees
- Crypto attack trees

**Phase 3** - Future
- Full decision tree implementations per category
- Exploit template library
- Performance optimizations
- Comprehensive test suite

## Research & Papers

This framework is based on:
- **Pangr** - Behavior-based vulnerability detection
- **Automated Exploit Generation (AEG)** - CGC systems
- **Classical CTF techniques** - Academic and community research

See `Research Paper - CTF Toolkit.md` for detailed analysis and references.

## Requirements

- Python 3.11+
- Linux environment with standard tools:
  - `nmap`, `curl`, `ffuf`/`dirsearch`
  - `binwalk`, `zsteg`, `exiftool`
  - `tshark`, `volatility`
  - `gdb`, `objdump`, `strings`
  - Crypto libraries (cryptography, pycryptodome, etc.)

## License

MIT

---

**Built for CTF players who want autonomous exploitation. Deterministic. Rule-based. No magic.**
