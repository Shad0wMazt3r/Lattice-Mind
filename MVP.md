# CTF Autopwn MVP - Autonomous Exploitation Framework

**Status:** MVP Ready for Integration Testing

## Overview

CTF Autopwn is an **autonomous, decision-tree-based vulnerability detection framework** that deterministically identifies and exploits CTF challenges without machine learning or LLMs. It uses classical security analysis techniques grounded in research.

## Architecture

### Core Components

1. **Orchestrator** (`ctf_autopwn/core/orchestrator.py`)
   - Central execution engine
   - Manages challenge state
   - Monitors for flag detection
   - Coordinates between detection trees

2. **Decision Tree Framework** (`ctf_autopwn/core/nodes.py`)
   - Base `DecisionNode` ABC
   - Every node: `run(context) → NodeResult`
   - Every node: `next_node(result) → Optional[DecisionNode]`
   - Deterministic routing based on observations

3. **Detection Trees** (50 total nodes across 5 categories)
   - **Asset Classification (D-0)**: 5 nodes - Route challenges to specialized trees
   - **Web Vulnerabilities (W-*)**: 28 nodes - SQLi, CMD, LFI, XSS, IDOR, Upload, SSRF
   - **Binary Exploitation (P-Detect)**: 5 nodes - Stack overflow, format strings, etc.
   - **Cryptography (C-Detect)**: 5 nodes - Encoding, substitution, XOR, RSA, stream cipher
   - **Forensics/Stego (F-Detect)**: 7 nodes - Images, PCAP, memory dumps, embedded files

4. **Tool Adapters** (`ctf_autopwn/adapters/`)
   - `CurlAdapter` - HTTP requests for web testing
   - `NmapAdapter` - Network scanning
   - `FFufAdapter` - Directory/parameter enumeration
   - `BinwalkAdapter` - Embedded file extraction
   - `ExiftoolAdapter` - Metadata extraction
   - `FileTypeAdapter` - File type detection

5. **Global Services**
   - **FlagRecognizer** - Automatically detects flags in ALL outputs
   - **KnowledgeBase** - Registry of vulnerability archetypes
   - **HumanLoop** - Escalation when automation uncertain

### MVP Entry Point

The **MVPSolver** (`ctf_autopwn/mvp.py`) orchestrates the complete workflow:

```
Challenge Input
    ↓
[Asset Classification D-0]
    ↓
├─→ [Web Detection W-*] ──→ SQLi/CMD/LFI/XSS/IDOR/Upload/SSRF
├─→ [Binary Detection P-Detect] ──→ Stack Overflow/Format String/etc.
├─→ [Crypto Detection C-Detect] ──→ Encoding/Substitution/XOR/RSA/Stream
└─→ [Forensics Detection F-Detect] ──→ Stego/PCAP/Memory/Embedded

[Global Flag Recognizer monitors ALL outputs]
    ↓
Flag Output / Human-in-the-Loop
```

## How It Works

### 1. Challenge Classification

The framework first runs **Asset Classification Tree (D-0)** which:
- Checks if target is a network endpoint → **WEB**
- Checks if it's a binary file → **PWN**
- Checks if it's a container → **FORENSICS**
- Checks if it's crypto text → **CRYPTO**
- Falls back to **MISC**

```python
from ctf_autopwn.trees.asset.classify import AssetClassifyNetworkNode
root = AssetClassifyNetworkNode()
asset_type = orchestrator.run_tree(root)
```

### 2. Vulnerability Detection

Each category has specialized detection trees using rule-based logic:

#### Web Vulnerabilities
- **SQLi**: Boolean-based, error-based, union-based probes
- **CMD**: Output-based and time-based blind detection
- **LFI**: Path traversal with encoding bypass attempts
- **XSS**: Reflected, stored, and filter bypass tests
- **IDOR**: ID enumeration
- **Upload**: Restriction bypass testing
- **SSRF**: URL parameter testing

#### Binary Exploitation
- Static analysis: binary metadata, symbols, dangerous functions
- Pattern detection: stack arrays + unbounded reads
- Format string detection: printf with user input
- Symbolic execution hooks for dynamic analysis

#### Cryptography
- Iterative decoding (base64, hex, URL encoding)
- Frequency analysis (index of coincidence for substitution)
- Brute force (XOR 256 keys, Caesar 26 shifts)
- RSA parameter extraction and attack planning
- Stream cipher reuse detection

#### Forensics
- Image steganography (zsteg for LSB/DCT)
- Embedded file carving (binwalk)
- Metadata extraction (exiftool)
- PCAP reconstruction (tshark)
- Memory dump analysis (volatility)

### 3. Flag Detection

The **FlagRecognizer** is a global singleton that monitors all outputs:
- Automatically detects `flag{...}`, `ctf{...}`, `FLAG{...}` patterns
- Case-insensitive matching
- Runs on every node output without explicit checks
- Returns immediately when flag found

## Usage Examples

### Basic Usage

```python
from ctf_autopwn.mvp import MVPSolver
from ctf_autopwn.core.types import ChallengeDescriptor, ChallengeType

# Create solver
solver = MVPSolver()

# Define challenge
challenge = ChallengeDescriptor(
    id="ctf_001",
    name="SQL Injection",
    type=ChallengeType.WEB,
    url="http://target.com/search",
    description="Find the flag"
)

# Solve autonomously
flag = solver.solve(challenge)
print(f"Flag: {flag}")
```

### Custom Detection Tree

```python
from ctf_autopwn.core.orchestrator import Orchestrator
from ctf_autopwn.trees.web.sqli import SQLiDetectReflectionNode

orchestrator = Orchestrator()
orchestrator.set_challenge(challenge)

root = SQLiDetectReflectionNode()
flag = orchestrator.run_tree(root)
```

### Chain Multiple Trees

```python
# Manually run multiple detection trees
web_root = WebReconProbeNode()
flag = orchestrator.run_tree(web_root)

if not flag:
    pwn_root = PwnDetectMetadataNode()
    flag = orchestrator.run_tree(pwn_root)

if not flag:
    crypto_root = CryptoDetectEncodingNode()
    flag = orchestrator.run_tree(crypto_root)
```

## Implementation Details

### Decision Node Pattern

Every node implements this interface:

```python
class MyDetectionNode(DecisionNode):
    def __init__(self):
        super().__init__("node_id", "Display Name")
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Execute detection logic."""
        challenge = context.get("challenge")
        
        try:
            # Perform detection
            result_data = {...}
            
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data=result_data
            )
        except Exception as e:
            return NodeResult(
                status=NodeStatus.FAILURE,
                error=str(e)
            )
    
    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        """Route to next node based on result."""
        if result.status == NodeStatus.SUCCESS:
            if result.data.get("is_vulnerable"):
                return ExploitNode()
            else:
                return AnotherDetectionNode()
        return None
```

### Context Passing

Shared execution context allows nodes to:
- Access challenge descriptor
- Read observations from previous nodes
- Store findings for downstream nodes
- Monitor execution history

```python
context = {
    "challenge": ChallengeDescriptor(...),
    "observations": {
        "is_reflected": True,
        "response_hash": "abc123...",
        "parameter": "id",
        # ... shared state
    }
}
```

### Error Handling

Graceful degradation:
- Missing tools → fallback to alternative tools
- Network errors → automatic retry with backoff
- Parse failures → continue with limited data
- Timeouts → escalate to human-in-the-loop

## Project Structure

```
ctf-autopwn/
├── ctf_autopwn/
│   ├── core/
│   │   ├── types.py              # Data types, enums
│   │   ├── nodes.py              # DecisionNode ABC
│   │   ├── orchestrator.py       # Central execution engine
│   │   ├── flag_recognizer.py    # Global flag detector
│   │   ├── knowledge_base.py     # Vulnerability registry
│   │   └── human_loop.py         # Interactive fallback
│   ├── adapters/
│   │   ├── base.py               # ToolAdapter ABC
│   │   ├── curl_adapter.py       # HTTP requests
│   │   ├── nmap_adapter.py       # Network scanning
│   │   ├── ffuf_adapter.py       # Directory enumeration
│   │   └── file_adapter.py       # File analysis (binwalk, exiftool)
│   ├── engines/
│   │   ├── detection.py          # DetectionEngine ABC
│   │   └── exploitation.py       # ExploitationEngine ABC
│   ├── trees/
│   │   ├── asset/
│   │   │   ├── __init__.py
│   │   │   └── classify.py       # Asset classification (D-0)
│   │   ├── web/
│   │   │   ├── __init__.py
│   │   │   ├── recon.py          # Web reconnaissance
│   │   │   ├── sqli.py           # SQL injection
│   │   │   ├── cmd.py            # Command injection
│   │   │   ├── lfi.py            # Local file inclusion
│   │   │   ├── xss.py            # XSS detection
│   │   │   └── additional.py     # IDOR, upload, SSRF
│   │   ├── pwn/
│   │   │   ├── __init__.py
│   │   │   └── detect.py         # Binary exploitation (P-Detect)
│   │   ├── crypto/
│   │   │   ├── __init__.py
│   │   │   └── detect.py         # Cryptography (C-Detect)
│   │   └── forensics/
│   │       ├── __init__.py
│   │       └── detect.py         # Forensics/Stego (F-Detect)
│   ├── config.py                 # Global configuration
│   ├── cli.py                    # CLI interface
│   ├── mvp.py                    # MVP solver
│   └── __init__.py
├── setup.py
├── README.md
├── GETTING_STARTED.md
├── Architecture.md
├── detections.md                 # Research document
├── .gitignore
└── .github/
    └── copilot-instructions.md
```

## Statistics

- **Total Lines of Code**: ~12,000
- **Decision Tree Nodes**: 50
- **Tool Adapters**: 6
- **Git Commits**: 6
- **Test Coverage**: Framework ready for integration testing

## Technology Stack

- **Language**: Python 3.8+
- **Type Hints**: Full type coverage
- **Logging**: Structured logging throughout
- **Dependencies**: 
  - requests (for HTTP)
  - click (for CLI)
  - Optional: pycryptodome (crypto), sympy (RSA)

## Running the MVP

### Installation

```bash
cd ctf-autopwn
pip install -e .
```

### Run MVPSolver Directly

```bash
python -m ctf_autopwn.mvp
```

### Use in Your Code

```python
from ctf_autopwn.mvp import MVPSolver
from ctf_autopwn.core.types import ChallengeDescriptor, ChallengeType

solver = MVPSolver()
flag = solver.solve(challenge_descriptor)
```

### CLI Usage

```bash
ctf-autopwn solve --challenge-file challenge.json
ctf-autopwn detect --type web --target http://vulnerable-app.com
ctf-autopwn test --category sqli --endpoint /search
```

## Next Steps for Full Implementation

### Phase 4: API & Web UI (Not in MVP)
- FastAPI REST API
- React.js web dashboard
- Real-time progress monitoring
- Challenge management UI

### Phase 5: Exploitation Templates (Not in MVP)
- ret2win exploit builder
- ROP gadget finder
- Crypto attack templates
- Forensics automation

### Phase 6: Docker & Deployment (Not in MVP)
- Dockerfile with all tools
- Docker Compose setup
- Kubernetes manifests
- Cloud deployment guides

## Contributing

The framework is designed for extensibility:

1. **Add Detection Tree**: Create new `DecisionNode` in appropriate category
2. **Add Tool Adapter**: Implement `ToolAdapter` interface
3. **Add Exploitation**: Implement `ExploitationEngine` for new vuln type
4. **Improve Heuristics**: Update detection logic in existing nodes

## License

TBD

## References

- **Architecture Document**: `Architecture.md`
- **Detection Methodologies**: `detections.md`
- **Development Guide**: `.github/copilot-instructions.md`
- **Getting Started**: `GETTING_STARTED.md`

---

**Built with expert rules, not machine learning. Autonomous exploitation for CTF challenges.**
