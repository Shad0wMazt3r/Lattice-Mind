# CTF Autopwn - Quick Start Guide

## ✅ Status: Deployment Complete

Your CTF Autopwn framework is **fully deployed and tested locally**.

---

## 0. Launch the Web Dashboard (New!)

```bash
pip install -e .
uvicorn ctf_autopwn.api.server:app --host 0.0.0.0 --port 8000
# or run the shortcut
ctf-autopwn-api

# Docker option
docker compose up --build
```

Visit <http://localhost:8000> to submit challenge descriptors, stream solver status, and view execution logs/flags directly in your browser.

---

## 1. Verify Installation (30 seconds)

```bash
cd C:\Users\er123\OneDrive\Desktop\Projects\copilot
python test_deployment.py
```

**Expected Output:**
```
✅ PASS: Imports
✅ PASS: Framework
✅ PASS: Adapters
✅ PASS: Decision Nodes
✅ PASS: MVP Solver
✅ PASS: Tree Nodes

Total: 6/6 tests passed ✓
```

---

## 2. View Examples (5 minutes)

```bash
python example_usage.py
```

This shows:
1. **Web Challenge** - Detecting SQLi
2. **Binary Challenge** - Analyzing binary
3. **Crypto Challenge** - Solving cipher
4. **Forensics Challenge** - Extracting stego data
5. **Direct Node Execution** - Low-level API

---

## 3. Use in Your Code (Right Now)

```python
from ctf_autopwn.mvp import MVPSolver
from ctf_autopwn.core.types import ChallengeDescriptor, ChallengeType

# Create solver
solver = MVPSolver()

# Define challenge
challenge = ChallengeDescriptor(
    type=ChallengeType.WEB,
    name="My Challenge",
    url="http://vulnerable-app.local/search"
)

# Solve
flag = solver.solve(challenge)
print(f"Flag: {flag}")
```

---

## 4. Test Against Real Vulnerabilities (30 minutes)

### Option A: DVWA (Recommended)
```bash
# Set up DVWA
git clone https://github.com/digininja/DVWA.git
cd DVWA
docker-compose up -d

# Test against it
# Edit example_usage.py:
challenge = ChallengeDescriptor(
    type=ChallengeType.WEB,
    url="http://localhost/DVWA/vulnerabilities/sqli/"
)

# Run
python example_usage.py
```

### Option B: WebGoat
```bash
# Run WebGoat
docker run -p 8888:8888 -it webgoat/goatandwolf

# Test against it
challenge = ChallengeDescriptor(
    type=ChallengeType.WEB,
    url="http://localhost:8888/WebGoat/start.mvc"
)
```

---

## What's Included

### Framework
- 50 decision tree nodes (all working)
- 6 tool adapters with fallbacks
- MVPSolver for end-to-end integration
- Full type hints and error handling

### Detection Categories
| Category | Nodes | Coverage |
|----------|-------|----------|
| Web | 28 | SQLi, CMD, LFI, XSS, IDOR, Upload, SSRF |
| Binary | 5 | Stack overflow, Format string, ROP |
| Crypto | 7 | Encoding, Substitution, XOR, RSA |
| Forensics | 7 | Stego, PCAP, Memory, Disk |
| Classification | 5 | Route to specialized tree |
| **TOTAL** | **50** | **Autonomous exploitation** |

### Tools Supported
- HTTP requests (cURL/requests)
- Network scanning (nmap)
- Directory enumeration (ffuf/dirsearch)
- Binary analysis (binwalk)
- Metadata extraction (exiftool)
- File type detection (magic bytes)

---

## Common Tasks

### Import Framework in Notebook/Script
```python
from ctf_autopwn.mvp import MVPSolver
from ctf_autopwn.core.orchestrator import Orchestrator
from ctf_autopwn.core.types import ChallengeDescriptor, ChallengeType
```

### Create Custom Detection Node
```python
from ctf_autopwn.core.nodes import DecisionNode
from ctf_autopwn.core.types import NodeResult, NodeStatus

class MyNode(DecisionNode):
    def run(self, context):
        # Your detection logic
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={"finding": "something"}
        )
```

### Test Specific Vulnerability Type
```python
challenge = ChallengeDescriptor(
    type=ChallengeType.WEB,
    name="SQLi Test",
    url="http://target/search?q=",
    metadata={"suspected_vuln": "sql_injection"}
)

flag = solver.solve(challenge)
```

### Access Flag Recognizer
```python
from ctf_autopwn.core.flag_recognizer import get_flag_recognizer

recognizer = get_flag_recognizer()
text = "Here is flag{test_12345} somewhere"
flag = recognizer.recognize(text)  # Returns "flag{test_12345}"
```

---

## Documentation

**For Detailed Info:**
- `README.md` - Project overview
- `GETTING_STARTED.md` - Development setup
- `LOCAL_DEPLOYMENT.md` - Deployment guide
- `DEPLOYMENT_COMPLETE.md` - Full reference
- `MVP.md` - Architecture details
- `Architecture.md` - System design

---

## Next Steps

1. ✅ Run `python test_deployment.py` - Verify installation
2. ✅ Run `python example_usage.py` - See usage patterns
3. ✅ Launch FastAPI + dashboard (`ctf-autopwn-api` or `docker compose up`)
4. 🚀 Test against real vulnerabilities (DVWA, WebGoat)
5. 🚀 Push to GitHub (create private repo)
6. 🚀 Extend Docker/Kubernetes deployment for team usage

---

## Troubleshooting

### Tests Fail
```bash
pip uninstall -y ctf-autopwn
pip install -e .
python test_deployment.py
```

### Import Errors
```bash
# Make sure you're in the project directory
cd C:\Users\er123\OneDrive\Desktop\Projects\copilot
pip install -e .
```

### Missing Tools
Some adapters need system tools:
```bash
# Ubuntu/Debian
sudo apt-get install curl nmap binwalk exiftool

# macOS
brew install curl nmap binwalk exiftool

# Windows: Use WSL or install tools directly
```

---

## Command Reference

```bash
# Test everything
python test_deployment.py

# View examples
python example_usage.py

# Use in Python
python -c "from ctf_autopwn.mvp import MVPSolver; print(MVPSolver())"

# Check git status
git status

# View commit history
git log --oneline

# Install fresh
pip install -e . --force-reinstall
```

---

## Summary

✅ Framework: **Fully built** (50 nodes, 6 adapters, MVPSolver)  
✅ Testing: **All passing** (6/6 tests)  
✅ Documentation: **Complete** (examples, guides, API docs)  
✅ Ready for: **Real-world testing and deployment**  

**Start here:** `python test_deployment.py`

Then: `python example_usage.py`

Finally: Test against real vulnerabilities

---

**Questions?** See `LOCAL_DEPLOYMENT.md` or `MVP.md` for detailed information.
