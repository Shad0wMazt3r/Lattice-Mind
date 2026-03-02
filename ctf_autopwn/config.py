"""Global configuration for CTF autopwn toolkit."""
import re
from pathlib import Path
from typing import Dict, List

# Flag patterns - can be extended per CTF
FLAG_PATTERNS: List[str] = [
    r"flag\{[^}]+\}",
    r"FLAG\{[^}]+\}",
    r"ctf\{[^}]+\}",
    r"CTF\{[^}]+\}",
    r"flag\([^)]+\)",
    r"FLAG\([^)]+\)",
]

# Compiled regex patterns for flag matching
COMPILED_FLAG_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in FLAG_PATTERNS]

# Default tool paths (customize per system)
TOOL_PATHS: Dict[str, str] = {
    "nmap": "nmap",
    "curl": "curl",
    "ffuf": "ffuf",
    "dirsearch": "dirsearch",
    "binwalk": "binwalk",
    "exiftool": "exiftool",
    "zsteg": "zsteg",
    "tshark": "tshark",
    "volatility": "volatility",
    "file": "file",
    "strings": "strings",
    "objdump": "objdump",
    "checksec": "checksec",
    "gdb": "gdb",
    "pwntools": "python3",  # via python -c "import pwntools; ..."
}

# Timeouts (in seconds)
TIMEOUTS: Dict[str, float] = {
    "tool_execution": 30.0,
    "http_request": 10.0,
    "port_scan": 60.0,
    "directory_scan": 120.0,
    "crypto_attack": 300.0,
}

# Project root
PROJECT_ROOT = Path(__file__).parent.parent
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
ARTIFACTS_DIR.mkdir(exist_ok=True)

# Logging
LOG_LEVEL = "INFO"
