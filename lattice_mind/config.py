"""Global configuration for Lattice Mind CTF automation toolkit."""
import re
from pathlib import Path
from typing import Dict, List

# Flag patterns - can be extended per CTF
FLAG_PATTERNS: List[str] = [
    r"picoCTF\{[^}]+\}",
    r"flag\{[^}]+\}",
    r"FLAG\{[^}]+\}",
    r"ctf\{[^}]+\}",
    r"CTF\{[^}]+\}",
    r"flag\([^)]+\)",
    r"FLAG\([^)]+\)",
    # env-style: FLAG=picoCTF{...} or CTF_FLAG=...
    r"(?:FLAG|flag|CTF_FLAG|ctf_flag)\s*=\s*(\S+\{[^}]+\})",
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

# Web crawl frontier (F4) — defaults match ROADMAP recommended limits
CRAWL_MAX_DEPTH: int = 3
CRAWL_MAX_PAGES: int = 50
CRAWL_MAX_REQUEST_CANDIDATES: int = 200
CRAWL_MAX_QUEUE_SIZE: int = 500
CRAWL_MAX_ENDPOINTS: int = 200
CRAWL_MAX_PARAMS: int = 200
CRAWL_MAX_FORM_SUBMISSIONS: int = 10
# YAML TreeExecutor baseline probe specs from recon (was hard-coded [:2])
MAX_PROBE_BASE_SPECS: int = 30


# ── Feature Flags ─────────────────────────────────────────────────────────────
class FeatureFlags:
    """Simple mutable feature-flag singleton readable by any module."""
    dir_scan_enabled: bool = False  # off by default (slow); toggle via UI
    crawl_max_depth: int = CRAWL_MAX_DEPTH
    crawl_max_pages: int = CRAWL_MAX_PAGES
    crawl_max_request_candidates: int = CRAWL_MAX_REQUEST_CANDIDATES
    crawl_max_queue_size: int = CRAWL_MAX_QUEUE_SIZE
    crawl_max_endpoints: int = CRAWL_MAX_ENDPOINTS
    crawl_max_params: int = CRAWL_MAX_PARAMS
    crawl_max_form_submissions: int = CRAWL_MAX_FORM_SUBMISSIONS
    max_probe_base_specs: int = MAX_PROBE_BASE_SPECS


FEATURE_FLAGS = FeatureFlags()

# Response differential / evidence (F3) — conservative defaults; timing is noisy on real networks.
RESPONSE_DIFF_TIMING_THRESHOLD_MS: float = 500.0
RESPONSE_DIFF_TIMING_EVIDENCE_MS: float = 800.0
RESPONSE_DIFF_BODY_SIMILARITY_HIGH: float = 0.92
RESPONSE_DIFF_MAX_HEADER_CHANGES: int = 12
RESPONSE_DIFF_MAX_TOKENS: int = 40
RESPONSE_DIFF_AUTH_COOKIE_NAMES: tuple = (
    "session",
    "jwt",
    "token",
    "sid",
    "auth",
    "access_token",
    "refresh",
    "id_token",
)
