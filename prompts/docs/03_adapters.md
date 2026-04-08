# Adapters Reference

> Covers: `adapters/base.py`, `adapters/curl_adapter.py`, `adapters/ffuf_adapter.py`, `adapters/nmap_adapter.py`, `adapters/file_adapter.py`

---

## base.py — ToolAdapter & CommandToolAdapter

### ToolAdapter (ABC)

```python
class ToolAdapter(ABC):
    timeout: int          # default varies by subclass
    last_output: str      # mutated after every execute_command — shared state risk
    last_result: Dict     # same

    @abstractmethod
    def run(self, target: str, args: Dict[str, Any]) -> Dict[str, Any]: ...
    @abstractmethod
    def build_command(self, target: str, args: Dict[str, Any]) -> List[str]: ...
    def normalize_output(self, raw: str) -> Dict[str, Any]: ...
```

### CommandToolAdapter

Extends `ToolAdapter`. Provides `execute_command()`.

```python
def execute_command(self, cmd: List[str]) -> str:
    result = subprocess.run(
        cmd,                # ALWAYS a list — no shell=True (no classic shell injection)
        capture_output=True,
        text=True,
        timeout=self.timeout,   # per-call timeout in seconds
        check=False
    )
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {result.stderr}")
    return result.stdout
```

**No shell=True** — argv list prevents classic shell injection. Risk is argument injection into the tool itself (e.g., nmap `--script` injection via `ports` string).

**State leakage:** `last_output` and `last_result` are instance fields. Adapter instances should not be reused across concurrent operations.

---

## curl_adapter.py — RequestsAdapter (primary) + CurlAdapter (fallback)

The file is named `curl_adapter.py` but the primary class is `RequestsAdapter` which uses the Python `requests` library. `CurlAdapter` is a subprocess fallback.

### RequestsAdapter

```python
class RequestsAdapter(ToolAdapter):
    def __init__(self, timeout=10.0):
        # Uses stateless requests.request() — no Session, no cookie persistence

def run(self, target: str, args: Dict[str, Any]) -> Dict[str, Any]:
    method  = args.get("method", "GET").upper()
    headers = dict(args.get("headers", {}))
    params  = args.get("params", {}) or {}      # passed to requests as dict — URL-encoded automatically
    data    = args.get("data")
    json_body = args.get("json")
    sni_hostname = args.get("sni_hostname", "")  # optional SNI override — sets Host header
    cookies = args.get("cookies")

    response = requests.request(method, target, headers=headers,  # BUG 10 (open): CRLF not stripped
                                params=params, data=data, ...)
```

### Open issue

| Bug | Detail |
|-----|--------|
| **Bug 10** (High, open) | `headers` dict passed to `requests.request()` without CRLF sanitization. YAML step headers containing `\r\n` can inject extra headers. Fix: strip `\r`/`\n` from all header names/values before dispatch. |

---

## ffuf_adapter.py — FFUFAdapter

Wraps `ffuf` (directory/parameter fuzzer) via subprocess.

```python
class FFUFAdapter(CommandToolAdapter):
    OUTPUT_FILE = "/tmp/ffuf_output.json"    # legacy constant — not used for concurrent runs
    DEFAULT_WORDLIST = "/usr/share/dirb/wordlists/common.txt"
    timeout = 300
```

### run() flow

Per-run temp file is created via `tempfile.mkstemp()` to prevent cross-run collision. The `OUTPUT_FILE` constant remains for backward-compat pre-run cleanup only.

```python
def run(self, target: str, args: Dict[str, Any]) -> Dict[str, Any]:
    fd, output_file = tempfile.mkstemp(prefix="ffuf_", suffix=".json")
    os.close(fd)
    merged_args["_output_file"] = output_file
    cmd = self.build_command(target, merged_args)
    ...
```

### build_command() args

| Key | Default | Type |
|-----|---------|------|
| `wordlist` | DEFAULT_WORDLIST | str |
| `extensions` | `[]` | list of str |
| `match_status` | auto-calibrate | list of int |
| `threads` | `100` | int |
| `timeout` | `5` | int (per-request) |
| `headers` | `{}` | dict |

### Remaining issue

| Issue | Detail |
|-------|--------|
| Stale class constant | `OUTPUT_FILE = "/tmp/ffuf_output.json"` still defined; can confuse readers. Safe to remove along with the `os.remove(self.OUTPUT_FILE)` pre-run cleanup. |

---

## nmap_adapter.py — NmapAdapter + SimplePortScanAdapter

### NmapAdapter

Uses `nmap` binary. Output is XML, parsed with `xml.etree.ElementTree`.

```python
class NmapAdapter(CommandToolAdapter):
    timeout = 60

    def build_command(self, target: str, args: Dict) -> List[str]:
        ports   = args.get("ports", "1-1000")    # no charset validation
        scripts = args.get("scripts", [])
        cmd = ["nmap", "-oX", "-", "-p", ports, target]
        for s in scripts:
            cmd.extend(["--script", s])           # potential argument injection
        return cmd
```

### SimplePortScanAdapter

Fallback when nmap unavailable. Uses `nc -zv -w 2` per port. Enforces aggregate deadline via `max_total_seconds` (default 30s).

```python
max_total_seconds = float(args.get("max_total_seconds", 30.0))
started_at = time.monotonic()
for port in ports:
    if time.monotonic() - started_at >= max_total_seconds:
        break   # aggregate deadline enforced
    ...
```

### Notes

| Issue | Detail |
|-------|--------|
| Input validation absent | `ports`, `target`, `scripts` values not sanitized — nmap argument injection possible |
| Error swallowing | `except RuntimeError: pass` masks timeouts and unexpected errors alongside expected "port closed" |

---

## file_adapter.py — BinwalkAdapter, ExiftoolAdapter, FileTypeAdapter

File analysis adapters. All use `CommandToolAdapter.execute_command()`.

### BinwalkAdapter

```python
cmd = ["binwalk"]
if args.get("extract", False):
    cmd.append("-e")    # writes extracted files to disk — no output dir control
cmd.append(target)      # no path validation
```

### ExiftoolAdapter

```python
cmd = ["exiftool", "-j", target]   # -j = JSON output; target not validated
```

### FileTypeAdapter

```python
cmd = ["file", "-b", target]
```

### Shared issues across file adapters

| Issue | Detail |
|-------|--------|
| No path validation | `target` passed directly as argv — arbitrary file path. No symlink policy, no boundary enforcement. |
| `binwalk -e` disk writes | Extracted files written to CWD or `_target.extracted/` — could fill disk or overwrite files if target path is crafted |
| Error swallowing | All three: `except Exception` with `result["error"] = str(e)` |
| `last_output` / `last_result` | Instance-level shared state; reuse across runs leaks previous result |

---

## Adapter Instantiation Pattern

In `executor.py`:
```python
adapter = RequestsAdapter()   # new instance per step
```

In `mvp.py` / `orchestrator.py` (legacy Python trees):
```python
# Adapters created at solve-time and may be shared across nodes in the tree
```

**Rule of thumb for new code:** always instantiate adapters per-step or per-run, never share across concurrent operations.
