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

**State leakage:** `last_output` and `last_result` are instance fields. If an adapter instance is reused across runs without reinstantiation, stale results persist.

---

## curl_adapter.py — RequestsAdapter (primary) + CurlAdapter (fallback)

The file is named `curl_adapter.py` but the primary class is `RequestsAdapter` which uses the Python `requests` library. `CurlAdapter` is a subprocess fallback.

### RequestsAdapter

```python
class RequestsAdapter(ToolAdapter):
    def __init__(self):
        self._session = requests.Session()   # one session per instance
        # Cookies from target Set-Cookie responses persist within this session
```

```python
def run(self, target: str, args: Dict[str, Any]) -> Dict[str, Any]:
    method = args.get("method", "GET").lower()
    headers = args.get("headers", {})
    params  = args.get("params", {})    # BUG: not URL-encoded (Bug 8)
    body    = args.get("body")
    timeout = args.get("timeout", 10)

    response = getattr(self._session, method)(
        target,
        headers=headers,   # BUG: CRLF not stripped (Bug 10)
        params=params,
        data=body,
        timeout=timeout,
        verify=False       # SSL verification disabled
    )
    return {
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "body": response.text,
        "url": response.url,
    }
```

### Known issues

| Bug | Location | Detail |
|-----|----------|--------|
| **Bug 8** | `params` building | `{k: v}` dict passed to requests but values not manually sanitized — special chars in values can corrupt query string in edge cases with manual string building elsewhere |
| **Bug 10** | `headers` passthrough | YAML header values containing `\r\n` passed directly to requests. `requests` ≥2.26 rejects some CRLF but behavior varies by version |
| **Bug 9** | HTTPS to IP | No SNI override; many TLS stacks reject IP as SNI value |
| **Bug 18** | Session persistence | `requests.Session` accumulates `Set-Cookie` from target responses; if adapter instance is reused, attacker cookies replay on next request |

### Query param encoding (manual paths)

In parts of executor that manually build query strings (`f"{k}={v}"`), `&`, `=`, unicode, and spaces in values corrupt the string. Fix: use `urllib.parse.urlencode()`.

---

## ffuf_adapter.py — FFUFAdapter

Wraps `ffuf` (directory/parameter fuzzer) via subprocess.

```python
class FFUFAdapter(CommandToolAdapter):
    DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
    OUTPUT_FILE = "/tmp/ffuf_output.json"    # BUG: shared fixed path (Bug 12)
    timeout = 300
```

### run() flow

```python
def run(self, target: str, args: Dict[str, Any]) -> Dict[str, Any]:
    try:
        os.remove(self.OUTPUT_FILE)    # delete previous result
    except FileNotFoundError:
        pass
    cmd = self.build_command(target, args)
    output = self.execute_command(cmd)
    with open(self.OUTPUT_FILE) as f:
        data = json.load(f)            # reads whoever wrote last (Bug 12)
    return self.normalize_output(data)
```

### build_command() args

| Key | Default | Type |
|-----|---------|------|
| `wordlist` | DEFAULT_WORDLIST | str |
| `extensions` | `[]` | list of str |
| `match_status` | `[200,204,301,302,307,401,403]` | list of int |
| `threads` | `100` | int (no validation) |
| `timeout` | `5` | int (per-request, separate from subprocess timeout) |
| `headers` | `{}` | dict |
| `recursive` | `False` | bool |
| `depth` | `2` | int |

**No type validation** — non-numeric `threads` or `timeout` becomes a string in the command without error until ffuf rejects it.

### Known issues

| Bug | Detail |
|-----|--------|
| **Bug 12** (Critical) | `/tmp/ffuf_output.json` is a fixed shared path. Concurrent ffuf runs from different solver instances overwrite each other. Run A reads Run B's results as its own. Fix: `tempfile.mkstemp()` per invocation. |
| No aggregate timeout | Per-request `-timeout 5` is separate from subprocess timeout (300s). A very large wordlist runs for the full subprocess timeout. |
| Error swallowing | Broad `except Exception` in JSON parse — failures produce `{"error": "..."}` silently |

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

Fallback when nmap unavailable. Uses `nc -zv -w 2` per port.

```python
for port in ports:           # iterates every port in range
    cmd = ["nc", "-zv", "-w", "2", target, str(port)]
    try:
        output = self.execute_command(cmd)
    except RuntimeError:
        pass                 # swallows ALL RuntimeError — closed port AND timeout AND crash
```

### Known issues

| Bug | Detail |
|-----|--------|
| **Bug 13** (High) | `SimplePortScanAdapter` has no aggregate deadline. Scanning ports 1–65535 at 60s per call = up to 65535 minutes. `self.timeout` applies per `nc` call, not to the whole scan loop. |
| Input validation absent | `ports`, `target`, `scripts` values not sanitized — nmap argument injection possible |
| Memory | `len(list(ports))` materializes full range iterator for logging — wasteful for large ranges |
| Error swallowing | `except RuntimeError: pass` masks timeouts and unexpected errors alongside expected "port closed" |

---

## file_adapter.py — BinwalkAdapter, ExiftoolAdapter, FileTypeAdapter

File analysis adapters. All use `CommandToolAdapter.execute_command()`.

### BinwalkAdapter

```python
class BinwalkAdapter(CommandToolAdapter):
    timeout = 60

    def build_command(self, target: str, args: Dict) -> List[str]:
        cmd = ["binwalk"]
        if args.get("extract", False):
            cmd.append("-e")    # writes extracted files to disk — no output dir control
        cmd.append(target)      # no path validation
        return cmd
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
