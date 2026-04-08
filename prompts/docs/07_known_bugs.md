# Known Bugs & Open Issues

> Only unresolved and partially-resolved issues are tracked here.  
> Last verified: 2026-04-07.  
> 19 of 25 original audit bugs have been fully fixed and removed from this doc.

---

## Open (Not Fixed)

### Bug 10 — CRLF injection via unsanitized header values
- **File:** `adapters/curl_adapter.py` line 248
- **Severity:** High
- **Detail:** `RequestsAdapter.run()` passes the `headers` dict directly to `requests.request()` with no sanitization. YAML step headers can contain `\r\n` sequences that inject extra headers into the outgoing request.
- **Fix:** Add `_sanitize_headers(headers)` that strips `\r` and `\n` from all header names and values before dispatch.

## Partially Fixed

### Bug 1 — ReDoS via YAML-controlled signal regex
- **File:** `core/executor.py` lines 556–565
- **Severity:** Critical
- **What's done:** `_safe_signal_search()` compiles and caches regexes in `_signal_regex_cache`, preventing repeated compilation.
- **What's missing:** No execution timeout on `compiled.search(body)`. A crafted regex against a large response body can still cause exponential backtracking.
- **Remaining fix:** Wrap `compiled.search(body)` in a timeout — `signal.alarm(1)` on Unix or Python 3.11+ `re` timeout support.

### Bug 12 — Shared `/tmp/ffuf_output.json` — cross-run data mixing
- **File:** `adapters/ffuf_adapter.py` lines 34, 109, 113
- **Severity:** Critical
- **What's done:** `run()` creates a per-run temp file via `tempfile.mkstemp()` (line 113). Concurrent runs no longer collide on results.
- **What's missing:** The class-level `OUTPUT_FILE = "/tmp/ffuf_output.json"` constant still exists and is referenced for a backward-compat pre-run cleanup (line 109). The constant itself is dead weight and could confuse future readers.
- **Remaining fix:** Remove the `OUTPUT_FILE` class constant and the `os.remove(self.OUTPUT_FILE)` cleanup block.

### Bug 23 — Opaque exception strings to agent
- **File:** `mcp/server.py` lines 639, 657
- **Severity:** Medium
- **What's done:** Some error responses include an `error_code` field (`"invalid_arguments"`, `"request_failed"`).
- **What's missing:** No `LatticeError` exception hierarchy. Unhandled exception paths still return raw Python exception strings (e.g., `AttributeError`, `KeyError`) to the agent with no structured code.
- **Remaining fix:** Introduce `LatticeError(code, message)` and map all exception handlers in `_call_tool` to return `{"error_code": e.code, "message": str(e)}`.
