## 4. Autonomous vulnerability detection framework

### 4.1 Asset discovery and classification

**Goal:** Map each challenge to one of {web service, pwn/binary, crypto, forensics/misc} using observable features.

**Detection Decision Tree D‑0: Asset classification**

1. Node D‑0.1: “Is it a network endpoint?”
    - If given host:port or URL → treat as candidate **web/service** target.
    - Else go to D‑0.2.
2. Node D‑0.2: “Is it a binary file?”
    - Run `file artifact`. If ELF/PE → **pwn/binary**.
    - Else go to D‑0.3.
3. Node D‑0.3: “Is it a container of other files?”
    - If `file` / magic indicates zip/tar/pcap/disk image → **forensics**.
    - Else go to D‑0.4.
4. Node D‑0.4: “Is it textual crypto?”
    - If artifact is ASCII text with high entropy or clear cipher pattern (alphabetic only, hex, base64 etc.) → **crypto**.
    - Else mark as **misc** and fall back to generic heuristics (strings, binwalk, etc.).

This coarse classification drives which specialized detection tree runs next.

***

### 4.2 Web vulnerability detection

We focus on recurring web CTF vulns: SQLi, command injection, path traversal/LFI, file upload abuse, IDOR, CSRF, XSS, SSRF, JWT weaknesses, and backup/config leakage.[^19][^26][^27][^18]

#### 4.2.1 Web reconnaissance

**Detection Decision Tree W‑Recon: Service and surface discovery**

1. Node W‑R.1: “Is HTTP(S) reachable?”
    - Run `nmap -sV -Pn -p80,443,8000-9000 host`. If HTTP detected → proceed.
    - If service banners show other protocols (FTP, SSH) → optionally spawn protocol‑specific trees.
2. Node W‑R.2: “Enumerate paths and parameters.”
    - Use `ffuf`/`dirsearch` with wordlists to find directories and files (e.g., `/admin`, `/api`, `/upload`).[^37]
    - For each endpoint, crawl HTML forms and query parameters to build a parameter corpus.
3. Node W‑R.3: “Classify parameters.”
    - Based on names and values, categorize parameters as:
        - **ID‑like** (`id`, `user`, `post`, numeric).
        - **File‑like** (`file`, `path`, `page`, strings ending in extensions).
        - **URL‑like** (`url`, `callback`, `redirect`).
        - **Free‑form text / search.**
4. Node W‑R.4: “Select detection subtrees.”
    - ID‑like → IDOR/SQLi.
    - File‑like → LFI/path traversal.
    - URL‑like → SSRF.
    - Anything with uploads → file upload/webshell.
    - Generic input → XSS, command injection, SQLi.

This pre‑processing generates a structured target graph for subsequent specific detection trees.

#### 4.2.2 SQL injection detection

SQLi is routinely taught as a primary CTF web technique.[^27][^18][^19]

**Detection Decision Tree W‑SQLi‑Detect**

Given endpoint E with parameter p:

1. Node W‑S.1: “Is p reflected?”
    - Send benign value; if response echoes it (e.g., search/result page), mark as reflection point.
2. Node W‑S.2: “Boolean‑based probes.”
    - Send baseline: `p=1`. Record body hash/length.
    - Send `p=1' AND '1'='1` and `p=1' AND '1'='0`.
    - If responses differ (status code, length, or key string differences) → label as **likely SQLi**.
3. Node W‑S.3: “Error‑based signatures.”
    - Send payloads like `p='` and check for DB error substrings (“SQL syntax”, “near '”, “sqlite_error”, “pg_query”).
4. Node W‑S.4: “Union‑based hints.”
    - Try `ORDER BY`/`UNION SELECT` probes; if errors switch to success after tuning column counts, mark as **confirmed SQLi**.

The detection outcome attaches a vulnerability descriptor: `{type: "SQLi", technique: "boolean/union/error", endpoint: E, param: p}`.

#### 4.2.3 Command injection detection

**Detection Decision Tree W‑CMD‑Detect**

1. Node W‑C.1: “Is parameter semantically command‑ish?”
    - Name matches `host`, `ip`, `cmd`, `target`, or appears in `ping/traceroute`‑like endpoints.
2. Node W‑C.2: “Output‑based probes.”
    - Send value `127.0.0.1;echo CMDTEST` (and variants using `&&`, `|`).
    - If response includes `CMDTEST` or command output (e.g., `uid=0(root)`), mark as **command injection**.
3. Node W‑C.3: “Blind timing probes.”
    - If output not directly reflected, send `127.0.0.1; sleep 5` and measure latency vs. baseline.
    - Significant delay indicates blind command execution.

#### 4.2.4 Path traversal / LFI detection

**Detection Decision Tree W‑LFI‑Detect**

1. Node W‑L.1: “File‑like parameter?”
    - If value ends with `.php`, `.html`, `.txt` or file/path‑style names → candidate.
2. Node W‑L.2: “Traversal probes.”
    - Try `../../../../etc/passwd` (properly URL‑encoded).
    - If response contains `root:x:0:0` or other `/etc/passwd` signatures → **LFI**.
3. Node W‑L.3: “Filter‑aware probes.”
    - If certain traversal patterns blocked, attempt encodings (`..%2F`), doubled traversal, or null‑byte variations for legacy PHP environments.

#### 4.2.5 File upload abuse detection

**Detection Decision Tree W‑Upload‑Detect**

1. Node W‑U.1: “Multipart form present?”
    - HTML form with `enctype="multipart/form-data"` and file input.
2. Node W‑U.2: “File type enforcement?”
    - Try uploading `test.php` with content `<?php echo "UPTEST"; ?>`.
    - If blocked, try extension confusion (`test.php.jpg`) or MIME spoofing.
3. Node W‑U.3: “Upload location discovery.”
    - Analyze response or static hints for upload path.
    - Crawl predictable paths (`/uploads/test.php`, `/images/test.php`) and check if `UPTEST` executes.

If any uploaded file executes arbitrary code, mark vulnerability `{type: "file_upload_RCE", shell_url: ...}`.

#### 4.2.6 IDOR detection

**Detection Decision Tree W‑IDOR‑Detect**

1. Node W‑I.1: “ID‑like parameter?”
    - Name `id`, `user`, `order`, etc., numeric or simple tokens.
2. Node W‑I.2: “Baseline \& neighbors.”
    - Fetch `id=current` and store normalized response (length/structure).
    - Fetch `id=current+1`, `id=current-1` without additional auth changes.
3. Node W‑I.3: “Unauthorized access check.”
    - If status is success and structure similar but data references others (e.g., different usernames/emails) → **IDOR**.

#### 4.2.7 XSS / CSRF / SSRF / JWT / backup leaks

These are detected by similar targeted trees:

- XSS: reflect script payloads, observe DOM/script execution indicators or stored injection in later views.[^38][^18][^19]
- CSRF: replay state‑changing requests without proper CSRF tokens or from different origins and check if action succeeds.[^27]
- SSRF: parameters that accept URLs; confirm server‑side requests to controlled listener and to internal hosts (`127.0.0.1`, `localhost`).[^27]
- JWT: inspect tokens; test `alg=none` or weak HMAC secrets via brute force.[^7][^27]
- Backup leaks: probe `/.git`, `config.php.bak`, `index.php~`, etc.; check for accessible source or config.[^26][^19]

Each culminates in a structured vulnerability descriptor used by the exploitation phase.

***

### 4.3 Binary (pwn) vulnerability detection

Pangr and CGC‑style systems demonstrate that many binary bugs can be detected by combining static pattern recognition, symbolic execution, and crash triage.[^3][^8][^29][^30][^1][^4]

**Detection Decision Tree P‑Detect: Classic pwnable bugs**

For each ELF:

1. Node P‑D.1: “Binary metadata \& protections.”
    - Run `checksec`. Record NX, PIE, canary, RELRO.[^8][^29][^30]
    - Extract function symbols via `nm`/`objdump`; note presence of suspicious functions (`gets`, `strcpy`, `sprintf`) and interesting targets (`win`, `print_flag`, `system`).[^29][^30][^4][^8]
2. Node P‑D.2: “Stack buffer overflow candidates.”
    - Scan for patterns: local arrays plus unbounded reads (`gets`, `read` with length > buffer) using static analysis.
    - If found, label as `candidate_stack_overflow`.
3. Node P‑D.3: “Format string candidates.”
    - Identify `printf`‑style calls where user input is directly used as the format string; Pangr uses behavior‑based models for such patterns.[^4]
4. Node P‑D.4: “Symbolic/fuzzing triage.”
    - For candidates, generate random or structured inputs and instrument with tools (e.g., `afl`, `honggfuzz`, or custom harness) to detect crashes.
    - Optionally feed binaries into angr‑based symbolic exploration to detect paths where attacker‑controlled data reaches instruction pointer (EIP/RIP).[^4]
5. Node P‑D.5: “Vulnerability classification.”
    - If crash with cyclic patterns in IP/ret address → **stack overflow**.
    - If program prints attacker formats and leaks memory/address → **format string**.
    - If writes beyond heap chunk boundaries (detected via sanitizer builds or Pangr‑like modeling) → **heap overflow**.[^4]

Each vulnerability gets annotated with offsets, interesting functions, and relevant protection context for later exploitation.

***

### 4.4 Crypto challenge detection

Crypto CTF guides describe systematic ways to recognize common cipher types and misuses.[^11][^12][^13][^21][^22][^23][^24][^31][^32][^33][^10]

**Detection Decision Tree C‑Detect: Cipher and scheme identification**

Given a textual artifact:

1. Node C‑D.1: “Encoding vs. encryption.”
    - Check if text is valid hex, base64, URL‑encoded; if so, treat it as encoding and decode iteratively until not valid or until human‑readable text emerges.[^12][^39][^40]
2. Node C‑D.2: “Alphabetic‑only, uniform case?”
    - If so, compute index of coincidence and n‑gram statistics. High IC and periodicity suggest Vigenère or substitution.[^21][^22][^41]
3. Node C‑D.3: “Binary/XOR candidate.”
    - If bytes are in wide distribution and length moderate, test all 256 single‑byte XOR keys and 26 Caesar shifts; look for outputs containing `flag{` or English‑like distribution.[^13][^22]
4. Node C‑D.4: “RSA/number‑theoretic.”
    - If input includes large integers and statements like `n`, `e`, `d`, `c`, treat as RSA challenge and parse parameters.[^23][^33][^10]
5. Node C‑D.5: “Stream/CTR mode reuse.”
    - Multiple ciphertexts of same length with shared key/nonce plus suspicion of XOR/stream cipher usage → candidate for key/keystream reuse attacks.[^24][^32][^11]

The output is a **crypto scenario descriptor** (e.g., `{type: "vigenere", params: {...}}`) that drives exploitation.

***

### 4.5 Forensics and stego detection

Forensics CTF guides identify repeated toolchains: `binwalk` for embedded data, `zsteg` for LSB stego, `exiftool` for metadata, `tshark` for PCAPs, `volatility` for memory dumps.[^9][^20][^34][^35][^36][^6]

**Detection Decision Tree F‑Detect: Artifact‑type‑driven analysis**

1. Node F‑D.1: “Image vs. generic binary vs. PCAP vs. archive vs. memory image.”
    - `file` reveals PNG/JPEG/BMP → **image stego** pipeline.
    - PCAP → **network reconstruction**.
    - Disk/memory image → **carving \& volatility**.
    - Generic binary → **binwalk/exiftool**.
2. Node F‑D.2: “Image stego branch.”
    - Run `zsteg -a` on PNG/BMP; parse for text/flag‑like outputs.[^20][^34][^35][^36][^9]
    - If no hit, try color channel analysis and convert to spectrogram (for audio disguised in image) then OCR.
3. Node F‑D.3: “Embedded data branch.”
    - Run `binwalk -e` to carve embedded files from arbitrary binaries/images.[^35][^36][^6][^20]
    - Recursively apply `file` and `strings | grep "flag{"` on extracted artifacts.
4. Node F‑D.4: “Metadata branch.”
    - Run `exiftool` and grep for `flag{` or likely encodings of it.[^36][^6][^9][^20]
5. Node F‑D.5: “PCAP branch.”
    - Use `tshark` to export HTTP/FTP/SMTP objects and reconstruct files; then treat them as new artifacts and recurse.[^6]
6. Node F‑D.6: “Memory/disk image branch.”
    - Use `volatility` to list processes, dump memory segments, and run `strings`‑plus‑regex over them.[^6]

***
