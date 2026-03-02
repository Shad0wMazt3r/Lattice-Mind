# **Title:**
A Decision-Tree Framework for Autonomous Detection and Exploitation of CTF-Style Vulnerabilities

***

## Abstract

This paper proposes a framework for autonomously detecting and exploiting common CTF (Capture‑the‑Flag) challenge patterns across web, binary exploitation, cryptography, and forensics, with minimal human input and no reliance on large language models. We draw on patterns observed in CTF training material, common‑challenge collections, and research on automatic exploit generation and cyber‑reasoning systems to design a modular toolkit organized around decision trees for both detection and exploitation. The framework assumes a Linux environment with Python, standard CLI tools (e.g., `nmap`, `curl`, `binwalk`, `zsteg`, `exiftool`), and access to challenge artifacts (URLs, binaries, ciphertexts, PCAPs, disk images). We describe (1) how to autonomously discover and classify targets, (2) how to detect vulnerabilities by structured probing and static analysis, (3) how to exploit those vulnerabilities via deterministic algorithms and exploit templates, and (4) an architecture for a toolkit that orchestrates these workflows using explicit decision trees and a small human‑in‑the‑loop interface.

***

## 1. Introduction

We can treat CTFs as a **structured pattern‑recognition and exploitation problem**. The core contributions of this paper are:

- A set of **decision trees** for **autonomous vulnerability detection** across web, pwn, crypto, and forensics, grounded in CTF practice.
- Corresponding **decision trees and TTPs** for **autonomous exploitation**, designed to recover flags end‑to‑end.
- A **toolkit architecture** that orchestrates these decision trees, with a rule‑based knowledge base, a detection and exploitation engine, and a lightweight human‑in‑the‑loop pathway.

***

## 2. Background and problem formulation

### 2.1 CTF challenge landscape

CTFs typically expose the participant to one or more of the following artifact types:

- Networked services (HTTP, raw TCP, custom protocols).
- Standalone binaries (Linux ELF, sometimes Windows PE).
- Ciphertexts and related cryptographic parameters.
- PCAPs, disk images, images, documents, compressed archives.

In each category, there are canonical patterns frequently used in challenges and training material:

- **Web:** SQL injection, XSS, file upload \& path traversal, CSRF, SSRF, IDOR, JWT misconfig, config/backup leaks.
- **Pwn:** stack overflows leading to ret2win/ret2libc, format strings, shellcode injection on NX‑off binaries, simple heap misuse.
- **Crypto:** classical ciphers (Caesar/Vigenère), XOR/stream cipher key reuse, fragile RSA configurations (shared primes, small e), badly used hash/MAC schemes.
- **Forensics:** embedded data (binwalk), image stego (LSB), metadata flags, PCAP artifact reconstruction, memory dumps.

Our objective is to detect and exploit a broad subset of these patterns **without** LLM reasoning—using deterministic algorithms, rule‑based logic, and existing program analysis tools.J

***

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

## 5. Autonomous exploitation framework

Once a vulnerability or structure is detected, the exploitation engine follows a **decision tree per vulnerability type** to recover the flag. The trees encode TTPs (tactics, techniques, procedures) you would normally use by hand—but structured so a script can follow them.

### 5.1 Web exploitation trees

#### 5.1.1 SQL injection exploitation

**Exploitation Decision Tree W‑SQLi‑Exploit**

Input: `{endpoint E, param p, technique T}`.

1. Node W‑SE.1: “Determine exploit mode.”
    - If union‑based possible → aim for direct table dump.
    - Else use boolean‑based or time‑based blind.
2. Node W‑SE.2: “Enumerate schema.”
    - Craft union or blind queries to list table names:
        - `UNION SELECT table_name FROM information_schema.tables ...`.
    - Filter for names matching `flag`, `ctf`, `secret`.
3. Node W‑SE.3: “Extract candidate columns.”
    - Enumerate columns of suspected tables via `information_schema.columns`.
4. Node W‑SE.4: “Dump row(s).”
    - For each candidate column, dump values (union when possible; otherwise boolean brute force character by character).
    - Stop when value matches flag regex.

**TTP summary:** systematically pivot from detection to schema discovery, then targeted extraction based on table/column naming conventions.

#### 5.1.2 Command injection exploitation

**Exploitation Decision Tree W‑CMD‑Exploit**

Input: `{endpoint E, param p, cmd_syntax S}` (e.g., delimiter `;` vs. `&&`).

1. Node W‑CE.1: “Check direct flag path.”
    - Try commands like `cat /flag && echo END`, `ls / | grep flag`.
    - If output contains flag regex → success.
2. Node W‑CE.2: “Fallback enumeration.”
    - If path unknown, run bounded enumeration such as:
        - `find / -maxdepth 4 -iname '*flag*' 2>/dev/null | head -n 20`.
    - For each candidate path, run `cat` and parse output.
3. Node W‑CE.3: “Output truncation handling.”
    - If responses are truncated (e.g., webbody size limit), compress and encode:
        - `tar czf - /flag | base64` and download entire blob; decode locally.

#### 5.1.3 LFI exploitation

**Exploitation Decision Tree W‑LFI‑Exploit**

Input: `{endpoint E, param p}`.

1. Node W‑LE.1: “Known OS file test.”
    - Confirm LFI with `/etc/passwd` (if not already done).
2. Node W‑LE.2: “Flag path brute force.”
    - Try dictionary of typical locations: `/flag`, `/flag.txt`, `/var/www/flag.*`, `/home/*/flag*`.
    - For each, construct `../../..` traversal to reach path; search responses for flag regex.
3. Node W‑LE.3: “PHP filter exploitation (if PHP).”
    - Use `php://filter/convert.base64-encode/resource=...` to read `.php` source and identify flag locations in code; then request those file paths via LFI.

#### 5.1.4 File upload exploitation

**Exploitation Decision Tree W‑Upload‑Exploit**

Input: `{upload_endpoint U, shell_url S}`.

1. Node W‑UE.1: “Establish webshell protocol.”
    - Ensure shell accepts a `cmd` parameter and runs `system(cmd)`.
    - Test with `cmd=id`.
2. Node W‑UE.2: “Search for flag via shell.”
    - Same enumeration as command injection: try direct `/flag`, then `find / -iname '*flag*'` with bounds.
3. Node W‑UE.3: “Persist minimal shell.”
    - Optionally replace shell with minimal “flag dumper” script that directly prints `/flag` to simplify later calls.

#### 5.1.5 XSS + admin bot exploitation

**Exploitation Decision Tree W‑XSS‑Exploit**

Input: `{injection_point I}` and known “report URL” if any.

1. Node W‑XE.1: “Craft exfiltration payload.”
    - Inject JS that `fetch`es `/flag` or reads `document.cookie` and sends it to your HTTP endpoint.
2. Node W‑XE.2: “Trigger admin visit.”
    - If CTF provides “report to admin” feature, script hitting that endpoint with your injection URL.
    - Otherwise rely on challenge‑specific triggers (cron, message ingestion) where available.
3. Node W‑XE.3: “Parse exfiltrated data.”
    - Listener service automatically extracts `flag{...}` from incoming queries.

***

### 5.2 Pwn exploitation trees

#### 5.2.1 Ret2win stack overflow

**Exploitation Decision Tree P‑Ret2Win‑Exploit**

Input: `{binary B, offset O, win_addr}`.

1. Node P‑RE.1: “Build payload.”
    - `payload = "A"*O + pack(win_addr)`; account for architecture (32/64‑bit) and endianness.
2. Node P‑RE.2: “Connect and send.”
    - If remote, use socket; else run locally.
    - Send payload once program expects input.
3. Node P‑RE.3: “Read until EOF.”
    - Capture program output; parse for flag regex.

This is the quintessential CTF pwn warmup; systems like Pangr and CGC entrants generated such exploits automatically for many cases.[^30][^1][^3][^8][^29][^4]

#### 5.2.2 Ret2libc / ROP

**Exploitation Decision Tree P‑Ret2Libc‑Exploit**

Input: `{binary B, overflow_offset O, leak_primitive, libc_db}`.

1. Node P‑RL.1: “Stage‑1 leak.”
    - Use ROP to call `puts(GOT(some_func))` or similar, return to main.
    - Run binary, send stage‑1 payload, parse leaked address.
2. Node P‑RL.2: “Compute libc base.”
    - Look up leaked symbol offset in `libc_db` to compute base.
3. Node P‑RL.3: “Find system and "/bin/sh".”
    - `system = base + offset("system")`; `binsh = base + offset("/bin/sh")`.
4. Node P‑RL.4: “Stage‑2 payload.”
    - Build ROP chain `["A"*O, pop_rdi, binsh, system]` (or equivalent calling convention).
5. Node P‑RL.5: “Spawn shell, read flag.”
    - Once shell accessible, run scripted `cat /flag`.

Such multi‑stage exploits are well within automated ROP tools and were standard in CGC systems.[^1][^3][^8][^29][^30][^4]

#### 5.2.3 Format string exploitation

**Exploitation Decision Tree P‑Fmt‑Exploit**

Input: `{binary B, fmt_vuln_desc}`.

1. Node P‑FE.1: “Determine parameter index.”
    - Send `"AAAABBBB.%p.%p...%p"` and inspect which `%p` output contains `41414141`/`42424242` pattern to infer index.
2. Node P‑FE.2: “Leak pointers.”
    - Leak stack and GOT entries via `%<idx>$p` to find libc addresses.
3. Node P‑FE.3: “Compute libc base and target.”
    - As with ret2libc.
4. Node P‑FE.4: “Construct write payload.”
    - Use `%n` with carefully chosen widths to overwrite GOT entry (e.g., `exit@GOT`) with `system` address.
5. Node P‑FE.5: “Trigger overwritten function.”
    - Invoke function that calls the overwritten GOT entry with `"/bin/sh"` or similar, then script `cat /flag`.

#### 5.2.4 Shellcode injection

**Exploitation Decision Tree P‑Shellcode‑Exploit**

Input: `{binary B, offset O, buf_addr}` where NX disabled.

1. Node P‑SE.1: “Generate shellcode.”
    - Use a pre‑built minimal `execve("/bin/sh")` shellcode for the relevant architecture.
2. Node P‑SE.2: “Build payload.”
    - `payload = shellcode + "A"*(O-len(shellcode)) + pack(buf_addr)`.
3. Node P‑SE.3: “Send, then issue commands.”
    - On success, script `cat /flag`.

***

### 5.3 Crypto exploitation trees

#### 5.3.1 Caesar / single‑byte XOR

**Exploitation Decision Tree C‑XOR‑Exploit**

Input: `{ciphertext C}`.

1. Node C‑XE.1: “Brute force keys.”
    - For `k in 0..25` (Caesar) or `0..255` (XOR), compute `P_k`.
2. Node C‑XE.2: “Evaluate candidates.”
    - If `P_k` contains `flag{` or passes an English‑scoring threshold, return `P_k` and `k`.[^22][^13]

This is trivially fully automated.

#### 5.3.2 Vigenère

**Exploitation Decision Tree C‑Vig‑Exploit**

Input: `{ciphertext C}`.

1. Node C‑VE.1: “Estimate key length.”
    - Use Kasiski examination or index‑of‑coincidence scans for period t; choose top candidates.[^41][^42][^12][^21]
2. Node C‑VE.2: “Per‑column Caesar solve.”
    - For each key position i, treat C[i::t] as monoalphabetic substitution and solve via frequency analysis.
3. Node C‑VE.3: “Construct key and decrypt.”
    - Build key from best Caesar shifts; decrypt C.
4. Node C‑VE.4: “Select best decryption.”
    - Choose candidate with flag regex or highest language score.

Existing Vigenère crackers implement this flow; we just wrap them in a decision tree wrapper.[^12][^21][^41]

#### 5.3.3 Stream cipher / CTR reuse

**Exploitation Decision Tree C‑Stream‑Exploit**

Input: `{ciphertexts C1..Cn}` suspected of keystream reuse.

1. Node C‑SE.1: “Compute pairwise XORs.”
    - For pairs `(Ci, Cj)`, compute `Di,j = Ci XOR Cj = Pi XOR Pj`.[^32][^11][^24]
2. Node C‑SE.2: “Crib‑dragging / known plaintext.”
    - Slide likely words (“flag{”, “http”, or known file headers) across `Di,j` to guess bytes of `Pi`/`Pj` and thus keystream.
3. Node C‑SE.3: “Extend keystream.”
    - Combine overlapping keystream fragments across ciphertexts.
4. Node C‑SE.4: “Decrypt target and search for flag.”
    - Apply keystream to chosen ciphertext, scan plaintext for flag.

#### 5.3.4 RSA misconfiguration

**Exploitation Decision Tree C‑RSA‑Exploit**

Input: `{RSA params}` from CTF.

1. Node C‑RE.1: “Attack selection.”
    - If same modulus n with different exponents or multiple ciphertexts with same e and different moduli → try common‑modulus or Hastad attacks.[^33][^10][^23]
    - If `e` is small (3 or 5) and plaintext small → attempt low‑exponent integer‑root attack.[^33]
    - For multiple `n`s, compute pairwise gcd to detect shared primes.[^23][^33]
2. Node C‑RE.2: “Run RSA attack toolbox.”
    - Use scripts modeled on RsaCtfTool or crypto‑attacks project to run: factorization via shared primes, Wiener, Fermat, lattice‑based attacks.[^43][^10][^23][^33]
3. Node C‑RE.3: “Decrypt and parse.”
    - Once `d` or plaintext `m` found, convert to bytes; extract `flag{...}` substring.

***

### 5.4 Forensics exploitation trees

These are often composed of “apply the right tool, then recurse”.

#### 5.4.1 Image stego and embedded data

**Exploitation Decision Tree F‑Stego‑Exploit**

Input: `{image or binary file F}`.

1. Node F‑SE.1: “Run zsteg if image.”
    - Parse all textual outputs; if flag matches appear, return.[^34][^9][^20][^35][^36]
2. Node F‑SE.2: “Binwalk extraction.”
    - Run `binwalk -e F` and recurse into extracted artifacts; for each, run `file`, then decision tree F‑Detect again.[^20][^35][^36][^6]
3. Node F‑SE.3: “Metadata.”
    - For images/docs, run `exiftool` and regex/decoder pipeline.[^9][^36][^20][^6]

#### 5.4.2 PCAP reconstruction

**Exploitation Decision Tree F‑PCAP‑Exploit**

Input: `{pcap P}`.

1. Node F‑PE.1: “Extract objects.”
    - `tshark`/`wireshark` export HTTP/FTP/SMTP objects to directory.[^6]
2. Node F‑PE.2: “Scan exported files.”
    - For each file, run same F‑Stego‑Exploit tree, plus simple `strings | grep 'flag{'`.

#### 5.4.3 Memory/disk image

**Exploitation Decision Tree F‑Mem‑Exploit**

Input: `{memory or disk image M}`.

1. Node F‑ME.1: “Enumerate processes.”
    - `volatility pslist` / similar to find interesting processes (webserver, crypto services).[^6]
2. Node F‑ME.2: “Dump memory regions.”
    - For selected processes, dump heap/stack segments; run `strings` with regex.
3. Node F‑ME.3: “Search filesystem.”
    - If disk image, mount read‑only and run `grep -R 'flag{'` with path filters.

***

