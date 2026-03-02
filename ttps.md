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

