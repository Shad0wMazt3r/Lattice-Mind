## 3. System overview

### 3.1 Assumptions and environment

We assume:

- A Linux host with Python 3, `nmap`, `curl`, `ffuf`/`dirsearch`, `binwalk`, `zsteg`, `exiftool`, `tshark`, `volatility`, and common crypto libraries.
- Access to challenge artifacts: host:port for services, binary files, PCAPs, archives, ciphertexts, etc.
- Flag formats known (e.g., `flag{...}` or `CTF{...}`) so that detection/exploitation loops can terminate.

No LLM or external reasoning is required; the system is an **expert framework** combining static rules, pattern matching, and classical analysis techniques.

### 3.2 High-level pipeline

At a high level, the toolkit executes the following loop per challenge:

1. **Asset discovery \& classification.** Identify what kind of artifact we have (web service, binary, crypto text, forensics object).
2. **Detection phase.** Select a category‑specific decision tree and probe the target to infer likely vulnerability type(s).
3. **Exploitation phase.** Invoke the corresponding exploitation decision tree for each candidate vulnerability until a flag is recovered.
4. **Human‑in‑the‑loop fallbacks.** For nodes where automation is brittle (e.g., choosing non‑obvious web form values, skipping heavy scans), request minimal human hints and continue.

We now describe the overall architecture.

## 6. Toolkit architecture

### 6.1 Core components

We now describe a modular architecture that can implement the decision trees and workflows above.

**1. Orchestrator.**
Central engine that:

- Accepts challenge descriptors (e.g., `type=web, url=...` or `file=./binary`).
- Invokes classifiers (Section 4.1).
- Selects and runs detection and exploitation trees.
- Tracks state (what’s been tried, results, timeouts).

**2. Knowledge base \& decision trees.**

- Stores **vulnerability archetypes** as structured rules:
    - Preconditions (artifact type, observed features).
    - Probes (HTTP requests, tool calls, analysis actions).
    - Branch conditions (e.g., “if HTTP response status=200 and length changed > δ, go to node X”).
- Logical representation options:
    - A simple **DSL** in YAML/JSON describing nodes, actions, and transitions.
    - Or embedding decision logic in Python classes implementing a common interface (`detect()`, `exploit()`).

This is similar in spirit to Pangr’s behavior‑based models, which encode characteristic behaviors of format strings, stack/heap overflows and leverage them for detection and exploitation.[^4]

**3. Detection engine.**

- Executes tree actions that **observe** target behavior: HTTP probes, `checksec`, `file`, `zsteg`, `binwalk`, static analysis, etc.
- Consumes outputs and pushes observations back into the tree context, driving branch decisions.

**4. Exploitation engine.**

- Executes tree actions that **change** state or attempt exploitation: sending crafted payloads, launching ROP chains, running crypto attacks.
- Maintains per‑exploit context: remote connection state, leaked addresses, discovered keystreams.
- Provides reusable **exploit templates** (e.g., “ret2win with known win() address”, “small‑e RSA attack”).

AEG frameworks like Pangr and CGC systems have shown the viability of modeling vulnerabilities and generating exploits in a modular way, with detection handing structured vulnerabilities to an exploiter module.[^3][^1][^4]

**5. Tool adapters.**

Thin wrappers around external tools:

- `NmapAdapter` (for port/version scanning).[^2]
- `FFUFAdapter`, `CurlAdapter`, `RequestsAdapter` (HTTP).
- `BinwalkAdapter`, `ZstegAdapter`, `ExifAdapter`.[^34][^35][^36][^9][^20]
- `PwnAdapter` (using pwntools/gdb for binary interaction).[^28][^8][^29][^30]
- `CryptoAdapter` (wrapping RSA attack libraries, Vigenère crackers, etc.).[^10][^21][^43][^33]

These adapters normalize outputs into structured forms (e.g., JSON dicts) for decision trees.

**6. Flag recognizer and result store.**

- Global service that watches outputs of all actions for patterns like `flag{[^}]+}` and terminates the workflow as soon as a candidate is found.
- Stores intermediate artifacts (captured responses, derived keys, paths) for reproducibility.

***

### 6.2 Human‑in‑the‑loop interaction

Although much can be automated, some decision points benefit from light human guidance. The architecture should incorporate a **Human Interaction Manager** that:

- Exposes certain decision nodes as “askable”:
    - Example: “The web app has 10 forms; which should we prioritize?”
    - Example: “XSS scanning is noisy; skip it? (y/n).”
- Allows the operator to provide domain‑specific hints:
    - Known credentials, suspected flag locations, or confirmation that a partial flag is valid.
- Provides **override hooks**:
    - Skip entire trees (e.g., “don’t brute‑force long RSA, time‑boxed CTF”).
    - Mark some candidate flags as false positives.

The rest of the system remains deterministic; human input simply selects branches or sets parameters.

***

### 6.3 Control flow for a single challenge

A typical end‑to‑end run:

1. **Initialization.**
    - Operator gives challenge metadata; orchestrator calls classifier (D‑0).
2. **Tree selection.**
    - For a web URL, select W‑Recon; from its outputs, schedule specific detection trees (SQLi, LFI, etc.).
3. **Parallel detection.**
    - Run multiple detection trees in parallel when independent (e.g., path traversal vs. SQLi).
    - Feed results into knowledge base; mark confirmed vulnerabilities.
4. **Exploit scheduling.**
    - For each confirmed vulnerability, attach appropriate exploitation tree and run in priority order: easiest or fastest first (e.g., `ret2win` before complex heap exploitation).
5. **Flag monitoring.**
    - At each step, outputs are checked by the Flag Recognizer; once a valid flag is observed, orchestrator halts further attempts for that challenge.
6. **Logging and learning.**
    - Store which tree succeeded, what parameters worked; this can inform future tree tuning.

***

