# Features

Lattice Mind provides a comprehensive suite of features for automated security research and CTF participation.

## Functional Features

*   **Autonomous Asset Classification**: Automatically detects whether a target is a web application, a network service (Nmap integration), a binary executable (Pwn), or a cryptographic challenge.
*   **Rule-Based Decision Trees**:
    *   **YAML-Driven Trees**: High-level, plug-and-play vulnerability definitions (`web_sqli`, `web_lfi`, etc.) that can be updated without code changes.
    *   **Python Logic Nodes**: Complex, multi-step orchestration for advanced exploitation (e.g., ROP chain generation, RSA attacks).
*   **Adaptive Exploit Prioritization**: Ordered payload execution based on confidence seeds, ensuring higher-probability techniques are tried first.
*   **Flag Recognition Engine**: Configurable regex-based flag detection that monitors all tool outputs and HTTP responses.
*   **Dashboard**: A real-time web UI that visualizes tree execution, showing every branch taken, payload sent, and observation made.
*   **Human-in-the-Loop (HITL)**: Ability for the engine to pause and request human hints or manual overrides when automation hits a roadblock.

## Technical & Architectural Features

*   **Deterministic Execution Log**: Every single action—from a `curl` request to an RSA modulus factorizing—is logged with its justification and outcome.
*   **Modular Adapter System**: Standardized wrappers for CLI tools like `ffuf`, `nmap`, `gdb`, and `binwalk` that return normalized JSON for the engine to consume.
*   **Stateless Engine with Persistent History**: The executor is stateless per-run, while all progress and observations are persisted to a SQLite database.
*   **Model Context Protocol (MCP) Server**: Native support for orchestration by AI agents via a standard interface, allowing external tools to query "What have you found?" or "Run this scan."
*   **Embedded Knowledge Base**: A structured repository of vulnerability archetypes and remediation strategies.
*   **Template-Based Exploitation**: Jinja2-style templates for generating dynamic exploit scripts (e.g., Python `pwntools` scripts or specialized Payloads).

---

### Supported Vulnerability Categories

| Category | Typical Tools / Techniques |
| :--- | :--- |
| **Web** | SQLi, SSTI, LFI/RFI, SSRF, XSS, IDOR, JWT |
| **Pwn** | Stack/Heap Overflow, Format String, ROP, GOT Overwrites |
| **Crypto** | RSA (Small-e, Wiener's), Caesar, XOR, Padding Oracle |
| **Forensics** | Steganography (LSB), PCAP Analysis, Metadata extraction |
| **Misc** | OSINT, Binwalk analysis, Logic puzzles |
