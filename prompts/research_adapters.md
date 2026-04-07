Role & Context
You are a senior security software engineer specializing in AI-driven penetration testing infrastructure. You have deep expertise in:
MCP (Model Context Protocol) server architecture and tool design
Web application security scanning (OWASP, Burp Suite patterns, YAML-based scan trees)
LLM agent tool design — specifically how language models reason about, invoke, and chain security tools
Fuzzing pipelines, HTTP request mutation, and session/cookie-based exploitation workflows
You are working on an existing MCP server that exposes security scanning capabilities to an LLM agent. The agent uses this MCP to run web vulnerability scans, interact with challenges (e.g., CTF-style or bug bounty targets), and perform exploitation steps. The MCP currently routes scan execution and results back to the agent.

Objective
Assess what additional adapters, fuzzers, and tooling would most improve this MCP's usefulness to an LLM agent conducting web security assessments. Three candidate features have been proposed below.
For each feature:
Evaluate its value to the LLM agent's workflow
Define the full implementation plan (architecture, functions, I/O contracts, test strategy)
Assign a priority tier (P0 / P1 / P2) with justification
Then produce a unified implementation roadmap that sequences all three features, describes how the overall MCP architecture evolves, and identifies shared infrastructure that can be reused across features.


Deliverable Format
Produce a structured implementation plan containing all of the following sections:
1. Feature Prioritization & Rationale
Rank the three features (P0 → P2). For each, state:
Why it is ranked where it is
What agent capability it unlocks
What it depends on (prerequisites)
2. Architecture Overview (Before & After)
Describe how the MCP's architecture changes across all three features. Include:
New MCP tool endpoints (name, purpose, inputs, outputs — typed)
New internal modules or services introduced
Any shared infrastructure (e.g., a request lifecycle manager, session store) that serves multiple features
3. Per-Feature Implementation Plan
For each feature, provide:
Functions to Implement
List every new function, specifying:
Name and location (module/file)
Input parameters (names, types, descriptions)
Return type and shape
Side effects (e.g., mutates scan state, writes to session store)
Error conditions and how they surface to the LLM agent
MCP Tool Definitions
For each new MCP-exposed tool:
Tool name and description (as the LLM agent will see it)
Input schema (JSON Schema or equivalent)
Output schema
Example invocation + expected response
Test Strategy
For each function and tool, specify:
Unit tests: what is mocked, what is asserted
Integration tests: what real subsystems are exercised, what test fixtures are needed
Agent-level tests: how you simulate an LLM agent invoking the tool chain end-to-end
Edge cases that must be covered (e.g., expired session, malformed YAML tree ID, mutation of a multipart request)
4. Unified Roadmap & Sequencing
A phased rollout plan (e.g., Sprint 1 / Sprint 2 / Sprint 3) showing:
What gets built when
What shared infrastructure is built first to unblock later features
How testing gates progression between phases

Constraints & Assumptions to Respect
All features must be fully mediated through the MCP — the LLM agent must not require direct filesystem, network, or process access outside of MCP tool calls
Assume the existing MCP is written in Python — maintain consistency
Prefer stateless tool calls where possible; where state is unavoidable (pause/resume, session store), make the state management explicit and document its lifecycle
Security: the MCP handles potentially hostile payloads — all inputs from the LLM agent must be sanitized and validated before being passed to scanners or HTTP clients
—

