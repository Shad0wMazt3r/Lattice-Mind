"""Validation utilities for YAML decision-tree dependencies and signal wiring."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set


@dataclass
class ValidationResult:
    ok: bool
    cycles: List[List[str]] = field(default_factory=list)
    orphaned_signals: List[str] = field(default_factory=list)
    duplicate_ids: List[str] = field(default_factory=list)


class DAGValidator:
    """Validate tree-level dependency graph and signal references."""

    def validate(self, trees: List[object]) -> ValidationResult:
        ids: List[str] = []
        dupes: List[str] = []
        seen: Set[str] = set()
        for t in trees:
            tid = str(getattr(t, "id", ""))
            if not tid:
                continue
            ids.append(tid)
            if tid in seen and tid not in dupes:
                dupes.append(tid)
            seen.add(tid)

        graph = self._build_dep_graph(trees)
        cycles = self._detect_cycles(graph)
        orphans = self._find_orphaned_signals(trees)
        return ValidationResult(
            ok=not (dupes or cycles or orphans),
            cycles=cycles,
            orphaned_signals=orphans,
            duplicate_ids=dupes,
        )

    def _build_dep_graph(self, trees: List[object]) -> Dict[str, Set[str]]:
        graph: Dict[str, Set[str]] = {}
        for t in trees:
            tid = str(getattr(t, "id", ""))
            if not tid:
                continue
            deps = getattr(t, "depends_on", []) or []
            graph[tid] = {str(d) for d in deps if d}
        return graph

    def _detect_cycles(self, graph: Dict[str, Set[str]]) -> List[List[str]]:
        cycles: List[List[str]] = []
        visiting: Set[str] = set()
        visited: Set[str] = set()
        stack: List[str] = []

        def dfs(node: str) -> None:
            if node in visited:
                return
            if node in visiting:
                if node in stack:
                    idx = stack.index(node)
                    cycles.append(stack[idx:] + [node])
                return
            visiting.add(node)
            stack.append(node)
            for nxt in graph.get(node, set()):
                if nxt in graph:
                    dfs(nxt)
            stack.pop()
            visiting.remove(node)
            visited.add(node)

        for n in list(graph.keys()):
            dfs(n)
        return cycles

    def _find_orphaned_signals(self, trees: List[object]) -> List[str]:
        emitted: Dict[str, Set[str]] = {}
        required: Dict[str, Set[str]] = {}
        for t in trees:
            tid = str(getattr(t, "id", ""))
            if not tid:
                continue
            em: Set[str] = set()
            for p in getattr(t, "detection_paths", []) or []:
                for s in getattr(p, "steps", []) or []:
                    for sig in getattr(s, "signals", []) or []:
                        if not isinstance(sig, dict):
                            continue
                        on_match = sig.get("on_match") or {}
                        emit = on_match.get("emit")
                        if emit:
                            em.add(str(emit))
            emitted[tid] = em

            req: Set[str] = set()
            for p in getattr(t, "exploitation_paths", []) or []:
                rs = getattr(p, "requires_signal", "")
                if rs:
                    req.add(str(rs))
            required[tid] = req

        out: List[str] = []
        for tid, reqs in required.items():
            available = emitted.get(tid, set())
            for sig in sorted(reqs):
                if sig not in available:
                    out.append(f"{tid}:{sig}")
        return out

