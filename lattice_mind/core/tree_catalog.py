"""YAML tree catalog, selection resolution, and dependency ordering for targeted scans."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from lattice_mind.core.tree_loader import DecisionTree, TreeRegistry


class TreeCatalogError(ValueError):
    """Invalid catalog or selection input."""


class TreeDependencyError(TreeCatalogError):
    """Missing or cyclic tree dependencies."""


@dataclass
class TreeSummary:
    """Metadata for one decision tree (MCP / API catalog entry)."""

    id: str
    name: str
    category: str
    description: str
    version: str
    enabled: bool
    tags: List[str]
    depends_on: List[str]
    estimated_duration_seconds: Optional[int]
    challenge_types_hint: List[str]
    detection_path_count: int
    exploitation_path_count: int

    def to_jsonable(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "version": self.version,
            "enabled": self.enabled,
            "tags": list(self.tags),
            "depends_on": list(self.depends_on),
            "estimated_duration_seconds": self.estimated_duration_seconds,
            "challenge_types_hint": list(self.challenge_types_hint),
            "detection_path_count": self.detection_path_count,
            "exploitation_path_count": self.exploitation_path_count,
        }


@dataclass
class TreeGroupSummary:
    """Aggregate group for filtering (e.g. all trees in a category)."""

    type: str
    value: str
    tree_ids: List[str]

    def to_jsonable(self) -> Dict[str, Any]:
        return {"type": self.type, "value": self.value, "tree_ids": list(self.tree_ids)}


@dataclass
class TreeCatalog:
    summaries: List[TreeSummary]
    groups: List[TreeGroupSummary]

    def to_jsonable(self) -> Dict[str, Any]:
        return {
            "trees": [s.to_jsonable() for s in self.summaries],
            "groups": [g.to_jsonable() for g in self.groups],
        }


@dataclass
class DependencyValidationResult:
    ordered_ids: List[str]
    missing_dependencies: List[Tuple[str, str]]  # (tree_id, missing_dep)
    cycle: bool


_CHALLENGE_TYPE_RE = re.compile(
    r"context\.challenge\.type\s*==\s*['\"](\w+)['\"]", re.IGNORECASE
)


def _infer_challenge_types_from_applies_when(conditions: List[str]) -> List[str]:
    hints: List[str] = []
    for cond in conditions:
        if not isinstance(cond, str):
            continue
        for m in _CHALLENGE_TYPE_RE.finditer(cond):
            hints.append(m.group(1).lower())
    return list(dict.fromkeys(hints))


def _heuristic_duration_seconds(tree: DecisionTree) -> Optional[int]:
    if tree.estimated_duration_seconds is not None:
        return tree.estimated_duration_seconds
    det_steps = sum(len(p.steps) for p in tree.detection_paths)
    exp_steps = sum(len(p.steps) for p in tree.exploitation_paths)
    total = det_steps + exp_steps
    if total <= 0:
        return None
    # Rough seconds estimate for agent UX (not wall-clock guarantees).
    return min(600, max(5, total * 3))


def build_tree_catalog(registry: TreeRegistry) -> TreeCatalog:
    """Build catalog and group index from a loaded registry."""
    trees = registry.list_trees()
    summaries: List[TreeSummary] = []
    by_category: Dict[str, List[str]] = {}
    by_tag: Dict[str, List[str]] = {}

    for t in trees:
        ch = _infer_challenge_types_from_applies_when(t.applies_when)
        if not ch and t.category:
            ch = [str(t.category).lower()]
        summ = TreeSummary(
            id=t.id,
            name=t.name,
            category=t.category,
            description=(t.description or "")[:2000],
            version=t.version,
            enabled=t.enabled,
            tags=list(t.tags),
            depends_on=list(t.depends_on),
            estimated_duration_seconds=_heuristic_duration_seconds(t),
            challenge_types_hint=ch,
            detection_path_count=len(t.detection_paths),
            exploitation_path_count=len(t.exploitation_paths),
        )
        summaries.append(summ)
        by_category.setdefault(t.category.lower(), []).append(t.id)
        for tag in t.tags:
            by_tag.setdefault(tag.lower(), []).append(t.id)

    groups: List[TreeGroupSummary] = []
    for cat, ids in sorted(by_category.items()):
        groups.append(TreeGroupSummary(type="category", value=cat, tree_ids=sorted(set(ids))))
    for tag, ids in sorted(by_tag.items()):
        groups.append(TreeGroupSummary(type="tag", value=tag, tree_ids=sorted(set(ids))))

    summaries.sort(key=lambda s: s.id)
    return TreeCatalog(summaries=summaries, groups=groups)


def _summary_map(catalog: TreeCatalog) -> Dict[str, TreeSummary]:
    return {s.id: s for s in catalog.summaries}


def validate_tree_dependencies(
    selected_ids: List[str],
    dependency_graph: Dict[str, List[str]],
) -> DependencyValidationResult:
    """Topologically sort selected_ids respecting depends_on edges within the selection."""
    sel_set = set(selected_ids)
    missing: List[Tuple[str, str]] = []
    # For each tree T, deps_in = dependencies of T that are also selected (T runs after these).
    deps_in_sel: Dict[str, List[str]] = {}
    indeg: Dict[str, int] = {}

    for tid in selected_ids:
        deps = [d for d in dependency_graph.get(tid, []) if d]
        for d in deps:
            if d not in sel_set:
                missing.append((tid, d))
        inside = [d for d in deps if d in sel_set]
        deps_in_sel[tid] = inside
        indeg[tid] = len(inside)

    queue = [n for n in selected_ids if indeg.get(n, 0) == 0]
    ordered: List[str] = []
    seen: Set[str] = set()
    while queue:
        n = queue.pop(0)
        if n in seen:
            continue
        seen.add(n)
        ordered.append(n)
        # n finished; any node that depended on n has one fewer blocker
        for tid in selected_ids:
            if n in deps_in_sel.get(tid, []):
                indeg[tid] -= 1
                if indeg[tid] == 0 and tid not in seen:
                    queue.append(tid)

    cycle = len(ordered) != len(sel_set)
    if cycle:
        # Preserve stable fallback: original list order
        ordered = list(selected_ids)

    return DependencyValidationResult(
        ordered_ids=ordered,
        missing_dependencies=missing,
        cycle=cycle,
    )


@dataclass
class TreeSelectionResult:
    """Resolved tree IDs to run, plus warnings."""

    ordered_tree_ids: List[str]
    skipped_unknown_ids: List[str]
    skipped_disabled: List[str]
    dependency_warnings: List[str]
    cycle_detected: bool


def resolve_tree_selection(
    catalog: TreeCatalog,
    selection: Dict[str, Any],
    *,
    challenge_type: Optional[str] = None,
    include_disabled: bool = False,
) -> TreeSelectionResult:
    """
    Resolve explicit ids + group selectors into an ordered unique id list.

    selection shape:
      ids: list[str]
      groups: list[{"type": "category"|"tag"|"technique", "value": str}]
      exclude_ids: list[str] (optional)
    """
    smap = _summary_map(catalog)
    raw_ids = selection.get("ids") or []
    if not isinstance(raw_ids, list):
        raise TreeCatalogError("selection.ids must be a list of strings")
    id_order: List[str] = []
    seen_ids: Set[str] = set()
    for i in raw_ids:
        if not i:
            continue
        s = str(i)
        if s not in seen_ids:
            seen_ids.add(s)
            id_order.append(s)

    groups = selection.get("groups") or []
    if groups is not None and not isinstance(groups, list):
        raise TreeCatalogError("selection.groups must be a list")

    group_tree_ids: Set[str] = set()
    if groups:
        catalog_groups = {((g.type.lower(), g.value.lower())): g.tree_ids for g in catalog.groups}
        for g in groups:
            if not isinstance(g, dict):
                raise TreeCatalogError("each selection.groups entry must be an object")
            gtype = str(g.get("type", "")).strip().lower()
            gval = str(g.get("value", "")).strip().lower()
            if not gtype or not gval:
                raise TreeCatalogError("group entries require type and value")
            if gtype == "technique":
                gtype = "tag"
            key = (gtype, gval)
            if key not in catalog_groups:
                raise TreeCatalogError(f"Unknown group {gtype!r}={gval!r}")
            group_tree_ids.update(catalog_groups[key])

    exclude = selection.get("exclude_ids") or []
    if exclude is not None and not isinstance(exclude, list):
        raise TreeCatalogError("selection.exclude_ids must be a list")
    ex_set = {str(x) for x in exclude if x}
    combined_set = (set(id_order) | group_tree_ids) - ex_set

    ordered_candidates: List[str] = [t for t in id_order if t in combined_set]
    picked: Set[str] = set(ordered_candidates)
    for tid in sorted(group_tree_ids):
        if tid in combined_set and tid not in picked:
            ordered_candidates.append(tid)
            picked.add(tid)

    if challenge_type:
        ct = str(challenge_type).lower().strip()
        filtered: List[str] = []
        for tid in ordered_candidates:
            s = smap.get(tid)
            if not s:
                continue
            if not s.challenge_types_hint or ct in s.challenge_types_hint:
                filtered.append(tid)
        ordered_candidates = filtered

    skipped_unknown: List[str] = []
    skipped_disabled: List[str] = []
    known: List[str] = []
    for tid in ordered_candidates:
        s = smap.get(tid)
        if not s:
            skipped_unknown.append(tid)
            continue
        if not s.enabled and not include_disabled:
            skipped_disabled.append(tid)
            continue
        known.append(tid)

    if not known:
        raise TreeCatalogError(
            "Empty tree selection after resolving ids/groups/filters "
            f"(unknown={skipped_unknown}, disabled={skipped_disabled})"
        )

    dep_graph = {s.id: s.depends_on for s in catalog.summaries}
    dep_result = validate_tree_dependencies(known, dep_graph)

    warnings: List[str] = []
    for tid, dep in dep_result.missing_dependencies:
        warnings.append(f"DEPENDENCY_MISSING:{tid} needs {dep} (not in selection)")
    if dep_result.cycle:
        warnings.append("DEPENDENCY_CYCLE: could not topologically sort; using fallback order")

    ordered = [i for i in dep_result.ordered_ids if i in set(known)]
    # Include any known id missing from topo output (fallback)
    for k in known:
        if k not in ordered:
            ordered.append(k)

    return TreeSelectionResult(
        ordered_tree_ids=ordered,
        skipped_unknown_ids=skipped_unknown,
        skipped_disabled=skipped_disabled,
        dependency_warnings=warnings,
        cycle_detected=dep_result.cycle,
    )
