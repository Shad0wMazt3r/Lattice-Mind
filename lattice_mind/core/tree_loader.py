"""YAML Decision Tree loader and registry."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml

from lattice_mind.core.dag_validator import DAGValidator

logger = logging.getLogger(__name__)


@dataclass
class ConfidenceSeed:
    condition: str
    boost: float
    label: str


@dataclass
class DetectionStep:
    """params holds the full step ``with`` / ``params`` mapping."""

    id: str
    action: str
    params: Dict[str, Any]
    signals: List[Dict[str, Any]]
    on_success: Optional[str] = None
    on_failure: Optional[str] = None


@dataclass
class DetectionPath:
    id: str
    name: str
    description: str
    steps: List[DetectionStep]
    min_confidence: float = 0.10


@dataclass
class ExploitationStep:
    id: str
    action: str
    params: Dict[str, Any]
    capture: List[Dict[str, Any]] = field(default_factory=list)
    on_success: Optional[str] = None
    on_failure: Optional[str] = None


@dataclass
class ExploitationPath:
    id: str
    name: str
    requires_signal: str
    technique: str
    steps: List[ExploitationStep]


class DecisionTree:
    def __init__(self, raw_data: Dict[str, Any]):
        self.id = str(raw_data["id"])
        self.name = str(raw_data["name"])
        self.category = str(raw_data["category"])
        self.version = str(raw_data.get("version", "1.0"))
        self.author = str(raw_data.get("author", "system"))
        self.description = str(raw_data.get("description", ""))
        self.applies_when = [
            str(c) for c in (raw_data.get("applies_when", []) or []) if c is not None
        ]

        self.confidence_seeds = []
        for seed in (raw_data.get("confidence_seeds", []) or []):
            if not isinstance(seed, dict):
                raise ValueError("confidence_seeds entries must be objects")
            condition = seed.get("condition")
            if condition is None:
                condition = seed.get("if")
            if condition is None:
                raise ValueError("confidence seed missing condition/if")
            label = seed.get("label", "seed")
            boost = float(seed.get("boost", 0.0))
            self.confidence_seeds.append(
                ConfidenceSeed(str(condition), boost, str(label))
            )

        det = raw_data.get("detection", {}) or {}
        self.min_confidence = float(
            raw_data.get("min_confidence", det.get("min_confidence", 0.10))
        )
        raw_det_paths = det.get("paths") or raw_data.get("detection_paths", []) or []

        self.detection_paths = []
        for p in raw_det_paths:
            if not isinstance(p, dict):
                raise ValueError("detection_paths entries must be objects")
            steps = []
            for s in (p.get("steps", []) or []):
                if not isinstance(s, dict):
                    raise ValueError("detection step must be an object")
                sid = str(s.get("id", "")).strip()
                action = str(s.get("action", "")).strip()
                if not sid or not action:
                    raise ValueError("detection step missing id/action")
                step_params = s.get("params") or s.get("with", {}) or {}
                if not isinstance(step_params, dict):
                    raise ValueError("detection step params/with must be object")
                signals = s.get("signals", []) or []
                if not isinstance(signals, list):
                    raise ValueError("detection step signals must be list")
                steps.append(
                    DetectionStep(
                        sid,
                        action,
                        step_params,
                        [x for x in signals if isinstance(x, dict)],
                        s.get("on_success"),
                        s.get("on_failure"),
                    )
                )
            self.detection_paths.append(
                DetectionPath(
                    str(p["id"]),
                    str(p["name"]),
                    str(p.get("description", "")),
                    steps,
                    float(p.get("min_confidence", self.min_confidence)),
                )
            )

        exp = raw_data.get("exploitation", {}) or {}
        self.stop_on_flag = bool(raw_data.get("stop_on_flag", exp.get("stop_on_flag", True)))
        raw_exp_paths = exp.get("paths") or raw_data.get("exploitation_paths", []) or []

        self.exploitation_paths = []
        for p in raw_exp_paths:
            if not isinstance(p, dict):
                raise ValueError("exploitation_paths entries must be objects")
            steps = []
            for s in (p.get("steps", []) or []):
                if not isinstance(s, dict):
                    raise ValueError("exploitation step must be an object")
                sid = str(s.get("id", "")).strip()
                action = str(s.get("action", "")).strip()
                if not sid or not action:
                    raise ValueError("exploitation step missing id/action")
                step_params = s.get("params") or s.get("with", {}) or {}
                if not isinstance(step_params, dict):
                    raise ValueError("exploitation step params/with must be object")
                capture = s.get("capture", []) or []
                if not isinstance(capture, list):
                    raise ValueError("exploitation step capture must be list")
                steps.append(
                    ExploitationStep(
                        sid,
                        action,
                        step_params,
                        [x for x in capture if isinstance(x, dict)],
                        s.get("on_success"),
                        s.get("on_failure"),
                    )
                )
            self.exploitation_paths.append(
                ExploitationPath(
                    str(p["id"]),
                    str(p["name"]),
                    str(p["requires_signal"]),
                    str(p["technique"]),
                    steps,
                )
            )

        raw_tags = raw_data.get("tags", [])
        self.tags: List[str] = (
            [str(t).strip().lower() for t in raw_tags if t]
            if isinstance(raw_tags, list)
            else []
        )
        raw_dep = raw_data.get("depends_on") or raw_data.get("dependencies") or []
        self.depends_on: List[str] = (
            [str(x) for x in raw_dep if x] if isinstance(raw_dep, list) else []
        )
        ed = raw_data.get("estimated_duration_seconds")
        if ed is None:
            ed = raw_data.get("estimated_duration")
        try:
            self.estimated_duration_seconds: Optional[int] = int(ed) if ed is not None else None
        except (TypeError, ValueError):
            self.estimated_duration_seconds = None
        self.enabled = bool(raw_data.get("enabled", True))
        self.validation_error: Optional[str] = None


class TreeRegistry:
    def __init__(self):
        self.trees: Dict[str, DecisionTree] = {}
        self.validation_errors: Dict[str, Dict[str, str]] = {}
        self._validator = DAGValidator()

    def load_from_directory(self, directory: str):
        """Scan directory recursively for .yaml files."""
        self.trees = {}
        self.validation_errors = {}
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".yaml") or file.endswith(".yml"):
                    path = os.path.join(root, file)
                    self.load_file(path)
        self._validate_graph()

    def load_file(self, path: str):
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f)
            if not raw or "id" not in raw:
                return
            tree = DecisionTree(raw)
            if tree.id in self.trees:
                raise ValueError(f"duplicate tree id {tree.id!r}")
            self.trees[tree.id] = tree
        except Exception as e:
            logger.error("Failed to load tree from %s: %s", path, e)
            # Key by path for load failures (tree id may be unknown).
            self.validation_errors[path] = {"error": str(e), "path": path}

    def _validate_graph(self) -> None:
        result = self._validator.validate(self.list_trees())
        for dup in result.duplicate_ids:
            self.validation_errors[dup] = {"error": "duplicate tree id", "path": ""}
            self.trees.pop(dup, None)
        for orphan in result.orphaned_signals:
            tree_id = orphan.split(":", 1)[0]
            self.validation_errors[tree_id] = {
                "error": f"orphaned signal reference: {orphan}",
                "path": "",
            }
            self.trees.pop(tree_id, None)
        for cycle in result.cycles:
            for tid in cycle:
                self.validation_errors[tid] = {
                    "error": f"dependency cycle detected: {' -> '.join(cycle)}",
                    "path": "",
                }
                self.trees.pop(tid, None)

    def get_tree(self, tree_id: str) -> Optional[DecisionTree]:
        return self.trees.get(tree_id)

    def list_trees(self) -> List[DecisionTree]:
        return list(self.trees.values())


# Global registry
_global_registry = TreeRegistry()


def get_tree_registry() -> TreeRegistry:
    return _global_registry

