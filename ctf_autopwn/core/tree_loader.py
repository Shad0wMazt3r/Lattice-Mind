"""YAML Decision Tree loader and registry."""
import os
import yaml
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ConfidenceSeed:
    condition: str
    boost: float
    label: str


@dataclass
class DetectionStep:
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
        self.id = raw_data["id"]
        self.name = raw_data["name"]
        self.category = raw_data["category"]
        self.version = str(raw_data.get("version", "1.0"))
        self.author = raw_data.get("author", "system")
        self.description = raw_data.get("description", "")
        self.applies_when = raw_data.get("applies_when", [])
        
        self.confidence_seeds = [
            ConfidenceSeed(s["if"], s["boost"], s["label"])
            for s in raw_data.get("confidence_seeds", [])
        ]

        # Support two YAML schemas:
        #   Schema A (sqli.yaml style):  detection: {min_confidence, paths: [...]}
        #   Schema B (ssti.yaml style):  detection_paths: [...]  min_confidence: N  (top-level)
        det = raw_data.get("detection", {})
        self.min_confidence = (
            raw_data.get("min_confidence",          # schema B top-level
            det.get("min_confidence", 0.10))        # schema A nested
        )
        raw_det_paths = det.get("paths") or raw_data.get("detection_paths", [])

        self.detection_paths = []
        for p in raw_det_paths:
            steps = [
                DetectionStep(
                    s["id"], s["action"],
                    s.get("params") or s.get("with", {}),
                    s.get("signals", []), s.get("on_success"), s.get("on_failure")
                )
                for s in p.get("steps", [])
            ]
            self.detection_paths.append(
                DetectionPath(p["id"], p["name"], p.get("description", ""), steps,
                              p.get("min_confidence", self.min_confidence))
            )

        exp = raw_data.get("exploitation", {})
        self.stop_on_flag = (
            raw_data.get("stop_on_flag",            # schema B top-level
            exp.get("stop_on_flag", True))          # schema A nested
        )
        raw_exp_paths = exp.get("paths") or raw_data.get("exploitation_paths", [])

        self.exploitation_paths = []
        for p in raw_exp_paths:
            steps = [
                ExploitationStep(
                    s["id"], s["action"],
                    s.get("params") or s.get("with", {}),
                    s.get("capture", []), s.get("on_success"), s.get("on_failure")
                )
                for s in p.get("steps", [])
            ]
            self.exploitation_paths.append(
                ExploitationPath(p["id"], p["name"], p["requires_signal"], p["technique"], steps)
            )
        
        self.enabled = True


class TreeRegistry:
    def __init__(self):
        self.trees: Dict[str, DecisionTree] = {}

    def load_from_directory(self, directory: str):
        """Scan directory recursively for .yaml files."""
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".yaml") or file.endswith(".yml"):
                    path = os.path.join(root, file)
                    self.load_file(path)

    def load_file(self, path: str):
        try:
            with open(path, 'r') as f:
                raw = yaml.safe_load(f)
                if not raw or "id" not in raw:
                    return
                tree = DecisionTree(raw)
                if tree.id in self.trees:
                    # Could log warning here
                    pass
                self.trees[tree.id] = tree
        except Exception as e:
            # Could log error here
            print(f"Failed to load tree from {path}: {e}")

    def get_tree(self, tree_id: str) -> Optional[DecisionTree]:
        return self.trees.get(tree_id)

    def list_trees(self) -> List[DecisionTree]:
        return list(self.trees.values())


# Global registry
_global_registry = TreeRegistry()

def get_tree_registry() -> TreeRegistry:
    return _global_registry
