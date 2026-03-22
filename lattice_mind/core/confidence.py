"""Confidence pool management for decision trees."""
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class BoostRecord:
    source_id: str
    boost: float
    applied: float


@dataclass
class TreeConfidence:
    tree_id: str
    score: float = 0.0
    sources: List[BoostRecord] = field(default_factory=list)
    _fired_sources: Set[str] = field(default_factory=set)

    def add_boost(self, boost: float, source_label: str, phase: str = "detection"):
        """
        Apply a boost using the diminishing returns formula:
        new_score = old_score + boost * (1 - old_score)
        """
        source_id = f"{phase}:{self.tree_id}:{source_label}"
        
        if source_id in self._fired_sources:
            return 0.0
            
        # Hard cap boost at 1.0 (though it's asymptotic anyway)
        boost = max(-1.0, min(1.0, boost))
        
        old_score = self.score
        
        if boost >= 0:
            applied = boost * (1.0 - old_score)
            self.score += applied
        else:
            # Negative boost (penalty)
            # score = score * (1 + penalty) where penalty is negative
            # e.g. score=0.5, penalty=-0.3 -> 0.5 * 0.7 = 0.35
            applied = old_score * boost # negative value
            self.score += applied
            
        self.score = max(0.0, min(1.0, self.score))
        self._fired_sources.add(source_id)
        
        record = BoostRecord(source_id, boost, applied)
        self.sources.append(record)
        
        return applied


class ConfidencePool:
    """
    Central repository for tree-specific confidence scores.
    Enforces isolation and provenance tracking.
    """

    def __init__(self):
        self.tree_confidences: Dict[str, TreeConfidence] = {}
        self.frozen = False

    def get_tree_confidence(self, tree_id: str) -> TreeConfidence:
        if tree_id not in self.tree_confidences:
            self.tree_confidences[tree_id] = TreeConfidence(tree_id)
        return self.tree_confidences[tree_id]

    def apply_boost(self, tree_id: str, boost: float, source_label: str, phase: str = "detection"):
        if self.frozen:
            logger.warning(f"Attempted to apply boost to {tree_id} while pool is frozen")
            return 0.0
            
        conf = self.get_tree_confidence(tree_id)
        return conf.add_boost(boost, source_label, phase)

    def freeze(self):
        """Freeze the pool before the exploitation phase."""
        self.frozen = True

    def unfreeze(self):
        """Allow boosts again after YAML exploitation when reusing the pool for another phase."""
        self.frozen = False

    def get_scores(self) -> Dict[str, float]:
        return {tid: c.score for tid, c in self.tree_confidences.items()}

    def clear(self):
        self.tree_confidences.clear()
        self.frozen = False
