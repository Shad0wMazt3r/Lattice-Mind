"""Detection engine interface."""
from abc import ABC, abstractmethod
from typing import Dict, Any

from ctf_autopwn.core.types import NodeResult


class DetectionEngine(ABC):
    """Base class for detection engines.
    
    Executes observational actions: HTTP probes, tool calls, static analysis.
    """
    
    @abstractmethod
    def detect(self, context: Dict[str, Any]) -> NodeResult:
        """Run detection actions on the challenge.
        
        Args:
            context: Challenge context and observations
        
        Returns:
            NodeResult with detected vulnerabilities and observations.
        """
        pass


class SimpleDetectionEngine(DetectionEngine):
    """Placeholder detection engine for testing."""
    
    def detect(self, context: Dict[str, Any]) -> NodeResult:
        """Minimal detection implementation."""
        return NodeResult(
            status="success",
            data={"vulnerabilities": []}
        )
