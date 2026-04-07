"""Flag recognizer - global service for detecting flags in outputs."""
import re
from typing import Optional, List

from lattice_mind.config import COMPILED_FLAG_PATTERNS


class FlagRecognizer:
    """Detects flag patterns in arbitrary text/output."""
    
    def __init__(self):
        self.found_flags: List[str] = []
    
    def recognize(self, text: str) -> Optional[str]:
        """Search for a flag in the given text.
        
        Args:
            text: Output or response to search
        
        Returns:
            First matching flag pattern, or None if not found.
        """
        if not text:
            return None
        
        flag = self._probe(text)
        if flag is not None:
            self.found_flags.append(flag)
            return flag
        
        return None
    
    def recognize_all(self, text: str) -> List[str]:
        """Find all flags in the given text.
        
        Args:
            text: Output or response to search
        
        Returns:
            List of all matching flag patterns.
        """
        if not text:
            return []
        
        flags = []
        for pattern in COMPILED_FLAG_PATTERNS:
            matches = pattern.findall(text)
            flags.extend(matches)
        
        return flags
    
    def has_flag(self, text: str) -> bool:
        """Check if any flag pattern is present.
        
        Args:
            text: Output or response to check
        
        Returns:
            True if a flag pattern was found.
        """
        return self._probe(text) is not None

    def _probe(self, text: str) -> Optional[str]:
        """Find first matching flag without mutating recognizer state."""
        if not text:
            return None
        for pattern in COMPILED_FLAG_PATTERNS:
            match = pattern.search(text)
            if match:
                return match.group(0)
        return None
    
    def clear(self):
        """Reset found flags list."""
        self.found_flags.clear()


# Global instance
_global_flag_recognizer = FlagRecognizer()


def get_flag_recognizer() -> FlagRecognizer:
    """Get the global flag recognizer instance."""
    return _global_flag_recognizer
