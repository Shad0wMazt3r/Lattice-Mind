"""Human-in-the-loop interaction manager."""
from typing import Optional, List, Dict, Any


class HumanLoopManager:
    """Manages human-in-the-loop interactions for decision nodes."""
    
    def __init__(self, interactive: bool = True):
        self.interactive = interactive
        self.hints: Dict[str, Any] = {}
        self.overrides: Dict[str, bool] = {}
    
    def ask_user(self, question: str, options: Optional[List[str]] = None) -> str:
        """Ask the user a question and return their response.
        
        Args:
            question: The question to ask
            options: Optional list of valid responses
        
        Returns:
            User's response
        """
        if not self.interactive:
            raise RuntimeError("Interactive mode disabled")
        
        print(f"\n[HUMAN INPUT REQUIRED]\n{question}")
        if options:
            for i, opt in enumerate(options, 1):
                print(f"  {i}. {opt}")
        
        while True:
            response = input("Your choice: ").strip()
            if not options or response in options or response.isdigit():
                return response
            print("Invalid response. Please try again.")
    
    def set_hint(self, key: str, value: Any):
        """Store a user-provided hint.
        
        Args:
            key: Hint identifier
            value: Hint value
        """
        self.hints[key] = value
    
    def get_hint(self, key: str) -> Optional[Any]:
        """Retrieve a stored hint.
        
        Args:
            key: Hint identifier
        
        Returns:
            Hint value or None
        """
        return self.hints.get(key)
    
    def set_override(self, key: str, enabled: bool):
        """Set an override flag (e.g., skip certain trees).
        
        Args:
            key: Override identifier
            enabled: Whether the override is active
        """
        self.overrides[key] = enabled
    
    def is_overridden(self, key: str) -> bool:
        """Check if an override is active.
        
        Args:
            key: Override identifier
        
        Returns:
            True if override is active
        """
        return self.overrides.get(key, False)
    
    def clear(self):
        """Reset all hints and overrides."""
        self.hints.clear()
        self.overrides.clear()


# Global instance
_global_human_loop = HumanLoopManager(interactive=True)


def get_human_loop_manager() -> HumanLoopManager:
    """Get the global human loop manager instance."""
    return _global_human_loop
