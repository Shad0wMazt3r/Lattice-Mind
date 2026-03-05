"""Base class for all tool adapters."""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
import subprocess
import json
import logging

logger = logging.getLogger(__name__)


class ToolAdapter(ABC):
    """Abstract base class for tool wrappers.
    
    Tool adapters normalize outputs from external tools into structured
    JSON-like dicts for consumption by decision nodes.
    
    Example:
        CurlAdapter wraps HTTP requests:
        • Input: url, method, data, headers
        • Output: {status: 200, headers: {...}, body: "..."}
        
        NmapAdapter wraps network scans:
        • Input: target, ports, flags
        • Output: {open_ports: [...], services: [...], versions: [...]}
    """
    
    def __init__(self, name: str, timeout: float = 30.0):
        """Initialize adapter.
        
        Args:
            name: Tool name (for logging and identification)
            timeout: Command execution timeout in seconds
        """
        self.name = name
        self.timeout = timeout
        self.last_output: Optional[str] = None
        self.last_result: Optional[Dict[str, Any]] = None
    
    @abstractmethod
    def run(self, target: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the tool and return normalized output.
        
        Args:
            target: The target (URL, IP, file path, etc.)
            args: Tool-specific arguments as dict
        
        Returns:
            Normalized output as structured dict
        """
        pass
    
    def execute_command(self, cmd: List[str]) -> str:
        """Execute a shell command and return output.
        
        Args:
            cmd: Command as list of strings
        
        Returns:
            Command output as string
        
        Raises:
            RuntimeError: If command fails or times out
        """
        try:
            logger.debug(f"[{self.name}] Executing: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False
            )
            
            self.last_output = result.stdout + result.stderr
            
            if result.returncode != 0:
                logger.warning(
                    f"[{self.name}] Command failed (exit code {result.returncode}): "
                    f"{result.stderr[:200]}"
                )
            
            return self.last_output
        
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"[{self.name}] Command timed out after {self.timeout}s"
            )
        except Exception as e:
            raise RuntimeError(f"[{self.name}] Command failed: {str(e)}")
    
    def parse_json_output(self, output: str) -> Dict[str, Any]:
        """Parse JSON output from tool.
        
        Args:
            output: Tool output as string
        
        Returns:
            Parsed JSON as dict
        
        Raises:
            ValueError: If output is not valid JSON
        """
        try:
            return json.loads(output)
        except json.JSONDecodeError as e:
            raise ValueError(f"[{self.name}] Failed to parse JSON output: {str(e)}")
    
    def normalize_output(self, raw_output: str) -> Dict[str, Any]:
        """Normalize tool output to standard format.
        
        Override in subclasses to parse tool-specific output formats.
        
        Args:
            raw_output: Raw tool output
        
        Returns:
            Normalized output dict
        """
        return {"raw": raw_output}
    
    def __repr__(self):
        return f"{self.__class__.__name__}(name={self.name})"


class CommandToolAdapter(ToolAdapter):
    """Base class for adapters that wrap command-line tools.
    
    Subclass this to easily wrap tools that:
    1. Take a target as first argument
    2. Accept additional flags/options
    3. Output text that needs parsing
    """
    
    @abstractmethod
    def build_command(self, target: str, args: Dict[str, Any]) -> List[str]:
        """Build the command to execute.
        
        Args:
            target: Target for the tool
            args: Tool-specific arguments
        
        Returns:
            Command as list of strings
        """
        pass
    
    def run(self, target: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute command and normalize output."""
        cmd = self.build_command(target, args)
        output = self.execute_command(cmd)
        result = self.normalize_output(output)
        self.last_result = result
        return result


class MockToolAdapter(ToolAdapter):
    """Mock adapter for testing without real tools."""
    
    def __init__(self, name: str, mock_response: Dict[str, Any]):
        """Initialize with mock response.
        
        Args:
            name: Adapter name
            mock_response: Response to return on run()
        """
        super().__init__(name)
        self.mock_response = mock_response
    
    def run(self, target: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Return mock response."""
        logger.debug(f"[{self.name}] Mock adapter returning: {self.mock_response}")
        self.last_result = self.mock_response
        return self.mock_response
