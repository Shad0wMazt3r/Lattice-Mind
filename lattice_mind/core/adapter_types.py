"""Unified adapter type definitions for consistent tool integration.

All tool adapters must return AdapterResult to ensure consistent
output format across the system.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from enum import Enum


class AdapterStatus(str, Enum):
    """Status codes for adapter execution."""
    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"
    NOT_FOUND = "not_found"
    PARTIAL = "partial"


@dataclass
class AdapterResult:
    """Unified output schema for all tool adapters.
    
    All adapters (CurlAdapter, FFUFAdapter, NmapAdapter, etc.) must
    return this structure to enable consistent handling by decision nodes.
    
    Attributes:
        status: Execution status (success, error, timeout, etc.)
        data: Tool-specific output data (structured dict)
        error: Error message if status is ERROR
        metadata: Additional context (response time, tool version, etc.)
    """
    status: AdapterStatus
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_success(self) -> bool:
        """Check if adapter execution was successful."""
        return self.status == AdapterStatus.SUCCESS
    
    @property
    def is_error(self) -> bool:
        """Check if adapter execution failed."""
        return self.status in (AdapterStatus.ERROR, AdapterStatus.TIMEOUT)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get data field with default fallback (convenience method).
        
        Args:
            key: Data key to retrieve
            default: Default value if key not found
            
        Returns:
            Data value or default
        """
        return self.data.get(key, default)


# Standard data keys for common adapter types
class HttpDataKeys:
    """Standard keys for HTTP adapter data."""
    STATUS_CODE = "status_code"
    HEADERS = "headers"
    BODY = "body"
    COOKIES = "cookies"
    REDIRECTS = "redirects"


class FileDataKeys:
    """Standard keys for file adapter data."""
    CONTENT = "content"
    SIZE = "size"
    MIME_TYPE = "mime_type"
    HASH = "hash"
    PERMISSIONS = "permissions"


class NetworkDataKeys:
    """Standard keys for network adapter data."""
    OPEN_PORTS = "open_ports"
    SERVICES = "services"
    VERSIONS = "versions"
    OS_DETECTION = "os_detection"


class ScanDataKeys:
    """Standard keys for directory/fuzzing scan adapters."""
    RESULTS = "results"
    TOTAL_REQUESTS = "total_requests"
    FOUND_COUNT = "found_count"
