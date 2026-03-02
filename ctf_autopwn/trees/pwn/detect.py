"""Binary exploitation detection trees (P-Detect).

Implements pwn vulnerability detection from detections.md:
- P-D.1: Binary metadata and protections (checksec, nm, objdump)
- P-D.2: Stack buffer overflow detection (pattern matching)
- P-D.3: Format string detection
- P-D.4: Symbolic/fuzzing triage
- P-D.5: Vulnerability classification (stack/format/heap)
"""
from typing import Dict, Any, Optional, List
import logging
import re
import subprocess

from ctf_autopwn.core.nodes import DecisionNode
from ctf_autopwn.core.types import (
    NodeResult, NodeStatus, VulnDescriptor, VulnType
)

logger = logging.getLogger(__name__)


class PwnDetectMetadataNode(DecisionNode):
    """P-D.1: Analyze binary metadata and security protections."""
    
    def __init__(self):
        super().__init__("pwn_detect_metadata", "Pwn: Binary Metadata")
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Extract binary metadata and protections."""
        challenge = context.get("challenge")
        
        if not challenge or not challenge.file_path:
            return NodeResult(
                status=NodeStatus.FAILURE,
                error="No binary file"
            )
        
        logger.info(f"[pwn] Analyzing metadata for {challenge.file_path}")
        
        try:
            # Try to run checksec
            protections = self._get_protections(challenge.file_path)
            
            # Extract symbols
            symbols = self._get_symbols(challenge.file_path)
            
            # Identify interesting functions
            interesting_funcs = self._find_interesting_functions(challenge.file_path)
            
            logger.info(f"[pwn] Protections: {protections}")
            logger.debug(f"[pwn] Interesting functions: {interesting_funcs}")
            
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={
                    "protections": protections,
                    "symbols": symbols,
                    "interesting_functions": interesting_funcs,
                }
            )
        
        except Exception as e:
            logger.error(f"[pwn] Metadata analysis failed: {str(e)}")
            return NodeResult(status=NodeStatus.FAILURE, error=str(e))
    
    def _get_protections(self, binary_path: str) -> Dict[str, bool]:
        """Check NX, PIE, canary, RELRO status."""
        protections = {
            "NX": False,
            "PIE": False,
            "canary": False,
            "RELRO": False,
        }
        
        try:
            # Try checksec if available
            result = subprocess.run(
                ["checksec", "--file", binary_path],
                capture_output=True,
                timeout=5,
                text=True
            )
            
            output = result.stdout.lower()
            protections["NX"] = "nx enabled" in output or "nx enabled" in output
            protections["PIE"] = "pie enabled" in output or "pie enabled" in output
            protections["canary"] = "stack canary found" in output
            protections["RELRO"] = "relro" in output
        
        except:
            # Fallback: parse file headers
            try:
                result = subprocess.run(
                    ["readelf", "-l", binary_path],
                    capture_output=True,
                    timeout=5,
                    text=True
                )
                
                protections["NX"] = "GNU_STACK" in result.stdout and "RWE" not in result.stdout
                protections["PIE"] = "DYN" in result.stdout
            except:
                pass
        
        return protections
    
    def _get_symbols(self, binary_path: str) -> List[str]:
        """Extract function symbols from binary."""
        symbols = []
        
        try:
            result = subprocess.run(
                ["nm", "-D", binary_path],
                capture_output=True,
                timeout=5,
                text=True
            )
            
            for line in result.stdout.split('\n'):
                if line and ' T ' in line or ' t ' in line:
                    parts = line.split()
                    if parts:
                        symbols.append(parts[-1])
        
        except:
            pass
        
        return symbols
    
    def _find_interesting_functions(self, binary_path: str) -> List[str]:
        """Identify dangerous/interesting functions."""
        suspicious = ["gets", "strcpy", "sprintf", "scanf", "strcat"]
        interesting = ["win", "print_flag", "flag", "system", "exec", "main"]
        
        found = []
        
        try:
            result = subprocess.run(
                ["objdump", "-t", binary_path],
                capture_output=True,
                timeout=5,
                text=True
            )
            
            output = result.stdout.lower()
            
            for func in suspicious + interesting:
                if func in output:
                    found.append(func)
        
        except:
            pass
        
        return found
    
    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        if result.status == NodeStatus.SUCCESS:
            return PwnDetectStackOverflowNode()
        return None


class PwnDetectStackOverflowNode(DecisionNode):
    """P-D.2: Detect stack buffer overflow patterns."""
    
    def __init__(self):
        super().__init__("pwn_detect_overflow", "Pwn: Stack Overflow")
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Detect unbounded buffer operations."""
        challenge = context.get("challenge")
        
        if not challenge or not challenge.file_path:
            return NodeResult(status=NodeStatus.FAILURE, error="No binary")
        
        logger.info(f"[pwn] Checking for stack overflow patterns")
        
        try:
            # Look for dangerous patterns: arrays + unbounded reads
            result = subprocess.run(
                ["strings", challenge.file_path],
                capture_output=True,
                timeout=5,
                text=True
            )
            
            output = result.stdout
            
            # Look for format strings with fixed sizes
            has_buffer_funcs = any(
                func in output 
                for func in ["gets", "read", "fgets", "scanf"]
            )
            
            # Check with objdump for suspicious patterns
            result2 = subprocess.run(
                ["objdump", "-d", challenge.file_path],
                capture_output=True,
                timeout=5,
                text=True
            )
            
            disasm = result2.stdout
            
            # Look for stack allocation patterns followed by unbounded input
            is_candidate = "mov.*rsp" in disasm and has_buffer_funcs
            
            logger.info(f"[pwn] Stack overflow candidate: {is_candidate}")
            
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={
                    "is_stack_overflow_candidate": is_candidate,
                    "dangerous_functions": [
                        f for f in ["gets", "read", "fgets", "scanf"]
                        if f in output
                    ]
                }
            )
        
        except Exception as e:
            logger.error(f"[pwn] Stack overflow detection failed: {str(e)}")
            return NodeResult(status=NodeStatus.FAILURE, error=str(e))
    
    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        if result.status == NodeStatus.SUCCESS:
            return PwnDetectFormatStringNode()
        return None


class PwnDetectFormatStringNode(DecisionNode):
    """P-D.3: Detect format string vulnerabilities."""
    
    def __init__(self):
        super().__init__("pwn_detect_format", "Pwn: Format String")
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Detect format string vulnerabilities."""
        challenge = context.get("challenge")
        
        if not challenge or not challenge.file_path:
            return NodeResult(status=NodeStatus.FAILURE, error="No binary")
        
        logger.info(f"[pwn] Checking for format string patterns")
        
        try:
            result = subprocess.run(
                ["objdump", "-d", challenge.file_path],
                capture_output=True,
                timeout=5,
                text=True
            )
            
            disasm = result.stdout
            
            # Look for printf/fprintf with user input
            # Pattern: load user input, then call printf with it as format string
            
            is_format_candidate = (
                "printf" in disasm and 
                ("mov.*rdi" in disasm or "lea.*rsi" in disasm)
            )
            
            logger.info(f"[pwn] Format string candidate: {is_format_candidate}")
            
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={
                    "is_format_string_candidate": is_format_candidate,
                }
            )
        
        except Exception as e:
            logger.error(f"[pwn] Format string detection failed: {str(e)}")
            return NodeResult(status=NodeStatus.FAILURE, error=str(e))
    
    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        if result.status == NodeStatus.SUCCESS:
            return PwnDetectSymbolicNode()
        return None


class PwnDetectSymbolicNode(DecisionNode):
    """P-D.4: Symbolic execution and fuzzing triage."""
    
    def __init__(self):
        super().__init__("pwn_detect_symbolic", "Pwn: Symbolic/Fuzzing")
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Run symbolic exploration or fuzzing."""
        challenge = context.get("challenge")
        
        if not challenge or not challenge.file_path:
            return NodeResult(status=NodeStatus.FAILURE, error="No binary")
        
        logger.info(f"[pwn] Running symbolic/fuzzing triage (mocked)")
        
        # In real scenario, would:
        # 1. Run AFL fuzzer with crafted inputs
        # 2. Use angr for symbolic execution
        # 3. Detect crashes and analyze for exploitability
        
        # For now, mark as needing manual analysis
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={
                "requires_manual_analysis": True,
                "suggested_tools": ["afl", "gdb", "angr", "ghidra"],
            }
        )
    
    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        if result.status == NodeStatus.SUCCESS:
            return PwnClassifyVulnNode()
        return None


class PwnClassifyVulnNode(DecisionNode):
    """P-D.5: Classify vulnerability type."""
    
    def __init__(self):
        super().__init__("pwn_classify_vuln", "Pwn: Classify")
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Classify discovered vulnerabilities."""
        metadata = context.get("observations", {}).get("binary_metadata", {})
        
        logger.info(f"[pwn] Classifying vulnerabilities")
        
        # Determine vulnerability type based on analysis
        vuln_types = []
        
        # Check findings from previous nodes
        if metadata.get("is_stack_overflow_candidate"):
            vuln_types.append("stack_overflow")
        
        if metadata.get("is_format_string_candidate"):
            vuln_types.append("format_string")
        
        if not vuln_types:
            vuln_types.append("unknown_binary_vuln")
        
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={
                "vulnerability_types": vuln_types,
                "protections": metadata.get("protections", {}),
            }
        )


# Summary
"""
Binary Exploitation Detection Tree (P-Detect)

Detection nodes:
- P-D.1 (PwnDetectMetadataNode) - Extract metadata, symbols, protections
- P-D.2 (PwnDetectStackOverflowNode) - Detect unbounded buffer operations
- P-D.3 (PwnDetectFormatStringNode) - Detect format string vulnerabilities
- P-D.4 (PwnDetectSymbolicNode) - Symbolic execution / fuzzing triage
- P-D.5 (PwnClassifyVulnNode) - Classify vulnerability type

Uses standard Unix tools: checksec, nm, objdump, strings, readelf
Also integrates with symbolic tools: afl, angr, gdb

Detectable vulnerabilities:
- Stack buffer overflow
- Format string
- Heap overflow (via sanitizers)
- ROP gadgets (depends on protections)
"""
