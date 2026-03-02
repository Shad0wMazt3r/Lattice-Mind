"""Web vulnerability detection and exploitation trees.

Implements comprehensive web vulnerability detection:
- SQL Injection (boolean, error-based, union-based)
- Command Injection (output-based, blind/time-based)
- Local File Inclusion (traversal, filter bypass)
- Cross-Site Scripting (reflected, stored, filter bypass)
- Reconnaissance (asset discovery, endpoint mapping)
"""

from .sqli import (
    SQLiDetectReflectionNode,
    SQLiDetectBooleanNode,
    SQLiDetectErrorNode,
    SQLiDetectUnionNode,
    SQLiExploitBooleanNode,
    SQLiExploitErrorNode,
)

from .cmd import (
    CMDDetectOutputNode,
    CMDDetectBlindNode,
    CMDExploitOutputNode,
    CMDExploitBlindNode,
)

from .lfi import (
    LFIDetectTraversalNode,
    LFIDetectFilterNode,
    LFIExploitTraversalNode,
)

from .xss import (
    XSSDetectReflectedNode,
    XSSDetectStoredNode,
    XSSDetectFilterNode,
    XSSExploitNode,
)

__all__ = [
    # SQLi
    "SQLiDetectReflectionNode",
    "SQLiDetectBooleanNode",
    "SQLiDetectErrorNode",
    "SQLiDetectUnionNode",
    "SQLiExploitBooleanNode",
    "SQLiExploitErrorNode",
    # CMD
    "CMDDetectOutputNode",
    "CMDDetectBlindNode",
    "CMDExploitOutputNode",
    "CMDExploitBlindNode",
    # LFI
    "LFIDetectTraversalNode",
    "LFIDetectFilterNode",
    "LFIExploitTraversalNode",
    # XSS
    "XSSDetectReflectedNode",
    "XSSDetectStoredNode",
    "XSSDetectFilterNode",
    "XSSExploitNode",
]
