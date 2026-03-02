"""Shared data types for decision trees and engines."""
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class ChallengeType(str, Enum):
    """Challenge artifact types."""
    WEB = "web"
    PWN = "pwn"
    CRYPTO = "crypto"
    FORENSICS = "forensics"
    STEGANOGRAPHY = "steganography"
    REVERSE_ENGINEERING = "reverse_engineering"
    OSINT = "osint"
    NETWORK = "network"
    MISC = "misc"


class VulnType(str, Enum):
    """Vulnerability types."""
    SQL_INJECTION = "sql_injection"
    LFI = "lfi"
    RFI = "rfi"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    BUFFER_OVERFLOW = "buffer_overflow"
    FORMAT_STRING = "format_string"
    ROP_CHAIN = "rop_chain"
    HEAP_EXPLOIT = "heap_exploit"
    RACE_CONDITION = "race_condition"
    WEAK_CRYPTO = "weak_crypto"
    SIDE_CHANNEL = "side_channel"
    BROKEN_AUTH = "broken_auth"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DESERIALIZATION = "deserialization"
    HIDDEN_DATA = "hidden_data"
    COMPRESSION_BOMB = "compression_bomb"
    POLYGLOT_FILE = "polyglot_file"


class NodeStatus(str, Enum):
    """Result status of a decision node."""
    SUCCESS = "success"
    FAILURE = "failure"
    FAILED = "failure"  # Alias for compatibility
    PENDING = "pending"
    SKIPPED = "skipped"
    QUEUED = "queued"  # For exploitation plans
    ESCALATE = "escalate"
    ASK_HUMAN = "ask_human"
    TIMEOUT = "timeout"


@dataclass
class ChallengeDescriptor:
    """Descriptor for a CTF challenge."""
    type: ChallengeType
    name: Optional[str] = None
    url: Optional[str] = None
    file_path: Optional[str] = None
    flag_format: str = "flag{...}"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VulnDescriptor:
    """Descriptor for an identified vulnerability."""
    type: VulnType
    technique: str
    endpoint: Optional[str] = None
    param: Optional[str] = None
    confidence: float = 0.5  # 0.0 to 1.0
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NodeResult:
    """Result returned by a decision node execution."""
    status: NodeStatus
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    next_node: Optional[str] = None
