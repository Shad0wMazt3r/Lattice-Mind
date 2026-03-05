"""Knowledge base - stores vulnerability archetypes and decision tree references."""
from typing import Dict, List, Optional

from lattice_mind.core.types import ChallengeType, VulnType, VulnDescriptor


class KnowledgeBase:
    """Central repository for vulnerability archetypes and detection strategies."""
    
    def __init__(self):
        # Maps challenge type -> list of applicable vulnerability types
        self.vuln_map: Dict[ChallengeType, List[VulnType]] = {
            ChallengeType.WEB: [
                VulnType.SQL_INJECTION,
                VulnType.LFI,
                VulnType.RFI,
                VulnType.XSS,
                VulnType.COMMAND_INJECTION,
                VulnType.PATH_TRAVERSAL,
                VulnType.BROKEN_AUTH,
                VulnType.DESERIALIZATION,
            ],
            ChallengeType.PWN: [
                VulnType.BUFFER_OVERFLOW,
                VulnType.FORMAT_STRING,
                VulnType.ROP_CHAIN,
                VulnType.HEAP_EXPLOIT,
                VulnType.RACE_CONDITION,
                VulnType.PRIVILEGE_ESCALATION,
            ],
            ChallengeType.CRYPTO: [
                VulnType.WEAK_CRYPTO,
                VulnType.SIDE_CHANNEL,
            ],
            ChallengeType.FORENSICS: [
                VulnType.HIDDEN_DATA,
                VulnType.COMPRESSION_BOMB,
            ],
            ChallengeType.STEGANOGRAPHY: [
                VulnType.HIDDEN_DATA,
                VulnType.POLYGLOT_FILE,
            ],
            ChallengeType.REVERSE_ENGINEERING: [
                VulnType.WEAK_CRYPTO,
                VulnType.HIDDEN_DATA,
            ],
            ChallengeType.OSINT: [
                VulnType.HIDDEN_DATA,
            ],
            ChallengeType.NETWORK: [
                VulnType.BROKEN_AUTH,
                VulnType.WEAK_CRYPTO,
            ],
            ChallengeType.MISC: [
                VulnType.HIDDEN_DATA,
                VulnType.POLYGLOT_FILE,
            ],
        }
        
        # Confirmed vulnerabilities per challenge
        self.confirmed_vulns: List[VulnDescriptor] = []
    
    def get_applicable_vulns(self, challenge_type: ChallengeType) -> List[VulnType]:
        """Get list of vulnerability types applicable to a challenge type.
        
        Args:
            challenge_type: The type of challenge
        
        Returns:
            List of VulnType that should be tested.
        """
        return self.vuln_map.get(challenge_type, [])
    
    def add_confirmed_vuln(self, vuln: VulnDescriptor):
        """Record a confirmed vulnerability.
        
        Args:
            vuln: VulnDescriptor to add
        """
        self.confirmed_vulns.append(vuln)
    
    def get_confirmed_vulns(self) -> List[VulnDescriptor]:
        """Get all confirmed vulnerabilities."""
        return self.confirmed_vulns
    
    def clear(self):
        """Reset confirmed vulnerabilities."""
        self.confirmed_vulns.clear()


# Global instance
_global_knowledge_base = KnowledgeBase()


def get_knowledge_base() -> KnowledgeBase:
    """Get the global knowledge base instance."""
    return _global_knowledge_base
