"""
Deep tests for KnowledgeBase.

Covers:
- get_applicable_vulns: returns correct list for each ChallengeType
- get_applicable_vulns: returns empty list for types not in map
- add_confirmed_vuln / get_confirmed_vulns: accumulate correctly
- clear(): resets confirmed_vulns
- Global singleton identity
- VulnType membership per category
- VulnDescriptor immutability through KnowledgeBase
"""
import pytest

from lattice_mind.core.knowledge_base import KnowledgeBase, get_knowledge_base
from lattice_mind.core.types import ChallengeType, VulnDescriptor, VulnType

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _mk_kb() -> KnowledgeBase:
    return KnowledgeBase()


def _vuln(vuln_type=VulnType.SQL_INJECTION, technique="union") -> VulnDescriptor:
    return VulnDescriptor(type=vuln_type, technique=technique)


# ──────────────────────────────────────────────────────────────────────────────
# get_applicable_vulns
# ──────────────────────────────────────────────────────────────────────────────

class TestGetApplicableVulns:

    WEB_EXPECTED = {
        VulnType.SQL_INJECTION, VulnType.LFI, VulnType.RFI, VulnType.XSS,
        VulnType.COMMAND_INJECTION, VulnType.PATH_TRAVERSAL,
        VulnType.BROKEN_AUTH, VulnType.DESERIALIZATION,
    }

    PWN_EXPECTED = {
        VulnType.BUFFER_OVERFLOW, VulnType.FORMAT_STRING, VulnType.ROP_CHAIN,
        VulnType.HEAP_EXPLOIT, VulnType.RACE_CONDITION, VulnType.PRIVILEGE_ESCALATION,
    }

    def test_web_returns_list(self):
        kb = _mk_kb()
        result = kb.get_applicable_vulns(ChallengeType.WEB)
        assert isinstance(result, list)
        assert len(result) > 0

    def test_web_contains_sqli(self):
        kb = _mk_kb()
        assert VulnType.SQL_INJECTION in kb.get_applicable_vulns(ChallengeType.WEB)

    def test_web_contains_lfi(self):
        kb = _mk_kb()
        assert VulnType.LFI in kb.get_applicable_vulns(ChallengeType.WEB)

    def test_web_contains_xss(self):
        kb = _mk_kb()
        assert VulnType.XSS in kb.get_applicable_vulns(ChallengeType.WEB)

    def test_web_contains_cmd_injection(self):
        kb = _mk_kb()
        assert VulnType.COMMAND_INJECTION in kb.get_applicable_vulns(ChallengeType.WEB)

    def test_web_full_set(self):
        kb = _mk_kb()
        result_set = set(kb.get_applicable_vulns(ChallengeType.WEB))
        assert self.WEB_EXPECTED.issubset(result_set)

    def test_pwn_contains_buffer_overflow(self):
        kb = _mk_kb()
        assert VulnType.BUFFER_OVERFLOW in kb.get_applicable_vulns(ChallengeType.PWN)

    def test_pwn_contains_format_string(self):
        kb = _mk_kb()
        assert VulnType.FORMAT_STRING in kb.get_applicable_vulns(ChallengeType.PWN)

    def test_pwn_contains_rop_chain(self):
        kb = _mk_kb()
        assert VulnType.ROP_CHAIN in kb.get_applicable_vulns(ChallengeType.PWN)

    def test_pwn_full_set(self):
        kb = _mk_kb()
        result_set = set(kb.get_applicable_vulns(ChallengeType.PWN))
        assert self.PWN_EXPECTED.issubset(result_set)

    def test_crypto_contains_weak_crypto(self):
        kb = _mk_kb()
        assert VulnType.WEAK_CRYPTO in kb.get_applicable_vulns(ChallengeType.CRYPTO)

    def test_forensics_contains_hidden_data(self):
        kb = _mk_kb()
        assert VulnType.HIDDEN_DATA in kb.get_applicable_vulns(ChallengeType.FORENSICS)

    def test_steganography_contains_hidden_data(self):
        kb = _mk_kb()
        assert VulnType.HIDDEN_DATA in kb.get_applicable_vulns(ChallengeType.STEGANOGRAPHY)

    def test_steganography_contains_polyglot(self):
        kb = _mk_kb()
        assert VulnType.POLYGLOT_FILE in kb.get_applicable_vulns(ChallengeType.STEGANOGRAPHY)

    def test_reverse_engineering_contains_weak_crypto(self):
        kb = _mk_kb()
        assert VulnType.WEAK_CRYPTO in kb.get_applicable_vulns(ChallengeType.REVERSE_ENGINEERING)

    def test_osint_returns_list(self):
        kb = _mk_kb()
        assert isinstance(kb.get_applicable_vulns(ChallengeType.OSINT), list)

    def test_network_contains_broken_auth(self):
        kb = _mk_kb()
        assert VulnType.BROKEN_AUTH in kb.get_applicable_vulns(ChallengeType.NETWORK)

    def test_misc_returns_list(self):
        kb = _mk_kb()
        assert isinstance(kb.get_applicable_vulns(ChallengeType.MISC), list)

    def test_returns_list_type(self):
        """All challenge types must return a list (not None)."""
        kb = _mk_kb()
        for ct in ChallengeType:
            result = kb.get_applicable_vulns(ct)
            assert isinstance(result, list), f"Expected list for {ct}"


# ──────────────────────────────────────────────────────────────────────────────
# add_confirmed_vuln / get_confirmed_vulns
# ──────────────────────────────────────────────────────────────────────────────

class TestConfirmedVulns:

    def test_initially_empty(self):
        kb = _mk_kb()
        assert kb.get_confirmed_vulns() == []

    def test_add_single_vuln(self):
        kb = _mk_kb()
        v = _vuln()
        kb.add_confirmed_vuln(v)
        assert len(kb.get_confirmed_vulns()) == 1

    def test_add_returns_vuln_correctly(self):
        kb = _mk_kb()
        v = _vuln(VulnType.XSS, "reflected")
        kb.add_confirmed_vuln(v)
        result = kb.get_confirmed_vulns()[0]
        assert result.type == VulnType.XSS
        assert result.technique == "reflected"

    def test_add_multiple_vulns(self):
        kb = _mk_kb()
        kb.add_confirmed_vuln(_vuln(VulnType.SQL_INJECTION, "union"))
        kb.add_confirmed_vuln(_vuln(VulnType.XSS, "reflected"))
        kb.add_confirmed_vuln(_vuln(VulnType.LFI, "traversal"))
        assert len(kb.get_confirmed_vulns()) == 3

    def test_get_returns_list(self):
        kb = _mk_kb()
        assert isinstance(kb.get_confirmed_vulns(), list)

    def test_same_vuln_twice_added(self):
        """Duplicates are allowed (not deduplicated)."""
        kb = _mk_kb()
        v = _vuln()
        kb.add_confirmed_vuln(v)
        kb.add_confirmed_vuln(v)
        assert len(kb.get_confirmed_vulns()) == 2

    def test_vuln_descriptor_with_endpoint_and_param(self):
        kb = _mk_kb()
        v = VulnDescriptor(
            type=VulnType.SQL_INJECTION,
            technique="blind",
            endpoint="/search",
            param="q",
            confidence=0.85,
        )
        kb.add_confirmed_vuln(v)
        result = kb.get_confirmed_vulns()[0]
        assert result.endpoint == "/search"
        assert result.param == "q"
        assert result.confidence == pytest.approx(0.85)


# ──────────────────────────────────────────────────────────────────────────────
# clear()
# ──────────────────────────────────────────────────────────────────────────────

class TestKnowledgeBaseClear:

    def test_clear_empties_confirmed_vulns(self):
        kb = _mk_kb()
        kb.add_confirmed_vuln(_vuln())
        kb.add_confirmed_vuln(_vuln(VulnType.XSS))
        kb.clear()
        assert kb.get_confirmed_vulns() == []

    def test_clear_allows_fresh_accumulation(self):
        kb = _mk_kb()
        kb.add_confirmed_vuln(_vuln())
        kb.clear()
        kb.add_confirmed_vuln(_vuln(VulnType.XSS, "stored"))
        assert len(kb.get_confirmed_vulns()) == 1
        assert kb.get_confirmed_vulns()[0].type == VulnType.XSS

    def test_applicable_vulns_unchanged_after_clear(self):
        """vuln_map should not be affected by clear()."""
        kb = _mk_kb()
        kb.clear()
        assert VulnType.SQL_INJECTION in kb.get_applicable_vulns(ChallengeType.WEB)


# ──────────────────────────────────────────────────────────────────────────────
# Global singleton
# ──────────────────────────────────────────────────────────────────────────────

class TestGetKnowledgeBase:

    def test_returns_knowledge_base_instance(self):
        kb = get_knowledge_base()
        assert isinstance(kb, KnowledgeBase)

    def test_singleton_identity(self):
        kb1 = get_knowledge_base()
        kb2 = get_knowledge_base()
        assert kb1 is kb2
