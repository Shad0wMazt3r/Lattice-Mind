"""
Deep tests for FlagRecognizer.

Covers:
- recognize: returns None on empty/None input
- recognize: detects all standard flag formats (picoCTF, flag{}, FLAG{}, ctf{}, etc.)
- recognize: returns FIRST match only
- recognize: case-insensitive matching where applicable
- recognize_all: finds multiple flags in one string
- recognize_all: returns empty list on no match
- has_flag: boolean API
- found_flags accumulator grows on each recognize() call
- clear() resets found_flags
- Unusual but valid flag content (numbers, underscores, dots, hyphens)
- Flag inside larger text (mid-sentence)
- Flag across different patterns in the same string
"""

import pytest

from lattice_mind.core.flag_recognizer import FlagRecognizer, get_flag_recognizer

# ──────────────────────────────────────────────────────────────────────────────
# Recognised flag samples
# ──────────────────────────────────────────────────────────────────────────────

PICOCF_SAMPLE = "picoCTF{this_is_a_flag_1234}"
FLAG_CURLY = "flag{secret_value}"
FLAG_CURLY_UPPER = "FLAG{UPPER_CASE}"
CTF_CURLY = "ctf{lowercase_ctf_flag}"
CTF_CURLY_UPPER = "CTF{UPPERCASE_CTF}"
FLAG_PAREN = "flag(parenthesis_flag)"
FLAG_PAREN_UPPER = "FLAG(PAREN_UPPER)"

ALL_FORMATS = [
    PICOCF_SAMPLE,
    FLAG_CURLY,
    FLAG_CURLY_UPPER,
    CTF_CURLY,
    CTF_CURLY_UPPER,
    FLAG_PAREN,
    FLAG_PAREN_UPPER,
]


# ──────────────────────────────────────────────────────────────────────────────
# recognize()
# ──────────────────────────────────────────────────────────────────────────────


class TestFlagRecognizerRecognize:

    def mk(self):
        return FlagRecognizer()

    def test_empty_string_returns_none(self):
        fr = self.mk()
        assert fr.recognize("") is None

    def test_none_returns_none(self):
        fr = self.mk()
        assert fr.recognize(None) is None  # type: ignore

    def test_no_flag_returns_none(self):
        fr = self.mk()
        assert fr.recognize("hello world, no flag here") is None

    def test_garbage_text_returns_none(self):
        fr = self.mk()
        assert fr.recognize("!@#$%^&*()zxcvbnm") is None

    @pytest.mark.parametrize("flag_str", ALL_FORMATS)
    def test_detects_flag_format(self, flag_str):
        fr = self.mk()
        result = fr.recognize(flag_str)
        assert result is not None, f"Should detect: {flag_str}"

    def test_picoctf_format(self):
        fr = self.mk()
        result = fr.recognize(PICOCF_SAMPLE)
        assert "picoCTF" in result
        assert "this_is_a_flag_1234" in result

    def test_flag_curly_format(self):
        fr = self.mk()
        result = fr.recognize(FLAG_CURLY)
        assert result is not None
        assert "secret_value" in result

    def test_flag_with_numbers(self):
        fr = self.mk()
        assert fr.recognize("flag{abc123}") is not None

    def test_flag_with_underscores(self):
        fr = self.mk()
        assert fr.recognize("flag{foo_bar_baz}") is not None

    def test_flag_with_hyphens(self):
        fr = self.mk()
        assert fr.recognize("flag{foo-bar}") is not None

    def test_flag_with_dots(self):
        fr = self.mk()
        assert fr.recognize("flag{v1.2.3}") is not None

    def test_flag_embedded_in_html(self):
        fr = self.mk()
        text = "<p>The solution is: flag{hidden_in_html} congratulations!</p>"
        result = fr.recognize(text)
        assert result is not None
        assert "hidden_in_html" in result

    def test_flag_embedded_in_json(self):
        fr = self.mk()
        text = '{"message": "You won!", "flag": "picoCTF{json_flag_123}"}'
        assert fr.recognize(text) is not None

    def test_returns_first_match_only(self):
        fr = self.mk()
        # Two flags in the same string
        text = "flag{first} and flag{second}"
        result = fr.recognize(text)
        assert result is not None
        # Should return one flag only (the first match)
        assert "first" in result

    def test_found_flags_accumulates(self):
        fr = self.mk()
        fr.recognize("flag{one}")
        fr.recognize("flag{two}")
        assert len(fr.found_flags) == 2
        assert "flag{one}" in fr.found_flags
        assert "flag{two}" in fr.found_flags

    def test_no_match_does_not_accumulate(self):
        fr = self.mk()
        fr.recognize("no flag here")
        assert len(fr.found_flags) == 0

    def test_flag_returned_is_string(self):
        fr = self.mk()
        result = fr.recognize("flag{test}")
        assert isinstance(result, str)


# ──────────────────────────────────────────────────────────────────────────────
# recognize_all()
# ──────────────────────────────────────────────────────────────────────────────


class TestFlagRecognizerRecognizeAll:

    def mk(self):
        return FlagRecognizer()

    def test_empty_string_returns_empty_list(self):
        fr = self.mk()
        assert fr.recognize_all("") == []

    def test_none_returns_empty_list(self):
        fr = self.mk()
        assert fr.recognize_all(None) == []  # type: ignore

    def test_no_match_returns_empty_list(self):
        fr = self.mk()
        assert fr.recognize_all("no flags here at all") == []

    def test_single_flag_returned(self):
        fr = self.mk()
        result = fr.recognize_all("flag{only_one}")
        # Multiple compiled patterns may match the same flag string; at least 1 expected
        assert len(result) >= 1
        assert any("only_one" in r for r in result)

    def test_multiple_flags_same_pattern(self):
        fr = self.mk()
        text = "flag{first} and flag{second}"
        result = fr.recognize_all(text)
        assert len(result) >= 2

    def test_returns_list(self):
        fr = self.mk()
        result = fr.recognize_all("flag{x}")
        assert isinstance(result, list)


# ──────────────────────────────────────────────────────────────────────────────
# has_flag()
# ──────────────────────────────────────────────────────────────────────────────


class TestFlagRecognizerHasFlag:

    def mk(self):
        return FlagRecognizer()

    def test_true_when_flag_present(self):
        fr = self.mk()
        assert fr.has_flag("The flag is: flag{found_it}") is True

    def test_false_when_no_flag(self):
        fr = self.mk()
        assert fr.has_flag("no flag here") is False

    def test_empty_is_false(self):
        fr = self.mk()
        assert fr.has_flag("") is False


# ──────────────────────────────────────────────────────────────────────────────
# clear()
# ──────────────────────────────────────────────────────────────────────────────


class TestFlagRecognizerClear:

    def test_clear_empties_found_flags(self):
        fr = FlagRecognizer()
        fr.recognize("flag{one}")
        fr.recognize("flag{two}")
        fr.clear()
        assert fr.found_flags == []

    def test_clear_allows_fresh_accumulation(self):
        fr = FlagRecognizer()
        fr.recognize("flag{a}")
        fr.clear()
        fr.recognize("flag{b}")
        assert fr.found_flags == ["flag{b}"]


# ──────────────────────────────────────────────────────────────────────────────
# Global singleton
# ──────────────────────────────────────────────────────────────────────────────


class TestGetFlagRecognizer:

    def test_returns_flag_recognizer_instance(self):
        fr = get_flag_recognizer()
        assert isinstance(fr, FlagRecognizer)

    def test_singleton_identity(self):
        fr1 = get_flag_recognizer()
        fr2 = get_flag_recognizer()
        assert fr1 is fr2

    def test_env_style_flag_pattern(self):
        """FLAG=flag{value} style should be recognised."""
        fr = FlagRecognizer()
        text = "FLAG=picoCTF{env_style_flag}"
        result = fr.recognize(text)
        assert result is not None
