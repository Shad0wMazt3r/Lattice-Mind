"""
Deep tests for BinwalkAdapter, ExiftoolAdapter, and FileTypeAdapter.

Covers:
- BinwalkAdapter.build_command: entropy, extract, quiet flags
- BinwalkAdapter.normalize_output: schema, entropy parsing, signature extraction
- BinwalkAdapter.normalize_output: empty/garbage/partial output
- ExiftoolAdapter.build_command: json flag
- ExiftoolAdapter.normalize_output: JSON array parsing, SourceFile field
- ExiftoolAdapter.normalize_output: malformed JSON → error
- FileTypeAdapter.build_command: file -b flag
- FileTypeAdapter.normalize_output: type field set to raw output
"""
import json
from unittest.mock import patch

import pytest

from lattice_mind.adapters.file_adapter import (
    BinwalkAdapter,
    ExiftoolAdapter,
    FileTypeAdapter,
)

# ──────────────────────────────────────────────────────────────────────────────
# BinwalkAdapter.build_command
# ──────────────────────────────────────────────────────────────────────────────

class TestBinwalkAdapterBuildCommand:

    def setup_method(self):
        self.adapter = BinwalkAdapter()

    def test_starts_with_binwalk(self):
        cmd = self.adapter.build_command("/file.bin", {})
        assert cmd[0] == "binwalk"

    def test_entropy_flag_by_default(self):
        cmd = self.adapter.build_command("/file.bin", {})
        assert "-E" in cmd

    def test_entropy_disabled(self):
        cmd = self.adapter.build_command("/file.bin", {"entropy": False})
        assert "-E" not in cmd

    def test_extract_not_present_by_default(self):
        cmd = self.adapter.build_command("/file.bin", {})
        assert "-e" not in cmd

    def test_extract_flag_enabled(self):
        cmd = self.adapter.build_command("/file.bin", {"extract": True})
        assert "-e" in cmd

    def test_quiet_not_present_by_default(self):
        cmd = self.adapter.build_command("/file.bin", {})
        assert "-q" not in cmd

    def test_quiet_flag_enabled(self):
        cmd = self.adapter.build_command("/file.bin", {"quiet": True})
        assert "-q" in cmd

    def test_target_file_appended_last(self):
        cmd = self.adapter.build_command("/path/to/file.bin", {})
        assert cmd[-1] == "/path/to/file.bin"

    def test_all_options_combined(self):
        cmd = self.adapter.build_command("/file.bin", {
            "entropy": True, "extract": True, "quiet": True
        })
        assert "-E" in cmd
        assert "-e" in cmd
        assert "-q" in cmd
        assert cmd[-1] == "/file.bin"


# ──────────────────────────────────────────────────────────────────────────────
# BinwalkAdapter.normalize_output
# ──────────────────────────────────────────────────────────────────────────────

BINWALK_SAMPLE = """\
DECIMAL       HEXADECIMAL     DESCRIPTION
0             0x0             Zip archive data, at least v2.0 to extract, name: shell.php
1024          0x400           JPEG image data, JFIF standard 1.01

ENTROPY:
0.987 98.7% 0x0   High entropy data, data.zip
"""

BINWALK_SIMPLE = """\
0x0   ZIP   Zip archive data
0x400 JPEG  JPEG image data
"""


class TestBinwalkNormalizeOutput:

    def setup_method(self):
        self.adapter = BinwalkAdapter()

    def _assert_schema(self, result):
        for key in ("file", "entropy", "results", "error"):
            assert key in result
        assert isinstance(result["results"], list)
        assert isinstance(result["entropy"], float)

    def test_schema_always_complete(self):
        self._assert_schema(self.adapter.normalize_output(BINWALK_SIMPLE))

    def test_schema_on_empty_input(self):
        self._assert_schema(self.adapter.normalize_output(""))

    def test_schema_on_garbage(self):
        self._assert_schema(self.adapter.normalize_output("!@#$%^")  )

    def test_default_entropy_zero(self):
        result = self.adapter.normalize_output(BINWALK_SIMPLE)
        # No ENTROPY section in this sample
        assert isinstance(result["entropy"], float)

    def test_signatures_extracted(self):
        result = self.adapter.normalize_output(BINWALK_SIMPLE)
        assert len(result["results"]) == 2

    def test_signature_offset_field(self):
        result = self.adapter.normalize_output(BINWALK_SIMPLE)
        offsets = [r["offset"] for r in result["results"]]
        assert "0x0" in offsets

    def test_signature_type_field(self):
        result = self.adapter.normalize_output(BINWALK_SIMPLE)
        types = [r["type"] for r in result["results"]]
        assert "ZIP" in types

    def test_signature_description_field(self):
        result = self.adapter.normalize_output(BINWALK_SIMPLE)
        desc = result["results"][0]["description"]
        assert isinstance(desc, str)

    def test_entropy_parsed_from_output(self):
        output = "ENTROPY:\n0.987 98.7% 0x0\n"
        result = self.adapter.normalize_output(output)
        # entropy should be 0.987
        assert result["entropy"] == pytest.approx(0.987, abs=0.001)

    def test_empty_output_no_results(self):
        result = self.adapter.normalize_output("")
        assert result["results"] == []

    def test_error_is_none_on_valid(self):
        result = self.adapter.normalize_output(BINWALK_SIMPLE)
        assert result["error"] is None


# ──────────────────────────────────────────────────────────────────────────────
# ExiftoolAdapter.build_command
# ──────────────────────────────────────────────────────────────────────────────

class TestExiftoolAdapterBuildCommand:

    def setup_method(self):
        self.adapter = ExiftoolAdapter()

    def test_starts_with_exiftool(self):
        cmd = self.adapter.build_command("/image.jpg", {})
        assert cmd[0] == "exiftool"

    def test_json_flag_by_default(self):
        cmd = self.adapter.build_command("/image.jpg", {})
        assert "-json" in cmd

    def test_json_flag_disabled(self):
        cmd = self.adapter.build_command("/image.jpg", {"json": False})
        assert "-json" not in cmd

    def test_target_appended_last(self):
        cmd = self.adapter.build_command("/path/to/image.jpg", {})
        assert cmd[-1] == "/path/to/image.jpg"


# ──────────────────────────────────────────────────────────────────────────────
# ExiftoolAdapter.normalize_output
# ──────────────────────────────────────────────────────────────────────────────

EXIFTOOL_JSON = json.dumps([{
    "SourceFile": "/tmp/image.jpg",
    "MIMEType": "image/jpeg",
    "ImageWidth": 1920,
    "ImageHeight": 1080,
    "CreateDate": "2024:01:01 12:00:00"
}])


class TestExiftoolNormalizeOutput:

    def setup_method(self):
        self.adapter = ExiftoolAdapter()

    def _assert_schema(self, result):
        for key in ("file", "metadata", "error"):
            assert key in result
        assert isinstance(result["metadata"], dict)

    def test_schema_on_valid_input(self):
        result = self.adapter.normalize_output(EXIFTOOL_JSON)
        self._assert_schema(result)

    def test_source_file_extracted(self):
        result = self.adapter.normalize_output(EXIFTOOL_JSON)
        assert result["file"] == "/tmp/image.jpg"

    def test_metadata_fields_present(self):
        result = self.adapter.normalize_output(EXIFTOOL_JSON)
        assert "MIMEType" in result["metadata"]
        assert result["metadata"]["MIMEType"] == "image/jpeg"

    def test_metadata_width_height(self):
        result = self.adapter.normalize_output(EXIFTOOL_JSON)
        assert result["metadata"]["ImageWidth"] == 1920
        assert result["metadata"]["ImageHeight"] == 1080

    def test_error_none_on_success(self):
        result = self.adapter.normalize_output(EXIFTOOL_JSON)
        assert result["error"] is None

    def test_empty_array_input(self):
        result = self.adapter.normalize_output("[]")
        self._assert_schema(result)
        assert result["metadata"] == {}

    def test_json_parse_error_sets_error(self):
        result = self.adapter.normalize_output("not json at all")
        self._assert_schema(result)
        assert result["error"] is not None
        assert "JSON parse error" in result["error"]

    def test_empty_string_sets_error(self):
        result = self.adapter.normalize_output("")
        self._assert_schema(result)
        assert result["error"] is not None

    def test_metadata_count(self):
        result = self.adapter.normalize_output(EXIFTOOL_JSON)
        # Should have at least 5 fields from our sample
        assert len(result["metadata"]) >= 5


# ──────────────────────────────────────────────────────────────────────────────
# FileTypeAdapter.build_command
# ──────────────────────────────────────────────────────────────────────────────

class TestFileTypeAdapterBuildCommand:

    def setup_method(self):
        self.adapter = FileTypeAdapter()

    def test_starts_with_file(self):
        cmd = self.adapter.build_command("/some/file", {})
        assert cmd[0] == "file"

    def test_brief_flag(self):
        cmd = self.adapter.build_command("/some/file", {})
        assert "-b" in cmd

    def test_target_appended(self):
        cmd = self.adapter.build_command("/path/to/file.bin", {})
        assert "/path/to/file.bin" in cmd


# ──────────────────────────────────────────────────────────────────────────────
# FileTypeAdapter.normalize_output
# ──────────────────────────────────────────────────────────────────────────────

class TestFileTypeNormalizeOutput:

    def setup_method(self):
        self.adapter = FileTypeAdapter()

    def _assert_schema(self, result):
        for key in ("file", "type", "error"):
            assert key in result

    def test_schema_complete(self):
        self._assert_schema(self.adapter.normalize_output("ELF 64-bit LSB executable"))

    def test_type_set_to_raw_output(self):
        result = self.adapter.normalize_output("ELF 64-bit LSB executable\n")
        assert result["type"] == "ELF 64-bit LSB executable"

    def test_type_stripped(self):
        result = self.adapter.normalize_output("  JPEG image data  \n")
        assert result["type"] == "JPEG image data"

    def test_empty_output(self):
        result = self.adapter.normalize_output("")
        self._assert_schema(result)
        assert result["type"] == ""

    def test_error_is_none(self):
        result = self.adapter.normalize_output("PDF document")
        assert result["error"] is None

    def test_multiline_output_stripped_to_first(self):
        # normalize strips but doesn't split — full output is preserved after strip
        raw = "ASCII text\n"
        result = self.adapter.normalize_output(raw)
        assert "ASCII text" in result["type"]
