"""
Deep tests for FFUFAdapter command building and text-output fallback parser.

Covers:
- build_command core flags always present (-o, -of, -noninteractive, -ac, -ic)
- build_command: wordlist flag
- build_command: extensions flag
- build_command: match/filter status codes
- build_command: match/filter response size
- build_command: threads
- build_command: timeout
- build_command: custom headers
- build_command: URL appended with -u
- run(): stale output file removed before each run
- run(): returns canonical schema on error (RuntimeError from execute_command)
- run(): parses JSON output file correctly
- run(): fallback to text parser when JSON file missing/corrupt
- _parse_text_output: extracts paths from 200/301/302 lines
- DirSearchAdapter.build_command: core flags
- DirSearchAdapter.normalize_output: JSON parsing
"""

import json
import os
from unittest.mock import MagicMock, mock_open, patch

import pytest

from lattice_mind.adapters.ffuf_adapter import DirSearchAdapter, FFUFAdapter

# ──────────────────────────────────────────────────────────────────────────────
# FFUFAdapter.build_command
# ──────────────────────────────────────────────────────────────────────────────


class TestFFUFAdapterBuildCommand:

    def setup_method(self):
        self.adapter = FFUFAdapter()

    def test_starts_with_ffuf(self):
        cmd = self.adapter.build_command("http://example.com/FUZZ", {})
        assert cmd[0] == "ffuf"

    def test_output_file_flag(self):
        cmd = self.adapter.build_command("http://example.com/FUZZ", {})
        assert "-o" in cmd
        idx = cmd.index("-o")
        assert cmd[idx + 1] == "/tmp/ffuf_output.json"

    def test_output_format_json(self):
        cmd = self.adapter.build_command("http://example.com/FUZZ", {})
        assert "-of" in cmd
        idx = cmd.index("-of")
        assert cmd[idx + 1] == "json"

    def test_noninteractive_flag(self):
        cmd = self.adapter.build_command("http://example.com/FUZZ", {})
        assert "-noninteractive" in cmd

    def test_auto_calibrate_flag(self):
        cmd = self.adapter.build_command("http://example.com/FUZZ", {})
        assert "-ac" in cmd

    def test_ignore_comments_flag(self):
        cmd = self.adapter.build_command("http://example.com/FUZZ", {})
        assert "-ic" in cmd

    def test_default_wordlist(self):
        cmd = self.adapter.build_command("http://example.com/FUZZ", {})
        assert "-w" in cmd
        idx = cmd.index("-w")
        assert cmd[idx + 1] == FFUFAdapter.DEFAULT_WORDLIST

    def test_custom_wordlist(self):
        cmd = self.adapter.build_command(
            "http://example.com/FUZZ", {"wordlist": "/my/wordlist.txt"}
        )
        idx = cmd.index("-w")
        assert cmd[idx + 1] == "/my/wordlist.txt"

    def test_extensions_flag(self):
        cmd = self.adapter.build_command(
            "http://example.com/FUZZ", {"extensions": ".php,.html"}
        )
        assert "-e" in cmd
        idx = cmd.index("-e")
        assert cmd[idx + 1] == ".php,.html"

    def test_no_extensions_by_default(self):
        cmd = self.adapter.build_command("http://example.com/FUZZ", {})
        assert "-e" not in cmd

    def test_match_status_flag(self):
        cmd = self.adapter.build_command(
            "http://example.com/FUZZ", {"match_status": "200,301"}
        )
        assert "-mc" in cmd
        assert cmd[cmd.index("-mc") + 1] == "200,301"

    def test_filter_status_flag(self):
        cmd = self.adapter.build_command(
            "http://example.com/FUZZ", {"filter_status": "404,403"}
        )
        assert "-fc" in cmd

    def test_match_size_flag(self):
        cmd = self.adapter.build_command(
            "http://example.com/FUZZ", {"match_size": 1234}
        )
        assert "-ms" in cmd
        assert cmd[cmd.index("-ms") + 1] == "1234"

    def test_filter_size_flag(self):
        cmd = self.adapter.build_command("http://example.com/FUZZ", {"filter_size": 0})
        assert "-fs" in cmd
        assert cmd[cmd.index("-fs") + 1] == "0"

    def test_default_threads(self):
        cmd = self.adapter.build_command("http://example.com/FUZZ", {})
        assert "-t" in cmd
        assert cmd[cmd.index("-t") + 1] == "100"

    def test_custom_threads(self):
        cmd = self.adapter.build_command("http://example.com/FUZZ", {"threads": 200})
        assert cmd[cmd.index("-t") + 1] == "200"

    def test_default_timeout(self):
        cmd = self.adapter.build_command("http://example.com/FUZZ", {})
        assert "-timeout" in cmd
        assert cmd[cmd.index("-timeout") + 1] == "5"

    def test_custom_timeout(self):
        cmd = self.adapter.build_command("http://example.com/FUZZ", {"timeout": 10})
        assert cmd[cmd.index("-timeout") + 1] == "10"

    def test_custom_headers(self):
        cmd = self.adapter.build_command(
            "http://example.com/FUZZ", {"headers": {"Authorization": "Bearer t0k3n"}}
        )
        assert "-H" in cmd
        idx = cmd.index("-H")
        assert "Authorization: Bearer t0k3n" in cmd[idx + 1]

    def test_url_appended_with_u_flag(self):
        url = "http://example.com/FUZZ"
        cmd = self.adapter.build_command(url, {})
        assert "-u" in cmd
        assert cmd[cmd.index("-u") + 1] == url

    def test_no_match_status_by_default(self):
        cmd = self.adapter.build_command("http://example.com/FUZZ", {})
        assert "-mc" not in cmd


# ──────────────────────────────────────────────────────────────────────────────
# FFUFAdapter.run()
# ──────────────────────────────────────────────────────────────────────────────

SAMPLE_FFUF_JSON = {
    "results": [
        {
            "input": {"FUZZ": "admin"},
            "url": "http://example.com/admin",
            "status": 200,
            "length": 1234,
            "lines": 30,
            "words": 100,
        },
        {
            "input": {"FUZZ": "login"},
            "url": "http://example.com/login",
            "status": 301,
            "length": 0,
            "lines": 0,
            "words": 0,
        },
    ]
}


class TestFFUFAdapterRun:

    def setup_method(self):
        self.adapter = FFUFAdapter()

    def _assert_schema(self, result):
        assert "target" in result
        assert "results" in result
        assert "error" in result
        assert isinstance(result["results"], list)

    def test_returns_error_schema_on_execute_failure(self):
        with patch.object(
            self.adapter, "execute_command", side_effect=RuntimeError("ffuf missing")
        ):
            with patch("os.remove"):
                result = self.adapter.run("http://example.com/FUZZ", {})
        self._assert_schema(result)
        assert result["error"] is not None
        assert result["results"] == []

    def test_stale_output_file_removed_before_run(self, tmp_path):
        stale = tmp_path / "ffuf_output.json"
        stale.write_text('{"results":[]}')
        # Patch OUTPUT_FILE to our temp file
        self.adapter.OUTPUT_FILE = str(stale)
        with patch.object(
            self.adapter, "execute_command", side_effect=RuntimeError("err")
        ):
            self.adapter.run("http://example.com/FUZZ", {})
        # File should have been removed (os.remove called before execute)
        # Since execute raised immediately, it was already removed by the try block
        assert not stale.exists()

    def test_json_output_parsed_correctly(self, tmp_path):
        output_file = tmp_path / "ffuf_output.json"
        output_path_str = str(output_file)
        self.adapter.OUTPUT_FILE = output_path_str

        def fake_exec(cmd):
            # Write the output file during "execution"
            output_file.write_text(json.dumps(SAMPLE_FFUF_JSON))
            return ""

        with patch.object(self.adapter, "execute_command", side_effect=fake_exec):
            result = self.adapter.run("http://example.com/FUZZ", {})

        self._assert_schema(result)
        assert len(result["results"]) == 2
        paths = [r["path"] for r in result["results"]]
        assert "admin" in paths
        assert "login" in paths

    def test_result_item_schema(self, tmp_path):
        output_file = tmp_path / "ffuf_output.json"
        output_path_str = str(output_file)
        self.adapter.OUTPUT_FILE = output_path_str

        def fake_exec(cmd):
            output_file.write_text(json.dumps(SAMPLE_FFUF_JSON))
            return ""

        with patch.object(self.adapter, "execute_command", side_effect=fake_exec):
            result = self.adapter.run("http://example.com/FUZZ", {})

        item = result["results"][0]
        for key in ("path", "url", "status", "length", "lines", "words"):
            assert key in item, f"Missing key in result item: {key}"

    def test_fallback_to_text_parser_when_json_missing(self):
        """When output file doesn't exist, fall back to _parse_text_output."""
        self.adapter.OUTPUT_FILE = "/nonexistent/path/ffuf_output.json"
        self.adapter.last_output = "200  /admin  1234\n"
        with patch.object(
            self.adapter, "execute_command", return_value="200  /admin  1234\n"
        ):
            result = self.adapter.run("http://example.com/FUZZ", {})
        self._assert_schema(result)

    def test_target_in_result(self, tmp_path):
        output_file = tmp_path / "ffuf_output.json"
        output_file.write_text(json.dumps({"results": []}))
        self.adapter.OUTPUT_FILE = str(output_file)
        with patch.object(self.adapter, "execute_command", return_value=""):
            result = self.adapter.run("http://example.com/FUZZ", {})
        assert result["target"] == "http://example.com/FUZZ"

    def test_empty_results_valid_schema(self, tmp_path):
        output_file = tmp_path / "ffuf_output.json"
        output_file.write_text(json.dumps({"results": []}))
        self.adapter.OUTPUT_FILE = str(output_file)
        with patch.object(self.adapter, "execute_command", return_value=""):
            result = self.adapter.run("http://example.com/FUZZ", {})
        self._assert_schema(result)
        assert result["results"] == []

    def test_last_result_stored(self, tmp_path):
        output_file = tmp_path / "ffuf_output.json"
        self.adapter.OUTPUT_FILE = str(output_file)

        def fake_exec(cmd):
            output_file.write_text(json.dumps({"results": []}))
            return ""

        with patch.object(self.adapter, "execute_command", side_effect=fake_exec):
            result = self.adapter.run("http://example.com/FUZZ", {})
        assert self.adapter.last_result is result


# ──────────────────────────────────────────────────────────────────────────────
# FFUFAdapter._parse_text_output
# ──────────────────────────────────────────────────────────────────────────────


class TestFFUFParseTextOutput:

    def setup_method(self):
        self.adapter = FFUFAdapter()

    def _base_result(self):
        return {"target": "http://x.com", "wordlist": "", "results": [], "error": None}

    def test_200_line_detected(self):
        text = "admin               [Status: 200, Size: 1234, Words: 50, Lines: 10]\n"
        result = self.adapter._parse_text_output(text, self._base_result())
        assert len(result["results"]) >= 1

    def test_301_line_detected(self):
        text = "login               [Status: 301, Size: 0, Words: 0, Lines: 0]\n"
        result = self.adapter._parse_text_output(text, self._base_result())
        assert len(result["results"]) >= 1

    def test_302_line_detected(self):
        text = "redirect            [Status: 302, Size: 0, Words: 0, Lines: 0]\n"
        result = self.adapter._parse_text_output(text, self._base_result())
        assert len(result["results"]) >= 1

    def test_404_line_not_included(self):
        text = "missing             [Status: 404, Size: 100, Words: 10, Lines: 5]\n"
        result = self.adapter._parse_text_output(text, self._base_result())
        # 404 lines should NOT be treated as found paths
        for r in result["results"]:
            assert "missing" not in r.get("path", "")

    def test_empty_text_no_results(self):
        result = self.adapter._parse_text_output("", self._base_result())
        assert result["results"] == []

    def test_multiple_lines(self):
        text = "admin  200\nlogin  301\nsecret  200\n"
        result = self.adapter._parse_text_output(text, self._base_result())
        assert len(result["results"]) >= 2


# ──────────────────────────────────────────────────────────────────────────────
# DirSearchAdapter.build_command
# ──────────────────────────────────────────────────────────────────────────────


class TestDirSearchAdapterBuildCommand:

    def setup_method(self):
        self.adapter = DirSearchAdapter()

    def test_starts_with_dirsearch(self):
        cmd = self.adapter.build_command("http://example.com", {})
        assert cmd[0] == "dirsearch"

    def test_url_flag(self):
        cmd = self.adapter.build_command("http://example.com", {})
        assert "-u" in cmd
        assert "http://example.com" in cmd

    def test_format_json(self):
        cmd = self.adapter.build_command("http://example.com", {})
        assert "--format=json" in cmd

    def test_custom_wordlist(self):
        cmd = self.adapter.build_command(
            "http://example.com", {"wordlist": "/my/wl.txt"}
        )
        assert "-w" in cmd
        assert "/my/wl.txt" in cmd

    def test_no_wordlist_by_default(self):
        cmd = self.adapter.build_command("http://example.com", {})
        assert "-w" not in cmd

    def test_extensions(self):
        cmd = self.adapter.build_command(
            "http://example.com", {"extensions": "php,html"}
        )
        assert "-e" in cmd
        assert "php,html" in cmd

    def test_default_threads(self):
        cmd = self.adapter.build_command("http://example.com", {})
        assert "--threads" in cmd
        idx = cmd.index("--threads")
        assert cmd[idx + 1] == "50"


# ──────────────────────────────────────────────────────────────────────────────
# DirSearchAdapter.normalize_output
# ──────────────────────────────────────────────────────────────────────────────


class TestDirSearchNormalizeOutput:

    def setup_method(self):
        self.adapter = DirSearchAdapter()

    def _assert_schema(self, result):
        for key in ("target", "wordlist", "results", "error"):
            assert key in result

    def test_valid_json_list(self):
        data = [
            {"path": "/admin", "status": 200, "length": 100, "lines": 5, "words": 20}
        ]
        result = self.adapter.normalize_output(json.dumps(data))
        self._assert_schema(result)
        assert len(result["results"]) == 1
        assert result["results"][0]["path"] == "/admin"

    def test_result_schema(self):
        data = [{"path": "/login", "status": 301, "length": 0, "lines": 0, "words": 0}]
        result = self.adapter.normalize_output(json.dumps(data))
        item = result["results"][0]
        for key in ("path", "status", "length", "lines", "words"):
            assert key in item

    def test_empty_list(self):
        result = self.adapter.normalize_output("[]")
        self._assert_schema(result)
        assert result["results"] == []

    def test_invalid_json_returns_error(self):
        result = self.adapter.normalize_output("not json at all")
        self._assert_schema(result)
        assert result["error"] is not None

    def test_empty_string_returns_error(self):
        result = self.adapter.normalize_output("")
        self._assert_schema(result)
        assert result["error"] is not None
