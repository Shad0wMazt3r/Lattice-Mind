"""
Deep tests for BaseToolAdapter, CommandToolAdapter, and MockToolAdapter.

Covers:
- ToolAdapter.__init__: name, timeout, last_output, last_result defaults
- execute_command: runs subprocess, captures stdout+stderr, handles timeout
- execute_command: RuntimeError on timeout, RuntimeError on general exception
- parse_json_output: valid JSON, invalid JSON raises ValueError
- normalize_output: default implementation
- CommandToolAdapter.run: build -> execute -> normalize pipeline
- MockToolAdapter: always returns mock_response, stores last_result
- __repr__ formats correctly
"""
import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from lattice_mind.adapters.base import CommandToolAdapter, MockToolAdapter, ToolAdapter

# ──────────────────────────────────────────────────────────────────────────────
# Concrete minimal implementations for testing abstract classes
# ──────────────────────────────────────────────────────────────────────────────

class MinimalToolAdapter(ToolAdapter):
    """Minimal concrete subclass for ToolAdapter."""
    def run(self, target, args):
        return {"raw": target}


class MinimalCommandAdapter(CommandToolAdapter):
    """Concrete CommandToolAdapter that echoes target."""
    def build_command(self, target, args):
        return ["echo", target]

    def normalize_output(self, raw_output):
        return {"parsed": raw_output.strip()}


# ──────────────────────────────────────────────────────────────────────────────
# ToolAdapter.__init__
# ──────────────────────────────────────────────────────────────────────────────

class TestToolAdapterInit:

    def test_name_stored(self):
        adapter = MinimalToolAdapter("mytool")
        assert adapter.name == "mytool"

    def test_default_timeout(self):
        adapter = MinimalToolAdapter("mytool")
        assert adapter.timeout == 30.0

    def test_custom_timeout(self):
        adapter = MinimalToolAdapter("mytool", timeout=60.0)
        assert adapter.timeout == 60.0

    def test_last_output_none(self):
        adapter = MinimalToolAdapter("mytool")
        assert adapter.last_output is None

    def test_last_result_none(self):
        adapter = MinimalToolAdapter("mytool")
        assert adapter.last_result is None

    def test_repr(self):
        adapter = MinimalToolAdapter("mytool")
        r = repr(adapter)
        assert "MinimalToolAdapter" in r
        assert "mytool" in r


# ──────────────────────────────────────────────────────────────────────────────
# ToolAdapter.execute_command
# ──────────────────────────────────────────────────────────────────────────────

class TestExecuteCommand:

    def setup_method(self):
        self.adapter = MinimalToolAdapter("test")

    def _mock_run(self, stdout="", stderr="", returncode=0):
        mock_result = MagicMock()
        mock_result.stdout = stdout
        mock_result.stderr = stderr
        mock_result.returncode = returncode
        return mock_result

    def test_returns_stdout_plus_stderr(self):
        with patch("subprocess.run", return_value=self._mock_run("out", "err")):
            output = self.adapter.execute_command(["echo", "test"])
        assert "out" in output
        assert "err" in output

    def test_stores_last_output(self):
        with patch("subprocess.run", return_value=self._mock_run("stored", "")):
            self.adapter.execute_command(["echo", "stored"])
        assert self.adapter.last_output == "stored"

    def test_nonzero_returncode_logs_warning_not_raises(self):
        """Non-zero exit should NOT raise an exception by itself."""
        with patch("subprocess.run", return_value=self._mock_run("", "error msg", returncode=1)):
            output = self.adapter.execute_command(["false"])
        assert output is not None  # Does not raise

    def test_timeout_raises_runtime_error(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="cmd", timeout=5)):
            with pytest.raises(RuntimeError) as exc_info:
                self.adapter.execute_command(["sleep", "999"])
        assert "timed out" in str(exc_info.value).lower()

    def test_general_exception_raises_runtime_error(self):
        with patch("subprocess.run", side_effect=OSError("No such file")):
            with pytest.raises(RuntimeError) as exc_info:
                self.adapter.execute_command(["nonexistent_binary"])
        assert "failed" in str(exc_info.value).lower()

    def test_empty_output(self):
        with patch("subprocess.run", return_value=self._mock_run("", "")):
            output = self.adapter.execute_command(["true"])
        assert output == ""

    def test_large_output_handled(self):
        large = "x" * 100_000
        with patch("subprocess.run", return_value=self._mock_run(large, "")):
            output = self.adapter.execute_command(["cat", "bigfile"])
        assert len(output) == 100_000


# ──────────────────────────────────────────────────────────────────────────────
# ToolAdapter.parse_json_output
# ──────────────────────────────────────────────────────────────────────────────

class TestParseJsonOutput:

    def setup_method(self):
        self.adapter = MinimalToolAdapter("test")

    def test_valid_json_object(self):
        result = self.adapter.parse_json_output('{"key": "value", "num": 42}')
        assert result == {"key": "value", "num": 42}

    def test_valid_json_array(self):
        result = self.adapter.parse_json_output('[1, 2, 3]')
        assert result == [1, 2, 3]

    def test_empty_json_object(self):
        result = self.adapter.parse_json_output('{}')
        assert result == {}

    def test_nested_json(self):
        data = {"a": {"b": [1, 2, 3]}}
        result = self.adapter.parse_json_output(json.dumps(data))
        assert result == data

    def test_invalid_json_raises_value_error(self):
        with pytest.raises(ValueError) as exc_info:
            self.adapter.parse_json_output("not valid json")
        assert "Failed to parse" in str(exc_info.value)

    def test_empty_string_raises_value_error(self):
        with pytest.raises(ValueError):
            self.adapter.parse_json_output("")

    def test_partial_json_raises_value_error(self):
        with pytest.raises(ValueError):
            self.adapter.parse_json_output('{"key": "val"')  # missing closing brace


# ──────────────────────────────────────────────────────────────────────────────
# ToolAdapter.normalize_output  (base implementation)
# ──────────────────────────────────────────────────────────────────────────────

class TestNormalizeOutputBase:

    def setup_method(self):
        self.adapter = MinimalToolAdapter("test")

    def test_returns_raw_dict(self):
        result = self.adapter.normalize_output("hello world")
        assert result == {"raw": "hello world"}

    def test_empty_string(self):
        result = self.adapter.normalize_output("")
        assert result == {"raw": ""}


# ──────────────────────────────────────────────────────────────────────────────
# CommandToolAdapter.run  pipeline
# ──────────────────────────────────────────────────────────────────────────────

class TestCommandToolAdapterRun:

    def setup_method(self):
        self.adapter = MinimalCommandAdapter("minimalcmd")

    def test_run_calls_build_then_execute_then_normalize(self):
        with patch.object(self.adapter, "execute_command", return_value="echo output") as mock_exec:
            result = self.adapter.run("hello", {})
        # build_command should have produced ["echo", "hello"]
        mock_exec.assert_called_once_with(["echo", "hello"])
        assert result == {"parsed": "echo output"}

    def test_run_stores_last_result(self):
        with patch.object(self.adapter, "execute_command", return_value="data"):
            result = self.adapter.run("target", {})
        assert self.adapter.last_result is result

    def test_run_passes_target_to_build_command(self):
        build_calls = []
        original_build = self.adapter.build_command

        def track_build(target, args):
            build_calls.append(target)
            return original_build(target, args)

        self.adapter.build_command = track_build
        with patch.object(self.adapter, "execute_command", return_value=""):
            self.adapter.run("special_target", {})
        assert build_calls == ["special_target"]

    def test_run_passes_args_to_build_command(self):
        build_args = []
        original_build = self.adapter.build_command

        def track_build(target, args):
            build_args.append(args)
            return original_build(target, args)

        self.adapter.build_command = track_build
        with patch.object(self.adapter, "execute_command", return_value=""):
            self.adapter.run("t", {"opt": "val"})
        assert build_args[-1] == {"opt": "val"}

    def test_run_propagates_execute_runtime_error(self):
        with patch.object(self.adapter, "execute_command", side_effect=RuntimeError("boom")):
            with pytest.raises(RuntimeError):
                self.adapter.run("t", {})


# ──────────────────────────────────────────────────────────────────────────────
# MockToolAdapter
# ──────────────────────────────────────────────────────────────────────────────

class TestMockToolAdapter:

    def test_returns_mock_response(self):
        resp = {"status": 200, "body": "mocked"}
        adapter = MockToolAdapter("mock", resp)
        result = adapter.run("anything", {})
        assert result == resp

    def test_stores_last_result(self):
        resp = {"key": "value"}
        adapter = MockToolAdapter("mock", resp)
        adapter.run("t", {})
        assert adapter.last_result == resp

    def test_different_targets_same_response(self):
        resp = {"data": 42}
        adapter = MockToolAdapter("mock", resp)
        r1 = adapter.run("http://url1", {})
        r2 = adapter.run("http://url2", {})
        assert r1 == r2

    def test_mock_with_empty_response(self):
        adapter = MockToolAdapter("mock", {})
        result = adapter.run("t", {})
        assert result == {}

    def test_name_set_correctly(self):
        adapter = MockToolAdapter("special_mock", {})
        assert adapter.name == "special_mock"
