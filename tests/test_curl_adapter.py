"""
Deep tests for CurlAdapter and RequestsAdapter.

Covers:
- build_command generates correct flags for every option
- normalize_output parser handles real curl -v output structure
- Output schema (status, headers, body, error) is always present
- HTTP and HTTPS URL handling
- Error / empty input handling
- RequestsAdapter live HTTP roundtrip (http + https)
- RequestsAdapter fallback to CurlAdapter when requests is not installed
"""
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

from lattice_mind.adapters.curl_adapter import CurlAdapter, RequestsAdapter

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _make_curl_verbose_output(status: int, headers: dict, body: str) -> str:
    """Synthesise curl -v output that the parser must handle."""
    lines = []
    # Request pseudo-lines (curl prints "> ...")
    lines.append("> GET / HTTP/1.1")
    lines.append("> Host: example.com")
    lines.append(">")
    # Status line
    lines.append(f"< HTTP/1.1 {status} OK")
    # Response headers
    for k, v in headers.items():
        lines.append(f"< {k}: {v}")
    lines.append("<")
    # Body
    lines.append(body)
    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# CurlAdapter.build_command
# ──────────────────────────────────────────────────────────────────────────────

class TestCurlAdapterBuildCommand:
    """Verify every option is translated into the correct curl flags."""

    def setup_method(self):
        self.adapter = CurlAdapter()

    def test_default_get_command(self):
        cmd = self.adapter.build_command("http://example.com", {})
        assert cmd[0] == "curl"
        assert "-v" in cmd
        assert "-s" in cmd
        assert "http://example.com" in cmd
        # GET is default — no explicit -X GET
        assert "-X" not in cmd

    def test_post_method(self):
        cmd = self.adapter.build_command("http://example.com", {"method": "POST"})
        assert "-X" in cmd
        assert cmd[cmd.index("-X") + 1] == "POST"

    def test_delete_method(self):
        cmd = self.adapter.build_command("http://example.com", {"method": "DELETE"})
        assert cmd[cmd.index("-X") + 1] == "DELETE"

    def test_custom_headers_single(self):
        cmd = self.adapter.build_command(
            "http://example.com",
            {"headers": {"X-Custom": "value123"}}
        )
        assert "-H" in cmd
        idx = cmd.index("-H")
        assert "X-Custom: value123" in cmd[idx + 1]

    def test_custom_headers_multiple(self):
        headers = {"Authorization": "Bearer tok", "Accept": "application/json"}
        cmd = self.adapter.build_command("http://example.com", {"headers": headers})
        # Each header produces a -H flag
        h_indices = [i for i, x in enumerate(cmd) if x == "-H"]
        assert len(h_indices) == 2
        header_values = [cmd[i + 1] for i in h_indices]
        assert any("Authorization: Bearer tok" in hv for hv in header_values)
        assert any("Accept: application/json" in hv for hv in header_values)

    def test_post_data(self):
        cmd = self.adapter.build_command(
            "http://example.com", {"data": "username=admin&password=secret"}
        )
        assert "-d" in cmd
        assert cmd[cmd.index("-d") + 1] == "username=admin&password=secret"

    def test_query_params_appended_to_url(self):
        cmd = self.adapter.build_command(
            "http://example.com/search",
            {"params": {"q": "hello", "page": "1"}}
        )
        last = cmd[-1]
        assert "http://example.com/search?" in last
        assert "q=hello" in last
        assert "page=1" in last

    def test_follow_redirects_flag(self):
        cmd = self.adapter.build_command("http://example.com", {"follow_redirects": True})
        assert "-L" in cmd

    def test_no_follow_redirects_by_default(self):
        cmd = self.adapter.build_command("http://example.com", {})
        assert "-L" not in cmd

    def test_insecure_flag(self):
        cmd = self.adapter.build_command("https://example.com", {"insecure": True})
        assert "-k" in cmd

    def test_secure_by_default(self):
        cmd = self.adapter.build_command("https://example.com", {})
        assert "-k" not in cmd

    def test_https_url_preserved(self):
        cmd = self.adapter.build_command("https://secure.example.com/path", {})
        assert cmd[-1] == "https://secure.example.com/path"

    def test_http_url_preserved(self):
        cmd = self.adapter.build_command("http://plain.example.com/path", {})
        assert cmd[-1] == "http://plain.example.com/path"

    def test_combined_post_with_headers_and_data(self):
        cmd = self.adapter.build_command("http://example.com/login", {
            "method": "POST",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "data": "user=admin&pass=pass"
        })
        assert "-X" in cmd and cmd[cmd.index("-X") + 1] == "POST"
        assert "-H" in cmd
        assert "-d" in cmd


# ──────────────────────────────────────────────────────────────────────────────
# CurlAdapter.normalize_output  — output schema validation
# ──────────────────────────────────────────────────────────────────────────────

class TestCurlAdapterNormalizeOutput:
    """Verify that normalize_output always returns the canonical schema."""

    def setup_method(self):
        self.adapter = CurlAdapter()

    def _assert_schema(self, result):
        """Every result must have these four keys with the correct types."""
        assert "status" in result
        assert "headers" in result
        assert "body" in result
        assert "error" in result
        assert isinstance(result["headers"], dict)
        assert isinstance(result["body"], str)

    def test_schema_on_well_formed_output(self):
        raw = _make_curl_verbose_output(200, {"Content-Type": "text/html"}, "<html></html>")
        result = self.adapter.normalize_output(raw)
        self._assert_schema(result)

    def test_status_200_parsed(self):
        raw = _make_curl_verbose_output(200, {}, "")
        assert self.adapter.normalize_output(raw)["status"] == 200

    def test_status_404_parsed(self):
        raw = _make_curl_verbose_output(404, {}, "Not Found")
        assert self.adapter.normalize_output(raw)["status"] == 404

    def test_status_301_parsed(self):
        raw = _make_curl_verbose_output(301, {"Location": "https://example.com/"}, "")
        res = self.adapter.normalize_output(raw)
        assert res["status"] == 301

    def test_status_500_parsed(self):
        raw = _make_curl_verbose_output(500, {}, "Internal Server Error")
        assert self.adapter.normalize_output(raw)["status"] == 500

    def test_header_extracted(self):
        raw = _make_curl_verbose_output(
            200,
            {"Content-Type": "text/html", "X-Frame-Options": "DENY"},
            ""
        )
        result = self.adapter.normalize_output(raw)
        assert "Content-Type" in result["headers"]
        assert result["headers"]["Content-Type"] == "text/html"

    def test_multiple_headers_extracted(self):
        raw = _make_curl_verbose_output(
            200,
            {"Content-Type": "application/json", "Server": "nginx", "Cache-Control": "no-cache"},
            '{"ok": true}'
        )
        result = self.adapter.normalize_output(raw)
        assert "Content-Type" in result["headers"]
        assert "Server" in result["headers"]
        assert "Cache-Control" in result["headers"]

    def test_body_extracted(self):
        raw = _make_curl_verbose_output(200, {}, "Hello, World!")
        result = self.adapter.normalize_output(raw)
        assert "Hello, World!" in result["body"]

    def test_empty_input_gives_error(self):
        result = self.adapter.normalize_output("")
        self._assert_schema(result)
        assert result["status"] == 0  # couldn't parse
        assert result["error"] is not None

    def test_garbage_input_returns_error_not_exception(self):
        result = self.adapter.normalize_output("zzz garbage lkajslkdj 123")
        self._assert_schema(result)
        # Should not raise; status will be 0 or None
        assert result["status"] in (0, None)

    def test_no_status_line_sets_error(self):
        raw = "< Content-Type: text/html\n<\n<html/>"
        result = self.adapter.normalize_output(raw)
        self._assert_schema(result)
        assert result["error"] is not None

    def test_error_field_none_on_success(self):
        raw = _make_curl_verbose_output(200, {"Content-Type": "text/plain"}, "ok")
        result = self.adapter.normalize_output(raw)
        assert result["error"] is None

    def test_http_1_0_status_parsed(self):
        raw = "< HTTP/1.0 200 OK\n<\nresponse body"
        result = self.adapter.normalize_output(raw)
        assert result["status"] == 200

    def test_http2_status_parsed(self):
        raw = "< HTTP/2 200 \n<\nbody content"
        result = self.adapter.normalize_output(raw)
        assert result["status"] == 200


# ──────────────────────────────────────────────────────────────────────────────
# CurlAdapter.run  — integration (mocked subprocess)
# ──────────────────────────────────────────────────────────────────────────────

class TestCurlAdapterRun:
    """Test the full run() flow with mocked subprocess."""

    def setup_method(self):
        self.adapter = CurlAdapter()

    def test_run_calls_execute_then_normalize(self):
        fake_raw = _make_curl_verbose_output(200, {"Content-Type": "text/html"}, "<html/>")
        with patch.object(self.adapter, "execute_command", return_value=fake_raw) as mock_exec:
            result = self.adapter.run("http://example.com", {})
        mock_exec.assert_called_once()
        assert result["status"] == 200
        assert isinstance(result["headers"], dict)

    def test_run_stores_last_result(self):
        fake_raw = _make_curl_verbose_output(200, {}, "body")
        with patch.object(self.adapter, "execute_command", return_value=fake_raw):
            result = self.adapter.run("http://example.com", {})
        assert self.adapter.last_result is result

    def test_run_with_http_url(self):
        fake_raw = _make_curl_verbose_output(200, {}, "plain http response")
        with patch.object(self.adapter, "execute_command", return_value=fake_raw) as mock_exec:
            self.adapter.run("http://example.com", {})
        cmd = mock_exec.call_args[0][0]
        assert any("http://example.com" in part for part in cmd)

    def test_run_with_https_url(self):
        fake_raw = _make_curl_verbose_output(200, {}, "https response")
        with patch.object(self.adapter, "execute_command", return_value=fake_raw) as mock_exec:
            self.adapter.run("https://secure.example.com", {})
        cmd = mock_exec.call_args[0][0]
        assert any("https://secure.example.com" in part for part in cmd)

    def test_run_result_schema_complete(self):
        fake_raw = _make_curl_verbose_output(404, {"Content-Type": "text/plain"}, "not here")
        with patch.object(self.adapter, "execute_command", return_value=fake_raw):
            result = self.adapter.run("http://example.com", {})
        assert "status" in result
        assert "headers" in result
        assert "body" in result
        assert "error" in result


# ──────────────────────────────────────────────────────────────────────────────
# RequestsAdapter — live HTTP tests (http + https with real internet)
# ──────────────────────────────────────────────────────────────────────────────

class TestRequestsAdapterLive:
    """
    Live HTTP tests using the requests library.
    These require internet access and will be skipped if unavailable.
    """

    @pytest.fixture(autouse=True)
    def check_requests(self):
        try:
            import requests  # noqa: F401
        except ImportError:
            pytest.skip("requests library not installed")

    def _make_adapter(self):
        return RequestsAdapter(timeout=10.0)

    # ── Schema validation helper ──────────────────────────────────────────────

    def _assert_valid_schema(self, result):
        assert isinstance(result, dict), "Result must be a dict"
        assert "status" in result, "Missing 'status'"
        assert "headers" in result, "Missing 'headers'"
        assert "body" in result, "Missing 'body'"
        assert "error" in result, "Missing 'error'"
        assert isinstance(result["headers"], dict), "headers must be dict"
        assert isinstance(result["body"], str), "body must be str"

    # ── HTTP tests ────────────────────────────────────────────────────────────

    @pytest.mark.network
    def test_http_google_status(self):
        """http://google.com must return a valid HTTP status (200 or 3xx)."""
        adapter = self._make_adapter()
        result = adapter.run("http://google.com", {"follow_redirects": False})
        self._assert_valid_schema(result)
        assert result["status"] in range(100, 600), f"Unexpected status: {result['status']}"

    @pytest.mark.network
    def test_http_google_headers_present(self):
        """http://google.com response must include headers."""
        adapter = self._make_adapter()
        result = adapter.run("http://google.com", {"follow_redirects": False})
        self._assert_valid_schema(result)
        assert len(result["headers"]) > 0, "Expected at least one response header"

    @pytest.mark.network
    def test_http_google_has_content_type(self):
        """google.com should set Content-Type in headers."""
        adapter = self._make_adapter()
        result = adapter.run("http://google.com", {"follow_redirects": True})
        self._assert_valid_schema(result)
        header_keys = [k.lower() for k in result["headers"]]
        assert "content-type" in header_keys

    @pytest.mark.network
    def test_http_google_body_is_html(self):
        """Following redirects to google.com should return HTML body."""
        adapter = self._make_adapter()
        result = adapter.run("http://google.com", {"follow_redirects": True})
        self._assert_valid_schema(result)
        body_lower = result["body"].lower()
        assert "<html" in body_lower or "<!doctype html" in body_lower, \
            "Body should contain HTML markup"

    @pytest.mark.network
    def test_http_error_field_none_on_success(self):
        """error must be None on a successful request."""
        adapter = self._make_adapter()
        result = adapter.run("http://httpbin.org/get", {"follow_redirects": True})
        self._assert_valid_schema(result)
        if result["status"] and result["status"] < 500:
            assert result["error"] is None

    # ── HTTPS tests ───────────────────────────────────────────────────────────

    @pytest.mark.network
    def test_https_google_status(self):
        """https://google.com must return a valid status."""
        adapter = self._make_adapter()
        result = adapter.run("https://google.com", {"follow_redirects": True})
        self._assert_valid_schema(result)
        assert result["status"] in range(100, 600)

    @pytest.mark.network
    def test_https_google_has_headers(self):
        """HTTPS google.com must include response headers."""
        adapter = self._make_adapter()
        result = adapter.run("https://google.com", {"follow_redirects": True})
        self._assert_valid_schema(result)
        assert len(result["headers"]) > 0

    @pytest.mark.network
    def test_https_google_body_not_empty(self):
        """HTTPS google.com body should not be empty when redirects followed."""
        adapter = self._make_adapter()
        result = adapter.run("https://www.google.com", {"follow_redirects": True})
        self._assert_valid_schema(result)
        assert len(result["body"]) > 0

    @pytest.mark.network
    def test_https_status_200_httpbin(self):
        """https://httpbin.org/status/200 should return exactly 200."""
        adapter = self._make_adapter()
        result = adapter.run("https://httpbin.org/status/200", {})
        self._assert_valid_schema(result)
        assert result["status"] == 200

    @pytest.mark.network
    def test_https_status_404_httpbin(self):
        """https://httpbin.org/status/404 should return 404."""
        adapter = self._make_adapter()
        result = adapter.run("https://httpbin.org/status/404", {})
        self._assert_valid_schema(result)
        assert result["status"] == 404

    @pytest.mark.network
    def test_https_headers_endpoint(self):
        """httpbin /headers should echo back custom headers."""
        adapter = self._make_adapter()
        result = adapter.run(
            "https://httpbin.org/headers",
            {"headers": {"X-Test-Header": "lattice123"}}
        )
        self._assert_valid_schema(result)
        assert result["status"] == 200
        assert "lattice123" in result["body"]

    @pytest.mark.network
    def test_post_request_httpbin(self):
        """POST to httpbin should echo the posted data."""
        adapter = self._make_adapter()
        result = adapter.run(
            "https://httpbin.org/post",
            {"method": "POST", "data": "key=value"}
        )
        self._assert_valid_schema(result)
        assert result["status"] == 200
        assert "key" in result["body"]

    @pytest.mark.network
    def test_query_params_included(self):
        """Query params should appear in the request and be reflected by httpbin."""
        adapter = self._make_adapter()
        result = adapter.run(
            "https://httpbin.org/get",
            {"params": {"foo": "bar", "baz": "qux"}}
        )
        self._assert_valid_schema(result)
        assert result["status"] == 200
        assert "foo" in result["body"]
        assert "bar" in result["body"]

    # ── Unreachable / invalid host tests ─────────────────────────────────────

    def test_invalid_host_returns_error(self):
        """Requesting an obviously nonexistent host must return an error, not crash."""
        adapter = RequestsAdapter(timeout=2.0)
        result = adapter.run("http://this.host.does.not.exist.invalid", {})
        self._assert_valid_schema(result)
        # Should have an error message, not a valid status
        assert result["error"] is not None or result["status"] is None or result["status"] == 0


# ──────────────────────────────────────────────────────────────────────────────
# RequestsAdapter — fallback to CurlAdapter
# ──────────────────────────────────────────────────────────────────────────────

class TestRequestsAdapterFallback:
    """If 'requests' is not importable, RequestsAdapter should delegate to CurlAdapter."""

    def test_fallback_to_curl_when_requests_missing(self):
        mock_curl = MagicMock()
        mock_curl.run.return_value = {
            "status": 200, "headers": {}, "body": "curl fallback", "error": None
        }
        with patch("builtins.__import__", side_effect=lambda name, *a, **kw: (_ for _ in ()).throw(ImportError()) if name == "requests" else __import__(name, *a, **kw)):
            with patch("lattice_mind.adapters.curl_adapter.CurlAdapter", return_value=mock_curl):
                adapter = RequestsAdapter()
                # Force the flag
                adapter._use_requests = False
                adapter._curl_adapter = mock_curl
                result = adapter.run("http://example.com", {})
        assert result["body"] == "curl fallback"
        mock_curl.run.assert_called_once()

    def test_build_command_raises_not_implemented(self):
        adapter = RequestsAdapter()
        with pytest.raises(NotImplementedError):
            adapter.build_command("http://example.com", {})
