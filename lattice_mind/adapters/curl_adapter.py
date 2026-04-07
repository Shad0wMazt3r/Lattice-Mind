"""HTTP request adapter using curl."""
from typing import Dict, Any, Optional
import json
import re
import logging
import time
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl

from lattice_mind.adapters.base import CommandToolAdapter
from lattice_mind.core.adapter_types import (
    AdapterResult,
    AdapterStatus,
    HttpDataKeys
)

logger = logging.getLogger(__name__)


class CurlAdapter(CommandToolAdapter):
    """HTTP request wrapper using curl.
    
    Returns AdapterResult with normalized HTTP response data:
    - data[status_code]: HTTP status code
    - data[headers]: Response headers dict
    - data[body]: Response body string
    - metadata[response_time_ms]: Request duration
    """
    
    def __init__(self, timeout: float = 10.0):
        super().__init__("curl", timeout=timeout)
    
    def build_command(self, target: str, args: Dict[str, Any]) -> list:
        """Build curl command.
        
        Args:
            target: URL
            args: Optional args
                - method: HTTP method (default: GET)
                - headers: Dict of headers
                - data: POST body
                - params: Dict of query parameters
                - follow_redirects: bool (default: False)
                - insecure: bool (default: False)
        
        Returns:
            curl command as list
        """
        cmd = ["curl", "-v", "-s"]
        
        method = args.get("method", "GET").upper()
        if method != "GET":
            cmd.extend(["-X", method])
        
        headers = dict(args.get("headers", {}))
        post_body: Optional[str] = None
        if "json" in args and args["json"] is not None:
            post_body = json.dumps(args["json"], separators=(",", ":"))
            if not any(k.lower() == "content-type" for k in headers):
                headers["Content-Type"] = "application/json"
        elif "data" in args:
            data = args["data"]
            if isinstance(data, dict):
                post_body = urlencode(data)
                if not any(k.lower() == "content-type" for k in headers):
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
            elif isinstance(data, list):
                post_body = urlencode(data)
                if not any(k.lower() == "content-type" for k in headers):
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                post_body = str(data)

        for key, value in headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

        cookies = args.get("cookies")
        if cookies:
            cookie_hdr = "; ".join(f"{k}={v}" for k, v in cookies.items())
            cmd.extend(["-b", cookie_hdr])

        if post_body is not None:
            cmd.extend(["-d", post_body])
        
        # Query parameters (dict or list of (key, value) for duplicate keys)
        if "params" in args:
            p = args["params"]
            if isinstance(p, list):
                new_pairs = p
            else:
                new_pairs = list(p.items())
            parts = urlsplit(target)
            existing = parse_qsl(parts.query, keep_blank_values=True)
            merged = existing + new_pairs
            target = urlunsplit(parts._replace(query=urlencode(merged)))
        
        # Redirects
        if args.get("follow_redirects", False):
            cmd.append("-L")
        
        # SSL verification
        if args.get("insecure", False):
            cmd.append("-k")
        
        cmd.append(target)
        return cmd
    
    def normalize_output(self, raw_output: str) -> AdapterResult:
        """Parse curl verbose output into AdapterResult.
        
        Curl with -v outputs headers to stderr, body to stdout.
        We parse both to extract status code and headers.
        
        Args:
            raw_output: Raw curl output
        
        Returns:
            AdapterResult with normalized HTTP response
        """
        try:
            lines = raw_output.split("\n")
            body_start = -1
            status_code = None
            headers = {}
            
            for i, line in enumerate(lines):
                # Extract HTTP status code
                if line.startswith("< HTTP/"):
                    # Format: "< HTTP/1.1 200 OK"
                    match = re.search(r"HTTP/[\d\.]+ (\d+)", line)
                    if match:
                        status_code = int(match.group(1))
                
                # Extract headers (lines starting with "<")
                elif line.startswith("< ") and ":" in line:
                    # Format: "< Content-Type: text/html"
                    header_line = line[2:].strip()
                    if header_line and ":" in header_line:
                        key, value = header_line.split(":", 1)
                        headers[key.strip()] = value.strip()
                
                # Body typically comes after the last empty line
                elif not line.startswith("<") and not line.startswith(">") and \
                     not line.startswith("*") and body_start == -1 and \
                     status_code is not None:
                    body_start = i
            
            # Combine remaining lines as body
            body = ""
            if body_start >= 0:
                body = "\n".join(lines[body_start:]).strip()
            
            # If no status was found, it's an error
            if status_code is None:
                return AdapterResult(
                    status=AdapterStatus.ERROR,
                    error="Could not parse HTTP response",
                    data={
                        HttpDataKeys.STATUS_CODE: 0,
                        HttpDataKeys.HEADERS: {},
                        HttpDataKeys.BODY: raw_output[:1000]  # First 1k chars
                    }
                )
            
            logger.debug(
                f"[curl] Parsed response: status={status_code}, "
                f"body_len={len(body)}, headers={len(headers)}"
            )
            
            return AdapterResult(
                status=AdapterStatus.SUCCESS,
                data={
                    HttpDataKeys.STATUS_CODE: status_code,
                    HttpDataKeys.HEADERS: headers,
                    HttpDataKeys.BODY: body
                }
            )
        
        except Exception as e:
            logger.error(f"[curl] Error parsing output: {str(e)}")
            return AdapterResult(
                status=AdapterStatus.ERROR,
                error=str(e),
                data={
                    HttpDataKeys.STATUS_CODE: 0,
                    HttpDataKeys.HEADERS: {},
                    HttpDataKeys.BODY: raw_output[:1000]
                }
            )


class RequestsAdapter(CommandToolAdapter):
    """HTTP request wrapper using Python requests library.
    
    Note: This requires 'requests' to be installed.
    Uses curl instead if requests is not available.
    """
    
    def __init__(self, timeout: float = 10.0):
        super().__init__("requests", timeout=timeout)
        self._session = None
        try:
            import requests
            self._session = requests.Session()
            self.requests = requests
            self._use_requests = True
        except ImportError:
            logger.warning("[requests] requests module not available, falling back to curl")
            self._use_requests = False
            self._curl_adapter = CurlAdapter(timeout=timeout)
    
    def build_command(self, target: str, args: Dict[str, Any]) -> list:
        """Not used, but required by interface."""
        raise NotImplementedError(
            "RequestsAdapter uses Python requests library, "
            "not shell commands. Use run() directly."
        )
    
    def run(self, target: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute HTTP request using requests library or fall back to curl."""
        if not self._use_requests:
            return self._curl_adapter.run(target, args)
        
        try:
            method = args.get("method", "GET").upper()
            headers = dict(args.get("headers", {}))
            sni_hostname = str(args.get("sni_hostname", "")).strip()
            if sni_hostname and "Host" not in headers:
                headers["Host"] = sni_hostname
            data = args.get("data", None)
            json_body = args.get("json")
            params = args.get("params", {}) or {}
            cookies = args.get("cookies")
            allow_redirects = args.get("follow_redirects", False)
            verify = not args.get("insecure", False)

            if json_body is not None and data is not None:
                raise ValueError("Pass only one of 'json' or 'data' to RequestsAdapter.run")

            req_kw: Dict[str, Any] = {
                "headers": headers,
                "params": params,
                "allow_redirects": allow_redirects,
                "verify": verify,
                "timeout": self.timeout,
            }
            if cookies:
                req_kw["cookies"] = cookies
            if json_body is not None:
                req_kw["json"] = json_body
            else:
                req_kw["data"] = data

            response = self._session.request(method, target, **req_kw)

            redirect_chain = [str(r.url) for r in response.history]
            redirect_chain.append(str(response.url))

            result = {
                "status": response.status_code,
                "headers": dict(response.headers),
                "body": response.text,
                "error": None,
                "redirect_chain": redirect_chain,
            }
            
            self.last_result = result
            return result
        
        except Exception as e:
            logger.error(f"[requests] Request failed: {str(e)}")
            return {
                "status": None,
                "headers": {},
                "body": "",
                "error": str(e),
                "redirect_chain": [],
            }

    def get_session_cookies(self) -> Dict[str, str]:
        """Return current requests-session cookies as a plain dict."""
        if not self._use_requests:
            return {}
        return dict(self._session.cookies)
