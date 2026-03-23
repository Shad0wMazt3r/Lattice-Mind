"""HTTP request adapter using curl."""
from typing import Dict, Any, Optional
import json
import re
import logging
from urllib.parse import urlencode

from lattice_mind.adapters.base import CommandToolAdapter

logger = logging.getLogger(__name__)


class CurlAdapter(CommandToolAdapter):
    """HTTP request wrapper using curl.
    
    Normalizes curl output to:
    {
        "status": 200,
        "headers": {"Content-Type": "text/html", ...},
        "body": "...",
        "error": None
    }
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
                params_str = urlencode(p)
            else:
                params_str = "&".join(f"{k}={v}" for k, v in p.items())
            target = f"{target}?{params_str}"
        
        # Redirects
        if args.get("follow_redirects", False):
            cmd.append("-L")
        
        # SSL verification
        if args.get("insecure", False):
            cmd.append("-k")
        
        cmd.append(target)
        return cmd
    
    def normalize_output(self, raw_output: str) -> Dict[str, Any]:
        """Parse curl verbose output.
        
        Curl with -v outputs headers to stderr, body to stdout.
        We parse both to extract status code and headers.
        
        Args:
            raw_output: Raw curl output
        
        Returns:
            Normalized response dict
        """
        result = {
            "status": None,
            "headers": {},
            "body": "",
            "error": None,
        }
        
        try:
            lines = raw_output.split("\n")
            body_start = -1
            
            for i, line in enumerate(lines):
                # Extract HTTP status code
                if line.startswith("< HTTP/"):
                    # Format: "< HTTP/1.1 200 OK"
                    match = re.search(r"HTTP/[\d\.]+ (\d+)", line)
                    if match:
                        result["status"] = int(match.group(1))
                
                # Extract headers (lines starting with "<")
                elif line.startswith("< ") and ":" in line:
                    # Format: "< Content-Type: text/html"
                    header_line = line[2:].strip()
                    if header_line and ":" in header_line:
                        key, value = header_line.split(":", 1)
                        result["headers"][key.strip()] = value.strip()
                
                # Body typically comes after the last empty line
                # In curl -v output, body comes after all headers
                elif not line.startswith("<") and not line.startswith(">") and \
                     not line.startswith("*") and body_start == -1 and \
                     result["status"] is not None:
                    body_start = i
            
            # Combine remaining lines as body
            if body_start >= 0:
                result["body"] = "\n".join(lines[body_start:]).strip()
            
            # If no status was found, it's an error
            if result["status"] is None:
                result["error"] = "Could not parse HTTP response"
                result["status"] = 0
            
            logger.debug(
                f"[curl] Parsed response: status={result['status']}, "
                f"body_len={len(result['body'])}, "
                f"headers={len(result['headers'])}"
            )
            
            return result
        
        except Exception as e:
            logger.error(f"[curl] Error parsing output: {str(e)}")
            return {
                "status": None,
                "headers": {},
                "body": raw_output,
                "error": str(e),
            }


class RequestsAdapter(CommandToolAdapter):
    """HTTP request wrapper using Python requests library.
    
    Note: This requires 'requests' to be installed.
    Uses curl instead if requests is not available.
    """
    
    def __init__(self, timeout: float = 10.0):
        super().__init__("requests", timeout=timeout)
        try:
            import requests
            self.requests = requests
            self._session = self.requests.Session()
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
            data = args.get("data", None)
            json_body = args.get("json")
            params = args.get("params", {}) or {}
            cookies = args.get("cookies")
            allow_redirects = args.get("follow_redirects", False)
            verify = not args.get("insecure", False)

            if json_body is not None and data is not None:
                raise ValueError("Pass only one of 'json' or 'data' to RequestsAdapter.run")

            request_func = getattr(self._session, method.lower())
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

            response = request_func(target, **req_kw)

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
        return {str(k): str(v) for k, v in self._session.cookies.get_dict().items()}
