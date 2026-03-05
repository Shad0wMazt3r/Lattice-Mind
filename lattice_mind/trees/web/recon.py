"""Web reconnaissance decision tree.

This tree probes a web target to gather information about:
- Service type (web framework, server, language)
- Available endpoints
- Parameters
- Potential vulnerabilities

This is the starting point for web exploitation - we probe first,
then route to specific vulnerability trees (SQLi, LFI, XSS, etc.)
"""
from typing import Dict, Any, Optional, List
import logging

from lattice_mind.core.nodes import DecisionNode
from lattice_mind.core.types import NodeResult, NodeStatus
from lattice_mind.adapters.curl_adapter import RequestsAdapter
from lattice_mind.adapters.ffuf_adapter import FFUFAdapter

logger = logging.getLogger(__name__)


class WebReconProbeNode(DecisionNode):
    """Initial HTTP probe to get basic information about the web service."""
    
    def __init__(self):
        super().__init__("web_recon_probe", "Web Reconnaissance Probe")
        self.http = RequestsAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Probe the web target."""
        challenge = context.get("challenge")
        if not challenge or not challenge.url:
            return NodeResult(
                status=NodeStatus.FAILURE,
                error="No URL provided in challenge descriptor"
            )
        
        logger.info(f"[web-recon] Probing {challenge.url}")
        
        try:
            result = self.http.run(challenge.url, {"follow_redirects": True})
            
            if result.get("error"):
                return NodeResult(
                    status=NodeStatus.FAILURE,
                    error=f"HTTP probe failed: {result['error']}"
                )
            
            observations = {
                "http_probe": result,
                "status_code": result.get("status"),
                "technologies": self._identify_technologies(result),
                "potential_params": self._extract_potential_params(result),
            }
            
            # Crawl the page for internal links + forms to enrich params/endpoints
            crawled = self._crawl_links(challenge.url, result.get("body", ""))
            observations["crawled_endpoints"] = crawled["endpoints"]
            observations["potential_params"] = list(set(
                observations["potential_params"] + crawled["params"]
            ))

            context["observations"]["http_response"] = result
            context["observations"]["technologies"] = observations["technologies"]
            context["observations"]["crawled_endpoints"] = crawled["endpoints"]
            context["observations"]["potential_params"] = observations["potential_params"]
            context["observations"]["forms"] = crawled["forms"]
            
            logger.info(
                f"[web-recon] Identified technologies: {observations['technologies']}"
            )
            
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data=observations,
                next_node="web_recon_directory_scan"
            )
        
        except Exception as e:
            logger.error(f"[web-recon] Probe failed: {str(e)}")
            return NodeResult(
                status=NodeStatus.FAILURE,
                error=str(e)
            )
    
    def _crawl_links(self, base_url: str, body: str) -> dict:
        """Extract internal links, form params, and form metadata from an HTML page."""
        import re
        from urllib.parse import urljoin, urlparse

        base = urlparse(base_url)
        endpoints = []
        params = []
        forms = []

        # Extract form metadata (action + method) and collect endpoints from actions
        for form_match in re.finditer(r'<form([^>]*)>', body, re.IGNORECASE | re.DOTALL):
            attrs = form_match.group(1)
            action = re.search(r'action=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
            method = re.search(r'method=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
            action_url = urljoin(base_url, action.group(1)) if action else base_url
            form_method = method.group(1).upper() if method else "GET"
            forms.append({"action": action_url, "method": form_method})
            p = urlparse(action_url)
            if p.netloc == base.netloc or not p.netloc:
                endpoints.append(action_url.rstrip('/'))

        # Extract href and non-form action links
        for pattern in [r'href=["\']([^"\'#?]+)["\']']:
            for match in re.findall(pattern, body, re.IGNORECASE):
                if not match or match.startswith(('javascript:', 'mailto:', '#')):
                    continue
                full = urljoin(base_url, match)
                p = urlparse(full)
                if p.netloc == base.netloc or not p.netloc:
                    endpoints.append(full.rstrip('/'))

        # Extract form input/select/textarea names as potential params
        for name in re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', body, re.IGNORECASE):
            params.append(name)
        for name in re.findall(r'<select[^>]+name=["\']([^"\']+)["\']', body, re.IGNORECASE):
            params.append(name)
        for name in re.findall(r'<textarea[^>]+name=["\']([^"\']+)["\']', body, re.IGNORECASE):
            params.append(name)

        # Extract query params already present in links
        for href in re.findall(r'href=["\'][^"\']*\?([^"\']+)["\']', body, re.IGNORECASE):
            for part in href.split('&'):
                key = part.split('=')[0]
                if key:
                    params.append(key)

        return {
            "endpoints": list(dict.fromkeys(endpoints))[:30],
            "params": list(dict.fromkeys(params))[:20],
            "forms": forms,
        }

    def _identify_technologies(self, http_result: dict) -> dict:
        """Extract technology hints from HTTP response."""
        import re
        techs = {}
        headers = http_result.get("headers", {})
        body = http_result.get("body", "")
        
        if "Server" in headers:
            techs["server"] = headers["Server"]
        if "X-Powered-By" in headers:
            techs["framework"] = headers["X-Powered-By"]
        
        for framework in ["Flask", "Django", "Rails", "Laravel"]:
            if framework.lower() in body.lower():
                techs["framework"] = framework
                break
        
        for cms in ["WordPress", "Joomla", "Drupal"]:
            if cms.lower() in body.lower():
                techs["cms"] = cms
                break
        
        return techs
    
    def _extract_potential_params(self, http_result: Dict[str, Any]) -> List[str]:
        """Extract potential parameters from response body."""
        import re
        body = http_result.get("body", "")
        params = []
        
        pattern = r'<input[^>]+name=["\']([^"\']+)["\']'
        matches = re.findall(pattern, body)
        params.extend(matches)
        
        for param in ["id", "page", "search", "query", "username", "password", "email"]:
            if param.lower() in body.lower():
                params.append(param)
        
        return list(set(params))
    
    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        """Route to directory scanning."""
        if result.status == NodeStatus.SUCCESS:
            return WebReconDirectoryScanNode()
        return None


class WebReconDirectoryScanNode(DecisionNode):
    """Scan for common directories and files."""

    # Tech → extra wordlist (bundled with dirb/wordlistslist)
    _TECH_WORDLISTS = {
        "tomcat":  "/usr/share/dirb/wordlists/common.txt",
        "apache":  "/usr/share/dirb/wordlists/common.txt",
        "nginx":   "/usr/share/dirb/wordlists/common.txt",
        "iis":     "/usr/share/dirb/wordlists/common.txt",
        "default": "/usr/share/dirb/wordlists/common.txt",
    }
    # Tech → file extensions to append
    _TECH_EXTENSIONS = {
        "php":     ".php,.html,.txt,.bak",
        "asp":     ".asp,.aspx,.html,.txt,.bak",
        "jsp":     ".jsp,.jspx,.html,.do,.action,.txt",
        "python":  ".py,.html,.txt",
        "ruby":    ".rb,.html,.txt",
        "default": ".php,.html,.asp,.aspx,.jsp,.txt",
    }

    def __init__(self):
        super().__init__("web_recon_dir_scan", "Web Directory Scan")
        self.ffuf = FFUFAdapter()

    def _detect_tech(self, context: Dict[str, Any]) -> str:
        """Infer server tech from observations to pick the right extensions."""
        obs   = context.get("observations", {})
        techs = obs.get("technologies", {})
        server = (techs.get("server") or "").lower()
        framework = (techs.get("framework") or "").lower()
        cookies = str(obs.get("http_response", {}).get("headers", {})).lower()

        if "coyote" in server or "tomcat" in server or "jsessionid" in cookies:
            return "jsp"
        if "php" in server or "php" in framework:
            return "php"
        if "iis" in server or "asp" in framework:
            return "asp"
        if "python" in server or "flask" in framework or "django" in framework:
            return "python"
        if "ruby" in server or "rails" in framework:
            return "ruby"
        return "default"

    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Scan for directories, adapting extensions to detected tech."""
        from lattice_mind.config import FEATURE_FLAGS
        challenge = context.get("challenge")
        if not challenge or not challenge.url:
            return NodeResult(status=NodeStatus.FAILURE, error="No URL provided")

        if not FEATURE_FLAGS.dir_scan_enabled:
            logger.info("[web-recon] Directory scan skipped (disabled via feature flag)")
            context.setdefault("observations", {})["directories"] = []
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"directories": [], "skipped": True},
                next_node="web_recon_analyze_vulns",
            )

        tech = self._detect_tech(context)
        extensions = self._TECH_EXTENSIONS.get(tech, self._TECH_EXTENSIONS["default"])
        logger.info(f"[web-recon] Scanning {challenge.url} (tech={tech}, ext={extensions})")

        try:
            target_url = f"{challenge.url}/FUZZ"
            result = self.ffuf.run(target_url, {
                "match_status": "200,204,301,302,403",
                "extensions": extensions,
            })

            if result.get("error"):
                logger.warning(f"[web-recon] Directory scan failed: {result['error']}")
                return NodeResult(status=NodeStatus.SUCCESS, data={"directories": [], "tech": tech})

            directories = [
                {"path": item["path"], "url": item.get("url", ""), "status": item["status"]}
                for item in result.get("results", [])
                if item.get("status") in [200, 204, 301, 302, 403]
            ]

            context["observations"]["directories"] = directories
            logger.info(f"[web-recon] Found {len(directories)} accessible paths")

            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"directories": directories, "count": len(directories), "tech": tech},
                next_node="web_recon_analyze_vulns"
            )

        except Exception as e:
            logger.warning(f"[web-recon] Directory scan exception: {str(e)}")
            return NodeResult(status=NodeStatus.SUCCESS, data={"directories": [], "tech": tech})
    
    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        """Route to vulnerability analysis."""
        if result.status == NodeStatus.SUCCESS:
            return WebReconAnalyzeVulnsNode()
        return None


class WebReconAnalyzeVulnsNode(DecisionNode):
    """Analyze collected data and identify likely vulnerability types."""
    
    def __init__(self):
        super().__init__("web_recon_analyze_vulns", "Analyze Vulnerabilities")
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Analyze for vulnerabilities."""
        observations = context.get("observations", {})
        params = observations.get("potential_params", [])
        directories = observations.get("directories", [])
        
        candidates = {
            "sql_injection": [],
            "lfi": [],
            "xss": [],
            "auth_bypass": [],
            "ssti": [],
        }
        
        # SQL Injection candidates
        if any(p in params for p in ["id", "page", "query"]):
            candidates["sql_injection"].append("parameter")
        
        # LFI candidates
        if any(p in params for p in ["file", "path", "include"]):
            candidates["lfi"].append("parameter")
        
        # SSTI candidates — any user-input param that could be template-reflected
        tech = [t.lower() for t in observations.get("tech_stack", [])]
        is_template_engine = any(x in tech for x in ["python", "flask", "jinja2", "django", "ruby", "rails", "erb", "php", "twig", "java", "freemarker"])
        ssti_params = ["name", "template", "msg", "message", "content", "text", "render", "greeting", "title", "query", "search", "input", "announce"]
        if is_template_engine or any(p in params for p in ssti_params):
            candidates["ssti"].append("parameter")
        
        # Check paths
        for dir_info in directories:
            path = dir_info.get("path", "").lower()
            if "admin" in path:
                candidates["auth_bypass"].append(path)
            if any(x in path for x in ["upload", "file", "download"]):
                candidates["lfi"].append(path)
        
        candidates = {k: v for k, v in candidates.items() if v}
        
        # Store in observations so mvp.py can read them after tree completes
        context["observations"]["vuln_candidates"] = candidates
        
        logger.info(f"[web-recon] Vulnerability candidates: {list(candidates.keys())}")
        
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={
                "vulnerability_candidates": candidates,
                "next_trees": list(candidates.keys())
            }
        )
