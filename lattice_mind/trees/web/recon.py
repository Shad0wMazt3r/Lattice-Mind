"""Web reconnaissance decision tree.

This tree probes a web target to gather information about:
- Service type (web framework, server, language)
- Available endpoints
- Parameters
- Potential vulnerabilities

This is the starting point for web exploitation - we probe first,
then route to specific vulnerability trees (SQLi, LFI, XSS, etc.)
"""

import logging
from typing import Any, Dict, List, Optional

from lattice_mind.adapters.curl_adapter import RequestsAdapter
from lattice_mind.adapters.ffuf_adapter import FFUFAdapter
from lattice_mind.config import FEATURE_FLAGS, TIMEOUTS
from lattice_mind.core.nodes import DecisionNode
from lattice_mind.core.types import NodeResult, NodeStatus
from lattice_mind.web.crawl_frontier import CrawlFrontier
from lattice_mind.web.request_models import spec_to_adapter_args
from lattice_mind.web.run_budget import CrawlBudget

logger = logging.getLogger(__name__)

class WebReconProbeNode(DecisionNode):
    """Initial HTTP probe to get basic information about the web service."""

    def __init__(self):
        super().__init__("web_recon_probe", "Web Reconnaissance Probe")
        self.http = RequestsAdapter(timeout=TIMEOUTS.get("http_request", 10.0))

    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Probe the web target."""
        challenge = context.get("challenge")
        if not challenge or not challenge.url:
            return NodeResult(
                status=NodeStatus.FAILURE,
                error="No URL provided in challenge descriptor",
            )

        logger.info(f"[web-recon] Probing {challenge.url}")

        try:
            result = self.http.run(challenge.url, {"follow_redirects": True})

            if result.get("error"):
                return NodeResult(
                    status=NodeStatus.FAILURE,
                    error=f"HTTP probe failed: {result['error']}",
                )

            observations = {
                "http_probe": result,
                "status_code": result.get("status"),
                "technologies": self._identify_technologies(result),
                "potential_params": self._extract_potential_params(result),
            }

            budget = CrawlBudget(
                max_depth=FEATURE_FLAGS.crawl_max_depth,
                max_pages=FEATURE_FLAGS.crawl_max_pages,
                max_request_candidates=FEATURE_FLAGS.crawl_max_request_candidates,
                max_queue_size=FEATURE_FLAGS.crawl_max_queue_size,
                max_endpoints=FEATURE_FLAGS.crawl_max_endpoints,
                max_params=FEATURE_FLAGS.crawl_max_params,
                max_form_submissions=FEATURE_FLAGS.crawl_max_form_submissions,
            )
            frontier = CrawlFrontier(
                budget,
                lambda u: self.http.run(u, {"follow_redirects": True}),
                lambda spec: self.http.run(spec.url, spec_to_adapter_args(spec)),
            )
            crawled = frontier.run(
                challenge.url, result.get("body", ""), result
            )
            observations["crawled_endpoints"] = crawled["endpoints"]
            observations["potential_params"] = list(
                set(observations["potential_params"] + crawled["params"])
            )
            observations["forms"] = crawled["forms"]
            observations["request_candidates"] = crawled["request_candidates"]
            observations["form_reviews"] = crawled.get("form_reviews", [])
            observations["crawl_graph"] = crawled["crawl_graph"]
            observations["crawl_stats"] = crawled["crawl_stats"]
            observations["flags"] = crawled.get("flags", [])
            observations["session_cookies"] = self.http.get_session_cookies()
            if observations["flags"]:
                observations["detected_flag"] = observations["flags"][0]
                context["flag_found"] = observations["detected_flag"]

            context["observations"]["http_response"] = result
            context["observations"]["technologies"] = observations["technologies"]
            context["observations"]["crawled_endpoints"] = crawled["endpoints"]
            context["observations"]["params"] = observations[  # Changed from potential_params
                "potential_params"
            ]
            context["observations"]["forms"] = observations["forms"]
            context["observations"]["request_candidates"] = observations[
                "request_candidates"
            ]
            context["observations"]["form_reviews"] = observations["form_reviews"]
            context["observations"]["crawl_graph"] = observations["crawl_graph"]
            context["observations"]["crawl_stats"] = observations["crawl_stats"]
            context["observations"]["flags"] = observations["flags"]
            context["observations"]["session_cookies"] = observations["session_cookies"]
            if observations.get("detected_flag"):
                context["observations"]["detected_flag"] = observations["detected_flag"]

            logger.info(
                f"[web-recon] Identified technologies: {observations['technologies']}"
            )

            return NodeResult(
                status=NodeStatus.SUCCESS,
                data=observations,
                next_node="web_recon_directory_scan",
            )

        except Exception as e:
            logger.error(f"[web-recon] Probe failed: {str(e)}")
            return NodeResult(status=NodeStatus.FAILURE, error=str(e))

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
        "tomcat": "/usr/share/dirb/wordlists/common.txt",
        "apache": "/usr/share/dirb/wordlists/common.txt",
        "nginx": "/usr/share/dirb/wordlists/common.txt",
        "iis": "/usr/share/dirb/wordlists/common.txt",
        "default": "/usr/share/dirb/wordlists/common.txt",
    }
    # Tech → file extensions to append
    _TECH_EXTENSIONS = {
        "php": ".php,.html,.txt,.bak",
        "asp": ".asp,.aspx,.html,.txt,.bak",
        "jsp": ".jsp,.jspx,.html,.do,.action,.txt",
        "python": ".py,.html,.txt",
        "ruby": ".rb,.html,.txt",
        "default": ".php,.html,.asp,.aspx,.jsp,.txt",
    }

    def __init__(self):
        super().__init__("web_recon_dir_scan", "Web Directory Scan")
        self.ffuf = FFUFAdapter()

    def _detect_tech(self, context: Dict[str, Any]) -> str:
        """Infer server tech from observations to pick the right extensions."""
        obs = context.get("observations", {})
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
            logger.info(
                "[web-recon] Directory scan skipped (disabled via feature flag)"
            )
            context.setdefault("observations", {})["directories"] = []
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"directories": [], "skipped": True},
                next_node="web_recon_analyze_vulns",
            )

        tech = self._detect_tech(context)
        extensions = self._TECH_EXTENSIONS.get(tech, self._TECH_EXTENSIONS["default"])
        logger.info(
            f"[web-recon] Scanning {challenge.url} (tech={tech}, ext={extensions})"
        )

        try:
            target_url = f"{challenge.url}/FUZZ"
            result = self.ffuf.run(
                target_url,
                {
                    "match_status": "200,204,301,302,403",
                    "extensions": extensions,
                },
            )

            if result.get("error"):
                logger.warning(f"[web-recon] Directory scan failed: {result['error']}")
                return NodeResult(
                    status=NodeStatus.SUCCESS, data={"directories": [], "tech": tech}
                )

            directories = [
                {
                    "path": item["path"],
                    "url": item.get("url", ""),
                    "status": item["status"],
                }
                for item in result.get("results", [])
                if item.get("status") in [200, 204, 301, 302, 403]
            ]

            context["observations"]["directories"] = directories
            context["observations"]["found_paths"] = [
                "/" + item["path"].lstrip("/") for item in directories
            ]
            logger.info(f"[web-recon] Found {len(directories)} accessible paths")

            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={
                    "directories": directories,
                    "count": len(directories),
                    "tech": tech,
                },
                next_node="web_recon_analyze_vulns",
            )

        except Exception as e:
            logger.warning(f"[web-recon] Directory scan exception: {str(e)}")
            return NodeResult(
                status=NodeStatus.SUCCESS, data={"directories": [], "tech": tech}
            )

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
        params = observations.get("params") or observations.get("potential_params", [])
        directories = observations.get("directories", [])

        candidates = {
            "sql_injection": [],
            "lfi": [],
            "xss": [],
            "auth_bypass": [],
            "ssti": [],
            "client_side_decode": [],
        }

        # SQL Injection candidates
        if any(p in params for p in ["id", "page", "query"]):
            candidates["sql_injection"].append("parameter")

        # LFI candidates
        if any(p in params for p in ["file", "path", "include"]):
            candidates["lfi"].append("parameter")

        # SSTI candidates — require a named template engine OR a clearly template-specific param/path
        # Generic params like 'name', 'query', 'search' are NOT sufficient evidence on their own.
        tech = [t.lower() for t in observations.get("tech_stack", [])]
        template_engines_detected = any(
            x in tech
            for x in ["jinja2", "twig", "smarty", "freemarker", "velocity", "erb"]
        )
        template_frameworks_detected = any(
            x in tech for x in ["flask", "django", "rails"]
        )
        ssti_specific_params = [
            "template",
            "render",
            "greeting",
            "tpl",
            "view",
            "layout",
        ]
        ssti_specific_paths = [
            "/render",
            "/preview",
            "/template",
            "/report",
            "/generate",
        ]
        has_ssti_param = any(p in params for p in ssti_specific_params)
        has_ssti_path = any(
            any(
                x in dir_info.get("path", "").lower()
                for x in ["render", "template", "generate", "preview"]
            )
            for dir_info in directories
        )
        if template_engines_detected or (
            template_frameworks_detected and (has_ssti_param or has_ssti_path)
        ):
            candidates["ssti"].append("parameter")

        # Client-side encoded/obfuscated flag logic (bookmarklet, JS decoder loops, atob)
        body = str(observations.get("http_response", {}).get("body", ""))
        lower_body = body.lower()
        has_js_decoder_pattern = (
            "charcodeat(" in lower_body
            and "string.fromcharcode" in lower_body
            and ("encrypted" in lower_body or "cipher" in lower_body)
            and ("var key" in lower_body or "key.charcodeat" in lower_body)
        )
        has_bookmarklet_hint = "javascript:(function()" in lower_body
        has_base64_hint = "atob(" in lower_body and ("decode" in lower_body or "flag" in lower_body)
        if has_js_decoder_pattern or has_bookmarklet_hint or has_base64_hint:
            candidates["client_side_decode"].append("js_obfuscation")

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
                "next_trees": list(candidates.keys()),
            },
        )
