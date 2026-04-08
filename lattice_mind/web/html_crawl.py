"""Parse a single HTML page for links, forms, and request candidates (F4)."""

from __future__ import annotations

import logging
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

from lattice_mind.web.request_models import request_spec_from_form_record, request_spec_to_jsonable

logger = logging.getLogger(__name__)


def _normalize_url(base_url: str, raw_url: str) -> Optional[str]:
    if not raw_url:
        return None
    raw_url = raw_url.strip()
    if raw_url.startswith(("#", "javascript:", "mailto:", "tel:")):
        return None
    base = urlparse(base_url)

    def _is_internal(url: str) -> bool:
        parsed = urlparse(url)
        return not parsed.netloc or parsed.netloc == base.netloc

    full = urljoin(base_url, raw_url)
    parsed = urlparse(full)
    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        return None
    if not _is_internal(full):
        return None
    return urlunparse(parsed._replace(fragment=""))


def parse_html_page(base_url: str, body: str) -> Dict[str, Any]:
    """Extract internal links, form params, forms, and GET URLs to enqueue for crawling."""
    base = urlparse(base_url)

    class CrawlParser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.endpoints: List[str] = []
            self.params: List[str] = []
            self.forms: List[Dict[str, Any]] = []
            self.request_candidates: List[Dict[str, Any]] = []
            self.get_crawl_targets: List[str] = []
            self.link_href_targets: List[str] = []
            self._form_stack: List[Dict[str, Any]] = []

        def _add_endpoint(self, raw_url: str) -> None:
            normalized = _normalize_url(base_url, raw_url)
            if not normalized:
                return
            self.endpoints.append(normalized.rstrip("/"))
            parsed = urlparse(normalized)
            for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
                if key:
                    self.params.append(key)

        def handle_starttag(self, tag: str, attrs):
            attr_map = {k.lower(): v for k, v in attrs if k}
            tag = tag.lower()

            if tag == "form":
                action = attr_map.get("action") or base_url
                method = (attr_map.get("method") or "GET").upper()
                normalized = _normalize_url(base_url, action) or base_url
                enctype = attr_map.get("enctype") or "application/x-www-form-urlencoded"
                form_id = attr_map.get("id")
                self._form_stack.append(
                    {
                        "action": normalized,
                        "method": method,
                        "enctype": enctype,
                        "id": form_id,
                        "fields": [],
                    }
                )
                self._add_endpoint(action)
                if method == "GET":
                    self.get_crawl_targets.append(normalized)
                return

            if tag in {"a", "area"}:
                href = attr_map.get("href", "")
                self._add_endpoint(href)
                n = _normalize_url(base_url, href)
                if n:
                    self.link_href_targets.append(n)

            if tag in {"input", "select", "textarea", "button"}:
                name = attr_map.get("name")
                if name:
                    self.params.append(name)
                if self._form_stack and name:
                    self._form_stack[-1]["fields"].append(
                        {
                            "name": name,
                            "value": attr_map.get("value") or "",
                            "type": (attr_map.get("type") or "text").lower(),
                        }
                    )
                if tag == "button" and attr_map.get("formaction"):
                    self._add_endpoint(attr_map.get("formaction", ""))

        def handle_endtag(self, tag: str):
            if tag.lower() != "form" or not self._form_stack:
                return
            ctx = self._form_stack.pop()
            self.forms.append(
                {
                    "action": ctx["action"],
                    "method": ctx["method"],
                    "enctype": ctx["enctype"],
                    "id": ctx.get("id"),
                    "fields": list(ctx["fields"]),
                }
            )
            try:
                spec = request_spec_from_form_record(ctx)
                self.request_candidates.append(request_spec_to_jsonable(spec))
            except Exception as e:
                logger.debug("[html_crawl] Skip request candidate for form: %s", e)

    parser = CrawlParser()
    parser.feed(body or "")

    return {
        "endpoints": list(dict.fromkeys(parser.endpoints)),
        "params": list(dict.fromkeys(parser.params)),
        "forms": parser.forms,
        "request_candidates": parser.request_candidates,
        "get_crawl_targets": list(dict.fromkeys(parser.get_crawl_targets)),
        "link_href_targets": list(dict.fromkeys(parser.link_href_targets)),
    }


def page_dedupe_key(url: str) -> str:
    """Stable key for visited/enqueued pages (no fragment)."""
    p = urlparse(url.strip())
    return urlunparse((p.scheme, p.netloc.lower(), p.path or "/", p.params, p.query, ""))
