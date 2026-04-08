"""Bounded same-origin BFS crawl frontier (F4)."""

from __future__ import annotations

import logging
import re
import json
from collections import deque
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from lattice_mind.core.human_loop import get_human_loop_manager
from lattice_mind.core.flag_recognizer import get_flag_recognizer
from lattice_mind.web.html_crawl import page_dedupe_key, parse_html_page
from lattice_mind.web.form_safety import assess_form_safety, build_submission_spec
from lattice_mind.web.request_models import (
    HTTPRequestSpec,
    request_spec_for_challenge_url,
    request_spec_to_jsonable,
)
from lattice_mind.web.run_budget import CrawlBudget, CrawlStats, StoppedReason

logger = logging.getLogger(__name__)

FetchFn = Callable[[str], Dict[str, Any]]
FetchRequestFn = Callable[[HTTPRequestSpec], Dict[str, Any]]


def _netloc(url: str) -> str:
    return urlparse(url).netloc.lower()


def _final_url(requested: str, result: Dict[str, Any]) -> str:
    chain = result.get("redirect_chain") or []
    if chain:
        return chain[-1]
    return requested


def _same_origin(url: str, allowed_netloc: str) -> bool:
    return _netloc(url) == allowed_netloc


def _candidate_dedupe_key(spec: Dict[str, Any]) -> Tuple:
    m = (spec.get("method") or "GET").upper()
    u = page_dedupe_key(spec.get("url") or "")
    qp = spec.get("query_params") or {}
    bp = spec.get("body_params") or {}
    qnames = tuple(sorted(qp.keys())) if isinstance(qp, dict) else ()
    bnames = tuple(sorted(bp.keys())) if isinstance(bp, dict) else ()
    return (m, u, qnames, bnames)


def _form_signature(form: Dict[str, Any]) -> Tuple:
    action = page_dedupe_key(form.get("action") or "")
    method = (form.get("method") or "GET").upper()
    names = tuple(sorted(f.get("name") or "" for f in (form.get("fields") or []) if f.get("name")))
    return (method, action, names)


def _auth_cookie_metadata_from_response(result: Dict[str, Any]) -> Dict[str, Any]:
    headers = result.get("headers") or {}
    flat: Dict[str, str] = {str(k).lower(): str(v) for k, v in headers.items()}
    set_cookie = flat.get("set-cookie", "")
    names = sorted(
        {
            m.group(1).lower()
            for m in re.finditer(r"(?:^|,)\s*([^=;,\s]+)\s*=", set_cookie)
        }
    )
    www_auth = flat.get("www-authenticate", "")
    return {
        "has_set_cookie": bool(set_cookie),
        "set_cookie_names": names,
        "set_cookie_count": len(names),
        "has_www_authenticate": bool(www_auth),
        "www_authenticate_preview": www_auth[:200],
    }


def _merge_bounded_list(
    acc: List[str],
    new_items: List[str],
    seen: Set[str],
    max_len: int,
) -> None:
    for x in new_items:
        if x in seen:
            continue
        seen.add(x)
        if len(acc) >= max_len:
            break
        acc.append(x)


class CrawlFrontier:
    """Breadth-first same-origin crawl with depth, page, and form budgets."""

    def __init__(
        self,
        budget: CrawlBudget,
        fetch_get: FetchFn,
        fetch_request: Optional[FetchRequestFn] = None,
        ask_user=None,
    ):
        self.budget = budget
        self.fetch_get = fetch_get
        self.fetch_request = fetch_request
        self.ask_user = ask_user
        self.flag_recognizer = get_flag_recognizer()

    def run(
        self,
        seed_url: str,
        seed_body: str,
        seed_http_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        stats = CrawlStats()
        seed_final = _final_url(seed_url, seed_http_result)
        allowed_netloc = _netloc(seed_final)
        if not allowed_netloc:
            logger.warning("[crawl] Empty netloc for seed, skipping frontier")
            return self._empty_outcome(stats, "empty_queue")

        graph: List[Dict[str, Any]] = []
        form_reviews: List[Dict[str, Any]] = []
        discovered_flags: List[str] = []
        seen_flags: Set[str] = set()
        next_id = 0
        stopped: Optional[StoppedReason] = None

        def alloc_node_id() -> str:
            nonlocal next_id
            nid = f"crawl_{next_id}"
            next_id += 1
            return nid

        def _request_key(spec: Optional[HTTPRequestSpec]) -> Optional[str]:
            if not spec:
                return None
            return "REQ:" + json.dumps(request_spec_to_jsonable(spec), sort_keys=True)

        def _page_key(url: str) -> str:
            return "PAGE:" + page_dedupe_key(url)

        seen_page_keys: Set[str] = set()
        seen_request_keys: Set[str] = set()
        queue: deque[Tuple[str, str, int, str]] = deque()
        enqueued_keys: Set[str] = set()

        endpoints: List[str] = []
        params: List[str] = []
        forms: List[Dict[str, Any]] = []
        request_candidates: List[Dict[str, Any]] = []

        endpoint_seen: Set[str] = set()
        param_seen: Set[str] = set()
        form_seen: Set[Tuple] = set()
        cand_seen: Set[Tuple] = set()

        def add_forms_and_candidates(parsed: Dict[str, Any]) -> None:
            for form in parsed.get("forms") or []:
                sig = _form_signature(form)
                if sig in form_seen:
                    continue
                form_seen.add(sig)
                forms.append(form)

            for cand in parsed.get("request_candidates") or []:
                ck = _candidate_dedupe_key(cand)
                if ck in cand_seen:
                    continue
                if stats.candidates_added >= self.budget.max_request_candidates:
                    stats.candidates_dropped += 1
                    continue
                cand_seen.add(ck)
                request_candidates.append(cand)
                stats.candidates_added += 1

        def merge_parsed(parsed: Dict[str, Any]) -> None:
            _merge_bounded_list(
                endpoints,
                parsed.get("endpoints") or [],
                endpoint_seen,
                self.budget.max_endpoints,
            )
            _merge_bounded_list(
                params,
                parsed.get("params") or [],
                param_seen,
                self.budget.max_params,
            )
            add_forms_and_candidates(parsed)

        def enqueue_children(parsed: Dict[str, Any], parent_node_id: str, depth: int) -> bool:
            if depth >= self.budget.max_depth:
                return False
            if stats.pages_visited >= self.budget.max_pages:
                return False
            targets: List[Tuple[str, str]] = []
            targets.extend((u, "anchor_link") for u in (parsed.get("link_href_targets") or []))
            targets.extend((u, "get_form") for u in (parsed.get("get_crawl_targets") or []))
            seen_t: Set[str] = set()
            for raw, via in targets:
                k = page_dedupe_key(raw)
                if k in seen_t:
                    continue
                seen_t.add(k)
                if not _same_origin(raw, allowed_netloc):
                    continue
                if k in seen_page_keys or k in enqueued_keys:
                    continue
                if len(queue) >= self.budget.max_queue_size:
                    return True
                enqueued_keys.add(k)
                queue.append((raw, parent_node_id, depth + 1, via))
            return False

        def process_response(
            request_spec: HTTPRequestSpec,
            result: Dict[str, Any],
            parent_node_id: Optional[str],
            depth: int,
            via: str,
            force_request_key: bool = False,
        ) -> Optional[str]:
            nonlocal stopped
            if stopped:
                return None

            requested_url = request_spec.url if request_spec else seed_url
            final_u = _final_url(requested_url, result)
            node_key = _request_key(request_spec) if (force_request_key or via.endswith("form_submit")) else _page_key(final_u)
            if node_key is None:
                node_key = _page_key(final_u)

            if node_key.startswith("REQ:"):
                if node_key in seen_request_keys:
                    return None
                seen_request_keys.add(node_key)
            else:
                if node_key in seen_page_keys:
                    return None
                seen_page_keys.add(node_key)

            node_id = alloc_node_id()
            node = {
                "id": node_id,
                "parent_id": parent_node_id,
                "url": final_u,
                "depth": depth,
                "discovered_via": via,
                "status_code": result.get("status"),
                "forms": [],
                "request_candidates": [],
                "auth_cookie_metadata": _auth_cookie_metadata_from_response(result),
                "request_spec": request_spec_to_jsonable(request_spec) if request_spec else None,
                "form_reviews": [],
            }

            if result.get("error"):
                node["error"] = result.get("error")
                graph.append(node)
                return node_id

            if not _same_origin(final_u, allowed_netloc):
                node["error"] = "off_origin_redirect"
                graph.append(node)
                return node_id

            graph.append(node)
            stats.pages_visited += 1

            body = result.get("body") or ""
            flag = self.flag_recognizer.recognize(body)
            if flag and flag not in seen_flags:
                seen_flags.add(flag)
                discovered_flags.append(flag)
                node["detected_flag"] = flag
            parsed = parse_html_page(final_u, body)
            node["forms"] = parsed.get("forms") or []
            node["request_candidates"] = parsed.get("request_candidates") or []
            merge_parsed(parsed)

            if depth < self.budget.max_depth:
                page_reviews = submit_forms_from_page(parsed, final_u, node_id, depth)
                node["form_reviews"] = page_reviews
                form_reviews.extend(page_reviews)
                if stopped:
                    return node_id

                if enqueue_children(parsed, node_id, depth):
                    stopped = "budget_queue"
            return node_id

        def submit_forms_from_page(
            parsed: Dict[str, Any],
            page_url: str,
            parent_node_id: str,
            depth: int,
        ) -> List[Dict[str, Any]]:
            reviews: List[Dict[str, Any]] = []
            if self.fetch_request is None:
                return reviews

            human_loop = self.ask_user or get_human_loop_manager().ask_user

            for form in parsed.get("forms") or []:
                if stats.forms_submitted >= self.budget.max_form_submissions:
                    reviews.append(
                        {
                            "decision": "skipped",
                            "outcome": "budget_skipped",
                            "form_summary": (
                                f"{str(form.get('method') or 'GET').upper()} "
                                f"{form.get('action') or page_url}"
                            ),
                            "score": 0.0,
                            "reasons": [
                                "Form submission budget exhausted for this crawl run"
                            ],
                            "risks": [],
                        }
                    )
                    continue

                method = str(form.get("method") or "GET").upper()
                if method == "GET":
                    reviews.append(
                        {
                            "decision": "skipped",
                            "outcome": "get_form",
                            "form_summary": f"GET {form.get('action') or page_url}",
                            "score": 0.0,
                            "reasons": ["GET forms are already covered by crawl links"],
                            "risks": [],
                        }
                    )
                    continue

                assessment = assess_form_safety(form, current_url=page_url)
                review = assessment.to_review_dict()
                review.update(
                    {
                        "action": form.get("action") or page_url,
                        "method": method,
                        "field_names": [f.get("name") for f in (form.get("fields") or []) if f.get("name")],
                    }
                )
                stats.forms_reviewed += 1

                if assessment.decision == "skip":
                    review["outcome"] = "skipped"
                    reviews.append(review)
                    continue

                approval = "submit"
                if assessment.decision == "hitl":
                    stats.hitl_questions += 1
                    approval = human_loop(
                        assessment.prompt,
                        options=["submit", "skip"],
                        node_id=parent_node_id,
                        details={
                            "form": review,
                            "page_url": page_url,
                            "suggested_answer": assessment.suggested_answer,
                        },
                        kind="form_submission_review",
                    )
                    review["hitl_answer"] = approval
                    if str(approval or "").strip().lower() not in {"submit", "yes", "y", "approve"}:
                        review["outcome"] = "human_skipped"
                        reviews.append(review)
                        continue

                try:
                    attempted_submissions: List[Dict[str, Any]] = []
                    submission_specs: List[Tuple[str, HTTPRequestSpec]] = [("default", build_submission_spec(form))]
                    field_names_lc = [
                        str(f.get("name") or "").strip().lower()
                        for f in (form.get("fields") or [])
                        if isinstance(f, dict) and f.get("name")
                    ]
                    has_otp_like_field = any(
                        any(tok in name for tok in ("otp", "code", "pin", "2fa", "mfa", "verify"))
                        for name in field_names_lc
                    )
                    if has_otp_like_field:
                        otp_omitted_form = {
                            **form,
                            "fields": [
                                dict(f)
                                for f in (form.get("fields") or [])
                                if not any(
                                    tok in str(f.get("name") or "").strip().lower()
                                    for tok in ("otp", "code", "pin", "2fa", "mfa", "verify")
                                )
                            ],
                        }
                        submission_specs.append(("otp_omitted", build_submission_spec(otp_omitted_form)))

                    submitted_any = False
                    for variant_name, submission_spec in submission_specs:
                        if stats.forms_submitted >= self.budget.max_form_submissions:
                            attempted_submissions.append(
                                {
                                    "variant": variant_name,
                                    "outcome": "budget_skipped",
                                    "reason": "Form submission budget exhausted for this crawl run",
                                }
                            )
                            continue
                        submission_result = self.fetch_request(submission_spec)
                        stats.forms_submitted += 1
                        attempted_submissions.append(
                            {
                                "variant": variant_name,
                                "outcome": "submitted",
                                "submission_request": request_spec_to_jsonable(submission_spec),
                                "submission_status": submission_result.get("status"),
                                "submission_redirect_chain": submission_result.get("redirect_chain") or [],
                            }
                        )
                        submitted_any = True
                        process_response(
                            submission_spec,
                            submission_result,
                            parent_node_id,
                            depth + 1,
                            "human_form_submit" if assessment.decision == "hitl" else "auto_form_submit",
                            force_request_key=True,
                        )
                        if stopped:
                            break

                    review["attempted_submissions"] = attempted_submissions
                    if attempted_submissions:
                        first = attempted_submissions[0]
                        review["submission_request"] = first.get("submission_request")
                        review["submission_status"] = first.get("submission_status")
                        review["submission_redirect_chain"] = first.get("submission_redirect_chain") or []
                    review["outcome"] = "submitted" if submitted_any else "budget_skipped"
                    reviews.append(review)
                    if stopped:
                        break
                except Exception as e:
                    review["outcome"] = "submit_error"
                    review["error"] = str(e)
                    reviews.append(review)
            return reviews

        seed_spec = request_spec_for_challenge_url(seed_final)
        process_response(seed_spec, seed_http_result, None, 0, "seed", force_request_key=False)

        while queue and not stopped:
            if stats.pages_visited >= self.budget.max_pages:
                stopped = "budget_pages"
                break

            url, parent_id, depth, via = queue.popleft()
            key = page_dedupe_key(url)
            if key in seen_page_keys:
                continue

            result = self.fetch_get(url)
            request_spec = request_spec_for_challenge_url(url)
            process_response(request_spec, result, parent_id, depth, via)
            if stopped:
                break

        if not stopped:
            if stats.pages_visited >= self.budget.max_pages and queue:
                stopped = "budget_pages"
            else:
                stopped = "empty_queue"

        stats.stopped_reason = stopped
        return {
            "endpoints": endpoints,
            "params": params,
            "forms": forms,
            "request_candidates": request_candidates,
            "form_reviews": form_reviews,
            "crawl_graph": graph,
            "flags": discovered_flags,
            "crawl_stats": {
                "pages_visited": stats.pages_visited,
                "candidates_dropped": stats.candidates_dropped,
                "forms_reviewed": stats.forms_reviewed,
                "forms_submitted": stats.forms_submitted,
                "hitl_questions": stats.hitl_questions,
                "stopped_reason": stats.stopped_reason,
            },
        }

    def _empty_outcome(self, stats: CrawlStats, reason: StoppedReason) -> Dict[str, Any]:
        stats.stopped_reason = reason
        return {
            "endpoints": [],
            "params": [],
            "forms": [],
            "request_candidates": [],
            "form_reviews": [],
            "crawl_graph": [],
            "flags": [],
            "crawl_stats": {
                "pages_visited": stats.pages_visited,
                "candidates_dropped": stats.candidates_dropped,
                "forms_reviewed": stats.forms_reviewed,
                "forms_submitted": stats.forms_submitted,
                "hitl_questions": stats.hitl_questions,
                "stopped_reason": stats.stopped_reason,
            },
        }
