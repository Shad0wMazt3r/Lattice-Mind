"""Bounded resource limits for web crawl frontier (F4)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional

StoppedReason = Literal["empty_queue", "budget_pages", "budget_candidates", "budget_queue"]


@dataclass
class CrawlBudget:
    max_depth: int = 3
    max_pages: int = 50
    max_request_candidates: int = 200
    max_queue_size: int = 500
    max_endpoints: int = 200
    max_params: int = 200
    max_form_submissions: int = 10


@dataclass
class CrawlStats:
    pages_visited: int = 0
    candidates_added: int = 0
    candidates_dropped: int = 0
    forms_reviewed: int = 0
    forms_submitted: int = 0
    hitl_questions: int = 0
    stopped_reason: Optional[StoppedReason] = None
