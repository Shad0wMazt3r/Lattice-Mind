"""Form safety rubric and heuristic submission filling for crawl HITL."""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from lattice_mind.web.request_models import HTTPRequestSpec, request_spec_from_form_record


_AUTH_TOKENS = {
    "login",
    "log in",
    "signin",
    "sign in",
    "register",
    "signup",
    "sign up",
    "otp",
    "verify",
    "verification",
    "forgot password",
    "reset password",
    "recover",
    "authenticate",
    "mfa",
    "2fa",
}

_BENIGN_TOKENS = {
    "search",
    "lookup",
    "preview",
    "check",
    "validate",
    "browse",
    "filter",
    "register",
    "login",
    "otp",
}

_DANGEROUS_TOKENS = {
    "delete",
    "remove",
    "destroy",
    "drop",
    "update",
    "modify",
    "edit",
    "publish",
    "deploy",
    "transfer",
    "purchase",
    "pay",
    "checkout",
    "admin",
    "settings",
    "ban",
    "invite",
    "unsubscribe",
    "email blast",
}


@dataclass
class FormSafetyAssessment:
    score: float
    decision: str
    form_summary: str
    reasons: List[str] = field(default_factory=list)
    risks: List[str] = field(default_factory=list)
    prompt: str = ""
    suggested_answer: str = "skip"

    def to_review_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "decision": self.decision,
            "form_summary": self.form_summary,
            "reasons": list(self.reasons),
            "risks": list(self.risks),
            "prompt": self.prompt,
            "suggested_answer": self.suggested_answer,
        }


def _clamp(score: float) -> float:
    return max(0.0, min(1.0, score))


def _text_blob(form: Dict[str, Any]) -> str:
    parts: List[str] = []
    for key in ("action", "id", "method", "enctype", "label", "title"):
        val = form.get(key)
        if val:
            parts.append(str(val))
    for field in form.get("fields") or []:
        if not isinstance(field, dict):
            continue
        for key in ("name", "value", "type", "placeholder", "label"):
            val = field.get(key)
            if val:
                parts.append(str(val))
    return " ".join(parts).lower()


def _field_names(form: Dict[str, Any]) -> List[str]:
    names: List[str] = []
    for field in form.get("fields") or []:
        if not isinstance(field, dict):
            continue
        name = field.get("name")
        if name:
            names.append(str(name))
    return names


def _field_types(form: Dict[str, Any]) -> List[str]:
    types: List[str] = []
    for field in form.get("fields") or []:
        if not isinstance(field, dict):
            continue
        ftype = field.get("type")
        if ftype:
            types.append(str(ftype).lower())
    return types


def _path_hint(action: str) -> str:
    parsed = urlparse(action or "")
    return (parsed.path or "/").lower()


def _fill_value(name: str, field_type: str, current_value: Any) -> str:
    raw_name = (name or "").strip().lower()
    raw_type = (field_type or "").strip().lower()
    current = "" if current_value is None else str(current_value)

    if raw_type in {"submit", "button", "reset", "image"}:
        return current or "Submit"

    if raw_type == "hidden":
        if any(tok in raw_name for tok in ("csrf", "xsrf", "authenticity", "token", "nonce", "session")):
            return current
        return current or "1"

    if any(tok in raw_name for tok in ("csrf", "xsrf", "authenticity", "token", "nonce")):
        return current or "token"
    if any(tok in raw_name for tok in ("email", "mail")):
        return current or "test@example.com"
    if any(tok in raw_name for tok in ("password", "pass")):
        return current or "Password123!"
    if any(tok in raw_name for tok in ("username", "user", "login", "account")):
        return current or "testuser"
    if any(tok in raw_name for tok in ("full_name", "fullname", "name")):
        return current or "Test User"
    if any(tok in raw_name for tok in ("phone", "mobile")):
        return current or "5551234567"
    if any(tok in raw_name for tok in ("city", "town")):
        return current or "Testville"
    if any(tok in raw_name for tok in ("otp", "code", "pin", "2fa", "mfa", "verify")):
        return current or "0000"
    if any(tok in raw_name for tok in ("search", "query", "q", "term", "filter")):
        return current or "test"
    if any(tok in raw_name for tok in ("message", "comment", "note", "body")):
        return current or "test"
    if any(tok in raw_name for tok in ("url", "link", "site", "target", "redirect")):
        return current or "https://example.com"
    if any(tok in raw_name for tok in ("amount", "price", "count", "qty", "quantity")):
        return current or "1"
    if any(tok in raw_name for tok in ("id", "uid", "record", "item", "page")):
        return current or "1"
    if raw_type in {"checkbox", "radio"}:
        return current or "on"
    if raw_type in {"number", "range"}:
        return current or "1"
    return current or "test"


def fill_form_record(form: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of the form with heuristic values filled in."""
    filled = copy.deepcopy(form)
    fields = []
    for field in filled.get("fields") or []:
        if not isinstance(field, dict):
            continue
        field = dict(field)
        field["value"] = _fill_value(
            str(field.get("name") or ""),
            str(field.get("type") or "text"),
            field.get("value"),
        )
        fields.append(field)
    filled["fields"] = fields
    return filled


def build_submission_spec(form: Dict[str, Any]) -> HTTPRequestSpec:
    """Build a request spec with safe heuristic values filled into the form."""
    return request_spec_from_form_record(fill_form_record(form))


def assess_form_safety(
    form: Dict[str, Any],
    *,
    current_url: Optional[str] = None,
) -> FormSafetyAssessment:
    """Score whether a form is safe enough to auto-submit or needs human review."""
    action = str(form.get("action") or current_url or "").strip()
    method = str(form.get("method") or "GET").upper()
    enctype = str(form.get("enctype") or "").lower()
    text = _text_blob(form)
    names = _field_names(form)
    types = _field_types(form)
    path = _path_hint(action)

    score = 0.35
    reasons: List[str] = []
    risks: List[str] = []

    if method == "GET":
        score += 0.12
        reasons.append("GET form is usually low risk")
    elif method in {"POST", "PUT", "PATCH"}:
        score += 0.05
        reasons.append(f"{method} form can be advanced safely if it looks like a benign flow")
    else:
        score -= 0.30
        risks.append(f"unexpected method {method}")

    if any(ftype == "file" for ftype in types):
        score -= 0.80
        risks.append("contains file upload")

    if "multipart/form-data" in enctype:
        score -= 0.25
        risks.append("multipart upload-style encoding")

    if any(tok in text for tok in _DANGEROUS_TOKENS):
        score -= 0.45
        risks.append("labels or action text suggest destructive behavior")

    if any(tok in path for tok in _DANGEROUS_TOKENS):
        score -= 0.45
        risks.append("action path looks destructive")

    if any(tok in text for tok in _AUTH_TOKENS):
        score += 0.30
        reasons.append("looks like an auth or onboarding flow")

    if any(tok in text for tok in _BENIGN_TOKENS):
        score += 0.10
        reasons.append("looks like a benign lookup or onboarding step")

    if any(tok in path for tok in ("login", "register", "signup", "signin", "otp", "reset", "forgot")):
        score += 0.20
        reasons.append("action path suggests a benign auth workflow")

    if any("csrf" in name.lower() or "token" in name.lower() for name in names):
        score += 0.08
        reasons.append("csrf/token field is present")

    if any(ftype == "password" for ftype in types):
        score += 0.05
        reasons.append("password field suggests a login or registration step")

    if any(tok in text for tok in ("otp", "one time", "verification", "verify")):
        score += 0.18
        reasons.append("looks like an OTP or verification step")

    if len(names) <= 8:
        score += 0.05
    else:
        score -= 0.05

    if current_url:
        current_host = urlparse(current_url).netloc.lower()
        action_host = urlparse(action).netloc.lower()
        if current_host and action_host and current_host == action_host:
            score += 0.05
            reasons.append("same-origin submission")

    score = _clamp(score)
    if score >= 0.72:
        decision = "auto_submit"
        suggested_answer = "submit"
    elif score >= 0.45:
        decision = "hitl"
        suggested_answer = "submit"
    else:
        decision = "skip"
        suggested_answer = "skip"

    summary = f"{method} {path or '/'}"
    prompt = (
        f"Submit {summary}? score={score:.2f}. "
        f"Reasons: {', '.join(reasons[:4]) or 'none'}. "
        f"Risks: {', '.join(risks[:3]) or 'none'}."
    )

    return FormSafetyAssessment(
        score=score,
        decision=decision,
        form_summary=summary,
        reasons=reasons,
        risks=risks,
        prompt=prompt,
        suggested_answer=suggested_answer,
    )
