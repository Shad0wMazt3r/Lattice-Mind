"""Tests for bounded same-origin crawl frontier (F4)."""

from __future__ import annotations

from lattice_mind.web.crawl_frontier import CrawlFrontier
from lattice_mind.web.form_safety import FormSafetyAssessment
from lattice_mind.web.html_crawl import page_dedupe_key
from lattice_mind.web.run_budget import CrawlBudget


def test_recursive_link_and_second_level_form():
    html_seed = '<html><body><a href="/page2">go</a></body></html>'
    html_p2 = """
    <html><body>
      <form action="/submit" method="post">
        <input type="text" name="comment">
      </form>
    </body></html>
    """
    bodies = {
        "http://ctf.local/": html_seed,
        "http://ctf.local/page2": html_p2,
    }

    def fetch_get(url: str):
        key = url.split("?", 1)[0].rstrip("/") or url
        if key == "http://ctf.local":
            key = "http://ctf.local/"
        body = bodies.get(key, "")
        return {
            "status": 200,
            "headers": {},
            "body": body,
            "error": None,
            "redirect_chain": [url],
        }

    budget = CrawlBudget(max_depth=3, max_pages=20, max_request_candidates=50)
    seed_result = {
        "status": 200,
        "body": html_seed,
        "redirect_chain": ["http://ctf.local/"],
    }
    out = CrawlFrontier(budget, fetch_get).run(
        "http://ctf.local/", html_seed, seed_result
    )

    assert "http://ctf.local/submit" in out["endpoints"] or any(
        "submit" in e for e in out["endpoints"]
    )
    assert any(f.get("action", "").endswith("/submit") for f in out["forms"])
    assert out["crawl_stats"]["pages_visited"] >= 2


def test_fragment_urls_deduped_for_enqueue():
    html_seed = """
    <html><body>
      <a href="/same#a">1</a>
      <a href="/same#b">2</a>
    </body></html>
    """
    fetched: list[str] = []

    def fetch_get(url: str):
        fetched.append(url)
        return {
            "status": 200,
            "headers": {},
            "body": "<html></html>",
            "error": None,
            "redirect_chain": [url],
        }

    budget = CrawlBudget(max_depth=2, max_pages=10, max_request_candidates=20)
    seed_result = {
        "status": 200,
        "body": html_seed,
        "redirect_chain": ["http://x.test/"],
    }
    CrawlFrontier(budget, fetch_get).run("http://x.test/", html_seed, seed_result)

    assert page_dedupe_key("http://x.test/same#a") == page_dedupe_key(
        "http://x.test/same#b"
    )
    same_norm = [u for u in fetched if "same" in u]
    assert len(same_norm) <= 1


def test_max_pages_stops_additional_fetches():
    html_seed = '<a href="/two">t</a><a href="/three">t</a>'
    html_other = "<html></html>"

    def fetch_get(url: str):
        return {
            "status": 200,
            "headers": {},
            "body": html_other,
            "error": None,
            "redirect_chain": [url],
        }

    budget = CrawlBudget(max_depth=3, max_pages=2, max_request_candidates=20)
    seed_result = {
        "status": 200,
        "body": html_seed,
        "redirect_chain": ["http://p.test/"],
    }
    out = CrawlFrontier(budget, fetch_get).run(
        "http://p.test/", html_seed, seed_result
    )

    assert out["crawl_stats"]["pages_visited"] == 2
    assert out["crawl_stats"]["stopped_reason"] == "budget_pages"


def test_queue_budget_returns_immediately():
    html_seed = "<a href='/a'>a</a><a href='/b'>b</a>"

    def fetch_get(url: str):
        return {
            "status": 200,
            "body": "",
            "error": None,
            "redirect_chain": [url],
        }

    budget = CrawlBudget(
        max_depth=3,
        max_pages=50,
        max_request_candidates=20,
        max_queue_size=1,
    )
    seed_result = {
        "status": 200,
        "body": html_seed,
        "redirect_chain": ["http://q.test/"],
    }
    out = CrawlFrontier(budget, fetch_get).run(
        "http://q.test/", html_seed, seed_result
    )

    assert out["crawl_stats"]["stopped_reason"] == "budget_queue"


def test_crawl_graph_nodes_include_page_local_metadata_and_provenance():
    html_seed = """
    <html><body>
      <a href="/from-anchor">A</a>
      <form action="/from-form" method="get"><input name="otp" value="1"></form>
      <form action="/post-submit" method="post"><input name="csrf" value="t"></form>
    </body></html>
    """

    def fetch_get(url: str):
        return {
            "status": 200,
            "headers": {
                "Set-Cookie": "session=abc123; Path=/; HttpOnly, csrftoken=xyz; Path=/",
                "WWW-Authenticate": "Basic realm=demo",
            },
            "body": "<html></html>",
            "error": None,
            "redirect_chain": [url],
        }

    budget = CrawlBudget(max_depth=2, max_pages=10, max_request_candidates=20)
    seed_result = {
        "status": 200,
        "headers": {
            "Set-Cookie": "sid=s1; Path=/",
        },
        "body": html_seed,
        "redirect_chain": ["http://meta.test/"],
    }
    out = CrawlFrontier(budget, fetch_get).run("http://meta.test/", html_seed, seed_result)
    graph = out["crawl_graph"]
    assert graph
    seed = graph[0]
    assert "forms" in seed and isinstance(seed["forms"], list)
    assert "request_candidates" in seed and isinstance(seed["request_candidates"], list)
    assert "auth_cookie_metadata" in seed and isinstance(seed["auth_cookie_metadata"], dict)
    assert seed["auth_cookie_metadata"]["has_set_cookie"] is True
    assert "sid" in seed["auth_cookie_metadata"]["set_cookie_names"]

    vias = {n.get("discovered_via") for n in graph[1:]}
    assert "anchor_link" in vias
    assert "get_form" in vias


def test_safe_form_submission_advances_to_follow_up_page():
    seed_html = """
    <html><body>
      <form action="/register" method="post">
        <input name="csrf_token" value="tok" type="hidden">
        <input name="full_name" value="" type="text">
        <input name="username" value="" type="text">
        <input name="password" value="" type="password">
        <input name="submit" value="Register" type="submit">
      </form>
    </body></html>
    """
    submitted = []

    def fetch_get(url: str):
        return {
            "status": 200,
            "headers": {},
            "body": seed_html,
            "error": None,
            "redirect_chain": [url],
        }

    def fetch_request(spec):
        submitted.append(spec)
        assert spec.method == "POST"
        assert spec.body_params["username"] == "testuser"
        return {
            "status": 200,
            "headers": {},
            "body": "<html><body>OTP PAGE</body></html>",
            "error": None,
            "redirect_chain": [spec.url, "http://meta.test/otp"],
        }

    budget = CrawlBudget(max_depth=3, max_pages=10, max_request_candidates=20)
    seed_result = {
        "status": 200,
        "headers": {},
        "body": seed_html,
        "redirect_chain": ["http://meta.test/"],
    }
    out = CrawlFrontier(budget, fetch_get, fetch_request).run(
        "http://meta.test/", seed_html, seed_result
    )

    assert submitted
    assert out["crawl_stats"]["forms_submitted"] >= 1
    assert any(n["url"].endswith("/otp") for n in out["crawl_graph"])
    assert any(review["outcome"] == "submitted" for review in out["form_reviews"])


def test_gray_form_uses_hitl_before_submission(monkeypatch):
    seed_html = """
    <html><body>
      <form action="/review" method="post">
        <input name="comment" value="" type="text">
        <input name="submit" value="Continue" type="submit">
      </form>
    </body></html>
    """
    submitted = []
    questions = []

    def fetch_get(url: str):
        return {
            "status": 200,
            "headers": {},
            "body": seed_html,
            "error": None,
            "redirect_chain": [url],
        }

    def fetch_request(spec):
        submitted.append(spec)
        return {
            "status": 200,
            "headers": {},
            "body": "<html><body>next</body></html>",
            "error": None,
            "redirect_chain": [spec.url],
        }

    def ask_user(question, options=None, node_id=None, timeout=None, details=None, kind=None):
        questions.append(
            {
                "question": question,
                "options": options,
                "node_id": node_id,
                "details": details,
                "kind": kind,
            }
        )
        return "submit"

    def fake_assessment(form, current_url=None):
        return FormSafetyAssessment(
            score=0.55,
            decision="hitl",
            form_summary="POST /review",
            reasons=["ambiguous flow"],
            risks=["manual approval needed"],
            prompt="Submit review form?",
            suggested_answer="submit",
        )

    monkeypatch.setattr("lattice_mind.web.crawl_frontier.assess_form_safety", fake_assessment)

    budget = CrawlBudget(max_depth=3, max_pages=10, max_request_candidates=20)
    seed_result = {
        "status": 200,
        "headers": {},
        "body": seed_html,
        "redirect_chain": ["http://gray.test/"],
    }
    out = CrawlFrontier(budget, fetch_get, fetch_request, ask_user=ask_user).run(
        "http://gray.test/", seed_html, seed_result
    )

    assert questions and questions[0]["kind"] == "form_submission_review"
    assert submitted
    assert out["crawl_stats"]["hitl_questions"] >= 1


def test_form_submission_budget_zero_disables_submission_attempts():
    seed_html = """
    <html><body>
      <form action="/register" method="post">
        <input name="username" value="" type="text">
        <input name="password" value="" type="password">
      </form>
    </body></html>
    """
    submitted = []

    def fetch_get(url: str):
        return {
            "status": 200,
            "headers": {},
            "body": seed_html,
            "error": None,
            "redirect_chain": [url],
        }

    def fetch_request(spec):
        submitted.append(spec)
        return {
            "status": 200,
            "headers": {},
            "body": "<html></html>",
            "error": None,
            "redirect_chain": [spec.url],
        }

    budget = CrawlBudget(
        max_depth=3, max_pages=10, max_request_candidates=20, max_form_submissions=0
    )
    seed_result = {
        "status": 200,
        "headers": {},
        "body": seed_html,
        "redirect_chain": ["http://budget.test/"],
    }
    out = CrawlFrontier(budget, fetch_get, fetch_request).run(
        "http://budget.test/", seed_html, seed_result
    )

    assert not submitted
    assert out["crawl_stats"]["forms_submitted"] == 0
    assert any(
        review["outcome"] == "budget_skipped" for review in out.get("form_reviews", [])
    )


def test_otp_form_submits_default_and_otp_omitted_variant_and_detects_flag():
    seed_html = """
    <html><body>
      <form action="/dashboard" method="post">
        <input name="otp" value="" type="text">
      </form>
    </body></html>
    """
    submitted = []

    def fetch_get(url: str):
        return {
            "status": 200,
            "headers": {},
            "body": seed_html,
            "error": None,
            "redirect_chain": [url],
        }

    def fetch_request(spec):
        submitted.append(spec)
        body = "<html>try again</html>"
        if spec.body_params is not None and "otp" not in spec.body_params:
            body = "<html>picoCTF{otp_omitted_wins}</html>"
        return {
            "status": 200,
            "headers": {},
            "body": body,
            "error": None,
            "redirect_chain": [spec.url],
        }

    budget = CrawlBudget(max_depth=2, max_pages=10, max_request_candidates=20)
    seed_result = {
        "status": 200,
        "headers": {},
        "body": seed_html,
        "redirect_chain": ["http://otp.test/"],
    }
    out = CrawlFrontier(budget, fetch_get, fetch_request).run(
        "http://otp.test/", seed_html, seed_result
    )

    assert len(submitted) >= 2
    bodies = [s.body_params or {} for s in submitted]
    assert any("otp" in b for b in bodies)
    assert any("otp" not in b for b in bodies)
    assert "picoCTF{otp_omitted_wins}" in out.get("flags", [])
    assert any(
        any(a.get("variant") == "otp_omitted" for a in review.get("attempted_submissions", []))
        for review in out.get("form_reviews", [])
    )
