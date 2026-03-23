from unittest.mock import patch

from lattice_mind.core.types import ChallengeDescriptor, ChallengeType, NodeStatus
from lattice_mind.trees.web.recon import WebReconProbeNode


def test_web_recon_probe_surfaces_crawl_flag_and_session_cookies():
    challenge = ChallengeDescriptor(type=ChallengeType.WEB, url="http://example.test/")
    context = {"challenge": challenge, "observations": {}}
    node = WebReconProbeNode()

    initial_http = {
        "status": 200,
        "headers": {"Server": "Werkzeug/3.0.1"},
        "body": "<html><form action='/dashboard' method='post'><input name='otp'></form></html>",
        "error": None,
    }
    crawled = {
        "endpoints": ["http://example.test/", "http://example.test/dashboard"],
        "params": ["otp"],
        "forms": [{"action": "http://example.test/dashboard", "method": "POST", "fields": [{"name": "otp"}]}],
        "request_candidates": [
            {
                "url": "http://example.test/dashboard",
                "method": "POST",
                "body_params": {"otp": ""},
            }
        ],
        "form_reviews": [{"outcome": "submitted"}],
        "crawl_graph": [{"id": "crawl_0", "url": "http://example.test/", "request_spec": {"url": "http://example.test/"}}],
        "crawl_stats": {"pages_visited": 1, "forms_submitted": 1, "stopped_reason": "empty_queue"},
        "flags": ["picoCTF{from_crawl_submit}"],
    }

    with patch.object(node.http, "run", return_value=initial_http), patch(
        "lattice_mind.trees.web.recon.CrawlFrontier"
    ) as mock_frontier:
        mock_instance = mock_frontier.return_value
        mock_instance.run.return_value = crawled
        with patch.object(node.http, "get_session_cookies", return_value={"session": "abc123"}):
            result = node.run(context)

    assert result.status == NodeStatus.SUCCESS
    assert context["flag_found"] == "picoCTF{from_crawl_submit}"
    assert context["observations"]["detected_flag"] == "picoCTF{from_crawl_submit}"
    assert context["observations"]["flags"] == ["picoCTF{from_crawl_submit}"]
    assert context["observations"]["session_cookies"] == {"session": "abc123"}
