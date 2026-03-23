from lattice_mind.web.html_crawl import parse_html_page


def test_crawl_links_extracts_internal_links_forms_and_params():
    html = """
    <html>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com/css2?family=Inter&display=swap">
      </head>
      <body>
        <a href="/admin?token=abc&view=1">Admin</a>
        <a href="javascript:void(0)">Skip</a>
        <form action="/submit" method="post">
          <input type="hidden" name="csrf" value="tok">
          <input type="text" name="username">
          <textarea name='message'></textarea>
          <button name="go" formaction="/alt">Go</button>
        </form>
      </body>
    </html>
    """

    result = parse_html_page("http://example.com", html)

    assert "http://example.com/admin?token=abc&view=1" in result["endpoints"]
    assert "http://example.com/submit" in result["endpoints"]
    assert "http://example.com/alt" in result["endpoints"]
    assert len(result["forms"]) == 1
    f0 = result["forms"][0]
    assert f0["action"] == "http://example.com/submit"
    assert f0["method"] == "POST"
    assert f0["enctype"] == "application/x-www-form-urlencoded"
    names = {fld["name"] for fld in f0["fields"]}
    assert names >= {"csrf", "username", "message", "go"}

    assert len(result["request_candidates"]) == 1
    cand = result["request_candidates"][0]
    assert cand["method"] == "POST"
    assert cand["body_params"]["csrf"] == "tok"
    assert "username" in cand["body_params"]

    assert "username" in result["params"]
    assert "message" in result["params"]
    assert "go" in result["params"]
    assert "csrf" in result["params"]
    assert "family" not in result["params"]
    assert "display" not in result["params"]

