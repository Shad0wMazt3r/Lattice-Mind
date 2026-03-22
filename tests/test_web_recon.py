from lattice_mind.trees.web.recon import WebReconProbeNode


def test_crawl_links_extracts_internal_links_forms_and_params():
    node = WebReconProbeNode()

    html = """
    <html>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com/css2?family=Inter&display=swap">
      </head>
      <body>
        <a href="/admin?token=abc&view=1">Admin</a>
        <a href="javascript:void(0)">Skip</a>
        <form action="/submit" method="post">
          <input type="text" name="username">
          <textarea name='message'></textarea>
          <button name="go" formaction="/alt">Go</button>
        </form>
      </body>
    </html>
    """

    result = node._crawl_links("http://example.com", html)

    assert "http://example.com/admin?token=abc&view=1" in result["endpoints"]
    assert "http://example.com/submit" in result["endpoints"]
    assert "http://example.com/alt" in result["endpoints"]
    assert result["forms"] == [{"action": "http://example.com/submit", "method": "POST"}]
    assert "username" in result["params"]
    assert "message" in result["params"]
    assert "go" in result["params"]
    assert "family" not in result["params"]
    assert "display" not in result["params"]

