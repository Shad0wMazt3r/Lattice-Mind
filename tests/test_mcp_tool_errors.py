from lattice_mind.core.mcp_tool_errors import tool_error


def test_tool_error_shape():
    d = tool_error("E_TEST", "msg", suggested_next_tool="auth_login")
    assert d["ok"] is False
    assert d["error"]["code"] == "E_TEST"
    assert d["error"]["suggested_next_tool"] == "auth_login"
