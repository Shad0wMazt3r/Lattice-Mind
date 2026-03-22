from lattice_mind.core.types import ChallengeDescriptor, ChallengeType, NodeStatus
from lattice_mind.trees.web.client_decode import WebClientDecodeNode
from lattice_mind.trees.web.recon import WebReconAnalyzeVulnsNode


def _encode_subtractive(plaintext: str, key: str) -> str:
    out = []
    for i, ch in enumerate(plaintext):
        out.append(chr((ord(ch) + ord(key[i % len(key)])) % 256))
    return "".join(out)


def test_client_decode_recovers_flag_from_js_pattern():
    key = "picoctf"
    flag = "picoCTF{client_side_decode_works}"
    encrypted = _encode_subtractive(flag, key)
    body = f"""
    <textarea>
    javascript:(function() {{
      var encryptedFlag = "{encrypted}";
      var key = "{key}";
      var decryptedFlag = "";
      for (var i = 0; i < encryptedFlag.length; i++) {{
        decryptedFlag += String.fromCharCode((encryptedFlag.charCodeAt(i) - key.charCodeAt(i % key.length) + 256) % 256);
      }}
      alert(decryptedFlag);
    }})();
    </textarea>
    """

    context = {
        "challenge": ChallengeDescriptor(type=ChallengeType.WEB, url="http://example.local"),
        "observations": {"http_response": {"body": body}},
    }

    result = WebClientDecodeNode().run(context)
    assert result.status == NodeStatus.SUCCESS
    assert result.data.get("decoded_flag") == flag
    assert context.get("flag_found") == flag


def test_recon_marks_client_side_decode_candidate():
    body = """
    <script>
      var encryptedFlag = "abc";
      var key = "k";
      var out = String.fromCharCode((encryptedFlag.charCodeAt(0) - key.charCodeAt(0) + 256) % 256);
    </script>
    """

    context = {
        "observations": {
            "potential_params": [],
            "directories": [],
            "http_response": {"body": body},
            "tech_stack": [],
        }
    }

    result = WebReconAnalyzeVulnsNode().run(context)
    assert result.status == NodeStatus.SUCCESS
    candidates = context["observations"]["vuln_candidates"]
    assert "client_side_decode" in candidates


def test_client_decode_recovers_flag_from_mojibake_encrypted_string():
    # This mirrors real-world HTTP decoding issues where UTF-8 bytes are read as Latin-1.
    flag = "picoCTF{mojibake_fix_works}"
    key = "picoctf"
    encrypted = _encode_subtractive(flag, key)
    mojibake = encrypted.encode("utf-8").decode("latin1")

    body = f"""
    <script>
      var encryptedFlag = "{mojibake}";
      var key = "{key}";
      var decryptedFlag = "";
      for (var i = 0; i < encryptedFlag.length; i++) {{
        decryptedFlag += String.fromCharCode((encryptedFlag.charCodeAt(i) - key.charCodeAt(i % key.length) + 256) % 256);
      }}
      alert(decryptedFlag);
    </script>
    """

    context = {
        "challenge": ChallengeDescriptor(type=ChallengeType.WEB, url="http://example.local"),
        "observations": {"http_response": {"body": body}},
    }

    result = WebClientDecodeNode().run(context)
    assert result.status == NodeStatus.SUCCESS
    assert result.data.get("decoded_flag") == flag
    assert context.get("flag_found") == flag
