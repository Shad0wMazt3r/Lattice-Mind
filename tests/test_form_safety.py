from lattice_mind.web.form_safety import assess_form_safety, build_submission_spec


def test_assess_form_safety_prefers_auth_flow():
    form = {
        "action": "http://example.test/register",
        "method": "POST",
        "fields": [
            {"name": "csrf_token", "value": "tok", "type": "hidden"},
            {"name": "full_name", "value": "", "type": "text"},
            {"name": "username", "value": "", "type": "text"},
            {"name": "password", "value": "", "type": "password"},
            {"name": "submit", "value": "Register", "type": "submit"},
        ],
    }

    assessment = assess_form_safety(form, current_url="http://example.test/")
    assert assessment.decision == "auto_submit"
    assert assessment.score >= 0.72
    assert "auth" in " ".join(assessment.reasons).lower()

    spec = build_submission_spec(form)
    assert spec.method == "POST"
    assert spec.body_params["full_name"] == "Test User"
    assert spec.body_params["username"] == "testuser"
    assert spec.body_params["password"] == "Password123!"
