from lattice_mind.web import strategy_memory as sm


def test_strategy_memory_ranking_and_reset(tmp_path, monkeypatch):
    db = tmp_path / "runs.db"
    monkeypatch.setenv("LATTICE_MIND_DB", str(db))
    monkeypatch.setattr(sm, "DEFAULT_DB_PATH", str(db))

    sm.ensure_schema()
    sm.record_strategy_outcomes(
        [
            {
                "challenge_type": "web",
                "host_fingerprint": "demo.test",
                "endpoint_pattern": "/verify/*",
                "mutation_kind": "param_remove",
                "meaningful_delta": True,
                "strong_candidate": True,
                "led_to_flag": False,
                "notes": "otp omission changed auth result",
            },
            {
                "challenge_type": "web",
                "host_fingerprint": "demo.test",
                "endpoint_pattern": "/verify/*",
                "mutation_kind": "value_empty",
                "meaningful_delta": False,
                "strong_candidate": False,
                "led_to_flag": False,
                "notes": "no effect",
            },
        ]
    )

    ranked, hints = sm.rank_mutation_families(
        ["value_empty", "param_remove", "body_drop"],
        challenge_type="web",
        host_fingerprint="demo.test",
        endpoint_pattern="/verify/*",
        request_spec={"method": "POST", "body_params": {"otp": "1"}},
    )
    assert ranked[0] == "param_remove"
    assert any(h["mutation_kind"] == "param_remove" for h in hints)

    rows = sm.list_strategy_memory()
    assert rows
    deleted = sm.reset_strategy_memory()
    assert deleted >= 1
    assert sm.list_strategy_memory() == []

