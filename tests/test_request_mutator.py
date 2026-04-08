"""Tests for structural request mutation planner (F2)."""

from lattice_mind.web.request_models import HTTPRequestSpec, spec_to_adapter_args
from lattice_mind.web.request_mutator import plan_mutation_variants


def test_families_sorted_priority_param_remove_before_method_flip():
    base = HTTPRequestSpec(
        url="https://ex.test/",
        method="POST",
        query_params=None,
        body_params={"user": "u"},
        content_type="application/x-www-form-urlencoded",
    )
    planned = plan_mutation_variants(
        base,
        ["method_flip", "param_remove"],
        ["user"],
        {"max_total_variants": 20, "max_per_family": 10},
    )
    kinds = [p.mutation_kind for p in planned]
    assert kinds[0] == "baseline"
    assert kinds[1] == "param_remove"
    assert kinds[2] == "method_flip"


def test_param_remove_drops_post_body_field():
    base = HTTPRequestSpec(
        url="https://ex.test/submit",
        method="POST",
        query_params=None,
        body_params={"otp": "123", "token": "x"},
        content_type="application/x-www-form-urlencoded",
    )
    planned = plan_mutation_variants(
        base,
        ["param_remove"],
        ["otp"],
        {"max_total_variants": 10, "max_per_family": 10},
    )
    kinds = [p.mutation_kind for p in planned]
    assert kinds[0] == "baseline"
    remove = next(p for p in planned if p.mutation_kind == "param_remove")
    assert remove.spec.body_params is None
    assert remove.spec.body_param_pairs is not None
    keys = [k for k, _ in remove.spec.body_param_pairs or []]
    assert "otp" not in keys
    assert "token" in keys


def test_body_drop_clears_body():
    base = HTTPRequestSpec(
        url="https://ex.test/p",
        method="POST",
        body_params={"a": "1"},
        content_type="application/x-www-form-urlencoded",
    )
    planned = plan_mutation_variants(base, ["body_drop"], [], {})
    drop = next(p for p in planned if p.mutation_kind == "body_drop")
    assert drop.spec.body_params is None
    assert drop.spec.body_param_pairs is None


def test_param_duplicate_query_yields_two_same_keys_in_adapter_args():
    base = HTTPRequestSpec(
        url="https://ex.test/",
        method="GET",
        query_params={"id": "1"},
    )
    planned = plan_mutation_variants(base, ["param_duplicate"], ["id"], {})
    dup = next(p for p in planned if p.mutation_kind == "param_duplicate")
    args = spec_to_adapter_args(dup.spec)
    params = args["params"]
    assert isinstance(params, list)
    assert params.count(("id", "1")) == 2


def test_method_flip_post_to_get_merges_body_into_query():
    base = HTTPRequestSpec(
        url="https://ex.test/action",
        method="POST",
        query_params={"q": "x"},
        body_params={"user": "u"},
        content_type="application/x-www-form-urlencoded",
    )
    planned = plan_mutation_variants(base, ["method_flip"], [], {})
    flip = next(p for p in planned if p.mutation_kind == "method_flip")
    assert flip.spec.method.upper() == "GET"
    args = spec_to_adapter_args(flip.spec)
    keys = [k for k, _ in args["params"]]
    assert "q" in keys and "user" in keys


def test_mutation_budget_limits_variants():
    base = HTTPRequestSpec(
        url="https://ex.test/",
        method="GET",
        query_params={"a": "1", "b": "2", "c": "3"},
    )
    planned = plan_mutation_variants(
        base,
        ["param_remove"],
        ["a", "b", "c"],
        {"max_total_variants": 1, "max_per_family": 10},
    )
    # baseline + at most 1 mutation
    assert len(planned) <= 2
