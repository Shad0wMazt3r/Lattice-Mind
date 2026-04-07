"""Tests for tree catalog and selection resolution."""

import pytest

from lattice_mind.core.tree_catalog import (
    TreeCatalogError,
    build_tree_catalog,
    resolve_tree_selection,
    validate_tree_dependencies,
)
from lattice_mind.core.tree_loader import DecisionTree, TreeRegistry


def _tree(raw_id: str, **kwargs) -> DecisionTree:
    base = {
        "id": raw_id,
        "name": raw_id,
        "category": "web",
        "applies_when": ["context.challenge.type == 'web'"],
        "min_confidence": 0.1,
        "detection_paths": [],
        "exploitation_paths": [],
    }
    base.update(kwargs)
    return DecisionTree(base)


def test_validate_tree_dependencies_order():
    graph = {"a": [], "b": ["a"], "c": ["b"]}
    r = validate_tree_dependencies(["c", "a", "b"], graph)
    assert not r.cycle
    assert r.ordered_ids.index("a") < r.ordered_ids.index("b")
    assert r.ordered_ids.index("b") < r.ordered_ids.index("c")


def test_validate_tree_dependencies_missing():
    r = validate_tree_dependencies(["child"], {"child": ["parent"]})
    assert ("child", "parent") in r.missing_dependencies


def test_resolve_tree_selection_ids_and_category():
    reg = TreeRegistry()
    reg.trees["t1"] = _tree("t1", tags=["sqli"])
    reg.trees["t2"] = _tree("t2", tags=["xss"])
    cat = build_tree_catalog(reg)
    sel = resolve_tree_selection(
        cat,
        {"ids": ["t2"], "groups": [{"type": "category", "value": "web"}]},
        challenge_type="web",
    )
    assert set(sel.ordered_tree_ids) == {"t1", "t2"}


def test_resolve_unknown_group_raises():
    reg = TreeRegistry()
    reg.trees["t1"] = _tree("t1")
    cat = build_tree_catalog(reg)
    with pytest.raises(TreeCatalogError):
        resolve_tree_selection(
            cat, {"groups": [{"type": "tag", "value": "nope"}]}, challenge_type="web"
        )
