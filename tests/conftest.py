"""Shared pytest fixtures and configuration for lattice_mind test suite."""
import textwrap
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Minimal YAML strings used by tree-loader tests
# ---------------------------------------------------------------------------

MINIMAL_TREE_YAML = textwrap.dedent("""\
    id: test_tree
    name: Test Tree
    category: web
    version: "1.0"
    author: tester
    description: A test tree
    min_confidence: 0.1
    stop_on_flag: true
    confidence_seeds:
      - if: "context.challenge.type == 'web'"
        boost: 0.5
        label: is_web
    detection_paths:
      - id: dp1
        name: Basic Detection
        description: Probe for SQL
        min_confidence: 0.1
        steps:
          - id: step1
            action: http_probe
            params:
              payloads: ["'"]
              inject_into: all_params
            signals:
              - match: "syntax error"
                on_match:
                  confidence_boost: 0.4
                  emit: sqli_reflected
    exploitation_paths:
      - id: ep1
        name: Union Exploit
        requires_signal: sqli_reflected
        technique: union_select
        steps:
          - id: ex1
            action: http_probe
            params:
              payloads: ["' UNION SELECT 1,flag FROM flags--"]
              inject_into: vulnerable_param
            capture:
              - pattern: "flag\\{([^}]+)\\}"
                as: flag_value
""")

SCHEMA_B_TREE_YAML = textwrap.dedent("""\
    id: schema_b_tree
    name: Schema B Style Tree
    category: web
    min_confidence: 0.2
    stop_on_flag: true
    confidence_seeds: []
    detection_paths:
      - id: dp_b
        name: Path B
        description: ''
        steps:
          - id: step_b
            action: http_probe
            with:
              payloads: ["<script>"]
              inject_into: all_params
            signals: []
    exploitation_paths: []
""")
