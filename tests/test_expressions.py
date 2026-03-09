"""
Deep tests for ExpressionEvaluator and evaluate_condition.

Covers:
- Empty expression always returns True
- Boolean literals
- Comparison operators: ==, !=, >, <, >=, <=
- Boolean logic: and, or, not
- Membership operators: in, not in
- Context variable access via context.<attr>
- Dot-notation attribute chaining
- Enum value unwrapping
- Function calls: len(), any(), all()
- any(x in y for x in [...]) generator pattern
- List literals
- Subscript access
- Unknown variable → NameError wrapped in ValueError
- Unsupported node → TypeError wrapped in ValueError
- Unsupported operator raises
- evaluate_condition convenience function
"""

import pytest

from lattice_mind.core.expressions import ExpressionEvaluator, evaluate_condition
from lattice_mind.core.types import ChallengeType

# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def simple_ctx():
    # Note: avoid 'items' key — conflicts with dict.items() builtin in attribute access
    return {"name": "alice", "score": 42, "tags": ["a", "b", "c"]}


@pytest.fixture
def nested_ctx():
    class Inner:
        value = "hello"
        count = 5

    class Outer:
        child = Inner()
        tag = "web"

    return {"outer": Outer()}


@pytest.fixture
def enum_ctx():
    class Challenge:
        type = ChallengeType.WEB

    return {"challenge": Challenge()}


# ──────────────────────────────────────────────────────────────────────────────
# Empty / None expressions
# ──────────────────────────────────────────────────────────────────────────────


class TestEmptyExpression:

    def test_empty_string_returns_true(self):
        ev = ExpressionEvaluator({})
        assert ev.evaluate("") is True

    def test_none_equivalent_empty(self):
        # evaluate_condition with empty string
        assert evaluate_condition("", {}) is True


# ──────────────────────────────────────────────────────────────────────────────
# Boolean literals
# ──────────────────────────────────────────────────────────────────────────────


class TestBooleanLiterals:

    def test_true_literal(self):
        ev = ExpressionEvaluator({})
        assert ev.evaluate("True") is True

    def test_false_literal(self):
        ev = ExpressionEvaluator({})
        assert ev.evaluate("False") is False


# ──────────────────────────────────────────────────────────────────────────────
# Comparison operators
# ──────────────────────────────────────────────────────────────────────────────


class TestComparisonOperators:

    def test_eq_strings(self, simple_ctx):
        assert ExpressionEvaluator(simple_ctx).evaluate("context.name == 'alice'")

    def test_eq_numbers(self, simple_ctx):
        assert ExpressionEvaluator(simple_ctx).evaluate("context.score == 42")

    def test_neq_true(self, simple_ctx):
        assert ExpressionEvaluator(simple_ctx).evaluate("context.name != 'bob'")

    def test_neq_false(self, simple_ctx):
        assert not ExpressionEvaluator(simple_ctx).evaluate("context.name != 'alice'")

    def test_gt_true(self, simple_ctx):
        assert ExpressionEvaluator(simple_ctx).evaluate("context.score > 10")

    def test_gt_false(self, simple_ctx):
        assert not ExpressionEvaluator(simple_ctx).evaluate("context.score > 100")

    def test_lt_true(self, simple_ctx):
        assert ExpressionEvaluator(simple_ctx).evaluate("context.score < 100")

    def test_lt_false(self, simple_ctx):
        assert not ExpressionEvaluator(simple_ctx).evaluate("context.score < 1")

    def test_gte_equal(self, simple_ctx):
        assert ExpressionEvaluator(simple_ctx).evaluate("context.score >= 42")

    def test_gte_greater(self, simple_ctx):
        assert ExpressionEvaluator(simple_ctx).evaluate("context.score >= 41")

    def test_lte_equal(self, simple_ctx):
        assert ExpressionEvaluator(simple_ctx).evaluate("context.score <= 42")

    def test_lte_less(self, simple_ctx):
        assert ExpressionEvaluator(simple_ctx).evaluate("context.score <= 43")

    def test_eq_false(self, simple_ctx):
        assert not ExpressionEvaluator(simple_ctx).evaluate("context.name == 'bob'")


# ──────────────────────────────────────────────────────────────────────────────
# Boolean logic
# ──────────────────────────────────────────────────────────────────────────────


class TestBooleanLogic:

    def test_and_true(self, simple_ctx):
        assert ExpressionEvaluator(simple_ctx).evaluate(
            "context.name == 'alice' and context.score == 42"
        )

    def test_and_false_left(self, simple_ctx):
        assert not ExpressionEvaluator(simple_ctx).evaluate(
            "context.name == 'bob' and context.score == 42"
        )

    def test_and_false_right(self, simple_ctx):
        assert not ExpressionEvaluator(simple_ctx).evaluate(
            "context.name == 'alice' and context.score == 99"
        )

    def test_or_both_false(self, simple_ctx):
        assert not ExpressionEvaluator(simple_ctx).evaluate(
            "context.name == 'bob' or context.score == 99"
        )

    def test_or_left_true(self, simple_ctx):
        assert ExpressionEvaluator(simple_ctx).evaluate(
            "context.name == 'alice' or context.score == 99"
        )

    def test_or_right_true(self, simple_ctx):
        assert ExpressionEvaluator(simple_ctx).evaluate(
            "context.name == 'bob' or context.score == 42"
        )

    def test_not_true(self, simple_ctx):
        assert ExpressionEvaluator(simple_ctx).evaluate("not context.name == 'bob'")

    def test_not_false(self, simple_ctx):
        assert not ExpressionEvaluator(simple_ctx).evaluate(
            "not context.name == 'alice'"
        )

    def test_complex_bool(self, simple_ctx):
        expr = "(context.name == 'alice' or context.score > 40) and context.score < 100"
        assert ExpressionEvaluator(simple_ctx).evaluate(expr)


# ──────────────────────────────────────────────────────────────────────────────
# Membership operators
# ──────────────────────────────────────────────────────────────────────────────


class TestMembershipOperators:

    def test_in_list_true(self, simple_ctx):
        assert ExpressionEvaluator(simple_ctx).evaluate("'a' in context.tags")

    def test_in_list_false(self, simple_ctx):
        assert not ExpressionEvaluator(simple_ctx).evaluate("'z' in context.tags")

    def test_not_in_list_true(self, simple_ctx):
        assert ExpressionEvaluator(simple_ctx).evaluate("'z' not in context.tags")

    def test_not_in_list_false(self, simple_ctx):
        assert not ExpressionEvaluator(simple_ctx).evaluate("'a' not in context.tags")

    def test_in_string(self):
        ctx = {"text": "hello world"}
        assert ExpressionEvaluator(ctx).evaluate("'hello' in context.text")

    def test_not_in_string(self):
        ctx = {"text": "hello world"}
        assert ExpressionEvaluator(ctx).evaluate("'goodbye' not in context.text")


# ──────────────────────────────────────────────────────────────────────────────
# Attribute / dot-notation access
# ──────────────────────────────────────────────────────────────────────────────


class TestAttributeAccess:

    def test_nested_attribute(self, nested_ctx):
        assert ExpressionEvaluator(nested_ctx).evaluate(
            "context.outer.child.value == 'hello'"
        )

    def test_dict_key_access(self):
        ctx = {"data": {"key": "found"}}
        assert ExpressionEvaluator(ctx).evaluate("context.data.key == 'found'")

    def test_missing_attribute_raises_value_error(self):
        ctx = {"obj": object()}
        with pytest.raises((ValueError, AttributeError)):
            ExpressionEvaluator(ctx).evaluate("context.obj.nonexistent == 'x'")

    def test_enum_unwrapped_as_value(self, enum_ctx):
        """context.challenge.type == 'web' should work when type is ChallengeType.WEB."""
        result = ExpressionEvaluator(enum_ctx).evaluate(
            "context.challenge.type == 'web'"
        )
        assert result is True

    def test_enum_neq(self, enum_ctx):
        result = ExpressionEvaluator(enum_ctx).evaluate(
            "context.challenge.type == 'pwn'"
        )
        assert result is False


# ──────────────────────────────────────────────────────────────────────────────
# len() function
# ──────────────────────────────────────────────────────────────────────────────


class TestLenFunction:

    def test_len_of_list(self, simple_ctx):
        assert ExpressionEvaluator(simple_ctx).evaluate("len(context.tags) == 3")

    def test_len_of_string(self):
        ctx = {"s": "hello"}
        assert ExpressionEvaluator(ctx).evaluate("len(context.s) == 5")

    def test_len_gt(self, simple_ctx):
        assert ExpressionEvaluator(simple_ctx).evaluate("len(context.tags) > 0")

    def test_len_eq_zero(self):
        ctx = {"lst": []}
        assert ExpressionEvaluator(ctx).evaluate("len(context.lst) == 0")


# ──────────────────────────────────────────────────────────────────────────────
# any() and all() with generator expressions
# ──────────────────────────────────────────────────────────────────────────────


class TestAnyAllGenerators:

    def test_any_generator_true(self):
        ctx = {"fields": ["id", "user", "page"]}
        ev = ExpressionEvaluator(ctx)
        assert ev.evaluate("any(p in context.fields for p in ['id', 'token'])")

    def test_any_generator_false(self):
        ctx = {"fields": ["name", "email"]}
        ev = ExpressionEvaluator(ctx)
        assert not ev.evaluate("any(p in context.fields for p in ['id', 'token'])")

    def test_all_generator_true(self):
        ctx = {"labels": ["sql", "xss", "lfi"]}
        ev = ExpressionEvaluator(ctx)
        assert ev.evaluate("all(t in context.labels for t in ['sql', 'xss'])")

    def test_all_generator_false(self):
        ctx = {"labels": ["sql", "xss"]}
        ev = ExpressionEvaluator(ctx)
        assert not ev.evaluate("all(t in context.labels for t in ['sql', 'lfi'])")


# ──────────────────────────────────────────────────────────────────────────────
# List literals
# ──────────────────────────────────────────────────────────────────────────────


class TestListLiterals:

    def test_membership_in_literal_list(self):
        ctx = {"kind": "sql_injection"}
        assert ExpressionEvaluator(ctx).evaluate(
            "context.kind in ['sql_injection', 'xss', 'lfi']"
        )

    def test_membership_not_in_literal_list(self):
        ctx = {"kind": "rce"}
        assert ExpressionEvaluator(ctx).evaluate(
            "context.kind not in ['sql_injection', 'xss', 'lfi']"
        )


# ──────────────────────────────────────────────────────────────────────────────
# Subscript access
# ──────────────────────────────────────────────────────────────────────────────


class TestSubscriptAccess:

    def test_list_index(self):
        ctx = {"elements": ["first", "second"]}
        assert ExpressionEvaluator(ctx).evaluate("context.elements[0] == 'first'")

    def test_dict_subscript(self):
        ctx = {"data": {"key": "val"}}
        assert ExpressionEvaluator(ctx).evaluate("context.data['key'] == 'val'")


# ──────────────────────────────────────────────────────────────────────────────
# Error handling
# ──────────────────────────────────────────────────────────────────────────────


class TestExpressionErrors:

    def test_undefined_variable_raises_value_error(self):
        ev = ExpressionEvaluator({})
        with pytest.raises(ValueError, match="Expression evaluation failed"):
            ev.evaluate("undefined_var == 'x'")

    def test_undefined_context_attribute_returns_false(self):
        # context is a dict; context.something looks up 'something' key
        # which returns None, and None == 'x' is False — no raise.
        ev = ExpressionEvaluator({})
        result = ev.evaluate("context.something == 'x'")
        assert result is False

    def test_syntax_error_raises_value_error(self):
        ev = ExpressionEvaluator({})
        with pytest.raises((ValueError, SyntaxError)):
            ev.evaluate("context.x ==")  # malformed

    def test_unsupported_builtin_raises_value_error(self):
        ev = ExpressionEvaluator({"x": 1})
        with pytest.raises((ValueError, TypeError)):
            ev.evaluate("print(context.x)")

    def test_unsupported_operator_raises_value_error(self):
        ev = ExpressionEvaluator({"x": 2})
        with pytest.raises((ValueError, TypeError)):
            ev.evaluate("context.x ** 2 == 4")  # ** is Pow, unsupported


# ──────────────────────────────────────────────────────────────────────────────
# evaluate_condition convenience wrapper
# ──────────────────────────────────────────────────────────────────────────────


class TestEvaluateConditionWrapper:

    def test_simple_condition(self):
        ctx = {"x": 10}
        assert evaluate_condition("context.x == 10", ctx) is True

    def test_empty_expression(self):
        assert evaluate_condition("", {}) is True

    def test_false_condition(self):
        ctx = {"y": "hello"}
        assert evaluate_condition("context.y == 'world'", ctx) is False

    def test_complex_context(self):
        ctx = {"status": 200, "open": ["admin", "login"]}
        result = evaluate_condition(
            "context.status == 200 and 'admin' in context.open", ctx
        )
        assert result is True
