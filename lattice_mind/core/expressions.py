"""Safe expression evaluator for the decision tree mini-language."""
import ast
import operator
import re
from typing import Any, Dict, Optional


class ExpressionEvaluator:
    """
    Evaluates mini-language expressions safely without using eval().
    Supports:
    - Basic operators: ==, !=, >, <, >=, <=, and, or, not, in, not in
    - Context variables via dot-notation (e.g., context.challenge.type)
    - Basic functions: len(), any(), all()
    """

    @staticmethod
    def _safe_in(a: Any, b: Any) -> bool:
        if b is None:
            return False
        try:
            return a in b
        except TypeError:
            return False

    OPERATORS = {
        ast.Eq: operator.eq,
        ast.NotEq: operator.ne,
        ast.Gt: operator.gt,
        ast.GtE: operator.ge,
        ast.Lt: operator.lt,
        ast.LtE: operator.le,
        ast.In: lambda a, b: ExpressionEvaluator._safe_in(a, b),
        ast.NotIn: lambda a, b: not ExpressionEvaluator._safe_in(a, b),
        ast.And: all,
        ast.Or: any,
        ast.Not: operator.not_,
    }

    def __init__(self, context: Dict[str, Any]):
        self.context = {"context": context}
        self.context.update(
            {"true": True, "false": False, "null": None, "None": None, "re": re}
        )

    def evaluate(self, expression: str) -> bool:
        """Parse and evaluate a boolean expression."""
        if not expression:
            return True
        try:
            tree = ast.parse(expression, mode='eval')
            return bool(self._eval_node(tree.body))
        except Exception as e:
            # In a real system, we'd log this more extensively
            raise ValueError(f"Expression evaluation failed: {expression}") from e

    def _eval_node(self, node: ast.AST) -> Any:
        if isinstance(node, ast.Constant):
            return node.value
        
        elif isinstance(node, ast.BoolOp):
            values = [self._eval_node(v) for v in node.values]
            if isinstance(node.op, ast.And):
                return all(values)
            elif isinstance(node.op, ast.Or):
                return any(values)
        
        elif isinstance(node, ast.UnaryOp):
            if isinstance(node.op, ast.Not):
                return not self._eval_node(node.operand)
        
        elif isinstance(node, ast.Compare):
            left = self._eval_node(node.left)
            for op, right_node in zip(node.ops, node.comparators):
                right = self._eval_node(right_node)
                # Normalize common YAML edge case: numeric value compared to quoted number.
                if isinstance(left, (int, float)) and isinstance(right, str):
                    try:
                        right = float(right) if "." in right else int(right)
                    except ValueError:
                        pass
                elif isinstance(right, (int, float)) and isinstance(left, str):
                    try:
                        left = float(left) if "." in left else int(left)
                    except ValueError:
                        pass
                op_func = self.OPERATORS.get(type(op))
                if not op_func:
                    raise TypeError(f"Unsupported operator: {type(op)}")
                if not op_func(left, right):
                    return False
                left = right
            return True
        
        elif isinstance(node, ast.Attribute):
            import enum as _enum
            value = self._eval_node(node.value)
            if hasattr(value, node.attr):
                result = getattr(value, node.attr)
                # Unwrap enums so YAML conditions like "context.challenge.type == 'web'" work.
                if isinstance(result, _enum.Enum):
                    return result.value
                return result
            elif isinstance(value, dict):
                return value.get(node.attr)
            raise AttributeError(f"Attribute {node.attr} not found")
        
        elif isinstance(node, ast.Name):
            if node.id in self.context:
                return self.context[node.id]
            raise NameError(f"Variable {node.id} not found in context")

        elif isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id

            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "re"
                and node.func.attr == "search"
            ):
                args = [self._eval_node(arg) for arg in node.args]
                if len(args) < 2:
                    raise TypeError("re.search requires pattern and text")
                pattern = str(args[0])
                text = str(args[1] if args[1] is not None else "")
                flags = 0
                if len(args) >= 3 and isinstance(args[2], int):
                    flags = int(args[2])
                return re.search(pattern, text, flags)

            elif isinstance(node.func, ast.Attribute):
                base = self._eval_node(node.func.value)
                meth = node.func.attr
                args = [self._eval_node(arg) for arg in node.args]
                if meth == "lower":
                    return str(base).lower()
                if meth == "upper":
                    return str(base).upper()
                if meth == "startswith":
                    return str(base).startswith(str(args[0]) if args else "")
                if meth == "endswith":
                    return str(base).endswith(str(args[0]) if args else "")
                if meth == "contains":
                    return (str(args[0]) if args else "") in str(base)
                raise TypeError(f"Unsupported method call: {meth}")
            
            if func_name in ("any", "all") and len(node.args) == 1 and isinstance(node.args[0], ast.GeneratorExp):
                gen = node.args[0]
                results = []
                # Simple implementation of generator expression
                # any(p in context.params for p in ['id','user'])
                if len(gen.generators) == 1:
                    comp = gen.generators[0]
                    iter_val = self._eval_node(comp.iter)
                    if iter_val is None:
                        iter_val = []
                    target_name = comp.target.id
                    for item in iter_val:
                        # Temporary add to context
                        self.context[target_name] = item
                        results.append(self._eval_node(gen.elt))
                        del self.context[target_name]
                
                return any(results) if func_name == "any" else all(results)

            args = [self._eval_node(arg) for arg in node.args]
            
            if func_name == "len":
                return len(args[0])
            elif func_name == "any":
                return any(args[0])
            elif func_name == "all":
                return all(args[0])
            
            raise TypeError(f"Unsupported function call: {func_name}")
        
        elif isinstance(node, ast.List):
            return [self._eval_node(elt) for elt in node.elts]

        elif isinstance(node, ast.Tuple):
            return tuple(self._eval_node(elt) for elt in node.elts)

        elif isinstance(node, ast.Set):
            return {self._eval_node(elt) for elt in node.elts}

        elif isinstance(node, ast.Dict):
            return {
                self._eval_node(k): self._eval_node(v)
                for k, v in zip(node.keys, node.values)
            }

        elif isinstance(node, ast.Subscript):
            value = self._eval_node(node.value)
            index = self._eval_node(node.slice)
            return value[index]

        raise TypeError(f"Unsupported AST node: {type(node)}")

def evaluate_condition(
    expression: str,
    context: Dict[str, Any],
    extra_roots: Optional[Dict[str, Any]] = None,
) -> bool:
    """Utility function for one-off evaluations.

    Names in ``context`` are available as ``context.<name>``. Optional ``extra_roots``
    are merged as top-level names (e.g. ``request``, ``response``) for YAML conditions.
    """
    evaluator = ExpressionEvaluator(context)
    if extra_roots:
        evaluator.context.update(extra_roots)
    return evaluator.evaluate(expression)
