"""Policy as data.

    lock = Airlock(policy=Policy.from_file("policy.yaml"), store=...)

```yaml
version: 1
caps:
  send_payment:
    max_per_call: 100
    max_per_day: 1000
    currency: USD
    scope_by: principal
approvals:
  - tool: send_payment
    when: amount > 100
    reason: large payments need a human
    ttl: 4h
  - tool: send_payment
    when: context.new_beneficiary
    reason: first payment to a new beneficiary
```

Written for the people who own the limits rather than the people who own the code: a limit
in a Python file can only be changed by a deploy and reviewed by an engineer, which is the
wrong shape for something risk and compliance are accountable for.

Predicates are a deliberately small expression language, not `eval`. The whole point of
Airlock is that the policy is the one thing a hostile input cannot reach, so a policy
format that could execute arbitrary code would give away the property being protected.
"""

from __future__ import annotations

import ast
import operator
from collections.abc import Callable, Mapping
from datetime import timedelta
from pathlib import Path
from typing import Any

from airlock.core.types import Call
from airlock.errors import PolicyError

# Everything the expression language can do. Nothing here can call, import, or mutate.
_BINARY: dict[type[ast.operator], Callable[[Any, Any], Any]] = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
}
_COMPARE: dict[type[ast.cmpop], Callable[[Any, Any], Any]] = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
}
_UNARY: dict[type[ast.unaryop], Callable[[Any], Any]] = {
    ast.Not: operator.not_,
    ast.USub: operator.neg,
}
_FUNCTIONS: dict[str, Callable[..., Any]] = {
    "len": len,
    "abs": abs,
    "lower": lambda value: str(value).lower(),
    "startswith": lambda value, prefix: str(value).startswith(prefix),
    "endswith": lambda value, prefix: str(value).endswith(prefix),
    "matches": lambda value, pattern: __import__("re").fullmatch(pattern, str(value)) is not None,
}

DURATIONS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


def parse_duration(value: str | int | float | None) -> timedelta | None:
    """``4h``, ``30m``, ``7d``, or a number of seconds."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return timedelta(seconds=float(value))
    text = str(value).strip()
    unit = DURATIONS.get(text[-1:])
    if unit is None:
        raise PolicyError(f"cannot read duration {value!r}; use 30s, 15m, 4h, 7d or 2w")
    try:
        return timedelta(**{unit: float(text[:-1])})
    except ValueError as exc:
        raise PolicyError(
            f"cannot read duration {value!r}; use 30s, 15m, 4h, 7d or 2w ({exc})"
        ) from exc


class Expression:
    """One predicate, compiled once and evaluated against a :class:`Call`."""

    def __init__(self, source: str) -> None:
        self.source = source
        try:
            self._tree = ast.parse(source, mode="eval").body
        except SyntaxError as exc:
            raise PolicyError(f"cannot read condition {source!r}: {exc}") from exc
        self._check(self._tree)

    def __call__(self, call: Call) -> bool:
        return bool(self._eval(self._tree, self._namespace(call)))

    def __repr__(self) -> str:
        return f"<Expression {self.source!r}>"

    @staticmethod
    def _namespace(call: Call) -> dict[str, Any]:
        return {
            **dict(call.args),
            "args": _Attr(call.args),
            "context": _Attr(call.context),
            "tool": call.tool,
            "intent": call.intent,
            "scope": call.scope,
            "principal": call.principal,
        }

    def _check(self, node: ast.AST) -> None:
        allowed = (
            ast.Expression,
            ast.BoolOp,
            ast.BinOp,
            ast.UnaryOp,
            ast.Compare,
            ast.Call,
            ast.Name,
            ast.Load,
            ast.Constant,
            ast.Attribute,
            ast.Subscript,
            ast.List,
            ast.Tuple,
            ast.Set,
            ast.And,
            ast.Or,
            ast.IfExp,
            *_BINARY,
            *_COMPARE,
            *_UNARY,
        )
        for child in ast.walk(node):
            if not isinstance(child, allowed):
                raise PolicyError(
                    f"{type(child).__name__} is not allowed in a policy condition; "
                    "conditions are comparisons and boolean logic, nothing else"
                )
            if isinstance(child, ast.Attribute) and child.attr.startswith("_"):
                # context.field is the point of attribute access; __class__ is the
                # first step of every Python sandbox escape ever written.
                raise PolicyError(
                    f"a policy condition may not read {child.attr!r}; "
                    "attribute access is for context fields, not Python internals"
                )
            if isinstance(child, ast.Call) and not isinstance(child.func, ast.Name):
                raise PolicyError("only the built-in policy functions may be called")
            if isinstance(child, ast.Call) and child.func.id not in _FUNCTIONS:  # type: ignore[attr-defined]
                raise PolicyError(
                    f"{child.func.id!r} is not a policy function; "  # type: ignore[attr-defined]
                    f"available: {', '.join(sorted(_FUNCTIONS))}"
                )

    def _eval(self, node: ast.AST, names: Mapping[str, Any]) -> Any:
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            return names.get(node.id)
        if isinstance(node, ast.Attribute):
            return getattr(self._eval(node.value, names), node.attr, None)
        if isinstance(node, ast.Subscript):
            container = self._eval(node.value, names)
            try:
                return container[self._eval(node.slice, names)]
            except (KeyError, IndexError, TypeError):
                return None
        if isinstance(node, ast.UnaryOp):
            return _UNARY[type(node.op)](self._eval(node.operand, names))
        if isinstance(node, ast.BinOp):
            return _BINARY[type(node.op)](
                self._eval(node.left, names), self._eval(node.right, names)
            )
        if isinstance(node, ast.BoolOp):
            values = (self._eval(v, names) for v in node.values)
            return any(values) if isinstance(node.op, ast.Or) else all(values)
        if isinstance(node, ast.IfExp):
            branch = node.body if self._eval(node.test, names) else node.orelse
            return self._eval(branch, names)
        if isinstance(node, ast.Compare):
            left = self._eval(node.left, names)
            for op, comparator in zip(node.ops, node.comparators, strict=True):
                right = self._eval(comparator, names)
                # A missing field is not a match, rather than a crash mid-decision.
                if (left is None or right is None) and type(op) not in (
                    ast.Eq,
                    ast.NotEq,
                    ast.In,
                    ast.NotIn,
                ):
                    return False
                if not _COMPARE[type(op)](left, right):
                    return False
                left = right
            return True
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return [self._eval(item, names) for item in node.elts]
        if isinstance(node, ast.Call):
            function = _FUNCTIONS[node.func.id]  # type: ignore[attr-defined]
            return function(*(self._eval(arg, names) for arg in node.args))
        raise PolicyError(f"cannot evaluate {type(node).__name__} in a policy condition")


class _Attr:
    """Lets a condition say ``context.new_beneficiary`` as well as ``context['x']``."""

    def __init__(self, data: Mapping[str, Any]) -> None:
        self._data = data

    def __getattr__(self, name: str) -> Any:
        return self._data.get(name)

    def __getitem__(self, name: str) -> Any:
        return self._data.get(name)

    def __contains__(self, name: str) -> bool:
        return name in self._data


def load(path: str | Path) -> dict[str, Any]:
    text = Path(path).read_text()
    try:
        import yaml
    except ImportError as exc:
        raise PolicyError(
            "reading a policy file needs pyyaml: pip install 'agent-airlock[yaml]'"
        ) from exc
    data = yaml.safe_load(text)
    if not isinstance(data, Mapping):
        raise PolicyError(f"{path} does not contain a policy mapping")
    return dict(data)
