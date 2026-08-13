from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError, create_model

from airlock.errors import PolicyError

LAYER = "tool"

RESERVED = ("_intent", "_context")


@dataclass(frozen=True)
class Tool:
    """A registered function, the only thing an agent is allowed to call."""

    name: str
    fn: Callable[..., Any]
    signature: inspect.Signature
    model: type[BaseModel]
    description: str = ""
    scope_by: str | None = None
    key_fields: tuple[str, ...] = ()

    def bind(self, args: tuple[Any, ...], kwargs: Mapping[str, Any]) -> dict[str, Any]:
        """Positional and keyword arguments as one fully defaulted mapping."""
        try:
            bound = self.signature.bind(*args, **kwargs)
        except TypeError as exc:
            raise ValueError(str(exc)) from exc
        bound.apply_defaults()
        return dict(bound.arguments)

    def validate(self, args: Mapping[str, Any]) -> dict[str, Any]:
        """Layer 1. Unknown or ill-typed arguments never reach the function."""
        try:
            return self.model(**dict(args)).model_dump()
        except ValidationError as exc:
            raise ValueError(_summarise(exc)) from exc

    def json_schema(self) -> dict[str, Any]:
        schema = self.model.model_json_schema()
        schema.pop("title", None)
        for prop in schema.get("properties", {}).values():
            prop.pop("title", None)
        return schema


@dataclass
class Registry:
    tools: dict[str, Tool] = field(default_factory=dict)

    def add(self, tool: Tool) -> None:
        if tool.name in self.tools:
            raise PolicyError(f"tool {tool.name!r} is already registered")
        self.tools[tool.name] = tool

    def get(self, name: str) -> Tool:
        try:
            return self.tools[name]
        except KeyError:
            raise PolicyError(f"tool {name!r} is not registered") from None

    def __iter__(self) -> Any:
        return iter(self.tools.values())

    def __len__(self) -> int:
        return len(self.tools)


def build(
    fn: Callable[..., Any],
    *,
    name: str | None = None,
    scope_by: str | None = None,
    key_fields: tuple[str, ...] = (),
) -> Tool:
    signature = inspect.signature(fn)
    tool_name = name or fn.__name__

    for parameter in signature.parameters.values():
        if parameter.kind in (parameter.VAR_POSITIONAL, parameter.VAR_KEYWORD):
            raise PolicyError(
                f"tool {tool_name!r} takes *{parameter.name}; an unbounded argument "
                "surface cannot be typed or capped"
            )
        if parameter.name in RESERVED:
            raise PolicyError(f"{parameter.name!r} is reserved by Airlock")

    return Tool(
        name=tool_name,
        fn=fn,
        signature=signature,
        model=_model_for(fn, tool_name, signature),
        description=inspect.getdoc(fn) or "",
        scope_by=scope_by,
        key_fields=tuple(key_fields),
    )


def _model_for(fn: Callable[..., Any], name: str, signature: inspect.Signature) -> type[BaseModel]:
    try:
        hints = inspect.get_annotations(fn, eval_str=True)
    except (NameError, TypeError) as exc:
        raise PolicyError(f"cannot resolve type hints for tool {name!r}: {exc}") from exc

    fields: dict[str, Any] = {}
    for parameter in signature.parameters.values():
        annotation = hints.get(parameter.name, Any)
        default = ... if parameter.default is inspect.Parameter.empty else parameter.default
        fields[parameter.name] = (annotation, default)

    return create_model(
        f"{name}_args",
        __config__=ConfigDict(extra="forbid", arbitrary_types_allowed=True),
        **fields,
    )


def _summarise(exc: ValidationError) -> str:
    parts = [
        f"{'.'.join(str(p) for p in error['loc']) or '<args>'}: {error['msg']}"
        for error in exc.errors()
    ]
    return "; ".join(parts)
