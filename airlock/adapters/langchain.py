"""LangChain and LangGraph tools.

    pip install 'agent-airlock[langchain]'

    from airlock.adapters.langchain import as_langchain_tools

    agent = create_react_agent(model, as_langchain_tools(lock))

LangChain has no place to put an intent, so the run id from the callback config is used:
it is stable across a retry of the same step and distinct across genuinely new ones, which
is exactly the property an intent needs. Pass ``intent_from`` to use something of your own.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from airlock.adapters.mcp import refusal
from airlock.errors import AirlockError, PolicyError

if TYPE_CHECKING:
    from airlock.lock import Airlock

try:
    from langchain_core.tools import StructuredTool
except ImportError:  # pragma: no cover - exercised by the error path below
    StructuredTool = None  # type: ignore[assignment,misc]


def as_langchain_tools(
    lock: Airlock,
    intent_from: Callable[[dict[str, Any]], str] | None = None,
) -> list[Any]:
    if StructuredTool is None:
        raise PolicyError(
            "the langchain adapter needs langchain-core: pip install 'agent-airlock[langchain]'"
        )

    lock.check_policy()
    return [_wrap(lock, tool, intent_from) for tool in lock.registry]


def _wrap(lock: Airlock, tool: Any, intent_from: Callable[[dict[str, Any]], str] | None) -> Any:
    guarded = lock.get(tool.name)

    def call(config: dict[str, Any] | None = None, **arguments: Any) -> str:
        intent = (
            intent_from(config or {})
            if intent_from is not None
            else str((config or {}).get("run_id") or (config or {}).get("run_name") or "")
        )
        try:
            result = guarded(**arguments, _intent=intent)
        except AirlockError as exc:
            # Returned, not raised: a refusal the model can read teaches it the limit.
            return json.dumps(refusal(exc))
        return json.dumps({"airlock": "executed", "result": result}, default=str)

    return StructuredTool.from_function(
        func=call,
        name=tool.name,
        description=tool.description,
        args_schema=tool.model,
        infer_schema=False,
    )
