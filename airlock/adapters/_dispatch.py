from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any

from airlock.errors import AirlockError, Blocked, PendingApproval

if TYPE_CHECKING:
    from airlock.lock import Airlock


def make_dispatcher(lock: Airlock) -> Callable[..., Any]:
    """Route a model's tool call through Airlock.

    Refusals come back as a payload rather than an exception, because an agent loop needs
    a tool result to feed the model: a blocked call should teach it what the limit was,
    not crash the loop. Pass ``raise_on_refusal=True`` to get the exceptions instead.
    """

    def dispatch(
        name: str,
        arguments: Mapping[str, Any] | str | None = None,
        *,
        intent: str | None = None,
        tool_call_id: str | None = None,
        context: Mapping[str, Any] | None = None,
        raise_on_refusal: bool = False,
    ) -> Any:
        try:
            args = _as_mapping(arguments)
            tool = lock.get(name)
        except (AirlockError, ValueError) as exc:
            if raise_on_refusal:
                raise
            return {"airlock": "blocked", "layer": "tool", "reason": str(exc)}

        try:
            return tool(**args, _intent=intent or tool_call_id or "", _context=dict(context or {}))
        except Blocked as exc:
            if raise_on_refusal:
                raise
            return {"airlock": "blocked", "layer": exc.layer, "reason": exc.reason}
        except PendingApproval as exc:
            if raise_on_refusal:
                raise
            return {
                "airlock": "pending_approval",
                "request_id": exc.request_id,
                "reason": exc.reason,
            }

    return dispatch


def _as_mapping(arguments: Mapping[str, Any] | str | None) -> dict[str, Any]:
    if arguments is None:
        return {}
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments or "{}")
        except json.JSONDecodeError as exc:
            raise ValueError(f"tool arguments are not valid JSON: {exc}") from exc
    if not isinstance(arguments, Mapping):
        raise ValueError(f"tool arguments must be an object, got {type(arguments).__name__}")
    return dict(arguments)
