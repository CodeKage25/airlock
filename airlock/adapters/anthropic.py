from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from airlock.adapters._dispatch import make_dispatcher

if TYPE_CHECKING:
    from airlock.lock import Airlock


def build(lock: Airlock) -> tuple[list[dict[str, Any]], Callable[..., Any]]:
    lock.check_policy()
    specs = [
        {
            "name": tool.name,
            "description": tool.description,
            "input_schema": tool.json_schema(),
        }
        for tool in lock.registry
    ]
    return specs, make_dispatcher(lock)
