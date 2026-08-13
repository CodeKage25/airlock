from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import replace

from airlock.core.types import Call, Decision

RiskHook = Callable[[Call], Decision]

LAYER = "risk"


def name_of(hook: RiskHook) -> str:
    return getattr(hook, "__name__", type(hook).__name__)


def evaluate(call: Call, hooks: Sequence[RiskHook]) -> Decision:
    """Layer 4. Hooks run in order, first non-allow wins, a raise is a block."""
    for hook in hooks:
        try:
            decision = hook(call)
        except Exception as exc:
            return Decision.block(
                f"risk hook {name_of(hook)!r} raised: {exc}", rule=f"raised:{name_of(hook)}"
            )
        if not isinstance(decision, Decision):
            return Decision.block(
                f"risk hook {name_of(hook)!r} returned {type(decision).__name__}, not a Decision",
                rule=f"invalid:{name_of(hook)}",
            )
        if not decision.allowed:
            # A hook that names no rule is still one identifiable source of verdicts.
            return decision if decision.rule else replace(decision, rule=name_of(hook))
    return Decision.allow()
