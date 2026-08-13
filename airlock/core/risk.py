from __future__ import annotations

from collections.abc import Callable, Sequence

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
            return Decision.block(f"risk hook {name_of(hook)!r} raised: {exc}")
        if not isinstance(decision, Decision):
            return Decision.block(
                f"risk hook {name_of(hook)!r} returned {type(decision).__name__}, not a Decision"
            )
        if not decision.allowed:
            return decision
    return Decision.allow()
