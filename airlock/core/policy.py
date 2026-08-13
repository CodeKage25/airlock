from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from airlock.core.canonical import to_decimal
from airlock.core.stores.base import SpendCheck, SpendViolation
from airlock.core.types import Call, Decision
from airlock.errors import PolicyError

if TYPE_CHECKING:
    from airlock.core.approvals import ApprovalRule
    from airlock.core.risk import RiskHook
    from airlock.core.stores.base import Store

LAYER = "caps"


class Caps(BaseModel):
    """Hard limits for one tool. Enforced in code, outside the model.

    Limits meter the argument named by ``amount_field`` when the tool has one, and
    otherwise count calls, so ``max_per_day=10`` on a tool with no amount means ten
    calls a day.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_per_call: Decimal | None = None
    max_per_day: Decimal | None = None
    max_per_window: Decimal | None = None
    window: timedelta | None = None
    currency: str | None = None
    scope_by: str | None = None
    amount_field: str = "amount"

    @field_validator("max_per_call", "max_per_day", "max_per_window", mode="before")
    @classmethod
    def _as_decimal(cls, value: Any) -> Any:
        return None if value is None else to_decimal(value)

    @field_validator("max_per_call", "max_per_day", "max_per_window")
    @classmethod
    def _non_negative(cls, value: Decimal | None) -> Decimal | None:
        if value is not None and value < 0:
            raise ValueError("caps cannot be negative")
        return value

    @model_validator(mode="after")
    def _window_pairs(self) -> Caps:
        if (self.max_per_window is None) != (self.window is None):
            raise ValueError("max_per_window and window must be set together")
        if self.window is not None and self.window <= timedelta(0):
            raise ValueError("window must be positive")
        return self

    def windows(self) -> list[tuple[str, timedelta, Decimal]]:
        rules: list[tuple[str, timedelta, Decimal]] = []
        if self.max_per_day is not None:
            rules.append(("max_per_day", timedelta(days=1), self.max_per_day))
        if self.max_per_window is not None and self.window is not None:
            rules.append(("max_per_window", self.window, self.max_per_window))
        return rules


@dataclass
class Policy:
    """The whole enforcement configuration. Plain data the model never sees."""

    caps: dict[str, Caps] = field(default_factory=dict)
    approvals: list[ApprovalRule] = field(default_factory=list)
    risk_hooks: list[RiskHook] = field(default_factory=list)

    def __post_init__(self) -> None:
        for hook in self.risk_hooks:
            if inspect.iscoroutinefunction(hook):
                raise PolicyError(
                    f"risk hook {getattr(hook, '__name__', hook)!r} is async; "
                    "v0.1 runs sync hooks only"
                )

    def caps_for(self, tool: str) -> Caps | None:
        return self.caps.get(tool)

    def rules_for(self, tool: str) -> list[ApprovalRule]:
        return [rule for rule in self.approvals if rule.tool == tool]


def resolve_scope(call: Call, scope_by: str | None) -> str | None:
    """Partition key for this call, or None when the tool is unscoped."""
    if scope_by is None:
        return None
    if scope_by not in call.context:
        raise PolicyError(f"scope key {scope_by!r} missing from context")
    return str(call.context[scope_by])


def meter(call: Call, caps: Caps) -> Decimal:
    """What this call spends against its caps."""
    if caps.amount_field not in call.args:
        return Decimal(1)
    return to_decimal(call.args[caps.amount_field])


def spend_checks(caps: Caps, now: datetime) -> list[SpendCheck]:
    return [SpendCheck(name, now - span, limit) for name, span, limit in caps.windows()]


def violation_reason(tool: str, scope: str | None, violation: SpendViolation) -> str:
    where = f" in scope {scope!r}" if scope else ""
    return (
        f"this would take {tool}{where} to {violation.total}, "
        f"over the {violation.name} of {violation.limit}"
    )


def check(call: Call, caps: Caps, store: Store, now: datetime, key: str) -> Decision:
    """Layer 2. Window totals exclude ``key`` so a retry is never charged twice.

    This is the advisory read that produces a good audit reason. The binding check
    happens inside the store transaction that writes the spend, so two concurrent
    calls cannot both pass an under-limit read.
    """
    if caps.currency is not None:
        currency = call.args.get("currency")
        if currency is not None and str(currency) != caps.currency:
            return Decision.block(
                f"currency {currency!r} is outside the {caps.currency} cap for {call.tool}"
            )

    try:
        amount = meter(call, caps)
    except ValueError as exc:
        return Decision.block(f"uncappable amount: {exc}")
    if amount < 0:
        return Decision.block(f"negative amount {amount} is not spendable")

    if caps.max_per_call is not None and amount > caps.max_per_call:
        return Decision.block(
            f"{amount} exceeds max_per_call of {caps.max_per_call} for {call.tool}"
        )

    for name, span, limit in caps.windows():
        spent = store.spend_since(call.tool, call.scope, now - span, exclude_key=key)
        if spent + amount > limit:
            where = f" in scope {call.scope!r}" if call.scope else ""
            return Decision.block(
                f"{amount} would take {call.tool}{where} to {spent + amount}, "
                f"over the {name} of {limit}"
            )

    return Decision.allow()
