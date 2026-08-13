from __future__ import annotations

import inspect
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from airlock.core.canonical import to_decimal
from airlock.core.stores.base import SpendCheck, SpendViolation
from airlock.core.types import Call, Decision
from airlock.errors import PolicyError

if TYPE_CHECKING:
    from airlock.core.approvals import ApprovalRule
    from airlock.core.risk import RiskHook

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
    max_calls_per_window: int | None = None
    call_window: timedelta | None = None

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
        if (self.max_calls_per_window is None) != (self.call_window is None):
            raise ValueError("max_calls_per_window and call_window must be set together")
        for span in (self.window, self.call_window):
            if span is not None and span <= timedelta(0):
                raise ValueError("a window must be positive")
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

    @classmethod
    def from_file(cls, path: str | Path) -> Policy:
        """Load a policy from YAML, so limits can be reviewed by whoever owns them."""
        from airlock.core.policyfile import load

        return cls.from_dict(load(path))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Policy:
        from airlock.core.approvals import when
        from airlock.core.policyfile import Expression, parse_duration

        version = data.get("version", 1)
        if version != 1:
            raise PolicyError(f"policy version {version!r} is not supported; this is version 1")

        caps = {name: Caps(**spec) for name, spec in (data.get("caps") or {}).items()}

        approvals = []
        for index, rule in enumerate(data.get("approvals") or []):
            missing = {"tool", "when"} - set(rule)
            if missing:
                raise PolicyError(f"approval rule {index} is missing {', '.join(sorted(missing))}")
            approvals.append(
                when(
                    rule["tool"],
                    Expression(rule["when"]),
                    rule.get("reason"),
                    ttl=parse_duration(rule.get("ttl")),
                )
            )

        return cls(caps=caps, approvals=approvals)

    def caps_for(self, tool: str) -> Caps | None:
        return self.caps.get(tool)

    def rules_for(self, tool: str) -> list[ApprovalRule]:
        return [rule for rule in self.approvals if rule.tool == tool]


PRINCIPAL = "principal"


def resolve_scope(call: Call, scope_by: str | None) -> str | None:
    """Partition key for this call, or None when the tool is unscoped.

    ``scope_by="principal"`` partitions by who is acting, which is how a support bot and
    a treasury bot stop sharing one budget.
    """
    if scope_by is None:
        return None
    if scope_by == PRINCIPAL:
        if not call.principal:
            raise PolicyError("caps are partitioned by principal but this call has no _principal")
        return call.principal
    if scope_by not in call.context:
        raise PolicyError(f"scope key {scope_by!r} missing from context")
    return str(call.context[scope_by])


def meter(call: Call, caps: Caps) -> Decimal:
    """What this call spends against its caps."""
    if caps.amount_field not in call.args:
        return Decimal(1)
    return to_decimal(call.args[caps.amount_field])


def spend_checks(caps: Caps, now: datetime) -> list[SpendCheck]:
    checks = [SpendCheck(name, now - span, limit) for name, span, limit in caps.windows()]
    if caps.max_calls_per_window is not None and caps.call_window is not None:
        checks.append(
            SpendCheck(
                "max_calls_per_window",
                now - caps.call_window,
                Decimal(caps.max_calls_per_window),
                counts=True,
            )
        )
    return checks


def violation_reason(tool: str, scope: str | None, violation: SpendViolation) -> str:
    where = f" in scope {scope!r}" if scope else ""
    if violation.name == "max_calls_per_window":
        return (
            f"this would be call {violation.total} to {tool}{where}, "
            f"over the rate limit of {violation.limit}"
        )
    return (
        f"this would take {tool}{where} to {violation.total}, "
        f"over the {violation.name} of {violation.limit}"
    )


def check(call: Call, caps: Caps) -> Decision:
    """Layer 2: the rules that depend only on this one call.

    Window limits are deliberately *not* checked here. They are enforced inside the same
    store transaction that writes the spend, because a read here and a write there can be
    raced by a second caller. Checking them in both places would also make every call pay
    for a redundant query, and would report each breach twice under shadow mode.
    """
    if caps.currency is not None:
        currency = call.args.get("currency")
        if currency is not None and str(currency) != caps.currency:
            return Decision.block(
                f"currency {currency!r} is outside the {caps.currency} cap for {call.tool}",
                rule="currency",
            )

    try:
        amount = meter(call, caps)
    except ValueError as exc:
        return Decision.block(f"uncappable amount: {exc}", rule="uncappable_amount")
    if amount < 0:
        return Decision.block(f"negative amount {amount} is not spendable", rule="negative_amount")

    if caps.max_per_call is not None and amount > caps.max_per_call:
        return Decision.block(
            f"{amount} exceeds max_per_call of {caps.max_per_call} for {call.tool}",
            rule=f"max_per_call:{caps.max_per_call}",
        )

    return Decision.allow()
