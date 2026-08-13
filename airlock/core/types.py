from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any


class Verdict(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    ESCALATE = "escalate"


@dataclass(frozen=True, slots=True)
class Decision:
    """What a layer or risk hook concluded.

    ``reason`` is for a human and names the specific call, so it carries amounts and
    running totals. ``rule`` names the thing that fired and stays identical across every
    call it fires on, which is what lets a shadow report group a thousand breaches of one
    limit into one line instead of a thousand.
    """

    verdict: Verdict
    reason: str = ""
    rule: str = ""

    @classmethod
    def allow(cls, reason: str = "") -> Decision:
        return cls(Verdict.ALLOW, reason)

    @classmethod
    def block(cls, reason: str, rule: str = "") -> Decision:
        return cls(Verdict.BLOCK, reason, rule)

    @classmethod
    def escalate(cls, reason: str, rule: str = "") -> Decision:
        return cls(Verdict.ESCALATE, reason, rule)

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.ALLOW


@dataclass(frozen=True, slots=True)
class Call:
    """A proposed action, as every layer sees it."""

    tool: str
    args: Mapping[str, Any]
    context: Mapping[str, Any] = field(default_factory=dict)
    intent: str = ""
    scope: str | None = None
    principal: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "args", MappingProxyType(dict(self.args)))
        object.__setattr__(self, "context", MappingProxyType(dict(self.context)))


class Outcome(StrEnum):
    PROPOSED = "proposed"
    EXECUTED = "executed"
    BLOCKED = "blocked"
    ESCALATED = "escalated"
    DEDUPLICATED = "deduplicated"
    APPROVED = "approved"
    REJECTED = "rejected"
    FAILED = "failed"
    EXPIRED = "expired"
    RESOLVED = "resolved"
    WOULD_BLOCK = "would_block"
    WOULD_ESCALATE = "would_escalate"


@dataclass(frozen=True, slots=True)
class AuditEntry:
    id: str
    at: datetime
    tool: str
    intent: str
    key: str
    outcome: Outcome
    layer: str | None = None
    reason: str | None = None
    scope: str | None = None
    args: Mapping[str, Any] = field(default_factory=dict)
    result_ref: str | None = None
    actor: str | None = None
    principal: str | None = None
    prev_hash: str | None = None
    entry_hash: str | None = None


class ReservationState(StrEnum):
    PENDING = "pending"
    DONE = "done"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class Reservation:
    """The idempotency record for one key. PENDING -> DONE | FAILED, never back."""

    key: str
    tool: str
    intent: str
    state: ReservationState
    created_at: datetime
    result_json: str | None = None
    replayable: bool = False
    reason: str | None = None
    heartbeat_at: datetime | None = None


class RequestStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    id: str
    tool: str
    intent: str
    key: str
    reason: str
    created_at: datetime
    args: Mapping[str, Any] = field(default_factory=dict)
    context: Mapping[str, Any] = field(default_factory=dict)
    scope: str | None = None
    principal: str | None = None
    status: RequestStatus = RequestStatus.PENDING
    expires_at: datetime | None = None
    decided_at: datetime | None = None
    decided_by: str | None = None
    decision_reason: str | None = None
