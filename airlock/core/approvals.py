from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from airlock.core.audit import AuditLog
from airlock.core.stores.base import Store
from airlock.core.types import (
    ApprovalRecord,
    Call,
    Decision,
    Outcome,
    RequestStatus,
)
from airlock.errors import AirlockError

LAYER = "approvals"

Predicate = Callable[[Call], bool]
Runner = Callable[[ApprovalRecord, str], Any]


@dataclass(frozen=True)
class ApprovalRule:
    """Route matching calls to a human instead of executing them."""

    tool: str
    predicate: Predicate
    reason: str | None = None
    ttl: timedelta | None = None

    def describe(self) -> str:
        if self.reason:
            return self.reason
        name = getattr(self.predicate, "__name__", "")
        return (
            f"{self.tool} matched approval rule {name}"
            if name and name != "<lambda>"
            else f"{self.tool} requires approval"
        )


def when(
    tool: str,
    predicate: Predicate,
    reason: str | None = None,
    ttl: timedelta | None = None,
) -> ApprovalRule:
    return ApprovalRule(tool=tool, predicate=predicate, reason=reason, ttl=ttl)


def evaluate(call: Call, rules: Sequence[ApprovalRule]) -> tuple[Decision, timedelta | None]:
    """Layer 5. First matching rule escalates; a rule that raises blocks."""
    for rule in rules:
        try:
            matched = bool(rule.predicate(call))
        except Exception as exc:
            return (
                Decision.block(
                    f"approval rule for {rule.tool!r} raised: {exc}",
                    rule=f"raised:{rule.tool}",
                ),
                None,
            )
        if matched:
            return Decision.escalate(rule.describe(), rule=rule.describe()), rule.ttl
    return Decision.allow(), None


class ApprovalRequest:
    """A parked call waiting on a human."""

    def __init__(self, record: ApprovalRecord, approvals: Approvals) -> None:
        self._record = record
        self._approvals = approvals

    @property
    def id(self) -> str:
        return self._record.id

    @property
    def tool(self) -> str:
        return self._record.tool

    @property
    def args(self) -> Mapping[str, Any]:
        return self._record.args

    @property
    def context(self) -> Mapping[str, Any]:
        return self._record.context

    @property
    def intent(self) -> str:
        return self._record.intent

    @property
    def scope(self) -> str | None:
        return self._record.scope

    @property
    def reason(self) -> str:
        return self._record.reason

    @property
    def status(self) -> RequestStatus:
        return self._record.status

    @property
    def created_at(self) -> datetime:
        return self._record.created_at

    @property
    def expires_at(self) -> datetime | None:
        return self._record.expires_at

    def approve(self, by: str) -> Any:
        """Re-run the pipeline and execute if still allowed."""
        return self._approvals.approve(self.id, by=by)

    def reject(self, reason: str) -> None:
        self._approvals.reject(self.id, reason=reason)

    def __repr__(self) -> str:
        return f"<ApprovalRequest {self.id} {self.tool} {self._record.status.value}>"


class Approvals:
    """The pending queue and the things a human can do to it."""

    def __init__(
        self,
        store: Store,
        clock: Callable[[], datetime],
        runner: Runner,
        audit: AuditLog,
        default_ttl: timedelta | None = None,
    ) -> None:
        self._store = store
        self._clock = clock
        self._runner = runner
        self._audit = audit
        self._default_ttl = default_ttl

    def open(
        self, call: Call, key: str, reason: str, ttl: timedelta | None = None
    ) -> ApprovalRecord:
        """Park a call. Reuses the request already open for this key, if any."""
        self.expire()
        existing = self._store.find_pending_by_key(key)
        if existing is not None:
            return existing

        now = self._clock()
        deadline = ttl if ttl is not None else self._default_ttl
        record = ApprovalRecord(
            id=uuid.uuid4().hex[:12],
            tool=call.tool,
            intent=call.intent,
            key=key,
            reason=reason,
            created_at=now,
            args=dict(call.args),
            context=dict(call.context),
            scope=call.scope,
            expires_at=now + deadline if deadline is not None else None,
        )
        self._store.create_request(record)
        return record

    def expire(self) -> list[ApprovalRecord]:
        """Retire requests past their deadline. A queue that never expires rots."""
        expired = self._store.expire_requests(self._clock())
        for record in expired:
            self._audit.record(
                tool=record.tool,
                intent=record.intent,
                key=record.key,
                outcome=Outcome.EXPIRED,
                layer=LAYER,
                reason=f"approval request {record.id} expired before anyone decided",
                scope=record.scope,
                args=record.args,
                result_ref=record.id,
            )
        return expired

    def pending(self) -> list[ApprovalRequest]:
        self.expire()
        return [
            ApprovalRequest(record, self)
            for record in self._store.list_requests(RequestStatus.PENDING)
        ]

    def get(self, request_id: str) -> ApprovalRequest | None:
        record = self._store.get_request(request_id)
        return ApprovalRequest(record, self) if record is not None else None

    def approve(self, request_id: str, by: str) -> Any:
        record = self._decide(request_id, RequestStatus.APPROVED, by=by, reason=None)
        return self._runner(record, by)

    def reject(self, request_id: str, reason: str) -> None:
        self._decide(request_id, RequestStatus.REJECTED, by=None, reason=reason)

    def _decide(
        self, request_id: str, status: RequestStatus, by: str | None, reason: str | None
    ) -> ApprovalRecord:
        self.expire()
        record = self._store.decide_request(
            request_id, status, by=by, reason=reason, at=self._clock()
        )
        if record is None:
            existing = self._store.get_request(request_id)
            if existing is None:
                raise AirlockError(f"no approval request {request_id!r}")
            raise AirlockError(
                f"approval request {request_id!r} is already {existing.status.value}"
            )
        return record
