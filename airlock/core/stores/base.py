from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any

from airlock.core.types import ApprovalRecord, AuditEntry, RequestStatus, Reservation


@dataclass(frozen=True, slots=True)
class SpendCheck:
    """One window limit, evaluated at the moment spend is written."""

    name: str
    since: datetime
    limit: Decimal


@dataclass(frozen=True, slots=True)
class SpendViolation:
    name: str
    limit: Decimal
    total: Decimal


@dataclass(frozen=True, slots=True)
class ReserveResult:
    """Outcome of the atomic check-and-set that guards execution.

    Exactly one of these is true: we own the key and may execute, a record already
    exists for it, or this intent is already bound to a different key.
    """

    owned: bool
    existing: Reservation | None = None
    conflict_key: str | None = None


class Store(ABC):
    """Durable state for idempotency, cap accounting, audit and approvals.

    Implementations must make :meth:`reserve` atomic against concurrent callers: for a
    given key exactly one caller may come away owning it.
    """

    url: str

    @abstractmethod
    def reserve(self, key: str, tool: str, intent: str, at: datetime) -> ReserveResult: ...

    @abstractmethod
    def complete(self, key: str, result_json: str | None, replayable: bool) -> None: ...

    @abstractmethod
    def fail(self, key: str, reason: str) -> None: ...

    @abstractmethod
    def get_reservation(self, key: str) -> Reservation | None: ...

    @abstractmethod
    def discard(self, key: str) -> None:
        """Drop a reservation and its spend, for a call that provably never executed.

        Used both when a binding cap check refuses at commit time and when an operator
        resolves a stuck intent as not executed. Either way the intent must be free to
        run again, and the budget must not stay consumed by something that never happened.
        """

    @abstractmethod
    def stuck_reservations(self, before: datetime, limit: int = 100) -> list[Reservation]:
        """Reservations no longer making progress: pending since before ``before``, or failed.

        Both mean an attempt whose real-world effect is unknown, which is exactly the
        state a human has to resolve.
        """

    @abstractmethod
    def resolve_reservation(
        self, key: str, result_json: str | None, reason: str
    ) -> Reservation | None:
        """Settle a stuck reservation as having executed. None if it was not stuck."""

    @abstractmethod
    def commit_spend(
        self,
        key: str,
        tool: str,
        scope: str | None,
        amount: Decimal,
        at: datetime,
        checks: Sequence[SpendCheck],
    ) -> SpendViolation | None:
        """Re-check every window and write the spend in one atomic step.

        Checking and writing separately lets two concurrent calls both read an
        under-limit total and both commit, so the limit has to be enforced here.
        """

    @abstractmethod
    def spend_since(
        self, tool: str, scope: str | None, since: datetime, exclude_key: str
    ) -> Decimal: ...

    @abstractmethod
    def append_audit(self, entry: AuditEntry) -> None: ...

    @abstractmethod
    def query_audit(
        self,
        *,
        tool: str | None = None,
        intent: str | None = None,
        outcome: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int | None = None,
    ) -> list[AuditEntry]: ...

    @abstractmethod
    def create_request(self, record: ApprovalRecord) -> None: ...

    @abstractmethod
    def get_request(self, request_id: str) -> ApprovalRecord | None: ...

    @abstractmethod
    def list_requests(self, status: RequestStatus | None = None) -> list[ApprovalRecord]: ...

    @abstractmethod
    def find_pending_by_key(self, key: str) -> ApprovalRecord | None:
        """The open request for this key, so a retrying agent cannot flood the queue."""

    @abstractmethod
    def expire_requests(self, now: datetime) -> list[ApprovalRecord]:
        """Move every pending request past its deadline to expired, and return them."""

    @abstractmethod
    def decide_request(
        self,
        request_id: str,
        status: RequestStatus,
        by: str | None,
        reason: str | None,
        at: datetime,
    ) -> ApprovalRecord | None:
        """Atomically move a pending request to a terminal status. None if it was not pending."""

    def close(self) -> None:
        return None


def _match(entry: AuditEntry, **filters: Any) -> bool:
    for name in ("tool", "intent"):
        wanted = filters.get(name)
        if wanted is not None and getattr(entry, name) != wanted:
            return False
    outcome = filters.get("outcome")
    if outcome is not None and entry.outcome.value != getattr(outcome, "value", outcome):
        return False
    since, until = filters.get("since"), filters.get("until")
    if since is not None and entry.at < since:
        return False
    return not (until is not None and entry.at > until)


def _limit(entries: Sequence[AuditEntry], limit: int | None) -> list[AuditEntry]:
    return list(entries[-limit:]) if limit else list(entries)


def _frozen(mapping: Mapping[str, Any]) -> dict[str, Any]:
    return dict(mapping)
