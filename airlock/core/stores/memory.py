from __future__ import annotations

import threading
from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime
from decimal import Decimal

from airlock.core.stores import migrations
from airlock.core.stores.base import (
    ReserveResult,
    SpendCheck,
    SpendViolation,
    Store,
    _limit,
    _match,
)
from airlock.core.types import (
    ApprovalRecord,
    AuditEntry,
    RequestStatus,
    Reservation,
    ReservationState,
)


class MemoryStore(Store):
    """In-process store. Tests only: nothing survives the process."""

    url = "memory://"

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._reservations: dict[str, Reservation] = {}
        self._intents: dict[tuple[str, str], str] = {}
        self._spend: dict[str, tuple[str, str | None, Decimal, datetime]] = {}
        self._audit: list[AuditEntry] = []
        self._requests: dict[str, ApprovalRecord] = {}

    def schema_version(self) -> int:
        return migrations.CURRENT

    def reserve(self, key: str, tool: str, intent: str, at: datetime) -> ReserveResult:
        with self._lock:
            bound = self._intents.setdefault((tool, intent), key)
            if bound != key:
                return ReserveResult(owned=False, conflict_key=bound)
            existing = self._reservations.get(key)
            if existing is not None:
                return ReserveResult(owned=False, existing=existing)
            self._reservations[key] = Reservation(
                key=key,
                tool=tool,
                intent=intent,
                state=ReservationState.PENDING,
                created_at=at,
            )
            return ReserveResult(owned=True)

    def complete(self, key: str, result_json: str | None, replayable: bool) -> None:
        with self._lock:
            current = self._reservations[key]
            self._reservations[key] = replace(
                current,
                state=ReservationState.DONE,
                result_json=result_json,
                replayable=replayable,
            )

    def fail(self, key: str, reason: str) -> None:
        with self._lock:
            current = self._reservations[key]
            self._reservations[key] = replace(current, state=ReservationState.FAILED, reason=reason)

    def get_reservation(self, key: str) -> Reservation | None:
        with self._lock:
            return self._reservations.get(key)

    def discard(self, key: str) -> None:
        with self._lock:
            self._reservations.pop(key, None)
            self._spend.pop(key, None)

    def stuck_reservations(self, before: datetime, limit: int = 100) -> list[Reservation]:
        with self._lock:
            stuck = [
                r
                for r in self._reservations.values()
                if r.state is ReservationState.FAILED
                or (r.state is ReservationState.PENDING and r.created_at < before)
            ]
        return sorted(stuck, key=lambda r: r.created_at)[:limit]

    def resolve_reservation(
        self, key: str, result_json: str | None, reason: str
    ) -> Reservation | None:
        with self._lock:
            current = self._reservations.get(key)
            if current is None or current.state is ReservationState.DONE:
                return None
            resolved = replace(
                current,
                state=ReservationState.DONE,
                result_json=result_json,
                replayable=True,
                reason=reason,
            )
            self._reservations[key] = resolved
            return resolved

    def commit_spend(
        self,
        key: str,
        tool: str,
        scope: str | None,
        amount: Decimal,
        at: datetime,
        checks: Sequence[SpendCheck],
    ) -> SpendViolation | None:
        with self._lock:
            for check in checks:
                total = self.spend_since(tool, scope, check.since, exclude_key=key) + amount
                if total > check.limit:
                    return SpendViolation(check.name, check.limit, total)
            self._spend.setdefault(key, (tool, scope, amount, at))
            return None

    def spend_since(
        self, tool: str, scope: str | None, since: datetime, exclude_key: str
    ) -> Decimal:
        with self._lock:
            return sum(
                (
                    amount
                    for key, (spend_tool, spend_scope, amount, at) in self._spend.items()
                    if spend_tool == tool
                    and spend_scope == scope
                    and at >= since
                    and key != exclude_key
                ),
                Decimal(0),
            )

    def append_audit(self, entry: AuditEntry) -> None:
        with self._lock:
            self._audit.append(entry)

    def query_audit(self, **filters: object) -> list[AuditEntry]:
        with self._lock:
            matched = [e for e in self._audit if _match(e, **filters)]
        return _limit(matched, filters.get("limit"))  # type: ignore[arg-type]

    def create_request(self, record: ApprovalRecord) -> None:
        with self._lock:
            self._requests[record.id] = record

    def get_request(self, request_id: str) -> ApprovalRecord | None:
        with self._lock:
            return self._requests.get(request_id)

    def list_requests(self, status: RequestStatus | None = None) -> list[ApprovalRecord]:
        with self._lock:
            return [r for r in self._requests.values() if status is None or r.status is status]

    def find_pending_by_key(self, key: str) -> ApprovalRecord | None:
        with self._lock:
            return next(
                (
                    r
                    for r in self._requests.values()
                    if r.key == key and r.status is RequestStatus.PENDING
                ),
                None,
            )

    def expire_requests(self, now: datetime) -> list[ApprovalRecord]:
        with self._lock:
            stale = [
                r
                for r in self._requests.values()
                if r.status is RequestStatus.PENDING
                and r.expires_at is not None
                and r.expires_at <= now
            ]
            for record in stale:
                self._requests[record.id] = replace(
                    record, status=RequestStatus.EXPIRED, decided_at=now
                )
            return [self._requests[r.id] for r in stale]

    def decide_request(
        self,
        request_id: str,
        status: RequestStatus,
        by: str | None,
        reason: str | None,
        at: datetime,
    ) -> ApprovalRecord | None:
        with self._lock:
            current = self._requests.get(request_id)
            if current is None or current.status is not RequestStatus.PENDING:
                return None
            decided = replace(
                current,
                status=status,
                decided_at=at,
                decided_by=by,
                decision_reason=reason,
            )
            self._requests[request_id] = decided
            return decided
