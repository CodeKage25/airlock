from __future__ import annotations

import json
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from airlock.core.stores import migrations
from airlock.core.stores.base import ReserveResult, SpendCheck, SpendViolation, Store
from airlock.core.types import (
    ApprovalRecord,
    AuditEntry,
    Outcome,
    RequestStatus,
    Reservation,
    ReservationState,
)
from airlock.errors import PolicyError, StoreUnavailable

try:
    import psycopg
    from psycopg.rows import dict_row
    from psycopg_pool import ConnectionPool

    _MISSING: str | None = None
except ImportError as exc:  # pragma: no cover - exercised by the error path below
    psycopg = None  # type: ignore[assignment]
    _MISSING = exc.name


class PostgresStore(Store):
    """Production store. The only backend that is safe across more than one host.

    Cap enforcement takes a transaction-scoped advisory lock per ``(tool, scope)`` so
    concurrent commits on one budget serialise against each other without forcing the
    whole transaction to SERIALIZABLE and dealing with retry storms.
    """

    def __init__(self, url: str, min_size: int = 1, max_size: int = 10) -> None:
        if psycopg is None:
            raise PolicyError(
                f"the postgres store needs {_MISSING!r}: pip install 'agent-airlock[postgres]'"
            )
        self.url = url
        try:
            self._pool = ConnectionPool(
                url,
                min_size=min_size,
                max_size=max_size,
                open=True,
                # Without this, timestamps come back in the server's local zone while the
                # other backends return UTC, and the same log reads differently per store.
                kwargs={"row_factory": dict_row, "options": "-c timezone=UTC"},
            )
            self._pool.wait(timeout=10)
        except Exception as exc:
            raise StoreUnavailable(url, exc) from exc
        self._migrate()

    @contextmanager
    def _tx(self) -> Iterator[Any]:
        try:
            with self._pool.connection() as conn, conn.transaction(), conn.cursor() as cur:
                yield cur
        except psycopg.Error as exc:
            raise StoreUnavailable(self.url, exc) from exc

    def _migrate(self) -> None:
        with self._tx() as cur:
            cur.execute(migrations.VERSION_TABLE[migrations.POSTGRES])
            # One writer at a time, so concurrent boots cannot both apply a migration.
            cur.execute("SELECT pg_advisory_xact_lock(hashtext('airlock_migrations'))")
            cur.execute("SELECT MAX(version) AS at FROM schema_version")
            current = (cur.fetchone() or {}).get("at") or 0
            for migration in migrations.pending(migrations.POSTGRES, current):
                for statement in migration.statements:
                    cur.execute(statement)
                cur.execute(
                    "INSERT INTO schema_version (version, name, applied_at) VALUES (%s, %s, %s)",
                    (migration.version, migration.name, datetime.now(UTC)),
                )

    def schema_version(self) -> int:
        with self._tx() as cur:
            cur.execute("SELECT MAX(version) AS at FROM schema_version")
            return int((cur.fetchone() or {}).get("at") or 0)

    def reserve(self, key: str, tool: str, intent: str, at: datetime) -> ReserveResult:
        with self._tx() as cur:
            cur.execute(
                "INSERT INTO intents (tool, intent, key) VALUES (%s, %s, %s) "
                "ON CONFLICT (tool, intent) DO NOTHING",
                (tool, intent, key),
            )
            cur.execute("SELECT key FROM intents WHERE tool = %s AND intent = %s", (tool, intent))
            bound = cur.fetchone()
            if bound is not None and bound["key"] != key:
                return ReserveResult(owned=False, conflict_key=bound["key"])
            cur.execute(
                "INSERT INTO reservations (key, tool, intent, state, created_at, heartbeat_at) "
                "VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (key) DO NOTHING",
                (key, tool, intent, ReservationState.PENDING.value, at, at),
            )
            if cur.rowcount == 1:
                return ReserveResult(owned=True)
            cur.execute("SELECT * FROM reservations WHERE key = %s", (key,))
            return ReserveResult(owned=False, existing=_reservation(cur.fetchone()))

    def complete(self, key: str, result_json: str | None, replayable: bool) -> None:
        with self._tx() as cur:
            cur.execute(
                "UPDATE reservations SET state = %s, result_json = %s, replayable = %s "
                "WHERE key = %s",
                (ReservationState.DONE.value, result_json, replayable, key),
            )

    def fail(self, key: str, reason: str) -> None:
        with self._tx() as cur:
            cur.execute(
                "UPDATE reservations SET state = %s, reason = %s WHERE key = %s",
                (ReservationState.FAILED.value, reason, key),
            )

    def get_reservation(self, key: str) -> Reservation | None:
        with self._tx() as cur:
            cur.execute("SELECT * FROM reservations WHERE key = %s", (key,))
            row = cur.fetchone()
        return _reservation(row) if row is not None else None

    def discard(self, key: str) -> None:
        with self._tx() as cur:
            cur.execute("DELETE FROM reservations WHERE key = %s", (key,))
            cur.execute("DELETE FROM spend WHERE key = %s", (key,))

    def stuck_reservations(self, before: datetime, limit: int = 100) -> list[Reservation]:
        with self._tx() as cur:
            cur.execute(
                "SELECT * FROM reservations WHERE state = %s "
                "OR (state = %s AND created_at < %s) ORDER BY created_at LIMIT %s",
                (ReservationState.FAILED.value, ReservationState.PENDING.value, before, limit),
            )
            return [_reservation(row) for row in cur.fetchall()]

    def resolve_reservation(
        self, key: str, result_json: str | None, reason: str
    ) -> Reservation | None:
        with self._tx() as cur:
            cur.execute(
                "UPDATE reservations SET state = %s, result_json = %s, replayable = TRUE, "
                "reason = %s WHERE key = %s AND state <> %s RETURNING *",
                (
                    ReservationState.DONE.value,
                    result_json,
                    reason,
                    key,
                    ReservationState.DONE.value,
                ),
            )
            row = cur.fetchone()
        return _reservation(row) if row is not None else None

    def commit_spend(
        self,
        key: str,
        tool: str,
        scope: str | None,
        amount: Decimal,
        at: datetime,
        checks: Sequence[SpendCheck],
        enforce: bool = True,
    ) -> SpendViolation | None:
        with self._tx() as cur:
            cur.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (f"airlock:spend:{tool}:{scope or ''}",),
            )
            violation = None
            for check in checks:
                cur.execute(
                    "SELECT COALESCE(SUM(amount), 0) AS total FROM spend "
                    "WHERE tool = %s AND scope IS NOT DISTINCT FROM %s AND at >= %s "
                    "AND key <> %s",
                    (tool, scope, check.since, key),
                )
                total = Decimal((cur.fetchone() or {}).get("total") or 0) + amount
                if total > check.limit:
                    violation = SpendViolation(check.name, check.limit, total)
                    break
            if violation is not None and enforce:
                return violation
            cur.execute(
                "INSERT INTO spend (key, tool, scope, amount, at) VALUES (%s, %s, %s, %s, %s) "
                "ON CONFLICT (key) DO NOTHING",
                (key, tool, scope, amount, at),
            )
        return violation

    def spend_since(
        self, tool: str, scope: str | None, since: datetime, exclude_key: str
    ) -> Decimal:
        with self._tx() as cur:
            cur.execute(
                "SELECT COALESCE(SUM(amount), 0) AS total FROM spend "
                "WHERE tool = %s AND scope IS NOT DISTINCT FROM %s AND at >= %s AND key <> %s",
                (tool, scope, since, exclude_key),
            )
            return Decimal((cur.fetchone() or {}).get("total") or 0)

    def append_audit(self, entry: AuditEntry) -> None:
        with self._tx() as cur:
            cur.execute(
                "INSERT INTO audit (id, at, tool, intent, key, outcome, layer, reason, scope, "
                "args, result_ref, actor) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    entry.id,
                    entry.at,
                    entry.tool,
                    entry.intent,
                    entry.key,
                    entry.outcome.value,
                    entry.layer,
                    entry.reason,
                    entry.scope,
                    json.dumps(dict(entry.args), sort_keys=True),
                    entry.result_ref,
                    entry.actor,
                ),
            )

    def query_audit(
        self,
        *,
        tool: str | None = None,
        intent: str | None = None,
        outcome: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int | None = None,
    ) -> list[AuditEntry]:
        clauses: list[str] = []
        params: list[Any] = []
        for column, value in (("tool", tool), ("intent", intent)):
            if value is not None:
                clauses.append(f"{column} = %s")
                params.append(value)
        if outcome is not None:
            clauses.append("outcome = %s")
            params.append(getattr(outcome, "value", outcome))
        for op, moment in ((">=", since), ("<=", until)):
            if moment is not None:
                clauses.append(f"at {op} %s")
                params.append(moment)
        sql = "SELECT * FROM audit"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY seq"
        with self._tx() as cur:
            cur.execute(sql, params)
            entries = [_audit(row) for row in cur.fetchall()]
        return entries[-limit:] if limit else entries

    def create_request(self, record: ApprovalRecord) -> None:
        with self._tx() as cur:
            cur.execute(
                "INSERT INTO approvals (id, tool, intent, key, reason, created_at, args, "
                "context, scope, status, expires_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    record.id,
                    record.tool,
                    record.intent,
                    record.key,
                    record.reason,
                    record.created_at,
                    json.dumps(dict(record.args), sort_keys=True),
                    json.dumps(dict(record.context), sort_keys=True),
                    record.scope,
                    record.status.value,
                    record.expires_at,
                ),
            )

    def get_request(self, request_id: str) -> ApprovalRecord | None:
        with self._tx() as cur:
            cur.execute("SELECT * FROM approvals WHERE id = %s", (request_id,))
            row = cur.fetchone()
        return _approval(row) if row is not None else None

    def list_requests(self, status: RequestStatus | None = None) -> list[ApprovalRecord]:
        sql = "SELECT * FROM approvals"
        params: list[Any] = []
        if status is not None:
            sql += " WHERE status = %s"
            params.append(status.value)
        sql += " ORDER BY created_at"
        with self._tx() as cur:
            cur.execute(sql, params)
            return [_approval(row) for row in cur.fetchall()]

    def find_pending_by_key(self, key: str) -> ApprovalRecord | None:
        with self._tx() as cur:
            cur.execute(
                "SELECT * FROM approvals WHERE key = %s AND status = %s "
                "ORDER BY created_at LIMIT 1",
                (key, RequestStatus.PENDING.value),
            )
            row = cur.fetchone()
        return _approval(row) if row is not None else None

    def expire_requests(self, now: datetime) -> list[ApprovalRecord]:
        with self._tx() as cur:
            cur.execute(
                "UPDATE approvals SET status = %s, decided_at = %s WHERE status = %s "
                "AND expires_at IS NOT NULL AND expires_at <= %s RETURNING *",
                (RequestStatus.EXPIRED.value, now, RequestStatus.PENDING.value, now),
            )
            return [_approval(row) for row in cur.fetchall()]

    def decide_request(
        self,
        request_id: str,
        status: RequestStatus,
        by: str | None,
        reason: str | None,
        at: datetime,
    ) -> ApprovalRecord | None:
        with self._tx() as cur:
            cur.execute(
                "UPDATE approvals SET status = %s, decided_at = %s, decided_by = %s, "
                "decision_reason = %s WHERE id = %s AND status = %s RETURNING *",
                (status.value, at, by, reason, request_id, RequestStatus.PENDING.value),
            )
            row = cur.fetchone()
        return _approval(row) if row is not None else None

    def close(self) -> None:
        self._pool.close()


def _reservation(row: dict[str, Any]) -> Reservation:
    return Reservation(
        key=row["key"],
        tool=row["tool"],
        intent=row["intent"],
        state=ReservationState(row["state"]),
        created_at=row["created_at"],
        result_json=row["result_json"],
        replayable=bool(row["replayable"]),
        reason=row["reason"],
        heartbeat_at=row.get("heartbeat_at"),
    )


def _audit(row: dict[str, Any]) -> AuditEntry:
    return AuditEntry(
        id=row["id"],
        at=row["at"],
        tool=row["tool"],
        intent=row["intent"],
        key=row["key"],
        outcome=Outcome(row["outcome"]),
        layer=row["layer"],
        reason=row["reason"],
        scope=row["scope"],
        args=row["args"],
        result_ref=row["result_ref"],
        actor=row["actor"],
    )


def _approval(row: dict[str, Any]) -> ApprovalRecord:
    return ApprovalRecord(
        id=row["id"],
        tool=row["tool"],
        intent=row["intent"],
        key=row["key"],
        reason=row["reason"],
        created_at=row["created_at"],
        args=row["args"],
        context=row["context"],
        scope=row["scope"],
        status=RequestStatus(row["status"]),
        expires_at=row.get("expires_at"),
        decided_at=row["decided_at"],
        decided_by=row["decided_by"],
        decision_reason=row["decision_reason"],
    )
