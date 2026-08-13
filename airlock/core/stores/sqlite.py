from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, suppress
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from airlock.core.canonical import chain_hash
from airlock.core.stores import migrations
from airlock.core.stores.base import (
    ReserveResult,
    SpendCheck,
    SpendViolation,
    Store,
    _chained,
)
from airlock.core.types import (
    ApprovalRecord,
    AuditEntry,
    Outcome,
    RequestStatus,
    Reservation,
    ReservationState,
)
from airlock.errors import StoreUnavailable

_TS = "%Y-%m-%dT%H:%M:%S.%f+00:00"


def _ts(value: datetime) -> str:
    return value.astimezone(UTC).strftime(_TS)


def _dt(value: str | None) -> datetime | None:
    return datetime.strptime(value, _TS).replace(tzinfo=UTC) if value else None


class SqliteStore(Store):
    """Durable store for local development and single-host services.

    Multiple processes may share one file: WAL plus ``BEGIN IMMEDIATE`` and a busy
    timeout make that correct. Multiple *hosts* may not, because SQLite locking does not
    survive a network filesystem. Use Postgres for that.
    """

    def __init__(self, path: str, busy_timeout_ms: int = 5_000) -> None:
        self.url = f"sqlite:///{path}"
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        with self._guard():
            self._conn.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
            self._conn.execute("PRAGMA foreign_keys=ON")
        if path != ":memory:":
            self._enable_wal(busy_timeout_ms)
        self._migrate()

    def _enable_wal(self, budget_ms: int) -> None:
        """Switch the database into WAL, waiting out other processes doing the same.

        Only the process that creates the file actually performs the switch; the rest
        read back ``wal`` and return. It needs its own retry because SQLite answers a
        journal-mode change with SQLITE_BUSY immediately, without consulting the busy
        timeout, so replicas booting together would otherwise kill each other.
        """
        deadline = time.monotonic() + budget_ms / 1000
        last: sqlite3.Error | None = None
        while True:
            try:
                mode = self._conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
                if str(mode).lower() == "wal":
                    return
            except sqlite3.OperationalError as exc:
                last = exc
            if time.monotonic() >= deadline:
                raise StoreUnavailable(
                    self.url, last or sqlite3.OperationalError("could not enable WAL")
                )
            time.sleep(0.02)

    @contextmanager
    def _guard(self) -> Iterator[None]:
        try:
            yield
        except sqlite3.Error as exc:
            raise StoreUnavailable(self.url, exc) from exc

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock, self._guard():
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")

    def _migrate(self) -> None:
        with self._tx() as conn:
            conn.execute(migrations.VERSION_TABLE[migrations.SQLITE])
            row = conn.execute("SELECT MAX(version) AS at FROM schema_version").fetchone()
            current = row["at"] or 0
            for migration in migrations.pending(migrations.SQLITE, current):
                for statement in migration.statements:
                    conn.execute(statement)
                conn.execute(
                    "INSERT INTO schema_version (version, name, applied_at) VALUES (?, ?, ?)",
                    (migration.version, migration.name, _ts(datetime.now(UTC))),
                )

    def schema_version(self) -> int:
        with self._lock, self._guard():
            row = self._conn.execute("SELECT MAX(version) AS at FROM schema_version").fetchone()
        return int(row["at"] or 0)

    def reserve(self, key: str, tool: str, intent: str, at: datetime) -> ReserveResult:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO intents (tool, intent, key) VALUES (?, ?, ?) "
                "ON CONFLICT (tool, intent) DO NOTHING",
                (tool, intent, key),
            )
            bound = conn.execute(
                "SELECT key FROM intents WHERE tool = ? AND intent = ?", (tool, intent)
            ).fetchone()
            if bound is not None and bound["key"] != key:
                return ReserveResult(owned=False, conflict_key=bound["key"])
            cursor = conn.execute(
                "INSERT INTO reservations (key, tool, intent, state, created_at, heartbeat_at) "
                "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (key) DO NOTHING",
                (key, tool, intent, ReservationState.PENDING.value, _ts(at), _ts(at)),
            )
            if cursor.rowcount == 1:
                return ReserveResult(owned=True)
            row = conn.execute("SELECT * FROM reservations WHERE key = ?", (key,)).fetchone()
            return ReserveResult(owned=False, existing=_reservation(row))

    def complete(self, key: str, result_json: str | None, replayable: bool) -> None:
        with self._tx() as conn:
            conn.execute(
                "UPDATE reservations SET state = ?, result_json = ?, replayable = ? WHERE key = ?",
                (ReservationState.DONE.value, result_json, int(replayable), key),
            )

    def fail(self, key: str, reason: str) -> None:
        with self._tx() as conn:
            conn.execute(
                "UPDATE reservations SET state = ?, reason = ? WHERE key = ?",
                (ReservationState.FAILED.value, reason, key),
            )

    def get_reservation(self, key: str) -> Reservation | None:
        with self._lock, self._guard():
            row = self._conn.execute("SELECT * FROM reservations WHERE key = ?", (key,)).fetchone()
        return _reservation(row) if row is not None else None

    def discard(self, key: str) -> None:
        with self._tx() as conn:
            conn.execute("DELETE FROM reservations WHERE key = ?", (key,))
            conn.execute("DELETE FROM spend WHERE key = ?", (key,))

    def stuck_reservations(self, before: datetime, limit: int = 100) -> list[Reservation]:
        with self._lock, self._guard():
            rows = self._conn.execute(
                "SELECT * FROM reservations WHERE state = ? "
                "OR (state = ? AND created_at < ?) ORDER BY created_at LIMIT ?",
                (
                    ReservationState.FAILED.value,
                    ReservationState.PENDING.value,
                    _ts(before),
                    limit,
                ),
            ).fetchall()
        return [_reservation(row) for row in rows]

    def resolve_reservation(
        self, key: str, result_json: str | None, reason: str
    ) -> Reservation | None:
        with self._tx() as conn:
            cursor = conn.execute(
                "UPDATE reservations SET state = ?, result_json = ?, replayable = 1, reason = ? "
                "WHERE key = ? AND state <> ?",
                (
                    ReservationState.DONE.value,
                    result_json,
                    reason,
                    key,
                    ReservationState.DONE.value,
                ),
            )
            if cursor.rowcount != 1:
                return None
            row = conn.execute("SELECT * FROM reservations WHERE key = ?", (key,)).fetchone()
        return _reservation(row)

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
        with self._tx() as conn:
            violation = None
            for check in checks:
                rows = conn.execute(
                    "SELECT amount FROM spend "
                    "WHERE tool = ? AND scope IS ? AND at >= ? AND key <> ?",
                    (tool, scope, _ts(check.since), key),
                ).fetchall()
                total = (
                    Decimal(len(rows) + 1)
                    if check.counts
                    else sum((Decimal(row["amount"]) for row in rows), Decimal(0)) + amount
                )
                if total > check.limit:
                    violation = SpendViolation(check.name, check.limit, total)
                    break
            if violation is not None and enforce:
                return violation
            conn.execute(
                "INSERT INTO spend (key, tool, scope, amount, at) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT (key) DO NOTHING",
                (key, tool, scope, str(amount), _ts(at)),
            )
        return violation

    def spend_since(
        self, tool: str, scope: str | None, since: datetime, exclude_key: str
    ) -> Decimal:
        with self._lock, self._guard():
            rows = self._conn.execute(
                "SELECT amount FROM spend WHERE tool = ? AND scope IS ? AND at >= ? AND key <> ?",
                (tool, scope, _ts(since), exclude_key),
            ).fetchall()
        return sum((Decimal(row["amount"]) for row in rows), Decimal(0))

    def append_audit(self, entry: AuditEntry, chain: bool = False) -> AuditEntry:
        with self._tx() as conn:
            if chain:
                # BEGIN IMMEDIATE already serialises writers, so reading the tip and
                # appending to it cannot interleave with another append.
                row = conn.execute(
                    "SELECT entry_hash FROM audit ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                previous = row["entry_hash"] if row else None
                entry = replace(
                    entry,
                    prev_hash=previous,
                    entry_hash=chain_hash(previous, _chained(entry)),
                )
            conn.execute(
                "INSERT INTO audit (id, at, tool, intent, key, outcome, layer, reason, scope, "
                "args, result_ref, actor, principal, prev_hash, entry_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    entry.id,
                    _ts(entry.at),
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
                    entry.principal,
                    entry.prev_hash,
                    entry.entry_hash,
                ),
            )
        return entry

    def query_audit(
        self,
        *,
        tool: str | None = None,
        intent: str | None = None,
        outcome: str | None = None,
        principal: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int | None = None,
    ) -> list[AuditEntry]:
        clauses: list[str] = []
        params: list[Any] = []
        for column, value in (("tool", tool), ("intent", intent), ("principal", principal)):
            if value is not None:
                clauses.append(f"{column} = ?")
                params.append(value)
        if outcome is not None:
            clauses.append("outcome = ?")
            params.append(getattr(outcome, "value", outcome))
        for op, moment in ((">=", since), ("<=", until)):
            if moment is not None:
                clauses.append(f"at {op} ?")
                params.append(_ts(moment))
        sql = "SELECT * FROM audit"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY seq"
        with self._lock, self._guard():
            rows = self._conn.execute(sql, params).fetchall()
        entries = [_audit(row) for row in rows]
        return entries[-limit:] if limit else entries

    def create_request(self, record: ApprovalRecord) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO approvals (id, tool, intent, key, reason, created_at, args, "
                "context, scope, status, expires_at, principal) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record.id,
                    record.tool,
                    record.intent,
                    record.key,
                    record.reason,
                    _ts(record.created_at),
                    json.dumps(dict(record.args), sort_keys=True),
                    json.dumps(dict(record.context), sort_keys=True),
                    record.scope,
                    record.status.value,
                    _ts(record.expires_at) if record.expires_at else None,
                    record.principal,
                ),
            )

    def get_request(self, request_id: str) -> ApprovalRecord | None:
        with self._lock, self._guard():
            row = self._conn.execute(
                "SELECT * FROM approvals WHERE id = ?", (request_id,)
            ).fetchone()
        return _approval(row) if row is not None else None

    def list_requests(self, status: RequestStatus | None = None) -> list[ApprovalRecord]:
        sql = "SELECT * FROM approvals"
        params: list[Any] = []
        if status is not None:
            sql += " WHERE status = ?"
            params.append(status.value)
        sql += " ORDER BY created_at"
        with self._lock, self._guard():
            rows = self._conn.execute(sql, params).fetchall()
        return [_approval(row) for row in rows]

    def find_pending_by_key(self, key: str) -> ApprovalRecord | None:
        with self._lock, self._guard():
            row = self._conn.execute(
                "SELECT * FROM approvals WHERE key = ? AND status = ? ORDER BY created_at LIMIT 1",
                (key, RequestStatus.PENDING.value),
            ).fetchone()
        return _approval(row) if row is not None else None

    def expire_requests(self, now: datetime) -> list[ApprovalRecord]:
        with self._tx() as conn:
            rows = conn.execute(
                "SELECT * FROM approvals WHERE status = ? AND expires_at IS NOT NULL "
                "AND expires_at <= ?",
                (RequestStatus.PENDING.value, _ts(now)),
            ).fetchall()
            if not rows:
                return []
            conn.execute(
                "UPDATE approvals SET status = ?, decided_at = ? WHERE status = ? "
                "AND expires_at IS NOT NULL AND expires_at <= ?",
                (RequestStatus.EXPIRED.value, _ts(now), RequestStatus.PENDING.value, _ts(now)),
            )
        return [_approval(row) for row in rows]

    def decide_request(
        self,
        request_id: str,
        status: RequestStatus,
        by: str | None,
        reason: str | None,
        at: datetime,
    ) -> ApprovalRecord | None:
        with self._tx() as conn:
            cursor = conn.execute(
                "UPDATE approvals SET status = ?, decided_at = ?, decided_by = ?, "
                "decision_reason = ? WHERE id = ? AND status = ?",
                (status.value, _ts(at), by, reason, request_id, RequestStatus.PENDING.value),
            )
            if cursor.rowcount != 1:
                return None
            row = conn.execute("SELECT * FROM approvals WHERE id = ?", (request_id,)).fetchone()
        return _approval(row)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __del__(self) -> None:
        # Callers should close explicitly; this only stops a forgotten store from
        # leaking its connection until the interpreter tears down.
        with suppress(Exception):
            self._conn.close()


def _reservation(row: sqlite3.Row) -> Reservation:
    return Reservation(
        key=row["key"],
        tool=row["tool"],
        intent=row["intent"],
        state=ReservationState(row["state"]),
        created_at=_dt(row["created_at"]),  # type: ignore[arg-type]
        result_json=row["result_json"],
        replayable=bool(row["replayable"]),
        reason=row["reason"],
        heartbeat_at=_dt(row["heartbeat_at"]),
    )


def _audit(row: sqlite3.Row) -> AuditEntry:
    return AuditEntry(
        id=row["id"],
        at=_dt(row["at"]),  # type: ignore[arg-type]
        tool=row["tool"],
        intent=row["intent"],
        key=row["key"],
        outcome=Outcome(row["outcome"]),
        layer=row["layer"],
        reason=row["reason"],
        scope=row["scope"],
        args=json.loads(row["args"]),
        result_ref=row["result_ref"],
        actor=row["actor"],
        principal=row["principal"],
        prev_hash=row["prev_hash"],
        entry_hash=row["entry_hash"],
    )


def _approval(row: sqlite3.Row) -> ApprovalRecord:
    return ApprovalRecord(
        id=row["id"],
        tool=row["tool"],
        intent=row["intent"],
        key=row["key"],
        reason=row["reason"],
        created_at=_dt(row["created_at"]),  # type: ignore[arg-type]
        args=json.loads(row["args"]),
        context=json.loads(row["context"]),
        scope=row["scope"],
        status=RequestStatus(row["status"]),
        principal=row["principal"],
        expires_at=_dt(row["expires_at"]),
        decided_at=_dt(row["decided_at"]),
        decided_by=row["decided_by"],
        decision_reason=row["decision_reason"],
    )
