from __future__ import annotations

import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from airlock.core.canonical import canonical, chain_hash
from airlock.core.redaction import REDACTED, Redactor
from airlock.core.stores.base import Store, _chained
from airlock.core.telemetry import DecisionEvent, NullTelemetry, Telemetry
from airlock.core.types import AuditEntry, Outcome

__all__ = ["REDACTED", "AuditLog", "ChainReport"]


@dataclass(frozen=True, slots=True)
class ChainReport:
    """Whether the recorded history is the history that was written."""

    checked: int
    intact: bool
    broken_at: str | None = None
    detail: str | None = None

    def __bool__(self) -> bool:
        return self.intact


class AuditLog:
    """Append-only record of every proposed action and how it resolved."""

    def __init__(
        self,
        store: Store,
        clock: Callable[[], datetime],
        redact: Iterable[str] = (),
        telemetry: Telemetry | None = None,
        chain: bool = False,
    ) -> None:
        self._store = store
        self._clock = clock
        self._redactor = Redactor(redact)
        self._telemetry = telemetry or NullTelemetry()
        self._chain = chain

    def record(
        self,
        *,
        tool: str,
        intent: str,
        key: str,
        outcome: Outcome,
        layer: str | None = None,
        reason: str | None = None,
        scope: str | None = None,
        args: Mapping[str, Any] | None = None,
        result_ref: str | None = None,
        actor: str | None = None,
        principal: str | None = None,
    ) -> AuditEntry:
        entry = AuditEntry(
            id=uuid.uuid4().hex,
            at=self._clock(),
            tool=tool,
            intent=intent,
            key=key,
            outcome=outcome,
            layer=layer,
            reason=reason,
            scope=scope,
            args=self.redacted(args or {}),
            result_ref=result_ref,
            actor=actor,
            principal=principal,
        )
        # The record is written first. If the store refuses, the action does not run,
        # and no metric should claim otherwise.
        written = self._store.append_audit(entry, chain=self._chain) or entry
        if outcome is not Outcome.PROPOSED:
            self._telemetry.decision(
                DecisionEvent(
                    tool=tool,
                    outcome=outcome,
                    intent=intent,
                    layer=layer,
                    scope=scope,
                    reason=reason,
                    actor=actor,
                )
            )
        return written

    def redacted(self, args: Mapping[str, Any]) -> dict[str, Any]:
        safe = {name: _safe(value) for name, value in args.items()}
        return self._redactor.apply(safe) if self._redactor else safe

    def query(
        self,
        *,
        tool: str | None = None,
        intent: str | None = None,
        outcome: Outcome | str | None = None,
        principal: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int | None = None,
    ) -> list[AuditEntry]:
        return self._store.query_audit(
            tool=tool,
            intent=intent,
            outcome=getattr(outcome, "value", outcome),
            principal=principal,
            since=since,
            until=until,
            limit=limit,
        )

    def verify(self) -> ChainReport:
        """Recompute the chain and report the first entry that does not match.

        Triggers stop the application rewriting history. This catches a rewrite by
        anyone who got past them, which is the question an auditor actually asks.
        """
        entries = self.query()
        if not self._chain:
            return ChainReport(
                checked=len(entries),
                intact=False,
                detail="chaining is off, so there is nothing to verify",
            )

        previous: str | None = None
        for entry in entries:
            if entry.entry_hash is None:
                return ChainReport(
                    checked=len(entries),
                    intact=False,
                    broken_at=entry.id,
                    detail="entry was written before chaining was switched on",
                )
            if entry.prev_hash != previous:
                return ChainReport(
                    checked=len(entries),
                    intact=False,
                    broken_at=entry.id,
                    detail="entry does not follow its predecessor; a record was removed",
                )
            if chain_hash(previous, _chained(entry)) != entry.entry_hash:
                return ChainReport(
                    checked=len(entries),
                    intact=False,
                    broken_at=entry.id,
                    detail="entry contents do not match its hash; a record was altered",
                )
            previous = entry.entry_hash
        return ChainReport(checked=len(entries), intact=True)

    def __iter__(self) -> Iterable[AuditEntry]:
        return iter(self.query())


def _safe(value: Any) -> Any:
    try:
        return canonical(value)
    except (TypeError, ValueError):
        return f"<{type(value).__name__}>"
