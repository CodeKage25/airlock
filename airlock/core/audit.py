from __future__ import annotations

import uuid
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime
from typing import Any

from airlock.core.canonical import canonical
from airlock.core.stores.base import Store
from airlock.core.telemetry import DecisionEvent, NullTelemetry, Telemetry
from airlock.core.types import AuditEntry, Outcome

REDACTED = "***"


class AuditLog:
    """Append-only record of every proposed action and how it resolved."""

    def __init__(
        self,
        store: Store,
        clock: Callable[[], datetime],
        redact: Iterable[str] = (),
        telemetry: Telemetry | None = None,
    ) -> None:
        self._store = store
        self._clock = clock
        self._redact = frozenset(redact)
        self._telemetry = telemetry or NullTelemetry()

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
        )
        # The record is written first. If the store refuses, the action does not run,
        # and no metric should claim otherwise.
        self._store.append_audit(entry)
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
        return entry

    def redacted(self, args: Mapping[str, Any]) -> dict[str, Any]:
        return {
            name: REDACTED if name in self._redact else _safe(value) for name, value in args.items()
        }

    def query(
        self,
        *,
        tool: str | None = None,
        intent: str | None = None,
        outcome: Outcome | str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int | None = None,
    ) -> list[AuditEntry]:
        return self._store.query_audit(
            tool=tool,
            intent=intent,
            outcome=getattr(outcome, "value", outcome),
            since=since,
            until=until,
            limit=limit,
        )

    def __iter__(self) -> Iterable[AuditEntry]:
        return iter(self.query())


def _safe(value: Any) -> Any:
    try:
        return canonical(value)
    except (TypeError, ValueError):
        return f"<{type(value).__name__}>"
