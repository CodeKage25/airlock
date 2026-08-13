"""Operator recovery for intents whose real-world effect is unknown.

Blocking every retry of a crashed or timed-out call is the correct default and the whole
point of failing closed. It is also, without this module, a dead end: the intent stays
blocked forever and the only way out is editing the database by hand, at exactly the
moment when nobody should be editing a database by hand.

Resolution is deliberately a human decision with two answers, because only a human can
go and look at whether the money moved.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from airlock.core.audit import AuditLog
from airlock.core.stores.base import Store
from airlock.core.types import Outcome, Reservation, ReservationState
from airlock.errors import AirlockError

LAYER = "idempotency"

DEFAULT_STUCK_AFTER = timedelta(minutes=5)


@dataclass(frozen=True)
class StuckIntent:
    """An attempt that stopped making progress, as an operator needs to see it."""

    key: str
    tool: str
    intent: str
    state: ReservationState
    created_at: datetime
    age: timedelta
    reason: str | None

    @property
    def description(self) -> str:
        if self.state is ReservationState.FAILED:
            return f"failed with an unknown outcome: {self.reason}"
        return f"pending with no progress for {self.age}"


class Intents:
    """Find and settle intents that are blocking retries."""

    def __init__(
        self,
        store: Store,
        clock: Callable[[], datetime],
        audit: AuditLog,
        stuck_after: timedelta = DEFAULT_STUCK_AFTER,
    ) -> None:
        self._store = store
        self._clock = clock
        self._audit = audit
        self._stuck_after = stuck_after

    def stuck(self, older_than: timedelta | None = None, limit: int = 100) -> list[StuckIntent]:
        now = self._clock()
        cutoff = now - (older_than if older_than is not None else self._stuck_after)
        return [
            self._view(reservation, now)
            for reservation in self._store.stuck_reservations(cutoff, limit)
        ]

    def get(self, key: str) -> StuckIntent | None:
        reservation = self._store.get_reservation(self.expand(key))
        if reservation is None or reservation.state is ReservationState.DONE:
            return None
        return self._view(reservation, self._clock())

    def expand(self, key_or_prefix: str) -> str:
        """Accept an abbreviated key, the way git accepts a short commit hash.

        Listings abbreviate, and an operator copying what they were shown must not be
        told it does not exist.
        """
        if self._store.get_reservation(key_or_prefix) is not None:
            return key_or_prefix
        matches = {
            reservation.key
            for reservation in self._store.stuck_reservations(self._clock(), limit=1_000)
            if reservation.key.startswith(key_or_prefix)
        }
        if len(matches) > 1:
            raise AirlockError(
                f"{key_or_prefix!r} matches {len(matches)} intents; use more characters"
            )
        return matches.pop() if matches else key_or_prefix

    def resolve(self, key: str, *, executed: bool, by: str, note: str = "") -> None:
        """Settle a stuck intent.

        ``executed=True`` records that the effect did land, so the intent stays closed and
        a retry replays instead of paying twice. ``executed=False`` records that it did
        not, releasing both the intent and the budget it reserved so a retry can proceed.
        """
        key = self.expand(key)
        reservation = self._store.get_reservation(key)
        if reservation is None:
            raise AirlockError(f"no reservation for key {key!r}")
        if reservation.state is ReservationState.DONE:
            raise AirlockError(f"intent {reservation.intent!r} is already settled")

        verdict = "executed" if executed else "did not execute"
        reason = f"resolved by {by}: the action {verdict}" + (f" ({note})" if note else "")

        if executed:
            payload = json.dumps(
                {"airlock": "resolved", "by": by, "note": note, "result": "unrecorded"},
                sort_keys=True,
            )
            if self._store.resolve_reservation(key, payload, reason) is None:
                raise AirlockError(f"intent {reservation.intent!r} is already settled")
        else:
            self._store.discard(key)

        self._audit.record(
            tool=reservation.tool,
            intent=reservation.intent,
            key=key,
            outcome=Outcome.RESOLVED,
            layer=LAYER,
            reason=reason,
            actor=by,
        )

    def _view(self, reservation: Reservation, now: datetime) -> StuckIntent:
        return StuckIntent(
            key=reservation.key,
            tool=reservation.tool,
            intent=reservation.intent,
            state=reservation.state,
            created_at=reservation.created_at,
            age=now - reservation.created_at,
            reason=reservation.reason,
        )
