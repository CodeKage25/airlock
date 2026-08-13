from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from airlock.core.canonical import idempotency_key
from airlock.core.types import Reservation, ReservationState
from airlock.errors import Blocked

LAYER = "idempotency"


def derive_key(
    tool: str,
    args: Mapping[str, Any],
    intent: str,
    context: Mapping[str, Any],
    key_fields: Sequence[str] = (),
) -> str:
    """Same logical intent, same key, across retries, processes and restarts."""
    payload: dict[str, Any] = {"args": dict(args)}
    if key_fields:
        payload["context"] = {name: context.get(name) for name in sorted(key_fields)}
    return idempotency_key(tool, payload, intent)


#: Beyond this a result is recorded as having happened but is not kept for replay.
#: A reservation row is not a blob store, and one oversized result should not be able to
#: slow every future read of the table.
MAX_RESULT_BYTES = 256 * 1024


def serialise(result: Any, limit: int = MAX_RESULT_BYTES) -> tuple[str | None, bool]:
    try:
        payload = json.dumps(result, sort_keys=True)
    except (TypeError, ValueError):
        return None, False
    if len(payload.encode("utf-8")) > limit:
        return None, False
    return payload, True


def replay(reservation: Reservation) -> Any:
    """The original result of a completed call. Never re-executes."""
    if not reservation.replayable:
        raise Blocked(
            f"intent {reservation.intent!r} already executed but its result was not kept "
            "(too large, or not serialisable), so it cannot be replayed safely",
            layer=LAYER,
        )
    return json.loads(reservation.result_json) if reservation.result_json is not None else None


def block_reason(reservation: Reservation) -> str:
    """Why a non-completed record for this key must stop a fresh attempt.

    A pending record means either a call in flight or a process that died mid-execution;
    a failed one means an attempt whose real-world effect is unknown. Both are the
    timeout-on-the-irreversible-leg case, and both fail closed.
    """
    if reservation.state is ReservationState.PENDING:
        return (
            f"a call with intent {reservation.intent!r} is already in flight; "
            "its outcome is unknown, so this attempt will not execute"
        )
    return (
        f"a previous attempt with intent {reservation.intent!r} failed with an unknown "
        f"outcome ({reservation.reason}); resolve it before retrying"
    )
