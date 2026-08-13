"""Recovery for intents whose effect is unknown.

Blocking every retry is right. Blocking them forever with no way out is an outage.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

from airlock import Caps, Policy
from airlock.errors import AirlockError, Blocked
from tests.conftest import Clock, build_lock


def timing_out(lock, calls):  # type: ignore[no-untyped-def]
    @lock.tool
    def settle(leg: str, amount: float) -> str:
        calls.append(amount)
        raise TimeoutError("no response from the rail")

    return settle


def test_a_timed_out_call_shows_up_as_stuck(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(store_url, clock)
    settle = timing_out(lock, calls)

    with pytest.raises(TimeoutError):
        settle(leg="off_ramp", amount=500, _intent="inv-88")

    stuck = lock.intents.stuck()
    assert [item.intent for item in stuck] == ["inv-88"]
    assert "unknown outcome" in stuck[0].description


def test_an_in_flight_call_is_not_reported_as_stuck(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(store_url, clock)

    @lock.tool
    def settle(amount: float) -> str:
        assert lock.intents.stuck() == []
        calls.append(amount)
        return "ok"

    settle(amount=1, _intent="i-1")
    assert calls == [1]


def test_a_pending_call_becomes_stuck_once_it_stops_making_progress(
    store_url: Any, clock: Clock
) -> None:
    lock = build_lock(store_url, clock)
    store = lock.store
    store.reserve("orphan-key", "settle", "inv-99", clock.now)

    assert lock.intents.stuck() == []
    clock.advance(minutes=6)
    assert [item.intent for item in lock.intents.stuck()] == ["inv-99"]


def test_resolving_as_executed_keeps_the_intent_closed(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(store_url, clock)
    settle = timing_out(lock, calls)

    with pytest.raises(TimeoutError):
        settle(leg="off_ramp", amount=500, _intent="inv-88")

    key = lock.intents.stuck()[0].key
    lock.intents.resolve(key, executed=True, by="ops@yourco.com", note="found in the rail")

    replayed = settle(leg="off_ramp", amount=500, _intent="inv-88")
    assert replayed["airlock"] == "resolved"
    assert calls == [500]
    assert lock.intents.stuck() == []


def test_resolving_as_not_executed_releases_the_intent(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(store_url, clock)

    attempts: list[int] = []

    @lock.tool
    def settle(leg: str, amount: float) -> str:
        attempts.append(1)
        if len(attempts) == 1:
            raise TimeoutError("no response from the rail")
        calls.append(amount)
        return "settled"

    with pytest.raises(TimeoutError):
        settle(leg="off_ramp", amount=500, _intent="inv-88")
    with pytest.raises(Blocked, match="unknown"):
        settle(leg="off_ramp", amount=500, _intent="inv-88")

    key = lock.intents.stuck()[0].key
    lock.intents.resolve(key, executed=False, by="ops@yourco.com", note="rail shows nothing")

    assert settle(leg="off_ramp", amount=500, _intent="inv-88") == "settled"
    assert calls == [500]


def test_resolving_as_not_executed_gives_the_budget_back(store_url: Any, clock: Clock) -> None:
    """Spend is not refunded on failure. An operator confirming a no-op is different."""
    lock = build_lock(store_url, clock, Policy(caps={"settle": Caps(max_per_day=100)}))

    @lock.tool
    def settle(amount: float) -> str:
        raise TimeoutError("no response")

    with pytest.raises(TimeoutError):
        settle(amount=100, _intent="i-1")
    with pytest.raises(Blocked, match="max_per_day"):
        settle(amount=100, _intent="i-2")

    key = lock.intents.stuck()[0].key
    lock.intents.resolve(key, executed=False, by="ops@yourco.com")

    with pytest.raises(TimeoutError):
        settle(amount=100, _intent="i-2")


def test_resolution_is_audited_with_the_person_who_made_the_call(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(store_url, clock)
    settle = timing_out(lock, calls)

    with pytest.raises(TimeoutError):
        settle(leg="off_ramp", amount=500, _intent="inv-88")
    lock.intents.resolve(
        lock.intents.stuck()[0].key, executed=True, by="ops@yourco.com", note="confirmed"
    )

    resolved = lock.audit.query(outcome="resolved")
    assert len(resolved) == 1
    assert resolved[0].actor == "ops@yourco.com"
    assert "confirmed" in (resolved[0].reason or "")


def test_an_unknown_or_settled_intent_cannot_be_resolved(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(store_url, clock)

    @lock.tool
    def pay(amount: float) -> str:
        calls.append(amount)
        return "txn"

    with pytest.raises(AirlockError, match="no reservation"):
        lock.intents.resolve("nope", executed=True, by="ops@yourco.com")

    pay(amount=1, _intent="i-1")
    key = lock.audit.query(outcome="executed")[0].key
    with pytest.raises(AirlockError, match="already settled"):
        lock.intents.resolve(key, executed=True, by="ops@yourco.com")


def test_the_stuck_threshold_is_configurable(store_url: Any, clock: Clock) -> None:
    lock = build_lock(store_url, clock, stuck_after=timedelta(hours=1))
    lock.store.reserve("orphan-key", "settle", "inv-99", clock.now)

    clock.advance(minutes=30)
    assert lock.intents.stuck() == []
    assert [item.intent for item in lock.intents.stuck(older_than=timedelta(minutes=10))] == [
        "inv-99"
    ]
