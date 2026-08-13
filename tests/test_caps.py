from __future__ import annotations

import threading
from contextlib import suppress
from datetime import timedelta

import pytest

from airlock import Caps, Policy
from airlock.errors import Blocked
from tests.conftest import Clock, build_lock


def payer(lock, calls):  # type: ignore[no-untyped-def]
    @lock.tool
    def pay(to: str, amount: float, currency: str = "USD") -> str:
        calls.append(amount)
        return f"txn_{len(calls)}"

    return pay


def test_a_call_exactly_at_the_cap_executes(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(store_url, clock, Policy(caps={"pay": Caps(max_per_call=100)}))
    pay = payer(lock, calls)

    assert pay(to="a", amount=100, _intent="i-1") == "txn_1"
    assert calls == [100]


def test_one_unit_over_the_cap_is_blocked(store_url: str, clock: Clock, calls: list[float]) -> None:
    lock = build_lock(store_url, clock, Policy(caps={"pay": Caps(max_per_call=100)}))
    pay = payer(lock, calls)

    with pytest.raises(Blocked) as caught:
        pay(to="a", amount=100.01, _intent="i-1")
    assert caught.value.layer == "caps"
    assert calls == []


def test_cap_boundaries_are_exact_not_floating_point(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(store_url, clock, Policy(caps={"pay": Caps(max_per_day=0.3)}))
    pay = payer(lock, calls)

    pay(to="a", amount=0.1, _intent="i-1")
    pay(to="a", amount=0.2, _intent="i-2")
    assert calls == [0.1, 0.2]


def test_a_runaway_loop_is_stopped_by_the_daily_cap(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(store_url, clock, Policy(caps={"pay": Caps(max_per_day=250)}))
    pay = payer(lock, calls)

    for n in range(2):
        pay(to="a", amount=100, _intent=f"i-{n}")

    with pytest.raises(Blocked, match="max_per_day"):
        pay(to="a", amount=100, _intent="i-2")
    assert sum(calls) == 200


def test_the_window_rolls_forward_with_the_clock(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(store_url, clock, Policy(caps={"pay": Caps(max_per_day=100)}))
    pay = payer(lock, calls)

    pay(to="a", amount=100, _intent="i-1")
    with pytest.raises(Blocked):
        pay(to="a", amount=100, _intent="i-2")

    clock.advance(hours=25)
    pay(to="a", amount=100, _intent="i-3")
    assert calls == [100, 100]


def test_a_custom_window_is_enforced(store_url: str, clock: Clock, calls: list[float]) -> None:
    caps = Caps(max_per_window=100, window=timedelta(minutes=10))
    lock = build_lock(store_url, clock, Policy(caps={"pay": caps}))
    pay = payer(lock, calls)

    pay(to="a", amount=60, _intent="i-1")
    with pytest.raises(Blocked, match="max_per_window"):
        pay(to="a", amount=60, _intent="i-2")

    clock.advance(minutes=11)
    pay(to="a", amount=60, _intent="i-3")
    assert calls == [60, 60]


def test_scopes_carry_separate_budgets(store_url: str, clock: Clock, calls: list[float]) -> None:
    caps = Caps(max_per_day=100, scope_by="corridor")
    lock = build_lock(store_url, clock, Policy(caps={"pay": caps}))
    pay = payer(lock, calls)

    pay(to="a", amount=100, _intent="i-1", _context={"corridor": "NGN-GHS"})
    pay(to="a", amount=100, _intent="i-2", _context={"corridor": "KES-XOF"})

    with pytest.raises(Blocked, match="NGN-GHS"):
        pay(to="a", amount=1, _intent="i-3", _context={"corridor": "NGN-GHS"})
    assert calls == [100, 100]


def test_a_missing_scope_key_blocks_rather_than_sharing_a_budget(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    caps = Caps(max_per_day=100, scope_by="corridor")
    lock = build_lock(store_url, clock, Policy(caps={"pay": caps}))
    pay = payer(lock, calls)

    with pytest.raises(Blocked, match="corridor"):
        pay(to="a", amount=1, _intent="i-1")
    assert calls == []


def test_a_cap_in_one_currency_does_not_authorise_another(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(
        store_url, clock, Policy(caps={"pay": Caps(max_per_call=100, currency="USD")})
    )
    pay = payer(lock, calls)

    with pytest.raises(Blocked, match="NGN"):
        pay(to="a", amount=50, currency="NGN", _intent="i-1")
    assert calls == []


def test_a_negative_amount_cannot_refund_the_budget(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(store_url, clock, Policy(caps={"pay": Caps(max_per_day=100)}))
    pay = payer(lock, calls)

    with pytest.raises(Blocked, match="negative"):
        pay(to="a", amount=-500, _intent="i-1")
    assert calls == []


def test_a_tool_without_an_amount_is_metered_by_call_count(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(store_url, clock, Policy(caps={"notify": Caps(max_per_day=2)}))

    @lock.tool
    def notify(to: str) -> str:
        calls.append(1)
        return "sent"

    notify(to="a", _intent="n-1")
    notify(to="a", _intent="n-2")
    with pytest.raises(Blocked, match="max_per_day"):
        notify(to="a", _intent="n-3")
    assert len(calls) == 2


def test_spend_is_not_refunded_when_the_tool_fails(store_url: str, clock: Clock) -> None:
    lock = build_lock(store_url, clock, Policy(caps={"pay": Caps(max_per_day=100)}))

    @lock.tool
    def pay(amount: float) -> str:
        raise RuntimeError("rail timeout")

    with pytest.raises(RuntimeError):
        pay(amount=100, _intent="i-1")

    with pytest.raises(Blocked, match="max_per_day"):
        pay(amount=100, _intent="i-2")


def test_concurrent_distinct_intents_cannot_overshoot_the_cap(store_url: str, clock: Clock) -> None:
    """Check-then-write is not enough: both halves have to be one atomic step."""
    lock = build_lock(store_url, clock, Policy(caps={"pay": Caps(max_per_day=500)}))
    spent: list[float] = []
    guard = threading.Lock()
    ready = threading.Barrier(20)

    @lock.tool
    def pay(amount: float) -> str:
        with guard:
            spent.append(amount)
        return "txn"

    def attempt(n: int) -> None:
        ready.wait()
        with suppress(Blocked):
            pay(amount=100, _intent=f"i-{n}")

    threads = [threading.Thread(target=attempt, args=(n,)) for n in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sum(spent) == 500


def test_a_capped_out_call_does_not_poison_its_intent(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(store_url, clock, Policy(caps={"pay": Caps(max_per_day=100)}))
    pay = payer(lock, calls)

    pay(to="a", amount=100, _intent="i-1")
    with pytest.raises(Blocked, match="max_per_day"):
        pay(to="a", amount=100, _intent="i-2")

    clock.advance(hours=25)
    assert pay(to="a", amount=100, _intent="i-2") == "txn_2"


def test_a_retry_is_not_charged_to_the_window_twice(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(store_url, clock, Policy(caps={"pay": Caps(max_per_day=100)}))
    pay = payer(lock, calls)

    assert pay(to="a", amount=100, _intent="i-1") == "txn_1"
    assert pay(to="a", amount=100, _intent="i-1") == "txn_1"
    assert calls == [100]
