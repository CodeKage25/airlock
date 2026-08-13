from __future__ import annotations

import threading

import pytest

from airlock import Policy
from airlock.core.idempotency import derive_key
from airlock.errors import Blocked, DuplicateIntent
from tests.conftest import Clock, build_lock


def test_a_retry_returns_the_original_result_without_executing(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(store_url, clock)

    @lock.tool
    def pay(to: str, amount: float) -> str:
        calls.append(amount)
        return f"txn_{len(calls)}"

    first = pay(to="a", amount=40, _intent="inv-77")
    for _ in range(5):
        assert pay(to="a", amount=40, _intent="inv-77") == first
    assert calls == [40]


def test_strict_mode_raises_instead_of_replaying(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(store_url, clock, strict_idempotency=True)

    @lock.tool
    def pay(amount: float) -> str:
        calls.append(amount)
        return "txn_1"

    pay(amount=40, _intent="inv-77")
    with pytest.raises(DuplicateIntent) as caught:
        pay(amount=40, _intent="inv-77")
    assert caught.value.original_result == "txn_1"
    assert calls == [40]


def test_the_same_intent_with_mutated_arguments_is_blocked(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(store_url, clock)

    @lock.tool
    def pay(to: str, amount: float) -> str:
        calls.append(amount)
        return "txn"

    pay(to="a", amount=40, _intent="inv-77")
    with pytest.raises(Blocked) as caught:
        pay(to="attacker", amount=40, _intent="inv-77")
    assert caught.value.layer == "idempotency"
    assert calls == [40]


def test_an_attempt_with_an_unknown_outcome_blocks_every_retry(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    """The irreversible leg timed out. Airlock will not gamble on it having been a no-op."""
    lock = build_lock(store_url, clock)

    @lock.tool
    def settle(leg: str, amount: float) -> str:
        calls.append(amount)
        raise TimeoutError("no response from the rail")

    with pytest.raises(TimeoutError):
        settle(leg="off-ramp", amount=500, _intent="inv-88")

    for _ in range(3):
        with pytest.raises(Blocked, match="unknown"):
            settle(leg="off-ramp", amount=500, _intent="inv-88")
    assert calls == [500]


def test_a_new_intent_is_a_new_action(store_url: str, clock: Clock, calls: list[float]) -> None:
    lock = build_lock(store_url, clock)

    @lock.tool
    def pay(amount: float) -> str:
        calls.append(amount)
        return f"txn_{len(calls)}"

    assert pay(amount=40, _intent="inv-77") == "txn_1"
    assert pay(amount=40, _intent="inv-78") == "txn_2"


def test_keys_survive_equivalent_argument_spellings() -> None:
    args = ("pay", {"amount": 40}, "inv-77", {})
    assert derive_key(*args) == derive_key("pay", {"amount": 40.0}, "inv-77", {})
    assert derive_key(*args) == derive_key("pay", {"amount": "40"}, "inv-77", {})


def test_keys_are_stable_across_argument_ordering() -> None:
    a = derive_key("pay", {"to": "x", "amount": 1}, "i", {})
    b = derive_key("pay", {"amount": 1, "to": "x"}, "i", {})
    assert a == b


def test_context_stays_out_of_the_key_unless_opted_in() -> None:
    base = derive_key("pay", {"amount": 1}, "i", {"corridor": "NGN"})
    other = derive_key("pay", {"amount": 1}, "i", {"corridor": "KES"})
    assert base == other

    scoped = derive_key("pay", {"amount": 1}, "i", {"corridor": "NGN"}, ["corridor"])
    scoped_other = derive_key("pay", {"amount": 1}, "i", {"corridor": "KES"}, ["corridor"])
    assert scoped != scoped_other


def test_concurrent_calls_on_one_intent_execute_exactly_once(store_url: str, clock: Clock) -> None:
    lock = build_lock(store_url, clock, Policy())
    started = threading.Barrier(4)
    executions: list[int] = []
    lock_guard = threading.Lock()

    @lock.tool
    def pay(amount: float) -> str:
        with lock_guard:
            executions.append(1)
        return "txn"

    outcomes: list[object] = []

    def attempt() -> None:
        started.wait()
        try:
            outcomes.append(pay(amount=40, _intent="inv-99"))
        except Exception as exc:
            outcomes.append(exc)

    threads = [threading.Thread(target=attempt) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(executions) == 1
    assert sum(1 for outcome in outcomes if outcome == "txn") >= 1
    assert all(outcome == "txn" or isinstance(outcome, Blocked) for outcome in outcomes)


def test_an_unserialisable_result_blocks_replay_rather_than_re_executing(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(store_url, clock)

    class Receipt:
        pass

    @lock.tool
    def pay(amount: float) -> object:
        calls.append(amount)
        return Receipt()

    assert isinstance(pay(amount=1, _intent="i-1"), Receipt)
    with pytest.raises(Blocked, match="not serialisable"):
        pay(amount=1, _intent="i-1")
    assert calls == [1]
