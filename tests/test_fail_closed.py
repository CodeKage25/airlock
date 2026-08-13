from __future__ import annotations

import pytest

from airlock import Airlock, Caps, Policy
from airlock.errors import Blocked, StoreUnavailable
from tests.conftest import BrokenStore, Clock, make_store


def locked(store_url: str, clock: Clock, *failing: str, **policy: object):  # type: ignore[no-untyped-def]
    store = BrokenStore(make_store(store_url), *failing)
    lock = Airlock(policy=Policy(**policy), store=store, clock=clock)  # type: ignore[arg-type]
    return lock


@pytest.mark.parametrize(
    "failing",
    ["append_audit", "get_reservation", "reserve", "spend_since", "commit_spend"],
)
def test_nothing_executes_while_a_dependency_is_down(
    store_url: str, clock: Clock, calls: list[float], failing: str
) -> None:
    lock = locked(store_url, clock, failing, caps={"pay": Caps(max_per_day=1_000)})

    @lock.tool
    def pay(amount: float) -> str:
        calls.append(amount)
        return "txn"

    with pytest.raises(Blocked) as caught:
        pay(amount=1, _intent="i-1")
    assert caught.value.layer == "fail-closed"
    assert calls == []


def test_an_unauditable_action_does_not_run(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    lock = locked(store_url, clock, "append_audit")

    @lock.tool
    def pay(amount: float) -> str:
        calls.append(amount)
        return "txn"

    with pytest.raises(Blocked, match="fail-closed"):
        pay(amount=1, _intent="i-1")
    assert calls == []


def test_a_store_that_dies_after_execution_is_not_reported_as_blocked(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    """Claiming nothing ran would be a lie. The caller gets the truth instead."""
    lock = locked(store_url, clock, "complete")

    @lock.tool
    def pay(amount: float) -> str:
        calls.append(amount)
        return "txn"

    with pytest.raises(StoreUnavailable):
        pay(amount=1, _intent="i-1")
    assert calls == [1]


def test_a_guardrail_error_blocks_rather_than_leaking_through(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    class ExplodingCaps(Caps):
        def windows(self):  # type: ignore[no-untyped-def]
            raise RuntimeError("policy is corrupt")

    lock = Airlock(
        policy=Policy(caps={"pay": ExplodingCaps(max_per_day=10)}),
        store=store_url,
        clock=clock,
    )

    @lock.tool
    def pay(amount: float) -> str:
        calls.append(amount)
        return "txn"

    with pytest.raises(Blocked) as caught:
        pay(amount=1, _intent="i-1")
    assert caught.value.layer == "fail-closed"
    assert calls == []
