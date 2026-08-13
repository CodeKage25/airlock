from __future__ import annotations

import pytest

from airlock import Call, Decision, Policy
from airlock.errors import Blocked, PendingApproval, PolicyError
from tests.conftest import Clock, build_lock


def build(store_url: str, clock: Clock, calls: list[float], *hooks: object):  # type: ignore[no-untyped-def]
    lock = build_lock(store_url, clock, Policy(risk_hooks=list(hooks)))  # type: ignore[arg-type]

    @lock.tool
    def pay(to: str, amount: float) -> str:
        calls.append(amount)
        return "txn"

    return lock, pay


def test_a_hook_can_block(store_url: str, clock: Clock, calls: list[float]) -> None:
    def fraud(call: Call) -> Decision:
        if call.args["to"] == "acct_evil":
            return Decision.block("fraud score above threshold")
        return Decision.allow()

    _, pay = build(store_url, clock, calls, fraud)

    pay(to="acct_good", amount=1, _intent="i-1")
    with pytest.raises(Blocked) as caught:
        pay(to="acct_evil", amount=1, _intent="i-2")
    assert caught.value.layer == "risk"
    assert caught.value.reason == "fraud score above threshold"
    assert calls == [1]


def test_a_hook_can_escalate(store_url: str, clock: Clock, calls: list[float]) -> None:
    def out_of_hours(call: Call) -> Decision:
        return Decision.escalate("outside business hours")

    lock, pay = build(store_url, clock, calls, out_of_hours)

    with pytest.raises(PendingApproval, match="outside business hours"):
        pay(to="a", amount=1, _intent="i-1")
    assert calls == []
    assert len(lock.approvals.pending()) == 1


def test_the_first_non_allow_wins(store_url: str, clock: Clock, calls: list[float]) -> None:
    seen: list[str] = []

    def first(call: Call) -> Decision:
        seen.append("first")
        return Decision.block("first said no")

    def second(call: Call) -> Decision:
        seen.append("second")
        return Decision.allow()

    _, pay = build(store_url, clock, calls, first, second)

    with pytest.raises(Blocked, match="first said no"):
        pay(to="a", amount=1, _intent="i-1")
    assert seen == ["first"]


def test_a_hook_that_raises_is_a_block(store_url: str, clock: Clock, calls: list[float]) -> None:
    def broken(call: Call) -> Decision:
        raise ConnectionError("fraud service down")

    _, pay = build(store_url, clock, calls, broken)

    with pytest.raises(Blocked) as caught:
        pay(to="a", amount=1, _intent="i-1")
    assert caught.value.layer == "risk"
    assert "fraud service down" in caught.value.reason
    assert calls == []


def test_a_hook_returning_junk_is_a_block(store_url: str, clock: Clock, calls: list[float]) -> None:
    _, pay = build(store_url, clock, calls, lambda call: True)

    with pytest.raises(Blocked, match="not a Decision"):
        pay(to="a", amount=1, _intent="i-1")
    assert calls == []


def test_async_hooks_are_refused_at_configuration_time() -> None:
    async def hook(call: Call) -> Decision:
        return Decision.allow()

    with pytest.raises(PolicyError, match="async"):
        Policy(risk_hooks=[hook])  # type: ignore[list-item]
