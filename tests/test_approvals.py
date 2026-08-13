from __future__ import annotations

import pytest

from airlock import Caps, Policy, approval
from airlock.errors import AirlockError, Blocked, PendingApproval
from tests.conftest import Clock, build_lock


def build(store_url: str, clock: Clock, calls: list[float], **policy: object):  # type: ignore[no-untyped-def]
    lock = build_lock(store_url, clock, Policy(**policy))  # type: ignore[arg-type]

    @lock.tool
    def pay(to: str, amount: float) -> str:
        calls.append(amount)
        return f"txn_{len(calls)}"

    return lock, pay


def test_a_matching_rule_parks_the_call_without_executing(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    lock, pay = build(
        store_url,
        clock,
        calls,
        approvals=[approval.when("pay", lambda call: call.args["amount"] > 100, "over 100")],
    )

    with pytest.raises(PendingApproval) as caught:
        pay(to="a", amount=500, _intent="i-1")
    assert caught.value.reason == "over 100"
    assert calls == []
    assert len(lock.approvals.pending()) == 1


def test_context_drives_approval_without_reaching_the_model(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    _, pay = build(
        store_url,
        clock,
        calls,
        approvals=[approval.when("pay", lambda call: bool(call.context.get("new_beneficiary")))],
    )

    pay(to="known", amount=10, _intent="i-1")
    with pytest.raises(PendingApproval):
        pay(to="new", amount=10, _intent="i-2", _context={"new_beneficiary": True})
    assert calls == [10]


def test_approving_executes_the_original_call(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    lock, pay = build(store_url, clock, calls, approvals=[approval.when("pay", lambda call: True)])

    with pytest.raises(PendingApproval):
        pay(to="a", amount=500, _intent="i-1")

    request = lock.approvals.pending()[0]
    assert request.approve(by="ops@yourco.com") == "txn_1"
    assert calls == [500]
    assert lock.approvals.pending() == []


def test_rejecting_never_executes(store_url: str, clock: Clock, calls: list[float]) -> None:
    lock, pay = build(store_url, clock, calls, approvals=[approval.when("pay", lambda call: True)])

    with pytest.raises(PendingApproval):
        pay(to="a", amount=500, _intent="i-1")

    lock.approvals.pending()[0].reject(reason="wrong beneficiary")
    assert calls == []
    assert lock.approvals.pending() == []


def test_caps_are_rechecked_at_approval_time(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    """A request can sit in the queue long enough for the budget to be spent elsewhere."""
    lock, pay = build(
        store_url,
        clock,
        calls,
        caps={"pay": Caps(max_per_day=100)},
        approvals=[approval.when("pay", lambda call: call.args["to"] == "new")],
    )

    with pytest.raises(PendingApproval):
        pay(to="new", amount=60, _intent="i-1")

    pay(to="known", amount=60, _intent="i-2")

    with pytest.raises(Blocked, match="max_per_day"):
        lock.approvals.pending()[0].approve(by="ops@yourco.com")
    assert calls == [60]


def test_a_request_cannot_be_approved_twice(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    lock, pay = build(store_url, clock, calls, approvals=[approval.when("pay", lambda call: True)])

    with pytest.raises(PendingApproval):
        pay(to="a", amount=500, _intent="i-1")

    request = lock.approvals.pending()[0]
    request.approve(by="ops@yourco.com")
    with pytest.raises(AirlockError, match="already approved"):
        request.approve(by="someone-else@yourco.com")
    assert calls == [500]


def test_a_retrying_agent_does_not_flood_the_queue(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    lock, pay = build(store_url, clock, calls, approvals=[approval.when("pay", lambda call: True)])

    ids = set()
    for _ in range(5):
        with pytest.raises(PendingApproval) as caught:
            pay(to="a", amount=500, _intent="i-1")
        ids.add(caught.value.request_id)

    assert len(ids) == 1
    assert len(lock.approvals.pending()) == 1


def test_a_rule_that_raises_blocks_rather_than_letting_the_call_through(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    def broken(call: object) -> bool:
        raise KeyError("beneficiary")

    _, pay = build(store_url, clock, calls, approvals=[approval.when("pay", broken)])

    with pytest.raises(Blocked) as caught:
        pay(to="a", amount=1, _intent="i-1")
    assert caught.value.layer == "approvals"
    assert calls == []


def test_approval_is_audited_with_the_approver(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    lock, pay = build(store_url, clock, calls, approvals=[approval.when("pay", lambda call: True)])

    with pytest.raises(PendingApproval):
        pay(to="a", amount=500, _intent="i-1")
    lock.approvals.pending()[0].approve(by="ops@yourco.com")

    executed = lock.audit.query(outcome="executed")
    assert [entry.actor for entry in executed] == ["ops@yourco.com"]
