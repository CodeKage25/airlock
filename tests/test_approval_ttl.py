from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

from airlock import Policy, approval
from airlock.errors import AirlockError, PendingApproval
from tests.conftest import Clock, build_lock


def build(store_url: Any, clock: Clock, calls: list[float], rules, **kwargs):  # type: ignore[no-untyped-def]
    lock = build_lock(store_url, clock, Policy(approvals=rules), **kwargs)

    @lock.tool
    def pay(to: str, amount: float) -> str:
        calls.append(amount)
        return f"txn_{len(calls)}"

    return lock, pay


def test_a_request_past_its_deadline_leaves_the_queue(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    lock, pay = build(
        store_url,
        clock,
        calls,
        [approval.when("pay", lambda call: True, "needs a human", ttl=timedelta(hours=1))],
    )

    with pytest.raises(PendingApproval):
        pay(to="a", amount=500, _intent="i-1")
    assert len(lock.approvals.pending()) == 1

    clock.advance(hours=2)
    assert lock.approvals.pending() == []
    assert calls == []


def test_expiry_is_audited(store_url: Any, clock: Clock, calls: list[float]) -> None:
    lock, pay = build(
        store_url,
        clock,
        calls,
        [approval.when("pay", lambda call: True, ttl=timedelta(hours=1))],
    )

    with pytest.raises(PendingApproval):
        pay(to="a", amount=500, _intent="i-1")
    clock.advance(hours=2)
    lock.approvals.pending()

    expired = lock.audit.query(outcome="expired")
    assert len(expired) == 1
    assert "expired before anyone decided" in (expired[0].reason or "")


def test_an_expired_request_cannot_be_approved(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    lock, pay = build(
        store_url,
        clock,
        calls,
        [approval.when("pay", lambda call: True, ttl=timedelta(hours=1))],
    )

    with pytest.raises(PendingApproval):
        pay(to="a", amount=500, _intent="i-1")
    request = lock.approvals.pending()[0]

    clock.advance(hours=2)
    with pytest.raises(AirlockError, match="already expired"):
        request.approve(by="ops@yourco.com")
    assert calls == []


def test_a_retry_after_expiry_opens_a_fresh_request(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    lock, pay = build(
        store_url,
        clock,
        calls,
        [approval.when("pay", lambda call: True, ttl=timedelta(hours=1))],
    )

    with pytest.raises(PendingApproval) as first:
        pay(to="a", amount=500, _intent="i-1")

    clock.advance(hours=2)
    with pytest.raises(PendingApproval) as second:
        pay(to="a", amount=500, _intent="i-1")

    assert first.value.request_id != second.value.request_id
    assert len(lock.approvals.pending()) == 1


def test_a_default_ttl_applies_to_rules_that_do_not_set_one(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    lock, pay = build(
        store_url,
        clock,
        calls,
        [approval.when("pay", lambda call: True)],
        approval_ttl=timedelta(minutes=30),
    )

    with pytest.raises(PendingApproval):
        pay(to="a", amount=500, _intent="i-1")

    clock.advance(minutes=31)
    assert lock.approvals.pending() == []


def test_a_rule_ttl_overrides_the_default(store_url: Any, clock: Clock, calls: list[float]) -> None:
    lock, pay = build(
        store_url,
        clock,
        calls,
        [approval.when("pay", lambda call: True, ttl=timedelta(days=7))],
        approval_ttl=timedelta(minutes=30),
    )

    with pytest.raises(PendingApproval):
        pay(to="a", amount=500, _intent="i-1")

    clock.advance(days=1)
    assert len(lock.approvals.pending()) == 1


def test_requests_without_a_ttl_never_expire(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    lock, pay = build(store_url, clock, calls, [approval.when("pay", lambda call: True)])

    with pytest.raises(PendingApproval):
        pay(to="a", amount=500, _intent="i-1")

    clock.advance(days=365)
    assert len(lock.approvals.pending()) == 1
