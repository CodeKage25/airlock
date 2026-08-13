"""Who is acting, and what that changes.

Autonomy is earned per action class. Without a principal, one organisation's support bot
and its treasury bot share a policy and a budget, which is the opposite of that.
"""

from __future__ import annotations

from typing import Any

import pytest

from airlock import Call, Caps, Decision, Policy, approval
from airlock.errors import Blocked, PendingApproval
from tests.conftest import Clock, build_lock

SUPPORT = "agent://support-bot"
TREASURY = "agent://treasury-bot"


def payer(lock, calls):  # type: ignore[no-untyped-def]
    @lock.tool
    def pay(to: str, amount: float) -> str:
        calls.append(amount)
        return f"txn_{len(calls)}"

    return pay


def test_each_principal_gets_its_own_budget(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(
        store_url, clock, Policy(caps={"pay": Caps(max_per_day=100, scope_by="principal")})
    )
    pay = payer(lock, calls)

    pay(to="a", amount=100, _intent="i-1", _principal=SUPPORT)
    pay(to="a", amount=100, _intent="i-2", _principal=TREASURY)

    with pytest.raises(Blocked, match="support-bot"):
        pay(to="a", amount=1, _intent="i-3", _principal=SUPPORT)
    assert calls == [100, 100]


def test_a_principal_scoped_cap_refuses_an_anonymous_call(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(
        store_url, clock, Policy(caps={"pay": Caps(max_per_day=100, scope_by="principal")})
    )
    pay = payer(lock, calls)

    with pytest.raises(Blocked, match="_principal"):
        pay(to="a", amount=1, _intent="i-1")
    assert calls == []


def test_a_default_principal_covers_a_whole_service(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(
        store_url,
        clock,
        Policy(caps={"pay": Caps(max_per_day=100, scope_by="principal")}),
        principal=SUPPORT,
    )
    pay = payer(lock, calls)

    pay(to="a", amount=100, _intent="i-1")
    with pytest.raises(Blocked, match="support-bot"):
        pay(to="a", amount=1, _intent="i-2")


def test_a_call_can_override_the_default_principal(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(
        store_url,
        clock,
        Policy(caps={"pay": Caps(max_per_day=100, scope_by="principal")}),
        principal=SUPPORT,
    )
    pay = payer(lock, calls)

    pay(to="a", amount=100, _intent="i-1")
    pay(to="a", amount=100, _intent="i-2", _principal=TREASURY)
    assert calls == [100, 100]


def test_approval_rules_can_read_the_principal(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(
        store_url,
        clock,
        Policy(approvals=[approval.when("pay", lambda c: c.principal != TREASURY, "not treasury")]),
    )
    pay = payer(lock, calls)

    pay(to="a", amount=1, _intent="i-1", _principal=TREASURY)
    with pytest.raises(PendingApproval, match="not treasury"):
        pay(to="a", amount=1, _intent="i-2", _principal=SUPPORT)
    assert calls == [1]


def test_risk_hooks_can_read_the_principal(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    def only_treasury_moves_big_money(call: Call) -> Decision:
        if call.args["amount"] > 100 and call.principal != TREASURY:
            return Decision.block(f"{call.principal} may not move more than 100")
        return Decision.allow()

    lock = build_lock(store_url, clock, Policy(risk_hooks=[only_treasury_moves_big_money]))
    pay = payer(lock, calls)

    pay(to="a", amount=500, _intent="i-1", _principal=TREASURY)
    with pytest.raises(Blocked, match="support-bot"):
        pay(to="a", amount=500, _intent="i-2", _principal=SUPPORT)


def test_the_audit_log_answers_what_did_this_agent_do(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(store_url, clock, Policy(caps={"pay": Caps(max_per_call=100)}))
    pay = payer(lock, calls)

    pay(to="a", amount=10, _intent="i-1", _principal=SUPPORT)
    with pytest.raises(Blocked):
        pay(to="a", amount=500, _intent="i-2", _principal=SUPPORT)
    pay(to="a", amount=10, _intent="i-3", _principal=TREASURY)

    assert len(lock.audit.query(principal=SUPPORT)) == 4
    assert len(lock.audit.query(principal=TREASURY)) == 2
    assert {e.outcome.value for e in lock.audit.query(principal=SUPPORT)} == {
        "proposed",
        "executed",
        "blocked",
    }


def test_an_approved_call_keeps_the_principal_that_proposed_it(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    """The approver is the actor. The agent is still the principal."""
    lock = build_lock(store_url, clock, Policy(approvals=[approval.when("pay", lambda c: True)]))
    pay = payer(lock, calls)

    with pytest.raises(PendingApproval):
        pay(to="a", amount=500, _intent="i-1", _principal=SUPPORT)

    request = lock.approvals.pending()[0]
    assert request.principal == SUPPORT
    request.approve(by="ops@yourco.com")

    executed = lock.audit.query(outcome="executed")[0]
    assert executed.principal == SUPPORT
    assert executed.actor == "ops@yourco.com"


def test_principal_is_not_part_of_the_idempotency_key(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    """Two agents claiming one intent id is a collision, not two actions."""
    lock = build_lock(store_url, clock)
    pay = payer(lock, calls)

    first = pay(to="a", amount=10, _intent="inv-77", _principal=SUPPORT)
    assert pay(to="a", amount=10, _intent="inv-77", _principal=TREASURY) == first
    assert calls == [10]
