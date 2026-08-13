"""Observe-only mode, and the lines it refuses to cross.

Shadow mode is only safe to switch on if it relaxes judgement and nothing else. Most of
these tests exist to prove the parts it must *not* relax.
"""

from __future__ import annotations

from typing import Any

import pytest

from airlock import Airlock, Call, Caps, Decision, Mode, Policy, approval
from airlock.errors import Blocked
from tests.conftest import BrokenStore, Clock, build_lock, make_store


def shadowed(store_url: Any, clock: Clock, calls: list[float], **policy: Any):  # type: ignore[no-untyped-def]
    lock = build_lock(store_url, clock, Policy(**policy), mode="shadow")

    @lock.tool
    def pay(to: str, amount: float) -> str:
        calls.append(amount)
        return f"txn_{len(calls)}"

    return lock, pay


def test_a_call_the_policy_would_block_still_runs(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    lock, pay = shadowed(store_url, clock, calls, caps={"pay": Caps(max_per_call=100)})

    assert pay(to="a", amount=5_000, _intent="i-1") == "txn_1"
    assert calls == [5_000]

    report = lock.shadow.report()
    assert report.would_block == 1
    assert "max_per_call" in report.findings[0].reason


def test_a_call_the_policy_would_escalate_still_runs_and_parks_nothing(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    lock, pay = shadowed(
        store_url, clock, calls, approvals=[approval.when("pay", lambda c: True, "needs a human")]
    )

    assert pay(to="a", amount=500, _intent="i-1") == "txn_1"
    # Filling the queue during a soak means a backlog nobody agreed to work.
    assert lock.approvals.pending() == []
    assert lock.shadow.report().would_escalate == 1


def test_a_risk_hook_block_is_observed_not_applied(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    def fraud(call: Call) -> Decision:
        return Decision.block("fraud score above threshold")

    lock, pay = shadowed(store_url, clock, calls, risk_hooks=[fraud])

    assert pay(to="a", amount=1, _intent="i-1") == "txn_1"
    assert lock.shadow.report().findings[0].layer == "risk"


# --------------------------------------------------------------- what it must not relax


def test_idempotency_still_enforces_in_shadow_mode(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    """The one thing shadow mode must never do is let a duplicate through.

    Doing it during a soak period would cause the exact double payment the library
    exists to prevent, at the moment everyone believed nothing was at risk.
    """
    _, pay = shadowed(store_url, clock, calls, caps={"pay": Caps(max_per_call=100)})

    first = pay(to="a", amount=5_000, _intent="i-1")
    for _ in range(4):
        assert pay(to="a", amount=5_000, _intent="i-1") == first
    assert calls == [5_000]


def test_a_mutated_retry_is_still_blocked_in_shadow_mode(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    _, pay = shadowed(store_url, clock, calls)

    pay(to="a", amount=40, _intent="i-1")
    with pytest.raises(Blocked) as caught:
        pay(to="attacker", amount=40, _intent="i-1")
    assert caught.value.layer == "idempotency"
    assert calls == [40]


def test_an_unknown_outcome_still_blocks_retries_in_shadow_mode(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(store_url, clock, mode="shadow")

    @lock.tool
    def settle(amount: float) -> str:
        calls.append(amount)
        raise TimeoutError("no response from the rail")

    with pytest.raises(TimeoutError):
        settle(amount=500, _intent="i-1")
    with pytest.raises(Blocked, match="unknown"):
        settle(amount=500, _intent="i-1")
    assert calls == [500]


def test_the_tool_layer_still_enforces_in_shadow_mode(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    """Arguments that fail validation cannot be passed to the function, so there is
    nothing to observe."""
    _, pay = shadowed(store_url, clock, calls)

    with pytest.raises(Blocked) as caught:
        pay(to="a", amount="not-a-number", _intent="i-1")
    assert caught.value.layer == "tool"

    with pytest.raises(Blocked, match="_intent"):
        pay(to="a", amount=1)
    assert calls == []


def test_shadow_mode_still_fails_closed(store_url: Any, clock: Clock, calls: list[float]) -> None:
    """An unreachable store means idempotency cannot be checked, and that is not optional."""
    store = BrokenStore(make_store(store_url), "reserve")
    lock = Airlock(store=store, clock=clock, mode="shadow")

    @lock.tool
    def pay(amount: float) -> str:
        calls.append(amount)
        return "txn"

    with pytest.raises(Blocked) as caught:
        pay(amount=1, _intent="i-1")
    assert caught.value.layer == "fail-closed"
    assert calls == []


def test_spend_is_still_ledgered_so_windows_stay_truthful(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    """A call shadow mode allowed really did spend the money."""
    lock, pay = shadowed(store_url, clock, calls, caps={"pay": Caps(max_per_day=100)})

    for n in range(3):
        pay(to="a", amount=100, _intent=f"i-{n}")

    assert calls == [100, 100, 100]
    report = lock.shadow.report()

    # The first call is within budget. The second and third are over a window that kept
    # counting, which is the point: shadow mode ledgers what it lets through.
    assert report.would_block == 2
    # Both breaches are one problem with one fix, so they are one line, not two.
    assert len(report.findings) == 1
    assert report.findings[0].rule == "max_per_day"
    assert "300" in report.findings[0].reason


def test_one_call_tripping_two_rules_counts_as_one_stopped_call(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    lock, pay = shadowed(
        store_url,
        clock,
        calls,
        caps={"pay": Caps(max_per_call=10)},
        approvals=[approval.when("pay", lambda c: True, "needs a human")],
    )

    pay(to="a", amount=500, _intent="i-1")

    report = lock.shadow.report()
    assert report.verdicts == 2
    assert report.affected == 1


# ------------------------------------------------------------------------- graduation


def test_one_tool_can_enforce_while_another_is_observed(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(
        store_url,
        clock,
        Policy(caps={"pay": Caps(max_per_call=10), "refund": Caps(max_per_call=10)}),
        mode="shadow",
    )

    @lock.tool(mode="enforce")
    def pay(amount: float) -> str:
        calls.append(amount)
        return "paid"

    @lock.tool
    def refund(amount: float) -> str:
        calls.append(amount)
        return "refunded"

    with pytest.raises(Blocked):
        pay(amount=500, _intent="i-1")
    assert refund(amount=500, _intent="i-2") == "refunded"
    assert calls == [500]


def test_a_tool_can_be_observed_inside_an_enforcing_lock(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(store_url, clock, Policy(caps={"pay": Caps(max_per_call=10)}))

    @lock.tool(mode="shadow")
    def pay(amount: float) -> str:
        calls.append(amount)
        return "paid"

    assert pay(amount=500, _intent="i-1") == "paid"
    assert lock.shadow.report().would_block == 1


def test_enforce_is_the_default(store_url: Any, clock: Clock, calls: list[float]) -> None:
    lock = build_lock(store_url, clock, Policy(caps={"pay": Caps(max_per_call=10)}))

    @lock.tool
    def pay(amount: float) -> str:
        calls.append(amount)
        return "paid"

    with pytest.raises(Blocked):
        pay(amount=500, _intent="i-1")
    assert lock.mode is Mode.ENFORCE


# ----------------------------------------------------------------------------- report


def test_the_report_groups_by_reason_and_counts(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    lock, pay = shadowed(store_url, clock, calls, caps={"pay": Caps(max_per_call=100)})

    for n in range(3):
        pay(to="a", amount=5_000, _intent=f"over-{n}")
    for n in range(2):
        pay(to="a", amount=10, _intent=f"fine-{n}")

    report = lock.shadow.report()
    assert len(report.findings) == 1
    assert report.findings[0].count == 3
    assert report.executed == 5
    assert report.by_layer() == {"caps": 3}
    assert "over-0" in report.findings[0].intents


def test_a_clean_report_says_the_policy_is_ready(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    lock, pay = shadowed(store_url, clock, calls, caps={"pay": Caps(max_per_call=100)})

    pay(to="a", amount=10, _intent="i-1")

    report = lock.shadow.report()
    assert report.clean
    assert "ready to enforce" in report.render()


def test_the_report_can_be_scoped_to_one_tool(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(
        store_url,
        clock,
        Policy(caps={"pay": Caps(max_per_call=10), "refund": Caps(max_per_call=10)}),
        mode="shadow",
    )

    @lock.tool
    def pay(amount: float) -> str:
        return "paid"

    @lock.tool
    def refund(amount: float) -> str:
        return "refunded"

    pay(amount=500, _intent="i-1")
    refund(amount=500, _intent="i-2")

    assert lock.shadow.report().would_block == 2
    assert lock.shadow.report(tool="pay").would_block == 1
    assert lock.shadow.report(tool="pay").findings[0].tool == "pay"


def test_shadow_verdicts_are_in_the_audit_log(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    lock, pay = shadowed(store_url, clock, calls, caps={"pay": Caps(max_per_call=100)})

    pay(to="a", amount=5_000, _intent="i-1")

    outcomes = [e.outcome.value for e in lock.audit.query(intent="i-1")]
    assert outcomes == ["proposed", "would_block", "executed"]


def test_an_enforcing_lock_reports_nothing(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    lock = build_lock(store_url, clock, Policy(caps={"pay": Caps(max_per_call=10)}))

    @lock.tool
    def pay(amount: float) -> str:
        return "paid"

    with pytest.raises(Blocked):
        pay(amount=500, _intent="i-1")

    assert lock.shadow.report().clean
