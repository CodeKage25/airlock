"""Async tools, and proof that they are governed identically.

The decision comes from one `prepare` function that both pipelines call, so the interesting
tests are the ones that would catch the two ever drifting apart.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from airlock import Airlock, Caps, Policy, approval
from airlock.aio import AsyncAirlock
from airlock.errors import Blocked, PendingApproval, PolicyError
from tests.conftest import Clock, build_lock


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def async_lock(store_url: Any, clock: Clock, policy: Policy | None = None, **kw: Any):  # type: ignore[no-untyped-def]
    return AsyncAirlock(policy=policy or Policy(), store=store_url, clock=clock, **kw)


def test_a_sync_lock_refuses_an_async_tool(store_url: Any, clock: Clock) -> None:
    """Calling a coroutine without awaiting returns instantly without running it, which
    would audit an execution that never happened."""
    lock = build_lock(store_url, clock)

    with pytest.raises(PolicyError, match="AsyncAirlock"):

        @lock.tool
        async def pay(amount: float) -> str:
            return "txn"


def test_an_async_lock_still_takes_plain_functions(store_url: Any, clock: Clock) -> None:
    """So a codebase can migrate one tool at a time."""
    lock = async_lock(store_url, clock)

    @lock.tool
    def pay(amount: float) -> str:
        return "txn"

    assert run(pay(amount=1, _intent="i-1")) == "txn"


def test_an_async_tool_is_awaited(store_url: Any, clock: Clock) -> None:
    lock = async_lock(store_url, clock)
    ran: list[float] = []

    @lock.tool
    async def pay(amount: float) -> str:
        await asyncio.sleep(0)
        ran.append(amount)
        return "txn"

    assert run(pay(amount=1, _intent="i-1")) == "txn"
    assert ran == [1]


def test_caps_still_bind(store_url: Any, clock: Clock) -> None:
    lock = async_lock(store_url, clock, Policy(caps={"pay": Caps(max_per_call=100)}))
    ran: list[float] = []

    @lock.tool
    async def pay(amount: float) -> str:
        ran.append(amount)
        return "txn"

    with pytest.raises(Blocked) as caught:
        run(pay(amount=500, _intent="i-1"))
    assert caught.value.layer == "caps"
    assert ran == []


def test_a_retry_replays_without_awaiting_the_tool_again(store_url: Any, clock: Clock) -> None:
    lock = async_lock(store_url, clock)
    ran: list[float] = []

    @lock.tool
    async def pay(amount: float) -> str:
        ran.append(amount)
        return f"txn_{len(ran)}"

    async def scenario() -> tuple[Any, Any]:
        return await pay(amount=1, _intent="i-1"), await pay(amount=1, _intent="i-1")

    first, second = run(scenario())
    assert first == second == "txn_1"
    assert ran == [1]


def test_a_failing_async_tool_blocks_later_retries(store_url: Any, clock: Clock) -> None:
    lock = async_lock(store_url, clock)
    attempts: list[int] = []

    @lock.tool
    async def settle(amount: float) -> str:
        attempts.append(1)
        raise TimeoutError("no response from the rail")

    async def scenario() -> None:
        with pytest.raises(TimeoutError):
            await settle(amount=1, _intent="i-1")
        with pytest.raises(Blocked, match="unknown"):
            await settle(amount=1, _intent="i-1")

    run(scenario())
    assert attempts == [1]


def test_concurrent_awaits_on_one_intent_execute_once(store_url: Any, clock: Clock) -> None:
    lock = async_lock(store_url, clock)
    ran: list[int] = []

    @lock.tool
    async def pay(amount: float) -> str:
        await asyncio.sleep(0.01)
        ran.append(1)
        return "txn"

    async def scenario() -> list[Any]:
        return await asyncio.gather(
            *[pay(amount=1, _intent="burst") for _ in range(8)], return_exceptions=True
        )

    outcomes = run(scenario())
    assert len(ran) == 1
    assert sum(1 for o in outcomes if o == "txn") == 1
    assert all(o == "txn" or isinstance(o, Blocked) for o in outcomes)


def test_a_shared_budget_is_not_overspent_by_concurrent_awaits(
    store_url: Any, clock: Clock
) -> None:
    lock = async_lock(store_url, clock, Policy(caps={"pay": Caps(max_per_day=500)}))
    spent: list[float] = []

    @lock.tool
    async def pay(amount: float) -> str:
        await asyncio.sleep(0.01)
        spent.append(amount)
        return "txn"

    async def scenario() -> None:
        await asyncio.gather(
            *[pay(amount=100, _intent=f"i-{n}") for n in range(20)], return_exceptions=True
        )

    run(scenario())
    assert sum(spent) == 500


def test_approving_an_async_call_needs_the_async_path(store_url: Any, clock: Clock) -> None:
    lock = async_lock(
        store_url, clock, Policy(approvals=[approval.when("pay", lambda c: True, "needs a human")])
    )
    ran: list[float] = []

    @lock.tool
    async def pay(amount: float) -> str:
        ran.append(amount)
        return "txn"

    async def scenario() -> None:
        with pytest.raises(PendingApproval):
            await pay(amount=500, _intent="i-1")

        request = lock.approvals.pending()[0]
        with pytest.raises(TypeError, match=r"await lock\.approve"):
            request.approve(by="ops@yourco.com")

        assert await lock.approve(request.id, by="ops@yourco.com") == "txn"

    run(scenario())
    assert ran == [500]


# --------------------------------------------------------------------------- parity


SCENARIOS = [
    ("under the cap", dict(amount=10, _intent="i-1"), "executed"),
    ("over the cap", dict(amount=5_000, _intent="i-2"), "blocked"),
    ("needs a human", dict(amount=200, _intent="i-3"), "escalated"),
    ("no intent", dict(amount=10), "blocked"),
    ("bad argument", dict(amount="nonsense", _intent="i-4"), "blocked"),
]


def _outcome(thunk: Any) -> str:
    try:
        thunk()
        return "executed"
    except Blocked:
        return "blocked"
    except PendingApproval:
        return "escalated"


def test_sync_and_async_reach_the_same_verdict(store_url: Any, tmp_path: Any) -> None:
    """The two share `prepare`, and this is what fails if that ever stops being true."""
    policy = lambda: Policy(  # noqa: E731
        caps={"pay": Caps(max_per_call=1_000)},
        approvals=[approval.when("pay", lambda c: c.args["amount"] > 100, "large")],
    )

    sync = Airlock(policy=policy(), store="memory://", clock=Clock())
    asynchronous = AsyncAirlock(policy=policy(), store="memory://", clock=Clock())

    @sync.tool(name="pay")
    def pay_sync(amount: float) -> str:
        return "txn"

    @asynchronous.tool(name="pay")
    async def pay_async(amount: float) -> str:
        return "txn"

    for label, kwargs, expected in SCENARIOS:
        got_sync = _outcome(lambda k=kwargs: sync.get("pay")(**k))
        got_async = _outcome(lambda k=kwargs: run(asynchronous.get("pay")(**k)))
        assert got_sync == got_async == expected, (
            f"{label}: sync={got_sync} async={got_async} expected={expected}"
        )

    assert [e.outcome.value for e in sync.audit.query()] == [
        e.outcome.value for e in asynchronous.audit.query()
    ]
