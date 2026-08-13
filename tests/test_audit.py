from __future__ import annotations

import sqlite3

import pytest

from airlock import Airlock, Caps, Policy
from airlock.errors import Blocked
from tests.conftest import Clock, build_lock


def test_every_execution_is_recorded_as_intent_then_outcome(store_url: str, clock: Clock) -> None:
    lock = build_lock(store_url, clock)

    @lock.tool
    def pay(amount: float) -> str:
        return "txn"

    pay(amount=10, _intent="i-1")
    assert [entry.outcome.value for entry in lock.audit.query()] == ["proposed", "executed"]


def test_a_block_records_the_deciding_layer_and_reason(store_url: str, clock: Clock) -> None:
    lock = build_lock(store_url, clock, Policy(caps={"pay": Caps(max_per_call=10)}))

    @lock.tool
    def pay(amount: float) -> str:
        return "txn"

    with pytest.raises(Blocked):
        pay(amount=99, _intent="i-1")

    blocked = lock.audit.query(outcome="blocked")
    assert len(blocked) == 1
    assert blocked[0].layer == "caps"
    assert "max_per_call" in (blocked[0].reason or "")
    assert blocked[0].intent == "i-1"


def test_redacted_arguments_never_reach_the_log(store_url: str, clock: Clock) -> None:
    lock = Airlock(store=store_url, clock=clock, audit_redact=["card_number"])

    @lock.tool
    def charge(card_number: str, amount: float) -> str:
        return "txn"

    charge(card_number="4111111111111111", amount=10, _intent="i-1")

    for entry in lock.audit.query():
        assert entry.args["card_number"] == "***"
        assert entry.args["amount"] == "10"


def test_the_log_can_be_queried_by_tool_intent_and_outcome(store_url: str, clock: Clock) -> None:
    lock = build_lock(store_url, clock, Policy(caps={"pay": Caps(max_per_call=10)}))

    @lock.tool
    def pay(amount: float) -> str:
        return "txn"

    @lock.tool
    def notify(to: str) -> str:
        return "sent"

    pay(amount=5, _intent="i-1")
    notify(to="ops", _intent="i-2")
    with pytest.raises(Blocked):
        pay(amount=50, _intent="i-3")

    assert len(lock.audit.query(tool="pay")) == 4
    assert len(lock.audit.query(tool="notify")) == 2
    assert len(lock.audit.query(intent="i-3")) == 2
    assert len(lock.audit.query(outcome="executed")) == 2
    assert len(lock.audit.query(outcome="blocked")) == 1


def test_the_log_can_be_queried_by_time_range(store_url: str, clock: Clock) -> None:
    lock = build_lock(store_url, clock)

    @lock.tool
    def pay(amount: float) -> str:
        return "txn"

    pay(amount=1, _intent="i-1")
    boundary = clock.now
    clock.advance(hours=1)
    pay(amount=1, _intent="i-2")

    assert len(lock.audit.query()) == 4
    assert {entry.intent for entry in lock.audit.query(until=boundary)} == {"i-1"}
    assert {entry.intent for entry in lock.audit.query(since=clock.now)} == {"i-2"}


def test_a_crash_mid_execution_leaves_an_intent_without_an_outcome(
    store_url: str, clock: Clock
) -> None:
    lock = build_lock(store_url, clock)

    @lock.tool
    def pay(amount: float) -> str:
        raise TimeoutError("no response")

    with pytest.raises(TimeoutError):
        pay(amount=1, _intent="i-1")

    outcomes = [entry.outcome.value for entry in lock.audit.query(intent="i-1")]
    assert outcomes == ["proposed", "failed"]


def test_sqlite_refuses_to_rewrite_history(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "airlock.db"
    lock = Airlock(store=f"sqlite:///{path}")

    @lock.tool
    def pay(amount: float) -> str:
        return "txn"

    pay(amount=1, _intent="i-1")
    lock.close()

    conn = sqlite3.connect(path)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("UPDATE audit SET reason = 'nothing to see here'")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("DELETE FROM audit")
    conn.close()


def test_the_log_survives_the_process(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "airlock.db"

    def pay(amount: float) -> str:
        return "txn"

    first = Airlock(store=f"sqlite:///{path}")
    first.tool(pay)(amount=1, _intent="i-1")
    first.close()

    second = Airlock(store=f"sqlite:///{path}")
    assert [entry.outcome.value for entry in second.audit.query()] == ["proposed", "executed"]
    second.close()
