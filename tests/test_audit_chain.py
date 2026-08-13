"""Tamper-evidence.

Triggers stop the application rewriting history. The chain is for everyone else: it does
not prevent a rewrite, it makes one impossible to hide.
"""

from __future__ import annotations

import sqlite3
from itertools import pairwise
from typing import Any

import pytest

from airlock import Airlock, Caps, Policy
from airlock.errors import Blocked
from tests.conftest import Clock, build_lock


def chained(store_url: Any, clock: Clock, **kwargs: Any) -> Airlock:
    return build_lock(store_url, clock, audit_chain=True, **kwargs)


def test_an_untouched_log_verifies(store_url: Any, clock: Clock) -> None:
    lock = chained(store_url, clock, policy=Policy(caps={"pay": Caps(max_per_call=100)}))

    @lock.tool
    def pay(amount: float) -> str:
        return "txn"

    for n in range(5):
        pay(amount=10, _intent=f"i-{n}")
    with pytest.raises(Blocked):
        pay(amount=500, _intent="i-big")

    report = lock.audit.verify()
    assert report.intact
    assert bool(report) is True
    assert report.checked == 12


def test_every_entry_links_to_the_one_before_it(store_url: Any, clock: Clock) -> None:
    lock = chained(store_url, clock)

    @lock.tool
    def pay(amount: float) -> str:
        return "txn"

    pay(amount=1, _intent="i-1")
    pay(amount=1, _intent="i-2")

    entries = lock.audit.query()
    assert entries[0].prev_hash is None
    for earlier, later in pairwise(entries):
        assert later.prev_hash == earlier.entry_hash
    assert len({e.entry_hash for e in entries}) == len(entries)


def test_altering_a_record_is_detected(tmp_path: Any) -> None:
    """The triggers block the application. This is what catches whoever gets past them."""
    path = tmp_path / "airlock.db"
    lock = Airlock(store=f"sqlite:///{path}", audit_chain=True)

    @lock.tool
    def pay(amount: float) -> str:
        return "txn"

    pay(amount=10, _intent="i-1")
    pay(amount=10, _intent="i-2")
    assert lock.audit.verify().intact
    lock.close()

    conn = sqlite3.connect(path)
    conn.execute("DROP TRIGGER audit_no_update")  # the attacker owns the table
    conn.execute("UPDATE audit SET reason = 'nothing happened' WHERE outcome = 'executed'")
    conn.commit()
    conn.close()

    report = Airlock(store=f"sqlite:///{path}", audit_chain=True).audit.verify()
    assert not report.intact
    assert "altered" in (report.detail or "")
    assert report.broken_at


def test_removing_a_record_is_detected(tmp_path: Any) -> None:
    path = tmp_path / "airlock.db"
    lock = Airlock(store=f"sqlite:///{path}", audit_chain=True)

    @lock.tool
    def pay(amount: float) -> str:
        return "txn"

    pay(amount=10, _intent="i-1")
    pay(amount=10, _intent="i-2")
    lock.close()

    conn = sqlite3.connect(path)
    conn.execute("DROP TRIGGER audit_no_delete")
    conn.execute("DELETE FROM audit WHERE outcome = 'executed'")
    conn.commit()
    conn.close()

    report = Airlock(store=f"sqlite:///{path}", audit_chain=True).audit.verify()
    assert not report.intact
    assert "removed" in (report.detail or "")


def test_chaining_is_off_by_default_and_says_so(store_url: Any, clock: Clock) -> None:
    """It costs a serialisation point per write, so it is not free and not default."""
    lock = build_lock(store_url, clock)

    @lock.tool
    def pay(amount: float) -> str:
        return "txn"

    pay(amount=1, _intent="i-1")

    assert lock.audit.query()[0].entry_hash is None
    report = lock.audit.verify()
    assert not report.intact
    assert "chaining is off" in (report.detail or "")


def test_switching_chaining_on_later_is_reported_honestly(tmp_path: Any) -> None:
    path = tmp_path / "airlock.db"

    plain = Airlock(store=f"sqlite:///{path}")

    @plain.tool
    def pay(amount: float) -> str:
        return "txn"

    pay(amount=1, _intent="before")
    plain.close()

    later = Airlock(store=f"sqlite:///{path}", audit_chain=True)
    report = later.audit.verify()
    assert not report.intact
    assert "before chaining was switched on" in (report.detail or "")
    later.close()
