"""Policy written as data, and the sandbox around its conditions.

A policy format that could execute arbitrary code would give away the exact property
Airlock exists to protect, so most of these tests are about what the language refuses.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

from airlock import Airlock, Policy
from airlock.core.policyfile import Expression, parse_duration
from airlock.core.types import Call
from airlock.errors import Blocked, PendingApproval, PolicyError

POLICY = """
version: 1
caps:
  send_payment:
    max_per_call: 100
    max_per_day: 1000
    currency: USD
approvals:
  - tool: send_payment
    when: amount > 50
    reason: over fifty needs a human
    ttl: 4h
  - tool: send_payment
    when: context.new_beneficiary
    reason: first payment to a new beneficiary
"""


def call(**args: Any) -> Call:
    context = args.pop("_context", {})
    return Call("pay", args, context, "i", principal=args.pop("_principal", None))


def test_a_condition_reads_arguments_and_context() -> None:
    over = Expression("amount > 100")
    assert over(call(amount=500))
    assert not over(call(amount=5))

    flagged = Expression("context.new_beneficiary")
    assert flagged(call(amount=1, _context={"new_beneficiary": True}))
    assert not flagged(call(amount=1))


def test_conditions_compose() -> None:
    rule = Expression("amount > 100 and not context.trusted")
    assert rule(call(amount=500))
    assert not rule(call(amount=500, _context={"trusted": True}))
    assert not rule(call(amount=5))


def test_the_helper_functions_work() -> None:
    assert Expression("startswith(to, 'new_')")(call(to="new_acct", amount=1))
    assert Expression("lower(currency) == 'usd'")(call(currency="USD", amount=1))
    assert Expression("matches(to, 'acct_[0-9]+')")(call(to="acct_12", amount=1))
    assert Expression("len(memo) > 3")(call(memo="hello", amount=1))


def test_a_missing_field_is_not_a_match_rather_than_a_crash() -> None:
    """A policy must not fall over because a tool grew an optional argument."""
    assert not Expression("amount > 100")(call(other=1))
    assert not Expression("context.absent")(call(amount=1))


@pytest.mark.parametrize(
    "source",
    [
        "__import__('os').system('rm -rf /')",
        "open('/etc/passwd').read()",
        "().__class__.__bases__",
        "[x for x in range(10)]",
        "exec('x = 1')",
        "globals()",
    ],
)
def test_a_condition_cannot_execute_anything(source: str) -> None:
    with pytest.raises(PolicyError):
        Expression(source)


@pytest.mark.parametrize(
    "source",
    ["tool.__class__", "context.x.__class__.__init__.__globals__", "amount.__reduce__"],
)
def test_attribute_access_cannot_walk_into_python_internals(source: str) -> None:
    """Attribute access exists for context.field. Dunders are the first step of every
    Python sandbox escape ever written, so they are refused outright."""
    with pytest.raises(PolicyError, match="not Python internals"):
        Expression(source)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("30s", timedelta(seconds=30)),
        ("15m", timedelta(minutes=15)),
        ("4h", timedelta(hours=4)),
        ("7d", timedelta(days=7)),
        ("2w", timedelta(weeks=2)),
        (90, timedelta(seconds=90)),
        (None, None),
    ],
)
def test_durations_read_the_way_people_write_them(text: Any, expected: Any) -> None:
    assert parse_duration(text) == expected


def test_a_bad_duration_says_what_is_accepted() -> None:
    with pytest.raises(PolicyError, match="30s, 15m, 4h"):
        parse_duration("4 hours")


def test_a_policy_file_enforces_exactly_as_python_would(tmp_path: Any) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(POLICY)

    lock = Airlock(policy=Policy.from_file(path))
    ran: list[float] = []

    @lock.tool
    def send_payment(to: str, amount: float, currency: str = "USD") -> str:
        ran.append(amount)
        return "txn"

    send_payment(to="a", amount=10, _intent="i-1")

    with pytest.raises(PendingApproval, match="over fifty"):
        send_payment(to="a", amount=80, _intent="i-2")
    with pytest.raises(Blocked, match="max_per_call"):
        send_payment(to="a", amount=500, _intent="i-3")
    with pytest.raises(PendingApproval, match="new beneficiary"):
        send_payment(to="a", amount=10, _intent="i-4", _context={"new_beneficiary": True})

    assert ran == [10]


def test_a_ttl_in_the_file_expires_the_request(tmp_path: Any, clock: Any) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(POLICY)
    lock = Airlock(policy=Policy.from_file(path), clock=clock)

    @lock.tool
    def send_payment(to: str, amount: float, currency: str = "USD") -> str:
        return "txn"

    with pytest.raises(PendingApproval):
        send_payment(to="a", amount=80, _intent="i-1")
    assert len(lock.approvals.pending()) == 1

    clock.advance(hours=5)
    assert lock.approvals.pending() == []


def test_an_unsupported_version_is_refused() -> None:
    with pytest.raises(PolicyError, match="version"):
        Policy.from_dict({"version": 99})


def test_an_incomplete_rule_says_what_is_missing() -> None:
    with pytest.raises(PolicyError, match="when"):
        Policy.from_dict({"approvals": [{"tool": "pay"}]})


def test_an_unknown_cap_field_is_refused_rather_than_ignored() -> None:
    """A typo in a limit must not silently enforce nothing."""
    with pytest.raises(Exception, match=r"max_per_dayy|extra"):
        Policy.from_dict({"caps": {"pay": {"max_per_dayy": 100}}})


def test_an_empty_policy_is_valid() -> None:
    policy = Policy.from_dict({"version": 1})
    assert policy.caps == {}
    assert policy.approvals == []
