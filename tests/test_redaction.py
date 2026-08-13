from __future__ import annotations

from typing import Any

from airlock import Airlock
from airlock.core.redaction import REDACTED, Redactor
from tests.conftest import Clock


def test_a_bare_name_matches_at_any_depth() -> None:
    """A secret does not stop being a secret by being nested one level deeper."""
    redactor = Redactor(["cvv"])
    assert redactor.apply({"cvv": "123", "card": {"cvv": "456", "last4": "4242"}}) == {
        "cvv": REDACTED,
        "card": {"cvv": REDACTED, "last4": "4242"},
    }


def test_a_path_matches_only_where_it_points() -> None:
    redactor = Redactor(["card.number"])
    assert redactor.apply({"number": "keep", "card": {"number": "hide"}}) == {
        "number": "keep",
        "card": {"number": REDACTED},
    }


def test_a_wildcard_covers_every_element_of_a_list() -> None:
    redactor = Redactor(["beneficiaries.*.iban"])
    assert redactor.apply(
        {"beneficiaries": [{"iban": "GB1", "name": "a"}, {"iban": "GB2", "name": "b"}]}
    ) == {"beneficiaries": [{"iban": REDACTED, "name": "a"}, {"iban": REDACTED, "name": "b"}]}


def test_nothing_configured_changes_nothing() -> None:
    assert not Redactor([])
    assert Redactor([]).apply({"a": 1}) == {"a": 1}


def test_a_nested_secret_never_reaches_the_log(store_url: Any, clock: Clock) -> None:
    lock = Airlock(store=store_url, clock=clock, audit_redact=["payload.card.number", "api_key"])

    @lock.tool
    def charge(payload: dict, api_key: str, amount: float) -> str:
        return "txn"

    charge(
        payload={"card": {"number": "4111111111111111", "expiry": "12/29"}, "ref": "inv-1"},
        api_key="sk_live_abcdef",
        amount=10,
        _intent="i-1",
    )

    for entry in lock.audit.query():
        assert entry.args["api_key"] == REDACTED
        assert entry.args["payload"]["card"]["number"] == REDACTED
        # Redaction is surgical: everything a reconciler needs is still there.
        assert entry.args["payload"]["card"]["expiry"] == "12/29"
        assert entry.args["payload"]["ref"] == "inv-1"
