from __future__ import annotations

from typing import Any

import pytest

from airlock import Airlock, Policy, approval
from airlock.cli import main
from airlock.core.stores import migrations
from airlock.errors import Blocked

APP_MODULE = "tests.cli_app"


def sqlite_url(tmp_path: Any) -> str:
    return f"sqlite:///{tmp_path / 'airlock.db'}"


def test_stuck_intents_can_be_listed_and_resolved(tmp_path: Any, capsys: Any) -> None:
    url = sqlite_url(tmp_path)
    lock = Airlock(store=url)

    @lock.tool
    def settle(amount: float) -> str:
        raise TimeoutError("no response from the rail")

    with pytest.raises(TimeoutError):
        settle(amount=500, _intent="inv-88")
    lock.close()

    assert main(["--store", url, "intents", "stuck"]) == 0
    listing = capsys.readouterr().out
    assert "inv-88" in listing
    assert "failed" in listing

    # Whatever the listing printed is what an operator will paste back, abbreviated
    # or not, so that is what the next command has to accept.
    key = listing.splitlines()[2].split()[0]

    assert (
        main(
            [
                "--store",
                url,
                "intents",
                "resolve",
                key,
                "--not-executed",
                "--by",
                "ops@yourco.com",
                "--note",
                "rail shows nothing",
            ]
        )
        == 0
    )
    assert "did not execute" in capsys.readouterr().out

    assert main(["--store", url, "intents", "stuck"]) == 0
    assert "no stuck intents" in capsys.readouterr().out


def test_resolve_demands_exactly_one_verdict(tmp_path: Any) -> None:
    url = sqlite_url(tmp_path)
    Airlock(store=url).close()

    with pytest.raises(SystemExit, match="exactly one"):
        main(["--store", url, "intents", "resolve", "k", "--by", "ops@yourco.com"])
    with pytest.raises(SystemExit, match="exactly one"):
        main(
            [
                "--store",
                url,
                "intents",
                "resolve",
                "k",
                "--executed",
                "--not-executed",
                "--by",
                "ops@yourco.com",
            ]
        )


def test_pending_approvals_can_be_listed_and_rejected(tmp_path: Any, capsys: Any) -> None:
    url = sqlite_url(tmp_path)
    executed: list[float] = []
    lock = Airlock(
        policy=Policy(approvals=[approval.when("pay", lambda call: True, "needs a human")]),
        store=url,
    )

    @lock.tool
    def pay(amount: float) -> str:
        executed.append(amount)
        return "txn"

    with pytest.raises(Exception, match="approval required"):
        pay(amount=500, _intent="i-1")
    request_id = lock.approvals.pending()[0].id
    lock.close()

    assert main(["--store", url, "approvals", "pending"]) == 0
    assert "needs a human" in capsys.readouterr().out

    assert main(["--store", url, "approvals", "reject", request_id, "--reason", "wrong acct"]) == 0
    assert "wrong acct" in capsys.readouterr().out
    assert executed == []


def test_approving_needs_the_application_object(tmp_path: Any) -> None:
    url = sqlite_url(tmp_path)
    Airlock(store=url).close()

    with pytest.raises(SystemExit, match="--app"):
        main(["--store", url, "approvals", "approve", "abc", "--by", "ops@yourco.com"])


def test_the_audit_log_is_queryable_from_the_shell(tmp_path: Any, capsys: Any) -> None:
    url = sqlite_url(tmp_path)
    lock = Airlock(store=url)

    @lock.tool
    def pay(amount: float) -> str:
        return "txn"

    pay(amount=1, _intent="i-1")
    lock.close()

    assert main(["--store", url, "audit", "--outcome", "executed"]) == 0
    out = capsys.readouterr().out
    assert "i-1" in out and "executed" in out


def test_the_schema_version_is_reportable(tmp_path: Any, capsys: Any) -> None:
    url = sqlite_url(tmp_path)
    Airlock(store=url).close()

    assert main(["--store", url, "migrate"]) == 0
    # Not hardcoded: a new migration must not break this test.
    assert f"schema version {migrations.CURRENT}" in capsys.readouterr().out


def test_a_missing_store_is_a_clear_error() -> None:
    with pytest.raises(SystemExit, match="AIRLOCK_STORE"):
        main(["intents", "stuck"])


def test_an_airlock_error_becomes_a_nonzero_exit(tmp_path: Any, capsys: Any) -> None:
    url = sqlite_url(tmp_path)
    Airlock(store=url).close()

    code = main(
        ["--store", url, "intents", "resolve", "missing", "--executed", "--by", "ops@yourco.com"]
    )
    assert code == 1
    assert "no reservation" in capsys.readouterr().err


def test_blocked_is_importable_for_downstream_handlers() -> None:
    assert issubclass(Blocked, Exception)
