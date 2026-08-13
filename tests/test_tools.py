from __future__ import annotations

import pytest

from airlock import Airlock, Caps, Policy
from airlock.errors import Blocked, PolicyError
from tests.conftest import Clock, build_lock


def test_unregistered_tools_have_no_path_to_execution(store_url: str, clock: Clock) -> None:
    lock = build_lock(store_url, clock)
    with pytest.raises(PolicyError):
        lock.get("send_payment")


def test_untyped_argument_surface_is_rejected_at_registration(store_url: str, clock: Clock) -> None:
    lock = build_lock(store_url, clock)
    with pytest.raises(PolicyError, match="unbounded argument surface"):

        @lock.tool
        def anything(**kwargs: object) -> None: ...


def test_reserved_parameter_names_are_rejected(store_url: str, clock: Clock) -> None:
    lock = build_lock(store_url, clock)
    with pytest.raises(PolicyError, match="reserved"):

        @lock.tool
        def pay(_intent: str) -> None: ...


def test_registering_the_same_name_twice_is_refused(store_url: str, clock: Clock) -> None:
    lock = build_lock(store_url, clock)

    @lock.tool(name="pay")
    def pay_one(amount: float) -> str:
        return "one"

    with pytest.raises(PolicyError, match="already registered"):

        @lock.tool(name="pay")
        def pay_two(amount: float) -> str:
            return "two"


def test_unknown_arguments_never_reach_the_function(
    store_url: str, clock: Clock, calls: list[dict[str, object]]
) -> None:
    lock = build_lock(store_url, clock)

    @lock.tool
    def pay(to: str, amount: float) -> str:
        calls.append({"to": to})
        return "ok"

    with pytest.raises(Blocked) as caught:
        pay(to="a", amount=1, override_limit=True, _intent="i-1")  # type: ignore[call-arg]
    assert caught.value.layer == "tool"
    assert calls == []


def test_ill_typed_arguments_are_blocked(
    store_url: str, clock: Clock, calls: list[dict[str, object]]
) -> None:
    lock = build_lock(store_url, clock)

    @lock.tool
    def pay(to: str, amount: float) -> str:
        calls.append({"amount": amount})
        return "ok"

    with pytest.raises(Blocked) as caught:
        pay(to="a", amount="not-a-number", _intent="i-1")
    assert caught.value.layer == "tool"
    assert calls == []


def test_a_call_without_an_intent_does_not_execute(
    store_url: str, clock: Clock, calls: list[dict[str, object]]
) -> None:
    lock = build_lock(store_url, clock)

    @lock.tool
    def pay(amount: float) -> str:
        calls.append({"amount": amount})
        return "ok"

    with pytest.raises(Blocked, match="_intent"):
        pay(amount=1)
    assert calls == []


def test_defaults_are_applied_before_the_layers_see_the_call(store_url: str, clock: Clock) -> None:
    lock = build_lock(
        store_url, clock, Policy(caps={"pay": Caps(max_per_call=100, currency="USD")})
    )

    @lock.tool
    def pay(amount: float, currency: str = "USD") -> str:
        return currency

    assert pay(amount=10, _intent="i-1") == "USD"


def test_a_cap_naming_an_unregistered_tool_is_loud(store_url: str, clock: Clock) -> None:
    lock = Airlock(
        policy=Policy(caps={"send_paymnet": Caps(max_per_call=1)}),
        store=store_url,
        clock=clock,
    )

    @lock.tool
    def send_payment(amount: float) -> str:
        return "ok"

    with pytest.raises(PolicyError, match="enforce nothing"):
        lock.tools()


def test_fail_open_cannot_be_configured(store_url: str, clock: Clock) -> None:
    with pytest.raises(PolicyError, match="no fail-open mode"):
        Airlock(store=store_url, clock=clock, fail_mode="open")
