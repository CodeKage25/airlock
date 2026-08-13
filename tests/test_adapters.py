from __future__ import annotations

import pytest

from airlock import Caps, Policy, approval
from airlock.errors import Blocked
from tests.conftest import Clock, build_lock


def build(store_url: str, clock: Clock, calls: list[float], **policy: object):  # type: ignore[no-untyped-def]
    lock = build_lock(store_url, clock, Policy(**policy))  # type: ignore[arg-type]

    @lock.tool
    def send_payment(to: str, amount: float, currency: str = "USD") -> str:
        """Send a payment."""
        calls.append(amount)
        return f"txn_{len(calls)}"

    return lock


def test_openai_specs_describe_the_typed_surface(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    specs, _ = build(store_url, clock, calls).as_openai_tools()

    assert len(specs) == 1
    function = specs[0]["function"]
    assert function["name"] == "send_payment"
    assert function["description"] == "Send a payment."
    parameters = function["parameters"]
    assert parameters["properties"]["amount"]["type"] == "number"
    assert set(parameters["required"]) == {"to", "amount"}
    assert parameters["additionalProperties"] is False


def test_anthropic_specs_use_input_schema(store_url: str, clock: Clock, calls: list[float]) -> None:
    specs, _ = build(store_url, clock, calls).as_anthropic_tools()

    assert specs[0]["name"] == "send_payment"
    assert specs[0]["input_schema"]["properties"]["to"]["type"] == "string"


def test_the_dispatcher_executes_and_uses_the_tool_call_id_as_the_intent(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    lock = build(store_url, clock, calls)
    _, dispatch = lock.as_anthropic_tools()

    result = dispatch("send_payment", {"to": "a", "amount": 40}, tool_call_id="toolu_01")
    assert result == "txn_1"

    replayed = dispatch("send_payment", {"to": "a", "amount": 40}, tool_call_id="toolu_01")
    assert replayed == "txn_1"
    assert calls == [40]


def test_a_refusal_comes_back_as_a_tool_result_the_model_can_read(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    lock = build(store_url, clock, calls, caps={"send_payment": Caps(max_per_call=100)})
    _, dispatch = lock.as_openai_tools()

    result = dispatch("send_payment", {"to": "a", "amount": 5000}, tool_call_id="toolu_01")
    assert result["airlock"] == "blocked"
    assert result["layer"] == "caps"
    assert "max_per_call" in result["reason"]
    assert calls == []


def test_an_escalation_comes_back_with_the_request_id(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    lock = build(
        store_url,
        clock,
        calls,
        approvals=[approval.when("send_payment", lambda call: True, "needs a human")],
    )
    _, dispatch = lock.as_anthropic_tools()

    result = dispatch("send_payment", {"to": "a", "amount": 1}, tool_call_id="toolu_01")
    assert result["airlock"] == "pending_approval"
    assert result["reason"] == "needs a human"
    assert lock.approvals.get(result["request_id"]) is not None


def test_openai_style_json_string_arguments_are_accepted(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    lock = build(store_url, clock, calls)
    _, dispatch = lock.as_openai_tools()

    assert dispatch("send_payment", '{"to": "a", "amount": 40}', tool_call_id="c1") == "txn_1"


def test_malformed_arguments_are_refused_not_executed(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    lock = build(store_url, clock, calls)
    _, dispatch = lock.as_openai_tools()

    result = dispatch("send_payment", "{not json", tool_call_id="c1")
    assert result["airlock"] == "blocked"
    assert calls == []


def test_a_hallucinated_tool_name_is_refused(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    lock = build(store_url, clock, calls)
    _, dispatch = lock.as_anthropic_tools()

    result = dispatch("wire_transfer", {"to": "a"}, tool_call_id="c1")
    assert result["airlock"] == "blocked"
    assert "not registered" in result["reason"]


def test_a_call_with_no_intent_at_all_is_refused(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    lock = build(store_url, clock, calls)
    _, dispatch = lock.as_anthropic_tools()

    result = dispatch("send_payment", {"to": "a", "amount": 1})
    assert result["airlock"] == "blocked"
    assert calls == []


def test_raise_on_refusal_gives_back_the_exception(
    store_url: str, clock: Clock, calls: list[float]
) -> None:
    lock = build(store_url, clock, calls, caps={"send_payment": Caps(max_per_call=1)})
    _, dispatch = lock.as_anthropic_tools()

    with pytest.raises(Blocked):
        dispatch(
            "send_payment",
            {"to": "a", "amount": 500},
            tool_call_id="c1",
            raise_on_refusal=True,
        )
