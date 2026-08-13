"""The two adapters that widen who can use this.

MCP is the answer to "does it work with my language": over the protocol the guardrail is a
service, and the agent can be anything. LangChain is the answer to "does it work with my
framework".
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from airlock import Caps, Policy, approval
from airlock.adapters.mcp import refusal
from airlock.errors import Blocked, PendingApproval
from tests.conftest import Clock, build_lock

mcp = pytest.importorskip("mcp", reason="MCP is an optional extra")


def build(store_url: Any, clock: Clock, calls: list[float], **policy: Any):  # type: ignore[no-untyped-def]
    lock = build_lock(store_url, clock, Policy(**policy))

    @lock.tool
    def send_payment(to: str, amount: float) -> str:
        """Send a payment."""
        calls.append(amount)
        return f"txn_{len(calls)}"

    return lock


def test_a_block_becomes_a_result_the_model_can_read() -> None:
    """Raising over the wire is a transport error and teaches the model nothing."""
    payload = refusal(Blocked("500 exceeds max_per_call of 100", layer="caps"))

    assert payload["airlock"] == "blocked"
    assert payload["layer"] == "caps"
    assert "max_per_call" in payload["reason"]
    assert "will not succeed on retry" in payload["guidance"]


def test_an_escalation_tells_the_model_not_to_retry() -> None:
    payload = refusal(PendingApproval("abc123", "needs a human"))

    assert payload["airlock"] == "pending_approval"
    assert payload["request_id"] == "abc123"
    assert "Do not retry" in payload["guidance"]


def test_the_server_exposes_every_registered_tool(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    from airlock.adapters.mcp import build as build_server

    lock = build(store_url, clock, calls)
    server = build_server(lock)

    import asyncio

    tools = asyncio.run(server.list_tools())
    names = {tool.name for tool in tools}
    assert "send_payment" in names
    assert "airlock_status" in names

    described = next(t for t in tools if t.name == "send_payment")
    assert "Send a payment." in (described.description or "")
    # The model has to be told what an intent is for, or it invents a new one per retry.
    assert "retrying the same" in (described.description or "")


def test_the_server_refuses_a_policy_that_enforces_nothing(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    from airlock.adapters.mcp import build as build_server
    from airlock.errors import PolicyError

    lock = build(store_url, clock, calls, caps={"typo_tool": Caps(max_per_call=1)})
    with pytest.raises(PolicyError, match="enforce nothing"):
        build_server(lock)


# ------------------------------------------------------------------------- langchain


def test_langchain_tools_carry_the_typed_schema(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    pytest.importorskip("langchain_core", reason="langchain is an optional extra")
    from airlock.adapters.langchain import as_langchain_tools

    lock = build(store_url, clock, calls)
    tools = as_langchain_tools(lock)

    assert [t.name for t in tools] == ["send_payment"]
    schema = tools[0].args_schema.model_json_schema()
    assert set(schema["required"]) == {"to", "amount"}


def test_langchain_uses_the_run_id_as_the_intent(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    """Stable across a retry of the same step, distinct across new ones."""
    pytest.importorskip("langchain_core", reason="langchain is an optional extra")
    from airlock.adapters.langchain import as_langchain_tools

    lock = build(store_url, clock, calls)
    tool = as_langchain_tools(lock)[0]

    first = json.loads(tool.func(config={"run_id": "step-1"}, to="a", amount=10))
    again = json.loads(tool.func(config={"run_id": "step-1"}, to="a", amount=10))
    fresh = json.loads(tool.func(config={"run_id": "step-2"}, to="a", amount=10))

    assert first["result"] == again["result"] == "txn_1"
    assert fresh["result"] == "txn_2"
    assert calls == [10, 10]


def test_langchain_returns_refusals_rather_than_raising(
    store_url: Any, clock: Clock, calls: list[float]
) -> None:
    pytest.importorskip("langchain_core", reason="langchain is an optional extra")
    from airlock.adapters.langchain import as_langchain_tools

    lock = build(
        store_url,
        clock,
        calls,
        caps={"send_payment": Caps(max_per_call=100)},
        approvals=[approval.when("send_payment", lambda c: c.args["to"] == "new", "unknown")],
    )
    tool = as_langchain_tools(lock)[0]

    blocked = json.loads(tool.func(config={"run_id": "s1"}, to="a", amount=5000))
    assert blocked["airlock"] == "blocked"
    assert blocked["layer"] == "caps"

    parked = json.loads(tool.func(config={"run_id": "s2"}, to="new", amount=10))
    assert parked["airlock"] == "pending_approval"
    assert calls == []
