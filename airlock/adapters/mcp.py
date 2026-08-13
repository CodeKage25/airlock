"""Expose guarded tools over MCP, so the agent does not have to be Python.

    pip install 'agent-airlock[mcp]'

    from airlock.adapters.mcp import serve

    serve(lock)          # stdio, ready for any MCP client

This is the answer to "does Airlock work with my language". It does not, as a library:
Airlock is in-process Python. Over MCP the guardrail becomes a service, and the agent can
be TypeScript, Go, Claude Desktop, or anything else that speaks the protocol. The policy,
the store, the audit log and the approval queue stay on this side, which is the point.

Every tool takes an extra ``intent`` argument, because the guarantee depends on it and
there is nowhere else in the protocol to put it. The description tells the model to reuse
the same intent when retrying, so a retry replays instead of paying twice.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from airlock.core.telemetry import Snapshot
from airlock.errors import AirlockError, Blocked, PendingApproval, PolicyError

if TYPE_CHECKING:
    from airlock.lock import Airlock


def _server_class() -> Any:
    """MCP 2.x renamed FastMCP to MCPServer, so accept whichever is installed."""
    try:
        from mcp.server import MCPServer

        return MCPServer
    except ImportError:
        pass
    try:
        from mcp.server.fastmcp import FastMCP  # type: ignore[import-not-found]

        return FastMCP
    except ImportError:
        return None


INTENT_GUIDANCE = (
    "Guarded by Airlock.\n\n"
    "`intent` must name the business action, for example 'pay invoice 77'. Reuse the "
    "same intent verbatim when retrying the same action, so the retry replays instead "
    "of executing twice. Use a new intent only for a genuinely different action."
)


def refusal(exc: AirlockError) -> dict[str, Any]:
    """A refusal the model can read.

    Raising over the wire surfaces as a transport error and tells the model nothing. A
    structured result teaches it what the limit was, which is the difference between an
    agent that adapts and one that retries the same rejected call forever.
    """
    if isinstance(exc, PendingApproval):
        return {
            "airlock": "pending_approval",
            "request_id": exc.request_id,
            "reason": exc.reason,
            "guidance": "A human has been asked. Do not retry; the decision is theirs.",
        }
    if isinstance(exc, Blocked):
        return {
            "airlock": "blocked",
            "layer": exc.layer,
            "reason": exc.reason,
            "guidance": "This will not succeed on retry. Change the request or stop.",
        }
    return {"airlock": "error", "reason": str(exc)}


def build(lock: Airlock, name: str = "airlock") -> Any:
    """An MCP server exposing every registered tool, guarded."""
    server_class = _server_class()
    if server_class is None:
        raise PolicyError("the MCP server needs mcp: pip install 'agent-airlock[mcp]'")

    lock.check_policy()
    server = server_class(name)

    for tool in lock.registry:
        _register(server, lock, tool)

    def airlock_status() -> dict[str, Any]:
        """Guardrail state: pending approvals, stuck intents, and the current mode."""
        snapshot: Snapshot = lock.snapshot()
        return {
            "pending_approvals": snapshot.pending_approvals,
            "stuck_intents": snapshot.stuck_intents,
            "mode": lock.mode.value,
        }

    server.add_tool(
        airlock_status,
        name="airlock_status",
        description="Guardrail state: pending approvals, stuck intents, and the mode.",
    )
    return server


def _register(server: Any, lock: Airlock, tool: Any) -> None:
    guarded = lock.get(tool.name)
    model = tool.model

    def call(intent: str, **arguments: Any) -> str:
        try:
            result = guarded(**arguments, _intent=intent)
        except AirlockError as exc:
            return json.dumps(refusal(exc))
        return json.dumps({"airlock": "executed", "result": result}, default=str)

    # The signature is what MCP turns into the advertised schema, so it has to carry the
    # tool's real arguments rather than **kwargs.
    call.__name__ = tool.name
    call.__signature__ = _signature_with_intent(model)  # type: ignore[attr-defined]
    call.__annotations__ = {
        "intent": str,
        **{name: field.annotation for name, field in model.model_fields.items()},
        "return": str,
    }

    server.add_tool(
        call,
        name=tool.name,
        description=f"{tool.description}\n\n{INTENT_GUIDANCE}".strip(),
    )


def _signature_with_intent(model: Any) -> Any:
    import inspect

    parameters = [inspect.Parameter("intent", inspect.Parameter.KEYWORD_ONLY, annotation=str)]
    for name, field in model.model_fields.items():
        parameters.append(
            inspect.Parameter(
                name,
                inspect.Parameter.KEYWORD_ONLY,
                annotation=field.annotation,
                default=(inspect.Parameter.empty if field.is_required() else field.get_default()),
            )
        )
    return inspect.Signature(parameters, return_annotation=str)


def serve(lock: Airlock, name: str = "airlock", transport: str = "stdio") -> None:
    build(lock, name).run(transport=transport)
