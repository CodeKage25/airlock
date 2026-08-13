"""Async tools.

    from airlock.aio import AsyncAirlock

    lock = AsyncAirlock(policy=policy, store="postgresql://...")

    @lock.tool
    async def send_payment(to: str, amount: float) -> str:
        return await rail.transfer(to=to, amount=amount)

    await send_payment(to="acct_1", amount=40, _intent="inv-77")

Everything else is identical, because it *is* identical: the decision comes from the same
`prepare` function the synchronous pipeline uses, so the two cannot drift into deciding
differently. Only the execution step changes, from calling the tool to awaiting it.

The store is synchronous and deciding runs in a worker thread. That is deliberate rather
than provisional: the guardrail does a handful of small queries, and keeping one code path
for the decision is worth more than saving a thread hop. It also means a risk hook may do
blocking I/O without stalling the loop, which is why hooks stay synchronous.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable, Mapping
from typing import Any

from airlock.core import pipeline
from airlock.core.tools import Tool
from airlock.core.types import ApprovalRecord, RequestStatus
from airlock.lock import Airlock

__all__ = ["AsyncAirlock"]


class AsyncAirlock(Airlock):
    """An :class:`~airlock.Airlock` whose tools are awaited.

    Accepts both async and plain functions, so a codebase can migrate one tool at a time.
    """

    accepts_async = True

    def _wrap(self, registered: Tool) -> Callable[..., Any]:
        @functools.wraps(registered.fn)
        async def wrapped(
            *args: Any,
            _intent: str = "",
            _context: Mapping[str, Any] | None = None,
            _principal: str | None = None,
            **kwargs: Any,
        ) -> Any:
            return await pipeline.run_async(
                self._runtime,
                registered,
                args,
                kwargs,
                intent=_intent,
                context=_context,
                principal=_principal or self.principal,
            )

        wrapped.airlock_tool = registered  # type: ignore[attr-defined]
        return wrapped

    async def approve(self, request_id: str, by: str) -> Any:
        """Approve a parked call and await it.

        The synchronous ``request.approve()`` cannot be used here: it would call an async
        tool and hand back a coroutine nobody awaits, recording an execution that never
        happened.
        """
        record = self.approvals._decide(request_id, RequestStatus.APPROVED, by=by, reason=None)
        return await self._run_approved_async(record, by)

    async def _run_approved_async(self, record: ApprovalRecord, actor: str) -> Any:
        return await pipeline.run_async(
            self._runtime,
            self.registry.get(record.tool),
            (),
            dict(record.args),
            intent=record.intent,
            context=dict(record.context),
            actor=actor,
            principal=record.principal,
            bypass_approval=True,
            key_override=record.key,
        )

    def _before_approval(self, record: ApprovalRecord) -> None:
        if inspect.iscoroutinefunction(self.registry.get(record.tool).fn):
            raise TypeError(
                f"{record.tool!r} is async; approve it with "
                "'await lock.approve(request_id, by=...)' so the call is awaited"
            )
