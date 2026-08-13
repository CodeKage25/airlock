from __future__ import annotations

import functools
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from airlock.core import pipeline
from airlock.core import tools as tool_layer
from airlock.core.approvals import Approvals
from airlock.core.audit import AuditLog
from airlock.core.intents import DEFAULT_STUCK_AFTER, Intents
from airlock.core.pipeline import Runtime
from airlock.core.policy import Policy
from airlock.core.shadow import Mode, Shadow
from airlock.core.stores import Store, from_url
from airlock.core.telemetry import Snapshot, Telemetry, resolve
from airlock.core.tools import Registry, Tool
from airlock.core.types import ApprovalRecord
from airlock.errors import PolicyError


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Airlock:
    """Wraps tools so an agent proposes actions and Airlock decides whether they run."""

    def __init__(
        self,
        policy: Policy | None = None,
        store: str | Store = "memory://",
        fail_mode: str = "closed",
        clock: Callable[[], datetime] | None = None,
        audit_redact: Sequence[str] = (),
        strict_idempotency: bool = False,
        approval_ttl: timedelta | None = None,
        stuck_after: timedelta = DEFAULT_STUCK_AFTER,
        mode: Mode | str = Mode.ENFORCE,
        telemetry: Telemetry | Sequence[Telemetry] | None = None,
    ) -> None:
        if fail_mode != "closed":
            raise PolicyError("fail_mode is always 'closed'; there is no fail-open mode")

        self.mode = Mode(mode)
        self.policy = policy or Policy()
        self.store: Store = from_url(store) if isinstance(store, str) else store
        self.clock = clock or _utcnow
        self.telemetry = resolve(telemetry)
        self.audit = AuditLog(self.store, self.clock, audit_redact, self.telemetry)
        self.approvals = Approvals(
            self.store, self.clock, self._run_approved, self.audit, approval_ttl
        )
        self.intents = Intents(self.store, self.clock, self.audit, stuck_after)
        self.shadow = Shadow(self.audit)
        self.registry = Registry()
        self._wrapped: dict[str, Callable[..., Any]] = {}
        self._runtime = Runtime(
            store=self.store,
            policy=self.policy,
            audit=self.audit,
            clock=self.clock,
            approvals=self.approvals,
            strict_idempotency=strict_idempotency,
            approval_ttl=approval_ttl,
            mode=self.mode,
            telemetry=self.telemetry,
        )

    def tool(
        self,
        fn: Callable[..., Any] | None = None,
        *,
        name: str | None = None,
        scope_by: str | None = None,
        key_fields: Iterable[str] = (),
        mode: Mode | str | None = None,
    ) -> Any:
        """Register a function. Usable bare (``@lock.tool``) or called with options.

        ``mode`` overrides the lock's mode for this tool alone, which is how a policy
        graduates: one tool enforces while the rest are still being observed.
        """

        def decorate(target: Callable[..., Any]) -> Callable[..., Any]:
            registered = tool_layer.build(
                target,
                name=name,
                scope_by=scope_by,
                key_fields=tuple(key_fields),
                mode=Mode(mode) if mode is not None else None,
            )
            self.registry.add(registered)
            wrapped = self._wrap(registered)
            self._wrapped[registered.name] = wrapped
            return wrapped

        return decorate(fn) if fn is not None else decorate

    def _wrap(self, registered: Tool) -> Callable[..., Any]:
        @functools.wraps(registered.fn)
        def wrapped(
            *args: Any,
            _intent: str = "",
            _context: Mapping[str, Any] | None = None,
            **kwargs: Any,
        ) -> Any:
            return pipeline.run(
                self._runtime,
                registered,
                args,
                kwargs,
                intent=_intent,
                context=_context,
            )

        wrapped.airlock_tool = registered  # type: ignore[attr-defined]
        return wrapped

    def tools(self) -> list[Callable[..., Any]]:
        self.check_policy()
        return list(self._wrapped.values())

    def get(self, name: str) -> Callable[..., Any]:
        try:
            return self._wrapped[name]
        except KeyError:
            raise PolicyError(f"tool {name!r} is not registered") from None

    def check_policy(self) -> None:
        """A cap or rule naming a tool that does not exist enforces nothing. Say so loudly."""
        known = set(self.registry.tools)
        unknown = sorted(
            {name for name in self.policy.caps if name not in known}
            | {rule.tool for rule in self.policy.approvals if rule.tool not in known}
        )
        if unknown:
            raise PolicyError(
                f"policy references unregistered tools: {', '.join(unknown)}. "
                "Those limits would enforce nothing."
            )

    def as_openai_tools(self) -> tuple[list[dict[str, Any]], Callable[..., Any]]:
        from airlock.adapters.openai import build

        return build(self)

    def as_anthropic_tools(self) -> tuple[list[dict[str, Any]], Callable[..., Any]]:
        from airlock.adapters.anthropic import build

        return build(self)

    def _run_approved(self, record: ApprovalRecord, actor: str) -> Any:
        return pipeline.run(
            self._runtime,
            self.registry.get(record.tool),
            (),
            dict(record.args),
            intent=record.intent,
            context=dict(record.context),
            actor=actor,
            bypass_approval=True,
            key_override=record.key,
        )

    def snapshot(self) -> Snapshot:
        """Queue and stuck-intent state, read on demand.

        These are the two things worth paging on and neither can be counted as it
        happens: a request ages while nothing occurs, and an intent becomes stuck by a
        process going away. Both have to be looked up.
        """
        now = self.clock()
        pending = self.approvals.pending()
        stuck = self.intents.stuck()
        return Snapshot(
            pending_approvals=len(pending),
            oldest_pending_seconds=max(
                ((now - r.created_at).total_seconds() for r in pending), default=0.0
            ),
            stuck_intents=len(stuck),
            oldest_stuck_seconds=max((item.age.total_seconds() for item in stuck), default=0.0),
        )

    def close(self) -> None:
        self.store.close()

    def __repr__(self) -> str:
        return f"<Airlock mode={self.mode.value} tools={len(self.registry)} store={self.store.url}>"
