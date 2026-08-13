from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from airlock.core import approvals as approvals_layer
from airlock.core import idempotency
from airlock.core import policy as caps_layer
from airlock.core import risk as risk_layer
from airlock.core import tools as tool_layer
from airlock.core.approvals import Approvals
from airlock.core.audit import AuditLog
from airlock.core.canonical import digest
from airlock.core.policy import Policy
from airlock.core.shadow import Mode
from airlock.core.stores.base import Store
from airlock.core.tools import Tool
from airlock.core.types import Call, Decision, Outcome, Reservation, ReservationState, Verdict
from airlock.errors import (
    Blocked,
    DuplicateIntent,
    PendingApproval,
    PolicyError,
    StoreUnavailable,
)

FAIL_CLOSED = "fail-closed"

LAYERS = (
    tool_layer.LAYER,
    caps_layer.LAYER,
    idempotency.LAYER,
    risk_layer.LAYER,
    approvals_layer.LAYER,
)


class _Passthrough(Exception):
    """Carries an error that must reach the caller unconverted."""

    def __init__(self, cause: BaseException) -> None:
        super().__init__(str(cause))
        self.cause = cause


@dataclass
class Runtime:
    store: Store
    policy: Policy
    audit: AuditLog
    clock: Callable[[], datetime]
    approvals: Approvals
    strict_idempotency: bool = False
    approval_ttl: timedelta | None = None
    mode: Mode = Mode.ENFORCE


def run(
    rt: Runtime,
    tool: Tool,
    args: tuple[Any, ...] = (),
    kwargs: Mapping[str, Any] | None = None,
    *,
    intent: str,
    context: Mapping[str, Any] | None = None,
    actor: str | None = None,
    bypass_approval: bool = False,
    key_override: str | None = None,
) -> Any:
    """Take a proposed action through every layer. Nothing else may call the tool."""
    try:
        return _run(
            rt,
            tool,
            args,
            dict(kwargs or {}),
            intent=intent,
            context=dict(context or {}),
            actor=actor,
            bypass_approval=bypass_approval,
            key_override=key_override,
        )
    except _Passthrough as passthrough:
        raise passthrough.cause from None
    except (Blocked, PendingApproval, DuplicateIntent):
        raise
    except StoreUnavailable as exc:
        raise Blocked(str(exc), layer=FAIL_CLOSED) from exc
    except Exception as exc:
        raise Blocked(f"guardrail error: {exc}", layer=FAIL_CLOSED) from exc


def _run(
    rt: Runtime,
    tool: Tool,
    raw_args: tuple[Any, ...],
    raw_kwargs: dict[str, Any],
    *,
    intent: str,
    context: dict[str, Any],
    actor: str | None,
    bypass_approval: bool,
    key_override: str | None,
) -> Any:
    if not intent:
        raise _reject(
            rt,
            tool.name,
            intent,
            context,
            {},
            tool_layer.LAYER,
            "every call needs an _intent naming the business action",
        )

    try:
        args = tool.validate(tool.bind(raw_args, raw_kwargs))
    except ValueError as exc:
        raise _reject(rt, tool.name, intent, context, {}, tool_layer.LAYER, str(exc)) from exc

    caps = rt.policy.caps_for(tool.name)
    scope_by = caps.scope_by if caps is not None and caps.scope_by else tool.scope_by
    try:
        scope = caps_layer.resolve_scope(Call(tool.name, args, context, intent), scope_by)
    except PolicyError as exc:
        raise _reject(rt, tool.name, intent, context, args, caps_layer.LAYER, str(exc)) from exc

    call = Call(tool=tool.name, args=args, context=context, intent=intent, scope=scope)
    key = key_override or idempotency.derive_key(tool.name, args, intent, context, tool.key_fields)

    rt.audit.record(
        tool=call.tool,
        intent=intent,
        key=key,
        outcome=Outcome.PROPOSED,
        scope=scope,
        args=args,
        actor=actor,
    )

    shadow = (tool.mode or rt.mode) is Mode.SHADOW

    if caps is not None:
        _enforce(
            rt,
            call,
            key,
            caps_layer.LAYER,
            actor,
            caps_layer.check(call, caps),
            shadow=shadow,
        )

    existing = rt.store.get_reservation(key)
    if existing is not None:
        return _resolve(rt, call, key, existing, actor)

    _enforce(
        rt,
        call,
        key,
        risk_layer.LAYER,
        actor,
        risk_layer.evaluate(call, rt.policy.risk_hooks),
        shadow=shadow,
    )

    if not bypass_approval:
        verdict, ttl = approvals_layer.evaluate(call, rt.policy.rules_for(tool.name))
        _enforce(rt, call, key, approvals_layer.LAYER, actor, verdict, ttl=ttl, shadow=shadow)

    return _commit(rt, tool, call, key, caps, actor, shadow=shadow)


def _commit(
    rt: Runtime,
    tool: Tool,
    call: Call,
    key: str,
    caps: Any,
    actor: str | None,
    shadow: bool = False,
) -> Any:
    now = rt.clock()
    reservation = rt.store.reserve(key, call.tool, call.intent, now)

    if reservation.conflict_key is not None:
        raise _reject(
            rt,
            call.tool,
            call.intent,
            call.context,
            call.args,
            idempotency.LAYER,
            f"intent {call.intent!r} is already bound to a different set of arguments "
            "for this tool; refusing to treat this as a new action",
            key=key,
            scope=call.scope,
        )
    if reservation.existing is not None:
        return _resolve(rt, call, key, reservation.existing, actor)

    if caps is not None:
        violation = rt.store.commit_spend(
            key,
            call.tool,
            call.scope,
            caps_layer.meter(call, caps),
            now,
            caps_layer.spend_checks(caps, now),
            enforce=not shadow,
        )
        if violation is not None:
            reason = caps_layer.violation_reason(call.tool, call.scope, violation)
            if shadow:
                _observe(
                    rt,
                    call,
                    key,
                    caps_layer.LAYER,
                    actor,
                    Outcome.WOULD_BLOCK,
                    reason,
                    rule=violation.name,
                )
            else:
                # Nothing ran, so the intent must not be left poisoned for a later retry.
                rt.store.discard(key)
                raise _reject(
                    rt,
                    call.tool,
                    call.intent,
                    call.context,
                    call.args,
                    caps_layer.LAYER,
                    reason,
                    key=key,
                    scope=call.scope,
                    actor=actor,
                )

    try:
        result = tool.fn(**dict(call.args))
    except Exception as exc:
        _mark_failed(rt, call, key, exc, actor)
        raise _Passthrough(exc) from None

    payload, replayable = idempotency.serialise(result)
    try:
        rt.store.complete(key, payload, replayable)
        rt.audit.record(
            tool=call.tool,
            intent=call.intent,
            key=key,
            outcome=Outcome.EXECUTED,
            scope=call.scope,
            args=call.args,
            result_ref=digest(payload)[:16] if replayable else None,
            actor=actor,
        )
    except StoreUnavailable as exc:
        raise _Passthrough(exc) from None
    return result


def _resolve(rt: Runtime, call: Call, key: str, reservation: Reservation, actor: str | None) -> Any:
    """What an existing record for this key means. DONE replays, anything else blocks."""
    if reservation.state is not ReservationState.DONE:
        raise _reject(
            rt,
            call.tool,
            call.intent,
            call.context,
            call.args,
            idempotency.LAYER,
            idempotency.block_reason(reservation),
            key=key,
            scope=call.scope,
        )

    try:
        result = idempotency.replay(reservation)
    except Blocked as exc:
        raise _reject(
            rt,
            call.tool,
            call.intent,
            call.context,
            call.args,
            idempotency.LAYER,
            exc.reason,
            key=key,
            scope=call.scope,
        ) from None

    rt.audit.record(
        tool=call.tool,
        intent=call.intent,
        key=key,
        outcome=Outcome.DEDUPLICATED,
        layer=idempotency.LAYER,
        reason="replayed the original result; the tool did not run",
        scope=call.scope,
        args=call.args,
        actor=actor,
    )
    if rt.strict_idempotency:
        raise DuplicateIntent(call.intent, result)
    return result


def _enforce(
    rt: Runtime,
    call: Call,
    key: str,
    layer: str,
    actor: str | None,
    decision: Decision,
    ttl: timedelta | None = None,
    shadow: bool = False,
) -> None:
    if decision.allowed:
        return

    if shadow:
        _observe(
            rt,
            call,
            key,
            layer,
            actor,
            Outcome.WOULD_ESCALATE if decision.verdict is Verdict.ESCALATE else Outcome.WOULD_BLOCK,
            decision.reason,
        )
        return

    if decision.verdict is Verdict.ESCALATE:
        record = rt.approvals.open(call, key, decision.reason, ttl)
        rt.audit.record(
            tool=call.tool,
            intent=call.intent,
            key=key,
            outcome=Outcome.ESCALATED,
            layer=layer,
            reason=decision.reason,
            scope=call.scope,
            args=call.args,
            result_ref=record.id,
            actor=actor,
        )
        raise PendingApproval(record.id, decision.reason, call)

    raise _reject(
        rt,
        call.tool,
        call.intent,
        call.context,
        call.args,
        layer,
        decision.reason,
        key=key,
        scope=call.scope,
        actor=actor,
    )


def _observe(
    rt: Runtime,
    call: Call,
    key: str,
    layer: str,
    actor: str | None,
    outcome: Outcome,
    reason: str,
    rule: str = "",
) -> None:
    """Record a verdict without applying it. Shadow mode's only effect."""
    rt.audit.record(
        tool=call.tool,
        intent=call.intent,
        key=key,
        outcome=outcome,
        layer=layer,
        reason=reason,
        scope=call.scope,
        args=call.args,
        result_ref=rule or None,
        actor=actor,
    )


def _reject(
    rt: Runtime,
    tool: str,
    intent: str,
    context: Mapping[str, Any],
    args: Mapping[str, Any],
    layer: str,
    reason: str,
    *,
    key: str = "",
    scope: str | None = None,
    actor: str | None = None,
) -> Blocked:
    rt.audit.record(
        tool=tool,
        intent=intent,
        key=key,
        outcome=Outcome.BLOCKED,
        layer=layer,
        reason=reason,
        scope=scope,
        args=args,
        actor=actor,
    )
    return Blocked(reason, layer=layer, call=Call(tool, args, context, intent, scope))


def _mark_failed(rt: Runtime, call: Call, key: str, exc: BaseException, actor: str | None) -> None:
    """Best effort. The reservation stays non-DONE either way, so retries stay blocked."""
    reason = f"{type(exc).__name__}: {exc}"
    try:
        rt.store.fail(key, reason)
        rt.audit.record(
            tool=call.tool,
            intent=call.intent,
            key=key,
            outcome=Outcome.FAILED,
            layer=idempotency.LAYER,
            reason=reason,
            scope=call.scope,
            args=call.args,
            actor=actor,
        )
    except StoreUnavailable:
        pass
