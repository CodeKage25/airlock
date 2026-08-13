"""Metrics and traces, for people who have to run this thing.

One deliberate asymmetry runs through here: **the audit log fails closed, telemetry fails
open.** The audit log is the compliance record, so a call that cannot be recorded does not
execute. A metric is not a record of anything; losing one costs a point on a dashboard.
A Prometheus registry or a trace exporter having a bad day must never stop a payment, so
every telemetry call is wrapped and every exception from it is swallowed.

Telemetry hangs off the audit writer rather than off the pipeline. Every outcome already
flows through exactly one place, so metrics cannot drift out of step with the audit trail
by construction, and there is no scattering of counter increments through the layers.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import ExitStack, contextmanager, suppress
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from airlock.core.types import Outcome

#: Outcomes that describe a decision. ``proposed`` is the intent record, not a verdict.
DECISIONS = tuple(o for o in Outcome if o is not Outcome.PROPOSED)


@dataclass(frozen=True, slots=True)
class DecisionEvent:
    tool: str
    outcome: Outcome
    intent: str
    layer: str | None = None
    scope: str | None = None
    reason: str | None = None
    actor: str | None = None


@runtime_checkable
class Telemetry(Protocol):
    """Where decisions and timings go. Implementations must not raise, but are wrapped
    anyway, because a metrics backend is not something to trust with an outage."""

    def decision(self, event: DecisionEvent) -> None: ...

    def duration(self, tool: str, seconds: float) -> None: ...

    def span(self, tool: str, intent: str) -> Any: ...


class NullTelemetry:
    """The default. Costs one attribute lookup and a no-op call."""

    def decision(self, event: DecisionEvent) -> None:
        return None

    def duration(self, tool: str, seconds: float) -> None:
        return None

    @contextmanager
    def span(self, tool: str, intent: str) -> Iterator[None]:
        yield


class MultiTelemetry:
    """Fan out to several backends, usually Prometheus for metrics and OTel for traces."""

    def __init__(self, *backends: Telemetry) -> None:
        self._backends = backends

    def decision(self, event: DecisionEvent) -> None:
        for backend in self._backends:
            backend.decision(event)

    def duration(self, tool: str, seconds: float) -> None:
        for backend in self._backends:
            backend.duration(tool, seconds)

    @contextmanager
    def span(self, tool: str, intent: str) -> Iterator[None]:
        with ExitStack() as stack:
            for backend in self._backends:
                stack.enter_context(backend.span(tool, intent))
            yield


class Safe:
    """Wraps a backend so nothing it does can affect whether an action executes."""

    def __init__(self, inner: Telemetry) -> None:
        self._inner = inner

    def decision(self, event: DecisionEvent) -> None:
        # A broken dashboard must never block a payment.
        with suppress(Exception):
            self._inner.decision(event)

    def duration(self, tool: str, seconds: float) -> None:
        with suppress(Exception):
            self._inner.duration(tool, seconds)

    @contextmanager
    def span(self, tool: str, intent: str) -> Iterator[Any]:
        """Guard entering and leaving the span, never the body.

        Wrapping the body would mean catching the very exception the pipeline uses to
        refuse an action, so the guard is only ever around the backend's own calls, and
        an exception from the body is always re-raised.
        """
        try:
            inner = self._inner.span(tool, intent)
            entered = inner.__enter__()
        except Exception:
            yield None
            return

        try:
            yield entered
        except BaseException as exc:
            with suppress(Exception):
                inner.__exit__(type(exc), exc, exc.__traceback__)
            raise
        with suppress(Exception):
            inner.__exit__(None, None, None)


def resolve(telemetry: Telemetry | Sequence[Telemetry] | None) -> Telemetry:
    if telemetry is None:
        return NullTelemetry()
    if isinstance(telemetry, Sequence):
        # Each backend is guarded individually, so one of them failing does not silence
        # the rest. Guarding the fan-out as a whole would do exactly that.
        return MultiTelemetry(*(Safe(backend) for backend in telemetry))
    return Safe(telemetry)


@dataclass(frozen=True, slots=True)
class Snapshot:
    """State worth alerting on, read on demand rather than tracked continuously."""

    pending_approvals: int
    oldest_pending_seconds: float
    stuck_intents: int
    oldest_stuck_seconds: float

    def as_dict(self) -> dict[str, float]:
        return {
            "airlock_pending_approvals": self.pending_approvals,
            "airlock_oldest_pending_approval_seconds": self.oldest_pending_seconds,
            "airlock_stuck_intents": self.stuck_intents,
            "airlock_oldest_stuck_intent_seconds": self.oldest_stuck_seconds,
        }
