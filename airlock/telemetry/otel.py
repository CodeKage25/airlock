"""OpenTelemetry traces.

    pip install 'agent-airlock[otel]'

    from airlock.telemetry.otel import OpenTelemetry

    lock = Airlock(policy=policy, store=..., telemetry=OpenTelemetry())

One span per proposed action, carrying the decision. The point of tracing here is to sit
the guardrail verdict next to the agent turn that caused it, so "why did this payment not
happen" is answerable from the same trace as "what was the model doing".
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from airlock.core.telemetry import DecisionEvent
from airlock.core.types import Outcome
from airlock.errors import PolicyError

try:
    from opentelemetry import trace
    from opentelemetry.trace import Status, StatusCode
except ImportError:  # pragma: no cover - exercised by the error path below
    trace = None  # type: ignore[assignment]

#: Outcomes that mean the action did not happen. Everything else is a normal span.
REFUSALS = (Outcome.BLOCKED, Outcome.ESCALATED, Outcome.FAILED, Outcome.EXPIRED)


class OpenTelemetry:
    def __init__(self, tracer: Any = None) -> None:
        if trace is None:
            raise PolicyError(
                "otel traces need opentelemetry-api: pip install 'agent-airlock[otel]'"
            )
        self._tracer = tracer or trace.get_tracer("airlock")

    @contextmanager
    def span(self, tool: str, intent: str) -> Iterator[Any]:
        with self._tracer.start_as_current_span(
            f"airlock {tool}",
            attributes={"airlock.tool": tool, "airlock.intent": intent},
        ) as span:
            yield span

    def decision(self, event: DecisionEvent) -> None:
        span = trace.get_current_span()
        if span is None or not span.is_recording():
            return
        span.set_attribute("airlock.outcome", event.outcome.value)
        if event.layer:
            span.set_attribute("airlock.layer", event.layer)
        if event.scope:
            span.set_attribute("airlock.scope", event.scope)
        if event.actor:
            span.set_attribute("airlock.actor", event.actor)
        if event.reason:
            # The reason is the whole point: a span saying "blocked" with no why is a
            # dashboard, not an explanation.
            span.set_attribute("airlock.reason", event.reason)
        if event.outcome in REFUSALS:
            span.set_status(Status(StatusCode.ERROR, event.reason or event.outcome.value))

    def duration(self, tool: str, seconds: float) -> None:
        return None
