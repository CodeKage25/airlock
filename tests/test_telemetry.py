"""Metrics and traces, and the rule that they can never affect a decision."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any

import pytest

from airlock import Airlock, Caps, Policy, approval
from airlock.core.telemetry import DecisionEvent, Snapshot
from airlock.errors import Blocked, PendingApproval
from tests.conftest import Clock, build_lock


class Recorder:
    def __init__(self) -> None:
        self.decisions: list[DecisionEvent] = []
        self.durations: list[tuple[str, float]] = []
        self.spans: list[tuple[str, str]] = []

    def decision(self, event: DecisionEvent) -> None:
        self.decisions.append(event)

    def duration(self, tool: str, seconds: float) -> None:
        self.durations.append((tool, seconds))

    @contextmanager
    def span(self, tool: str, intent: str) -> Any:
        self.spans.append((tool, intent))
        yield

    def outcomes(self) -> list[str]:
        return [e.outcome.value for e in self.decisions]


class Exploding:
    """Every backend is one bad deploy away from behaving like this."""

    def decision(self, event: DecisionEvent) -> None:
        raise RuntimeError("metrics backend is down")

    def duration(self, tool: str, seconds: float) -> None:
        raise RuntimeError("metrics backend is down")

    def span(self, tool: str, intent: str) -> Any:
        raise RuntimeError("metrics backend is down")


def test_every_outcome_is_reported(store_url: Any, clock: Clock) -> None:
    metrics = Recorder()
    lock = build_lock(
        store_url, clock, Policy(caps={"pay": Caps(max_per_call=100)}), telemetry=metrics
    )

    @lock.tool
    def pay(amount: float) -> str:
        return "txn"

    pay(amount=10, _intent="i-1")
    pay(amount=10, _intent="i-1")
    with pytest.raises(Blocked):
        pay(amount=500, _intent="i-2")

    assert metrics.outcomes() == ["executed", "deduplicated", "blocked"]
    assert metrics.decisions[-1].layer == "caps"
    assert "max_per_call" in (metrics.decisions[-1].reason or "")


def test_the_intent_record_is_not_reported_as_a_decision(store_url: Any, clock: Clock) -> None:
    """``proposed`` is written before the layers run. It is not a verdict."""
    metrics = Recorder()
    lock = build_lock(store_url, clock, telemetry=metrics)

    @lock.tool
    def pay(amount: float) -> str:
        return "txn"

    pay(amount=1, _intent="i-1")

    assert "proposed" not in metrics.outcomes()
    assert len(lock.audit.query(outcome="proposed")) == 1


def test_latency_is_observed_once_per_proposed_action(store_url: Any, clock: Clock) -> None:
    metrics = Recorder()
    lock = build_lock(store_url, clock, telemetry=metrics)

    @lock.tool
    def pay(amount: float) -> str:
        return "txn"

    pay(amount=1, _intent="i-1")
    with pytest.raises(Blocked):
        pay(amount=1)

    assert [tool for tool, _ in metrics.durations] == ["pay", "pay"]
    assert all(seconds >= 0 for _, seconds in metrics.durations)


def test_a_span_wraps_every_call_including_refusals(store_url: Any, clock: Clock) -> None:
    metrics = Recorder()
    lock = build_lock(
        store_url, clock, Policy(caps={"pay": Caps(max_per_call=10)}), telemetry=metrics
    )

    @lock.tool
    def pay(amount: float) -> str:
        return "txn"

    with pytest.raises(Blocked):
        pay(amount=500, _intent="i-1")

    assert metrics.spans == [("pay", "i-1")]


def test_escalation_and_approval_are_both_reported(store_url: Any, clock: Clock) -> None:
    metrics = Recorder()
    lock = build_lock(
        store_url,
        clock,
        Policy(approvals=[approval.when("pay", lambda c: True, "needs a human")]),
        telemetry=metrics,
    )

    @lock.tool
    def pay(amount: float) -> str:
        return "txn"

    with pytest.raises(PendingApproval):
        pay(amount=1, _intent="i-1")
    lock.approvals.pending()[0].approve(by="ops@yourco.com")

    assert metrics.outcomes() == ["escalated", "executed"]
    assert metrics.decisions[-1].actor == "ops@yourco.com"


# ------------------------------------------------------- telemetry must never block


def test_a_broken_backend_does_not_stop_an_action(store_url: Any, clock: Clock) -> None:
    """The audit log fails closed. Metrics do not: losing one costs a dashboard point."""
    lock = build_lock(store_url, clock, telemetry=Exploding())
    ran: list[float] = []

    @lock.tool
    def pay(amount: float) -> str:
        ran.append(amount)
        return "txn"

    assert pay(amount=1, _intent="i-1") == "txn"
    assert ran == [1]


def test_a_broken_backend_does_not_turn_a_block_into_something_else(
    store_url: Any, clock: Clock
) -> None:
    lock = build_lock(
        store_url, clock, Policy(caps={"pay": Caps(max_per_call=10)}), telemetry=Exploding()
    )

    @lock.tool
    def pay(amount: float) -> str:
        return "txn"

    with pytest.raises(Blocked) as caught:
        pay(amount=500, _intent="i-1")
    assert caught.value.layer == "caps"


def test_backends_can_be_combined(store_url: Any, clock: Clock) -> None:
    first, second = Recorder(), Recorder()
    lock = build_lock(store_url, clock, telemetry=[first, second])

    @lock.tool
    def pay(amount: float) -> str:
        return "txn"

    pay(amount=1, _intent="i-1")

    assert first.outcomes() == second.outcomes() == ["executed"]


def test_one_broken_backend_does_not_silence_the_others(store_url: Any, clock: Clock) -> None:
    working = Recorder()
    lock = build_lock(store_url, clock, telemetry=[Exploding(), working])

    @lock.tool
    def pay(amount: float) -> str:
        return "txn"

    pay(amount=1, _intent="i-1")

    assert working.outcomes() == ["executed"]
    assert working.spans == [("pay", "i-1")]


# ------------------------------------------------------------------------ snapshot


def test_the_snapshot_counts_what_has_to_be_read_not_counted(store_url: Any, clock: Clock) -> None:
    lock = build_lock(
        store_url,
        clock,
        Policy(approvals=[approval.when("pay", lambda c: c.args["amount"] > 100)]),
    )

    @lock.tool
    def pay(amount: float) -> str:
        if amount == 7:
            raise TimeoutError("no response")
        return "txn"

    with pytest.raises(PendingApproval):
        pay(amount=500, _intent="i-1")
    with pytest.raises(TimeoutError):
        pay(amount=7, _intent="i-2")
    clock.advance(minutes=30)

    snapshot = lock.snapshot()
    assert isinstance(snapshot, Snapshot)
    assert snapshot.pending_approvals == 1
    assert snapshot.oldest_pending_seconds == 1800
    assert snapshot.stuck_intents == 1
    assert snapshot.oldest_stuck_seconds == 1800


def test_a_quiet_system_snapshots_as_zero(store_url: Any, clock: Clock) -> None:
    snapshot = build_lock(store_url, clock).snapshot()
    assert snapshot.as_dict() == {
        "airlock_pending_approvals": 0,
        "airlock_oldest_pending_approval_seconds": 0.0,
        "airlock_stuck_intents": 0,
        "airlock_oldest_stuck_intent_seconds": 0.0,
    }


# ------------------------------------------------------------------------ backends


def test_prometheus_counts_decisions_and_exposes_gauges(clock: Clock) -> None:
    from prometheus_client import CollectorRegistry, generate_latest

    from airlock.telemetry.prometheus import PrometheusTelemetry

    registry = CollectorRegistry()
    metrics = PrometheusTelemetry(registry=registry)
    lock = Airlock(
        policy=Policy(caps={"pay": Caps(max_per_call=10)}), clock=clock, telemetry=metrics
    )
    metrics.watch(lock)

    @lock.tool
    def pay(amount: float) -> str:
        return "txn"

    pay(amount=1, _intent="i-1")
    with pytest.raises(Blocked):
        pay(amount=500, _intent="i-2")

    exposed = generate_latest(registry).decode()
    assert 'airlock_decisions_total{layer="none",outcome="executed",tool="pay"} 1.0' in exposed
    assert 'airlock_decisions_total{layer="caps",outcome="blocked",tool="pay"} 1.0' in exposed
    assert "airlock_pipeline_seconds_bucket" in exposed
    assert "airlock_stuck_intents 0.0" in exposed
    assert "airlock_pending_approvals 0.0" in exposed


def test_prometheus_gauges_survive_a_broken_store(clock: Clock, tmp_path: Any) -> None:
    """A scrape must not be able to take the process down."""
    from prometheus_client import CollectorRegistry, generate_latest

    from airlock.telemetry.prometheus import PrometheusTelemetry

    registry = CollectorRegistry()
    metrics = PrometheusTelemetry(registry=registry)
    lock = Airlock(clock=clock, telemetry=metrics)
    metrics.watch(lock)
    lock.close()  # the store is now unusable

    exposed = generate_latest(registry).decode()
    assert "airlock_decisions_total" in exposed


def test_otel_records_the_verdict_on_the_span(clock: Clock) -> None:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from airlock.telemetry.otel import OpenTelemetry

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    lock = Airlock(
        policy=Policy(caps={"pay": Caps(max_per_call=10)}),
        clock=clock,
        telemetry=OpenTelemetry(provider.get_tracer("test")),
    )

    @lock.tool
    def pay(amount: float) -> str:
        return "txn"

    with pytest.raises(Blocked):
        pay(amount=500, _intent="i-1")

    spans = exporter.get_finished_spans()
    assert [s.name for s in spans] == ["airlock pay"]
    attributes = dict(spans[0].attributes or {})
    assert attributes["airlock.tool"] == "pay"
    assert attributes["airlock.intent"] == "i-1"
    assert attributes["airlock.outcome"] == "blocked"
    assert attributes["airlock.layer"] == "caps"
    assert "max_per_call" in attributes["airlock.reason"]
    # A refusal is an error on the span, so it stands out in a trace view.
    assert spans[0].status.status_code.name == "ERROR"


def test_the_backends_report_what_they_need_when_missing() -> None:
    """The extras are optional, so the error has to say which one to install."""
    import airlock.telemetry.prometheus as prom

    original, prom.REGISTRY = prom.REGISTRY, None
    try:
        with pytest.raises(Exception, match="prometheus-client"):
            prom.PrometheusTelemetry()
    finally:
        prom.REGISTRY = original


def test_null_telemetry_is_the_default(store_url: Any, clock: Clock) -> None:
    lock = build_lock(store_url, clock)

    @lock.tool
    def pay(amount: float) -> str:
        return "txn"

    assert pay(amount=1, _intent="i-1") == "txn"
    with lock.telemetry.span("pay", "i-1") as span:
        assert span is None
