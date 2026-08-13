"""Prometheus metrics.

pip install 'agent-airlock[prometheus]'

from airlock.telemetry.prometheus import PrometheusTelemetry

metrics = PrometheusTelemetry()
lock = Airlock(policy=policy, store=..., telemetry=metrics)
metrics.watch(lock)          # adds the gauges that have to be read rather than counted
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

from airlock.core.telemetry import DecisionEvent
from airlock.errors import PolicyError

if TYPE_CHECKING:
    from airlock.lock import Airlock

try:
    from prometheus_client import REGISTRY, Counter, Gauge, Histogram
    from prometheus_client.core import GaugeMetricFamily
    from prometheus_client.registry import Collector
except ImportError:  # pragma: no cover - exercised by the error path below
    REGISTRY = None  # type: ignore[assignment]
    Collector = object  # type: ignore[assignment,misc]


# Guardrail overhead is sub-millisecond when it allows and only slightly more when it
# refuses, so the buckets are tight at the bottom. The top bucket exists to catch a store
# that has started to crawl, which is the failure this histogram is really for.
BUCKETS = (0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5, 1.0, 5.0)


class PrometheusTelemetry:
    """Counters and a latency histogram, plus pull-time gauges via :meth:`watch`."""

    def __init__(self, registry: Any = None, prefix: str = "airlock") -> None:
        if REGISTRY is None:
            raise PolicyError(
                "prometheus metrics need prometheus-client: pip install 'agent-airlock[prometheus]'"
            )
        self._registry = registry if registry is not None else REGISTRY
        self.decisions = Counter(
            f"{prefix}_decisions_total",
            "Proposed actions by how they resolved.",
            ["tool", "outcome", "layer"],
            registry=self._registry,
        )
        self.latency = Histogram(
            f"{prefix}_pipeline_seconds",
            "Time spent in the guardrail pipeline, excluding the tool itself.",
            ["tool"],
            buckets=BUCKETS,
            registry=self._registry,
        )
        self.info = Gauge(
            f"{prefix}_build_info",
            "Airlock version in this process.",
            ["version"],
            registry=self._registry,
        )
        from airlock import __version__

        self.info.labels(version=__version__).set(1)

    def decision(self, event: DecisionEvent) -> None:
        self.decisions.labels(
            tool=event.tool, outcome=event.outcome.value, layer=event.layer or "none"
        ).inc()

    def duration(self, tool: str, seconds: float) -> None:
        self.latency.labels(tool=tool).observe(seconds)

    @contextmanager
    def span(self, tool: str, intent: str) -> Iterator[None]:
        yield

    def watch(self, lock: Airlock, prefix: str = "airlock") -> None:
        """Expose the state that has to be read rather than counted.

        A request ages while nothing happens and an intent becomes stuck by a process
        disappearing, so neither can be incremented from the pipeline. They are collected
        when Prometheus scrapes.
        """
        self._registry.register(_SnapshotCollector(lock, prefix))


class _SnapshotCollector(Collector):
    def __init__(self, lock: Airlock, prefix: str) -> None:
        self._lock = lock
        self._prefix = prefix

    def collect(self) -> Iterator[Any]:
        descriptions = {
            "pending_approvals": "Requests waiting on a human.",
            "oldest_pending_approval_seconds": "Age of the oldest waiting request.",
            "stuck_intents": "Intents whose real-world effect is unknown.",
            "oldest_stuck_intent_seconds": "Age of the oldest stuck intent.",
        }
        try:
            values = self._lock.snapshot().as_dict()
        except Exception:  # a scrape must not be able to take the process down
            return
        for name, help_text in descriptions.items():
            metric = GaugeMetricFamily(f"{self._prefix}_{name}", help_text)
            metric.add_metric([], values[f"airlock_{name}"])
            yield metric
