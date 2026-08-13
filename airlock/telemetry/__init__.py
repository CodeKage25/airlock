"""Optional metrics and tracing backends.

Both are extras. The core has no telemetry dependency, and losing telemetry never
affects whether an action executes.
"""

from airlock.core.telemetry import (
    DecisionEvent,
    MultiTelemetry,
    NullTelemetry,
    Snapshot,
    Telemetry,
)

__all__ = [
    "DecisionEvent",
    "MultiTelemetry",
    "NullTelemetry",
    "Snapshot",
    "Telemetry",
]
