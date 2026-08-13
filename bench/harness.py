from __future__ import annotations

import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from airlock import Airlock, Policy
from airlock.errors import Blocked, PendingApproval

EXECUTE = "execute"
REPLAY = "replay"
BLOCK = "block"
ESCALATE = "escalate"
RAISE = "raise"


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **delta: float) -> None:
        self.now += timedelta(**delta)


@dataclass
class Attempt:
    case: str
    category: str
    step: str
    expected: str
    observed: str
    layer: str | None = None
    reason: str | None = None
    latency_ms: float = 0.0

    @property
    def ok(self) -> bool:
        return self.expected == self.observed


@dataclass
class CaseRun:
    """One adversarial scenario, with its own lock, clock and execution counter."""

    name: str
    category: str
    attempts: list[Attempt] = field(default_factory=list)
    executions: int = 0
    clock: Clock = field(default_factory=Clock)
    locks: list[Airlock] = field(default_factory=list)
    invariants: list[tuple[str, bool]] = field(default_factory=list)

    def invariant(self, description: str, holds: bool) -> None:
        self.invariants.append((f"{self.name}: {description}", holds))

    def airlock(self, policy: Policy | None = None, **kwargs: Any) -> Airlock:
        lock = Airlock(policy=policy or Policy(), clock=self.clock, **kwargs)
        self.locks.append(lock)
        return lock

    def executed(self) -> None:
        """Tool bodies call this. The only place a real side effect is counted."""
        self.executions += 1

    def expect(self, step: str, expected: str, thunk: Callable[[], Any]) -> Any:
        before = self.executions
        started = time.perf_counter()
        observed, layer, reason, result = RAISE, None, None, None
        try:
            result = thunk()
            observed = EXECUTE if self.executions > before else REPLAY
        except Blocked as exc:
            observed, layer, reason = BLOCK, exc.layer, exc.reason
        except PendingApproval as exc:
            observed, layer, reason = ESCALATE, "approvals", exc.reason
        except Exception as exc:
            observed, reason = RAISE, f"{type(exc).__name__}: {exc}"
        latency = (time.perf_counter() - started) * 1000

        self.attempts.append(
            Attempt(
                case=self.name,
                category=self.category,
                step=step,
                expected=expected,
                observed=observed,
                layer=layer,
                reason=reason,
                latency_ms=latency,
            )
        )
        return result

    def audit_executions(self) -> Counter[str]:
        """Real side effects per intent.

        A failed call counts: the tool body ran, and whether its effect landed is
        exactly what nobody knows. Two entries for one intent is a double execution
        however they are labelled.
        """
        counts: Counter[str] = Counter()
        for lock in self.locks:
            for outcome in ("executed", "failed"):
                for entry in lock.audit.query(outcome=outcome):
                    counts[entry.intent] += 1
        return counts


@dataclass
class Report:
    attempts: list[Attempt] = field(default_factory=list)
    duplicate_executions: int = 0
    fail_closed_violations: int = 0
    audit_discrepancies: int = 0
    cases: int = 0
    broken_invariants: list[str] = field(default_factory=list)

    def absorb(self, run: CaseRun) -> None:
        self.cases += 1
        self.attempts.extend(run.attempts)
        self.broken_invariants.extend(name for name, holds in run.invariants if not holds)

        audit = run.audit_executions()
        self.duplicate_executions += sum(count - 1 for count in audit.values() if count > 1)
        if sum(audit.values()) != run.executions:
            self.audit_discrepancies += 1
        if run.category == "fail-closed" and run.executions:
            self.fail_closed_violations += run.executions

    def rate(self, wanted: tuple[str, ...]) -> tuple[int, int]:
        relevant = [a for a in self.attempts if a.expected in wanted]
        return sum(1 for a in relevant if a.ok), len(relevant)

    def failures(self) -> list[Attempt]:
        return [a for a in self.attempts if not a.ok]

    def latencies(self) -> list[float]:
        return sorted(a.latency_ms for a in self.attempts)

    @property
    def green(self) -> bool:
        return (
            not self.failures()
            and not self.broken_invariants
            and self.duplicate_executions == 0
            and self.fail_closed_violations == 0
            and self.audit_discrepancies == 0
        )
