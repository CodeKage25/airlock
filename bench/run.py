#!/usr/bin/env python3
"""The adversarial guardrail benchmark. Green is the acceptance spec for v0.1."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bench.cases import CASES
from bench.harness import BLOCK, ESCALATE, EXECUTE, REPLAY, CaseRun, Report

GREEN, RED, DIM, BOLD, OFF = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    return values[min(int(len(values) * fraction), len(values) - 1)]


def main() -> int:
    report = Report()

    print(f"\n{BOLD}Airlock adversarial guardrail benchmark{OFF}\n")

    for name, category, scenario in CASES:
        run = CaseRun(name=name, category=category)
        scenario(run)
        report.absorb(run)

        failed = [a for a in run.attempts if not a.ok]
        broken = [text for text, holds in run.invariants if not holds]
        mark = f"{RED}FAIL{OFF}" if failed or broken else f"{GREEN} ok {OFF}"
        print(f"  {mark}  {category:<12} {name}")
        for attempt in failed:
            print(
                f"        {RED}{attempt.step}: expected {attempt.expected}, "
                f"got {attempt.observed} ({attempt.reason}){OFF}"
            )
        for text in broken:
            print(f"        {RED}invariant broken: {text}{OFF}")

    blocked_ok, blocked_total = report.rate((BLOCK,))
    allowed_ok, allowed_total = report.rate((EXECUTE, REPLAY))
    escalated_ok, escalated_total = report.rate((ESCALATE,))
    latencies = report.latencies()

    print(f"\n{BOLD}Metrics{OFF}")
    print(f"  cases                 {report.cases}")
    print(f"  attempts              {len(report.attempts)}")
    print(
        f"  block recall          {_pct(blocked_ok, blocked_total)}  ({blocked_ok}/{blocked_total})"
    )
    print(
        f"  false-block rate      {_pct(allowed_total - allowed_ok, allowed_total)}  "
        f"({allowed_total - allowed_ok}/{allowed_total})"
    )
    print(
        f"  escalation accuracy   {_pct(escalated_ok, escalated_total)}  "
        f"({escalated_ok}/{escalated_total})"
    )
    print(
        f"  guardrail latency     p50 {percentile(latencies, 0.5):.2f}ms  "
        f"p95 {percentile(latencies, 0.95):.2f}ms"
    )

    print(f"\n{BOLD}Hard invariants{OFF}")
    for label, value in (
        ("duplicate executions", report.duplicate_executions),
        ("fail-closed violations", report.fail_closed_violations),
        ("audit discrepancies", report.audit_discrepancies),
        ("broken invariants", len(report.broken_invariants)),
    ):
        colour = GREEN if value == 0 else RED
        print(f"  {label:<24} {colour}{value}{OFF}")

    if report.green:
        print(f"\n{GREEN}{BOLD}GREEN{OFF} {DIM}every guardrail held{OFF}\n")
        return 0

    print(f"\n{RED}{BOLD}RED{OFF} {DIM}a guardrail did not hold{OFF}\n")
    return 1


def _pct(part: int, whole: int) -> str:
    return f"{(100.0 * part / whole if whole else 0.0):6.2f}%"


if __name__ == "__main__":
    raise SystemExit(main())
