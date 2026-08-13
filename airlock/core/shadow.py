"""Observe-only evaluation, and the report that comes out of it.

Nobody switches a blocking guardrail on in a payment path on day one. They run it
alongside production for a fortnight, read what it *would* have stopped, argue about the
false positives, tune the policy, and only then enforce.

Shadow mode relaxes **judgement**, never **correctness**. Caps, risk hooks and the
approval gate are opinions about what should be allowed, so they can be observed instead
of applied. The tool layer, idempotency and fail-closed are not opinions:

- The tool layer cannot be shadowed. Arguments that fail validation cannot be passed to
  the function at all, so there is nothing to observe.
- Idempotency must never be shadowed. Letting a duplicate through during a soak period
  would cause exactly the double payment the library exists to prevent, and would do it
  while everyone believed nothing was at risk.
- Fail-closed still blocks. An unreachable store means idempotency cannot be checked, and
  that check is not optional in either mode.

So a shadow deployment is genuinely safe to switch on, and it is honest about the fact
that it is not literally a no-op.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from airlock.core.audit import AuditLog
from airlock.core.types import AuditEntry, Outcome


class Mode(StrEnum):
    ENFORCE = "enforce"
    SHADOW = "shadow"


SHADOW_OUTCOMES = (Outcome.WOULD_BLOCK, Outcome.WOULD_ESCALATE)


@dataclass
class Finding:
    """One reason, everything it would have stopped, and how often."""

    tool: str
    layer: str
    outcome: Outcome
    rule: str
    reason: str = ""
    count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    intents: list[str] = field(default_factory=list)

    def observe(self, entry: AuditEntry) -> None:
        self.count += 1
        self.reason = entry.reason or self.reason
        self.first_seen = min(self.first_seen or entry.at, entry.at)
        self.last_seen = max(self.last_seen or entry.at, entry.at)
        if len(self.intents) < 5 and entry.intent not in self.intents:
            self.intents.append(entry.intent)

    @property
    def verdict(self) -> str:
        return "block" if self.outcome is Outcome.WOULD_BLOCK else "escalate"


@dataclass
class Report:
    """What enforcing would have changed."""

    findings: list[Finding] = field(default_factory=list)
    executed: int = 0
    affected_intents: set[str] = field(default_factory=set)

    @property
    def would_block(self) -> int:
        return sum(f.count for f in self.findings if f.outcome is Outcome.WOULD_BLOCK)

    @property
    def would_escalate(self) -> int:
        return sum(f.count for f in self.findings if f.outcome is Outcome.WOULD_ESCALATE)

    @property
    def verdicts(self) -> int:
        return self.would_block + self.would_escalate

    @property
    def affected(self) -> int:
        """Distinct calls, not verdicts. One call can trip several rules at once."""
        return len(self.affected_intents)

    @property
    def clean(self) -> bool:
        return not self.findings

    def by_layer(self) -> dict[str, int]:
        totals: dict[str, int] = {}
        for finding in self.findings:
            totals[finding.layer] = totals.get(finding.layer, 0) + finding.count
        return totals

    def render(self) -> str:
        if self.clean:
            return (
                f"{self.executed} calls observed, none of which the policy would have "
                "stopped.\nNothing to tune; this policy is ready to enforce."
            )

        lines = [
            f"{self.executed} calls observed. Enforcing would have stopped "
            f"{self.affected} of them, on {self.verdicts} verdicts "
            f"({self.would_block} blocked, {self.would_escalate} sent to a human).",
            "",
        ]
        for finding in self.findings:
            share = f"{100 * finding.count / self.executed:.1f}%" if self.executed else "-"
            lines.append(
                f"  {finding.count:>5}  {share:>6}  {finding.verdict:<8} "
                f"{finding.tool} [{finding.layer}]"
            )
            lines.append(f"         {finding.reason}")
            lines.append(f"         e.g. {', '.join(finding.intents)}")
            lines.append("")
        lines.append("Tune the policy until only the calls you want stopped appear here,")
        lines.append("then switch that tool to mode='enforce'.")
        return "\n".join(lines)


class Shadow:
    """Reads back what observe-only evaluation recorded."""

    def __init__(self, audit: AuditLog) -> None:
        self._audit = audit

    def report(
        self,
        *,
        tool: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> Report:
        report = Report(
            executed=len(
                self._audit.query(tool=tool, outcome=Outcome.EXECUTED, since=since, until=until)
            )
        )
        findings: dict[tuple[str, str, Outcome, str], Finding] = {}
        for outcome in SHADOW_OUTCOMES:
            for entry in self._audit.query(tool=tool, outcome=outcome, since=since, until=until):
                # result_ref carries the rule identity, which is stable across calls;
                # the reason is not, because it names amounts and running totals.
                rule = entry.result_ref or entry.reason or ""
                key = (entry.tool, entry.layer or "", outcome, rule)
                finding = findings.get(key)
                if finding is None:
                    finding = Finding(
                        tool=entry.tool,
                        layer=entry.layer or "",
                        outcome=outcome,
                        rule=rule,
                    )
                    findings[key] = finding
                finding.observe(entry)
                report.affected_intents.add(entry.intent)

        report.findings = sorted(findings.values(), key=lambda f: f.count, reverse=True)
        return report

    def findings_for(self, tool: str) -> Sequence[Finding]:
        return self.report(tool=tool).findings
