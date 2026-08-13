# Engineering conventions

Rules this codebase lives by. They exist because Airlock is the thing standing between an
agent and someone's money, so "usually correct" is a defect.

## Non-negotiable

1. **Fail closed.** If a layer errors, a store is unreachable, or an outcome is unknown,
   the action does not execute. There is no fail-open mode and no flag that adds one.
2. **Enforcement lives outside the model.** Nothing in a prompt, a tool argument, or a
   model output may influence a limit. Policy is code.
3. **Layers are independent.** Any layer can block. No layer may bypass, disable, or reach
   into another. The order lives in exactly one place, `core/pipeline.py`.
4. **The audit log is append-only.** No update path, no delete path. SQLite enforces this
   with triggers, not just convention.
5. **Keys are deterministic.** The same logical action derives the same idempotency key
   across retries, processes and restarts. Canonicalisation changes are breaking changes.
6. **No secrets in logs.** Audit arguments pass through redaction. Result payloads are
   recorded as a digest reference, never inline.

## Correctness habits

- **Money is `Decimal`.** Never compare or accumulate float amounts. Parse via `str()`.
- **Check and write in one step.** A guardrail that reads a total, decides, and then
  writes can be raced by a second caller doing the same. Enforcement belongs inside the
  store transaction that records the effect.
- **Prefer one rule to several special cases.** The reservation state machine is
  `PENDING -> DONE | FAILED`, and "any existing non-`DONE` record blocks" covers the
  concurrent duplicate, the crashed process and the timed-out irreversible leg without a
  branch for each.
- **Uncertainty is not an edge case.** A timeout is the normal way payment systems fail.
  Design for not knowing.

## Tests

- Every guardrail change ships with a test proving it **blocks** what it should, not just
  that it allows what it should.
- Tests run against every store backend. A semantic difference between `memory://` and
  `sqlite://` is a bug in whichever one is wrong.
- Concurrency claims need a concurrency test. If a fix is for a race, temporarily revert
  the fix and confirm the test actually fails.
- Time is injected via `clock`. Never sleep in a test.

## Style

- Clean code, no verbose comments. A comment earns its place by explaining *why*, usually
  why the obvious approach is wrong. Never narrate what the next line does.
- Names describe intent. Test names are sentences about behaviour, not about functions.
- Small dependency surface. Pydantic and the standard library in core; everything else is
  an optional extra.
