# A payment agent that can't hurt you

```bash
python examples/payment_agent/run.py
```

A fake three-leg payment rail (on-ramp, transfer, off-ramp) with injectable failures, and
an agent proposing actions against it. The rail's last leg is one-way, which is what makes
the failure modes interesting.

The demo opens with the failures, not the happy path:

1. **A retry of a payment already made.** The rail moves 400, not 800.
2. **A payment above the per-call cap.** Blocked by `caps`.
3. **A retry with the beneficiary rewritten.** Same intent, different destination, blocked
   by `idempotency` rather than treated as a new action.
4. **FX moving 8% between quote and settlement.** A risk hook escalates.
5. **The irreversible leg timing out, then being retried blind.** The retry is blocked: the
   first attempt's real-world effect is unknown, and guessing is worse than stopping.
6. **A partial settlement.** Routed to a human.
7. **A one-way action over the threshold.** Parked, approved by ops, executed exactly once;
   the agent's follow-up retry replays rather than paying twice.
8. **A runaway loop.** Stopped at the daily cap.

It closes with the audit log's own tally and a redacted beneficiary, so the record proves
what happened without leaking who it happened to.

## Wiring in a real model

The demo drives the tools directly so it runs offline with no API key. To hand the same
guarded tools to a model, swap the direct calls for the adapter:

```python
specs, dispatch = lock.as_anthropic_tools()

result = dispatch(block.name, block.input, tool_call_id=block.id)
```

The tool-use id becomes the intent, which is exactly the property you want: stable across a
retry of the same model response, distinct across genuinely new decisions. Refusals come
back as a payload rather than an exception, so a blocked call teaches the model what the
limit was instead of crashing the loop.
