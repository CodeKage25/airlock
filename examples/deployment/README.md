# A working deployment

```bash
cd examples/deployment && docker compose up
```

Postgres, two agent replicas sharing it, and Prometheus scraping both. Two replicas rather
than one on purpose: it means the exactly-once and cap guarantees are being exercised across
processes rather than asserted in a README.

| | |
|---|---|
| `http://localhost:8000/pay` | the guarded tool, behind an HTTP API |
| `http://localhost:8000/metrics` | Prometheus exposition |
| `http://localhost:8000/health` | liveness, plus the stuck-intent count |
| `http://localhost:9090` | Prometheus |

## Try the guarantees

```bash
# Executes.
curl -s localhost:8000/pay -d '{"to":"acct_1","amount":100,"intent":"inv-1"}'

# Retry the same intent against the *other* replica. Replays; the rail is not hit twice.
curl -s localhost:8001/pay -d '{"to":"acct_1","amount":100,"intent":"inv-1"}'

# Over the per-call cap.
curl -s localhost:8000/pay -d '{"to":"acct_1","amount":5000,"intent":"inv-2"}'

# Over the approval threshold: parked, not executed.
curl -s localhost:8000/pay -d '{"to":"acct_1","amount":800,"intent":"inv-3"}'

# Each agent gets its own daily budget, because caps are scoped by principal.
curl -s localhost:8000/pay -d '{"to":"a","amount":100,"intent":"i-4","principal":"agent://treasury"}'
```

Then work the queue and the log from any machine with the store URL:

```bash
export AIRLOCK_STORE=postgresql://airlock:airlock@localhost:5432/airlock
airlock approvals pending
airlock audit --outcome blocked
airlock intents stuck
```

## What to copy

[`service.py`](service.py) is the whole wiring, and it is short on purpose: a Postgres
store, Prometheus telemetry with `metrics.watch(lock)` for the pull-time gauges, caps scoped
by principal with a rate limit alongside the budget, an approval rule with a TTL, and
redaction on the beneficiary. Refusals are returned in the same shape the MCP and LangChain
adapters use, so a client only has to learn one vocabulary.
