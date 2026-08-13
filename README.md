# Airlock

[![CI](https://github.com/CodeKage25/airlock/actions/workflows/ci.yml/badge.svg)](https://github.com/CodeKage25/airlock/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/agent-airlock)](https://pypi.org/project/agent-airlock/)
[![Python](https://img.shields.io/pypi/pyversions/agent-airlock)](https://pypi.org/project/agent-airlock/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Duplicate executions](https://img.shields.io/badge/duplicate%20executions-0-brightgreen)](BENCHMARK.md)
[![Fail-closed violations](https://img.shields.io/badge/fail--closed%20violations-0-brightgreen)](BENCHMARK.md)

**The safety layer between your AI agent and the real world.**

Airlock wraps your agent's tools with the guardrails production systems actually need: permission scoping, hard spending caps, idempotency, human-in-the-loop escalation, and an immutable audit trail. Your agent proposes actions. Airlock decides whether they execute.

Built for agents that touch things that matter, like payments, infrastructure, and user data, where "the model usually gets it right" is not an acceptable safety model.

```bash
pip install agent-airlock
```

> **Status: v0.2 in active development.** Deployable across replicas on Postgres, with operator recovery for stuck intents. APIs may change before 1.0. Adversarial issues and early contributors are especially welcome, see [Contributing](#contributing).

---

## Table of contents

- [Why this exists](#why-this-exists)
- [Sixty-second quickstart](#sixty-second-quickstart)
- [How it works](#how-it-works)
- [Decision semantics](#decision-semantics)
- [Core concepts](#core-concepts)
- [API reference](#api-reference)
- [Example: a payment agent that can't hurt you](#example-a-payment-agent-that-cant-hurt-you)
- [Production readiness](#production-readiness)
- [The benchmark](#the-benchmark)
- [Adopting it without a scary cutover](#adopting-it-without-a-scary-cutover)
- [Operating it](#operating-it)
- [Architecture and repo layout](#architecture-and-repo-layout)
- [What Airlock protects against, and what it doesn't](#what-airlock-protects-against-and-what-it-doesnt)
- [FAQ](#faq)
- [Development](#development)
- [Design principles](#design-principles)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Why this exists

Everyone building agents that take real actions ends up hand-rolling the same five things, badly, under deadline pressure:

1. Stopping the agent from calling things it shouldn't
2. Capping how much damage a single action (or a runaway loop) can do
3. Making sure a retry never executes the same action twice
4. Routing consequential actions to a human before they run
5. Being able to prove, afterwards, exactly what the agent did and why

Airlock packages these as composable, independently enforced layers. Each layer can block an action on its own. An action executes only if it clears **all** of them. No single failure, whether a bad prompt, a model mistake, or a compromised tool, is enough to cause an incident.

The core design principle: **autonomy is earned per action class, never granted globally.** Your agent gets trusted with the small and reversible long before the large and final.

## Sixty-second quickstart

```python
from airlock import Airlock, Policy, Caps, approval

lock = Airlock(
    policy=Policy(
        caps={
            "send_payment": Caps(max_per_call=100, max_per_day=1_000, currency="USD"),
        },
        approvals=[
            approval.when("send_payment", lambda call: call.args["amount"] > 100),
            approval.when("send_payment", lambda call: call.context.get("new_beneficiary")),
        ],
    ),
    store="sqlite:///airlock.db",  # audit log + idempotency store
)


@lock.tool
def send_payment(to: str, amount: float, currency: str = "USD") -> str:
    """Send a payment. Airlock decides if this actually runs."""
    return payments_api.transfer(to=to, amount=amount, currency=currency)


tools = lock.tools()  # hand these to your agent framework
```

What happens at runtime:

```python
send_payment(to="acct_123", amount=40, _intent="inv-77")
# passes caps, no approval rule fires, EXECUTES, audit-logged

send_payment(to="acct_123", amount=40, _intent="inv-77")  # the agent retries
# idempotency layer recognises the intent, returns the ORIGINAL result, does not execute twice

send_payment(to="acct_999", amount=500, _intent="inv-78")
# exceeds max_per_call, raises Blocked, audit-logged with the reason

send_payment(to="new_acct", amount=80, _intent="inv-79", _context={"new_beneficiary": True})
# approval rule fires, raises PendingApproval, waits in the queue
```

Handling the approval queue:

```python
for req in lock.approvals.pending():
    print(req.id, req.tool, req.args, req.reason)
    req.approve(by="ops@yourco.com")  # or req.reject(reason="wrong beneficiary")
```

## How it works

```
        Agent proposes an action
                  |
                  v
   +------------------------------+
   |  1. Tool Layer               |  only registered, typed tools. no raw API access
   +------------------------------+
   |  2. Policy / Caps            |  per-tool, per-scope, per-window limits, in code
   +------------------------------+
   |  3. Idempotency              |  deterministic keys. retries never double-execute
   +------------------------------+
   |  4. Risk Hooks               |  your custom checks (fraud score, business rules)
   +------------------------------+
   |  5. Approval Gate            |  consequential actions wait for a human
   +------------------------------+
                  |
                  v
        Execute  (result written to the append-only audit trail)
```

The pipeline order is fixed and lives in one place ([`core/pipeline.py`](airlock/core/pipeline.py)). Layers are independent: none can bypass, disable, or reach into another. If any layer errors, the action does not execute. There is no fail-open mode and there never will be.

Caps sit above idempotency, and stay correct for retries because cap spend is ledgered by idempotency key and each window check excludes the key being checked. A retry is the same money, so it passes caps and is then short-circuited by the idempotency layer, rather than being spuriously blocked for exceeding a window it already paid into.

## Decision semantics

Every proposed call resolves to exactly one of three outcomes:

| Outcome | What happens | How your code sees it |
|---|---|---|
| **Executed** | All layers allow. The wrapped function runs once. | Normal return value |
| **Blocked** | A layer refused (cap breach, policy violation, store down, risk hook block). | `airlock.errors.Blocked` raised, with `.reason` and `.layer` |
| **Escalated** | An approval rule matched. The call is parked, nothing runs. | `airlock.errors.PendingApproval` raised, with `.request_id` |

Special cases, precisely defined:

- **Idempotent repeat.** Same intent id as a previously executed call: the original result is returned, the function does not run again, and the audit log records a `deduplicated` entry. From the caller's view this looks like a normal successful return.
- **Same intent, different arguments.** Blocked. The intent id names one business action, so a retry that mutates its arguments is a new action wearing an old name, and the safe reading is to refuse it.
- **Attempt with an unknown outcome.** A call that crashed mid-execution, timed out, or is still in flight leaves a non-completed reservation. Any later attempt on that intent is Blocked until a human resolves it. This is the timeout-on-the-irreversible-leg case, and guessing is the one thing worse than stopping.
- **Approved later.** When a human approves a pending request, execution happens at approval time through the same pipeline (caps are re-checked at that moment, since windows may have moved).
- **Dependency failure.** Idempotency store or audit store unreachable: `Blocked` with `layer="fail-closed"`. Unauditable means it does not run.

## Core concepts

**Tools.** The only way an agent acts. You register plain Python functions; Airlock wraps them with the full guardrail stack and hands back callables or framework-native tool specs. Arguments are validated against the signature before any layer sees them, and `*args`/`**kwargs` tools are rejected at registration, because an unbounded argument surface cannot be typed or capped.

**Intents.** Every call carries an intent id (`_intent=...`), supplied by the caller, that names the business action ("pay invoice 77"). It is mandatory: no intent, no execution. The idempotency key is derived deterministically from the tool name, canonicalised arguments, and the intent id. Same logical intent, same key, across retries, processes, and restarts.

**Policies and Caps.** Hard limits per tool, per scope, per time window. Enforced in code, outside the model. A cap in a system prompt is a suggestion. A cap in Airlock is a wall.

**Scopes.** A policy can be partitioned by a scope key (a corridor, a user, a tenant, an environment) so one agent identity can carry different limits in different contexts. `Caps(max_per_day=1000, scope_by="corridor")`.

**Approval gates.** Predicate rules that route matching calls to a pending queue instead of executing. Approve or reject via the Python API or the CLI. Slack and webhook channels are on the roadmap.

**Risk hooks.** Your own checks that run before execution: fraud scoring, business-hours rules, anomaly checks. Each returns `allow`, `block`, or `escalate` with a reason.

**Audit trail.** Append-only record of every proposed action and its outcome: timestamp, tool, canonicalised args (with redaction applied), intent, decision, deciding layer, reason, result reference. SQLite by default, Postgres for real deployments.

**Fail closed.** If a layer errors or a store is unreachable, the action does not execute. Always.

## API reference

### `Airlock(...)`

```python
Airlock(
    policy: Policy,
    store: str = "memory://",         # "memory://" | "sqlite:///path.db" | "postgres://..."
    fail_mode: str = "closed",        # the only accepted value. exists to be explicit.
    clock: Callable[[], datetime] | None = None,   # injectable for testing time windows
    audit_redact: Sequence[str] = (), # argument names to redact from the audit log
    strict_idempotency: bool = False, # raise DuplicateIntent instead of replaying
    approval_ttl: timedelta | None = None,   # default deadline for parked requests
    stuck_after: timedelta = timedelta(minutes=5),   # when a pending call counts as stuck
    mode: str = "enforce",            # "shadow" evaluates and records without blocking
    telemetry: Telemetry | Sequence[Telemetry] | None = None,
)
```

| Member | What it does |
|---|---|
| `@lock.tool` / `lock.tool(name=..., scope_by=..., key_fields=...)` | Register and wrap a function |
| `lock.tools()` | All wrapped callables |
| `lock.get(name)` | One wrapped callable by tool name |
| `lock.as_openai_tools()` | OpenAI tool-calling specs plus a dispatcher |
| `lock.as_anthropic_tools()` | Anthropic tool-use specs plus a dispatcher |
| `lock.approvals.pending()` | Pending approval requests |
| `lock.audit.query(...)` | Query the audit log (by tool, decision, time range, intent) |
| `lock.intents.stuck()` | Intents whose real-world effect is unknown and are blocking retries |
| `lock.intents.resolve(...)` | Settle one, as executed or not executed |
| `lock.shadow.report()` | In observe-only mode, what enforcing would have changed |
| `lock.snapshot()` | Pending approvals and stuck intents, for alerting |
| `lock.check_policy()` | Raise if a cap or rule names a tool that was never registered |

### `Policy` and `Caps`

```python
Policy(
    caps: dict[str, Caps],            # tool name -> caps
    approvals: list[ApprovalRule],
    risk_hooks: list[RiskHook] = [],
)

Caps(
    max_per_call: Decimal | None = None,
    max_per_day: Decimal | None = None,
    max_per_window: Decimal | None = None,
    window: timedelta | None = None,
    currency: str | None = None,
    scope_by: str | None = None,      # partition caps by this context key
    amount_field: str = "amount",     # which argument the limits meter
)
```

Caps meter the argument named by `amount_field` when the tool has one, and otherwise count calls, so `max_per_day=10` on a tool with no amount means ten calls a day. Amounts are handled as `Decimal` internally, so cap boundaries are exact rather than floating point approximations.

Boundary semantics: `max_per_call` is inclusive. A call exactly at the cap executes; one unit over is blocked. Windows are rolling and accounted using the injected clock, so they are testable. Spend is recorded before execution and is not refunded if the tool then fails, because under-counting spend is the unsafe direction.

### Approvals

```python
approval.when(tool: str, predicate: Callable[[Call], bool], reason: str | None = None)

req = lock.approvals.pending()[0]
req.approve(by: str)      # re-runs the pipeline and executes if still allowed
req.reject(reason: str)   # closes the request, audit-logged
```

`Call` exposes `.tool`, `.args`, `.context`, `.intent`, `.scope`.

Approving is atomic: two operators racing on the same request produce one approval and one error, never two executions.

### Risk hooks

```python
def my_hook(call: Call) -> Decision:
    if fraud_score(call.args["to"]) > 0.9:
        return Decision.block("fraud score above threshold")
    return Decision.allow()


Policy(..., risk_hooks=[my_hook])
```

Hooks run in order. First non-allow wins. A hook that raises is treated as a block (fail closed). Async hooks are rejected at construction time in v0.1.

### Errors

All in `airlock.errors`, all carrying structured fields:

| Exception | Raised when | Fields |
|---|---|---|
| `Blocked` | Any layer refuses | `.reason`, `.layer`, `.call` |
| `PendingApproval` | An approval rule matched | `.request_id`, `.reason`, `.call` |
| `DuplicateIntent` | Only in `strict_idempotency=True` mode; default behaviour returns the original result instead | `.original_result`, `.intent` |
| `StoreUnavailable` | A store dependency failed | `.store`, `.cause` |
| `PolicyError` | Invalid configuration, at setup time rather than call time | — |

### Stores

| URL | Backing | Use for |
|---|---|---|
| `memory://` | In-process dict | Tests only. Not durable. |
| `sqlite:///airlock.db` | SQLite file | Local dev, and single-host services of any number of processes |
| `postgres://...` | Postgres | Production, multi-process, multi-host |

Guarantees: idempotency writes are atomic check-and-set, so concurrent same-intent calls have exactly one winner. Audit writes happen before execution (intent recorded) and after (outcome recorded), so a crash mid-execution is visible as an intent without an outcome. The SQLite audit table carries triggers that abort any `UPDATE` or `DELETE`, so append-only is enforced by the database and not only by the writer.

### Context

Pass per-call context through the reserved keyword `_context`. It feeds approval predicates, risk hooks, and scope resolution. It is never given to the model and never affects the idempotency key unless you opt a field in via `key_fields` at registration:

```python
@lock.tool(scope_by="corridor", key_fields=["corridor"])
def send_payment(to: str, amount: float) -> str: ...
```

## Adopting it without a scary cutover

Nobody switches a blocking guardrail on in a payment path on day one. Run it in observe-only
first:

```python
lock = Airlock(policy=policy, store="postgresql://...", mode="shadow")
```

Every layer still evaluates, every verdict is still audited, and nothing is blocked. After a
fortnight, read what enforcing would have done:

```bash
$ airlock shadow report
8 calls observed. Enforcing would have stopped 8 of them, on 12 verdicts (10 blocked, 2 sent to a human).

      6   75.0%  block    send_payment [caps]
         120.0 exceeds max_per_call of 100 for send_payment
         e.g. inv-0, inv-1, inv-2, inv-3, inv-4

      2   25.0%  escalate send_payment [approvals]
         first payment to a new beneficiary
         e.g. new-0, new-1
```

Tune the policy until only the calls you actually want stopped appear, then graduate one tool
at a time:

```python
@lock.tool(mode="enforce")  # this one is live; the rest are still being observed
def send_payment(to: str, amount: float) -> str: ...
```

`airlock shadow report --strict` exits non-zero when anything would still be stopped, so a
promotion can be gated on it in CI.

**Shadow mode relaxes judgement, never correctness.** Caps, risk hooks and the approval gate
are opinions about what should be allowed, so they can be observed instead of applied. Three
things are not opinions and are never shadowed:

- **The tool layer.** Arguments that fail validation cannot be passed to the function at all,
  so there is nothing to observe.
- **Idempotency.** Letting a duplicate through during a soak period would cause exactly the
  double payment this library exists to prevent, at the moment everyone believed nothing was
  at risk.
- **Fail-closed.** An unreachable store means idempotency cannot be checked, and that check
  is not optional in either mode.

Spend is still ledgered for calls shadow mode allows through, because they really did spend
the money and a window that pretended otherwise would under-report every breach after it.

## Operating it

### Metrics and traces

```bash
pip install 'agent-airlock[prometheus,otel]'
```

```python
from airlock.telemetry.prometheus import PrometheusTelemetry
from airlock.telemetry.otel import OpenTelemetry

metrics = PrometheusTelemetry()
lock = Airlock(policy=policy, store=..., telemetry=[metrics, OpenTelemetry()])
metrics.watch(lock)  # the gauges that have to be read rather than counted
```

```
airlock_decisions_total{tool="send_payment",outcome="executed",layer="none"}   3.0
airlock_decisions_total{tool="send_payment",outcome="blocked",layer="caps"}    2.0
airlock_decisions_total{tool="send_payment",outcome="escalated",layer="approvals"} 1.0
airlock_pipeline_seconds_bucket{tool="send_payment",le="0.001"}                6.0
airlock_pending_approvals                                                      1.0
airlock_oldest_pending_approval_seconds                                     1830.0
airlock_stuck_intents                                                          0.0
```

OpenTelemetry puts one span on every proposed action carrying the verdict, the deciding
layer and the reason, and marks refusals as errors. The point is to sit the guardrail
decision next to the agent turn that caused it, so "why did this payment not happen" is
answerable from the same trace as "what was the model doing".

Telemetry hangs off the audit writer, which is the one place every outcome already flows
through, so a counter cannot drift out of step with the audit trail.

**The audit log fails closed; telemetry fails open.** A call that cannot be audited does not
execute, because the audit log is the compliance record. A metrics backend having a bad day
costs a point on a dashboard, so every telemetry call is wrapped and its exceptions are
swallowed — including per-backend, so one broken exporter cannot silence another.

### Deploying more than one replica

Use Postgres. `sqlite://` is safe for any number of processes on one host, and unsafe across
hosts, because SQLite's locking does not survive a network filesystem.

```bash
pip install 'agent-airlock[postgres]'
```

```python
lock = Airlock(policy=policy, store="postgresql://user:pass@host/airlock")
```

Schema migrations run automatically at startup and are forward-only, guarded by an advisory
lock so replicas booting together cannot both apply one. `airlock migrate` reports the applied
version. Grant the application role `INSERT` and `SELECT` on `audit` and nothing more: the
append-only triggers stop the application from rewriting history, but not the table's owner
from removing the triggers.

### Stuck intents

A call that crashed or timed out blocks every retry of its intent, on purpose, because its
real-world effect is unknown. Someone has to go and look:

```bash
$ airlock intents stuck
KEY               TOOL    INTENT  STATE   AGE
----------------  ------  ------  ------  -------
20e297dffb062b7e  settle  inv-80  failed  0:04:11

$ airlock intents resolve 20e297dffb062b7e --not-executed --by ops@yourco.com \
    --note "rail shows nothing"
```

`--executed` keeps the intent closed, so a retry replays instead of paying twice.
`--not-executed` releases the intent *and* the budget it reserved, so a retry can proceed.
Either way the decision is audit-logged against the person who made it. Keys can be
abbreviated, the way git takes a short commit hash.

The same is available in-process as `lock.intents.stuck()` and `lock.intents.resolve(...)`.

### The approval queue

```bash
$ airlock approvals pending
$ airlock approvals reject 3d6c608ecf40 --reason "wrong beneficiary"
$ airlock approvals approve 3d6c608ecf40 --by ops@yourco.com --app myservice.agent:lock
```

Approving executes the parked call, so it needs your registered tools: point `--app` at the
module attribute holding the configured `Airlock`. Listing, rejecting and auditing need only
the store, so they work from anywhere with `--store` or `AIRLOCK_STORE` set.

Give consequential rules a deadline, so the queue cannot rot:

```python
approval.when("send_payment", is_one_way, "off-ramp is irreversible", ttl=timedelta(hours=4))
```

Expiry is audited as its own outcome, an expired request cannot be approved, and a later
retry opens a fresh one rather than reviving the stale decision.

### Reading the log

```bash
$ airlock audit --tool send_payment --outcome blocked --limit 20
```

## Example: a payment agent that can't hurt you

[`examples/payment_agent/`](examples/payment_agent/) is a complete runnable demo:

- A **fake multi-leg payment rail** (on-ramp, transfer, off-ramp) with injectable failures
- An agent driving it toward completed payments
- Airlock catching, live: a duplicate execution attempt, a cap breach, an over-tolerance FX slippage escalation, and a partial settlement routed to a human

```bash
python examples/payment_agent/run.py
```

The demo's output opens with the failures being caught, not the happy path. That is the point.

## The benchmark

[`bench/`](bench/) is an adversarial guardrail benchmark that runs against Airlock on every change: duplicate-intent retries (including the nasty timeout-on-the-irreversible-leg case), cap boundary cases, prompt injection through tool arguments, partial settlement, and fail-closed behaviour under store outages.

Two hard invariants fail the run if violated even once:

- **Duplicate executions = 0.** A repeated intent must never execute twice.
- **Fail-closed violations = 0.** Nothing executes while a dependency is down.

Reported metrics: block recall, false-block rate, escalation accuracy, guardrail latency. See [`BENCHMARK.md`](BENCHMARK.md). The benchmark doubles as the acceptance spec: v0.1 is done when `python bench/run.py` is green.

## Architecture and repo layout

```
airlock/
  cli.py             # operator commands: intents, approvals, audit, migrate
  core/
    pipeline.py      # the fixed layer ordering. the heart of the library
    tools.py         # registration and wrapping
    policy.py        # Policy, Caps, window accounting
    idempotency.py   # key derivation + store interface
    intents.py       # stuck-intent listing and operator resolution
    approvals.py     # rules, pending queue, expiry, approve/reject
    risk.py          # risk hook interface
    audit.py         # append-only writer + query API
    canonical.py     # argument canonicalisation + deterministic keys
    stores/          # memory, sqlite, postgres, forward-only migrations
  adapters/          # openai.py, anthropic.py
  cli.py             # operator commands: intents, approvals, audit, migrate
  errors.py
bench/               # adversarial benchmark (see BENCHMARK.md)
examples/
  payment_agent/
tests/
```

Rules the codebase lives by are in [`CLAUDE.md`](CLAUDE.md): fail closed everywhere, enforcement outside the model, independent layers, append-only audit, deterministic keys, no secrets in logs.

## Production readiness

An honest status, because a safety library that oversells itself is worse than no safety library.

**Verified today**, each by a test that fails if the property breaks:

| Property | How it is verified |
|---|---|
| One intent executes at most once | 8-way concurrent burst in one process, and 4 OS processes against one shared database |
| Caps hold under concurrency | 20 concurrent callers with distinct intents against a shared budget spend exactly the cap, in-process and across 12 processes |
| Nothing executes while a store is down | Five independent outage points, each asserted to execute zero times |
| Cap boundaries are exact | `Decimal` throughout; `0.1 + 0.2` is not more than `0.3` |
| The audit log cannot be rewritten | SQLite and Postgres both abort `UPDATE`, `DELETE` and `TRUNCATE` by trigger, asserted from a raw connection |
| An unknown outcome never retries blind | A timed-out attempt blocks every later attempt on that intent, until a human resolves it |
| Upgrades never lose history | A database at an older schema migrates forward with its audit rows intact |

Suite: 282 tests, every store-backed one run against all three backends, plus a 31-case
adversarial benchmark. `mypy` is strict over `core/`.

**Known limits.** These are real, and you should read them before deploying:

- **Redaction is shallow.** `audit_redact` matches top-level argument names only; a secret
  nested inside a dict argument still reaches the log.
- **Sync only.** Tools and risk hooks are synchronous. Async support is next.
- **Policy is Python.** No YAML policy files yet, so a policy change is a deploy and cannot
  be reviewed by anyone who does not write Python.
- **Audit and spend grow forever.** No retention, rollup or archival yet.
- **`TRUNCATE` protection needs role separation.** The triggers stop the application from
  rewriting history; they do not stop the table's owner from dropping the triggers. Grant
  the application role `INSERT` and `SELECT` on `audit` and nothing more.
- **Replay needs JSON.** A tool returning a non-serialisable object executes fine, but a
  later retry of that intent is blocked rather than replayed.
- **No production hours.** Nothing here has run against real volume yet. The
  canonicalisation logic in particular has been tested against the adversarial cases we
  thought of, which is not the same as all of them.

**Does it work with any language?** No. Airlock is an in-process Python library, so your
agent has to be Python. The design ports to any language, the code does not. Wrapping it as
an MCP server would make guarded tools reachable from any MCP client in any language, which
is the highest-leverage item on the roadmap for reach.

**Does it work with any database?** Three backends ship, and the same suite runs against all
of them, so the abstraction is known not to leak. `Store` is 17 methods, and any backend
offering an atomic conditional write can implement them: MySQL, DynamoDB and Redis all
qualify. That single primitive is what makes "executes at most once" true, so a backend
without it cannot be used.

## What Airlock protects against, and what it doesn't

Protects against:

- A prompted or manipulated model calling tools it shouldn't, or with values it shouldn't
- Retry storms and ambiguous timeouts causing double execution
- A runaway loop draining an account before anyone notices
- Consequential one-way actions happening without a human
- "What did the agent actually do?" being unanswerable after an incident

Does not protect against:

- A malicious human with direct access to your APIs (Airlock governs the agent path, not your whole perimeter)
- Bugs inside your tool implementations themselves
- Bad policy: if you set `max_per_call=1_000_000`, Airlock will faithfully allow it
- Model output quality. Airlock bounds actions, it does not make the model smarter

## FAQ

**Why not just put the limits in the system prompt?**
Prompts persuade, they do not enforce. A model under injection, distribution shift, or plain error will violate prompt-stated limits. Airlock's limits are code the model cannot see or negotiate with.

**What is the runtime overhead?**
The pipeline is a handful of dict lookups and one or two store writes per call. Against any real tool that touches a network, overhead is noise. The benchmark reports guardrail latency per call so the claim stays honest.

**Does it work with async tools?**
v0.1 wraps sync functions. Async tool support is v0.3 on the roadmap.

**A call crashed and now every retry of that intent is blocked. Is that a bug?**
No, that is the design. A crashed or timed-out attempt has an unknown real-world effect, and Airlock will not gamble on it having been a no-op. Find it with `airlock intents stuck`, check whether the action actually landed, and settle it with `airlock intents resolve ... --executed` or `--not-executed`. See [Operating it](#operating-it).

**Can I use it without an LLM at all?**
Yes. Airlock has no model dependency. Anything that calls functions, cron jobs, workflow engines, humans behind an API, gets the same guarantees.

**Why "Airlock"?**
An action leaves the agent, passes through a sealed chamber where every check runs, and only then reaches the outside world. Nothing goes straight through.

## Development

```bash
git clone https://github.com/CodeKage25/airlock && cd airlock
uv sync
uv run pytest            # fast suite, no network
AIRLOCK_TEST_POSTGRES=postgresql:///airlock_test uv run pytest   # adds the Postgres backend
uv run ruff check && uv run ruff format --check
uv run mypy airlock/     # core/ is strict
python bench/run.py      # the adversarial benchmark. green = v0.1 done
```

Python 3.11+. Core dependencies: pydantic and the standard library. Postgres, redis, and framework SDKs are optional extras.

## Design principles

1. **Fail closed.** Uncertainty means no execution.
2. **Enforcement lives outside the model.** Prompts persuade. Policies enforce.
3. **Every layer is independent.** Any one can block. None can be bypassed by another.
4. **Everything is auditable.** If you can't reconstruct why an action ran, the system is not done.
5. **Boring by design.** No magic, no hidden state, small dependency surface.

## Roadmap

- [x] **v0.1** core layers (tools, caps, idempotency, approvals via Python API), SQLite audit log, OpenAI and Anthropic adapters, benchmark green
- [x] **v0.2** Postgres store, schema migrations, stuck-intent recovery, approval TTLs,
      operator CLI
- [x] **v0.3** shadow mode with a graduation path per tool
- [x] **v0.4** OpenTelemetry and Prometheus
- [ ] **v0.5** async tools, agent identity, policy as data
- [ ] **v0.6** MCP server, LangChain/LangGraph adapter, Slack approval channel
- [ ] **Later** hash-chained audit, audit export and retention, anomaly-detection risk hook

Full detail and reasoning: [`ROADMAP.md`](ROADMAP.md).

## Contributing

Early contributors shape the architecture. This is the best time to get involved.

The most valuable thing you can send is **a way you broke a guardrail**. Adversarial issues are genuinely gold, and a failing benchmark case is the ideal form. Other good first contributions: a framework adapter, a risk-hook example, a store backend, or hardening the idempotency key canonicalisation.

Every PR runs three Python versions against three store backends, plus lint, types, the adversarial benchmark, and a clean-install check that the built wheel still enforces.

- [`CONTRIBUTING.md`](CONTRIBUTING.md) — setup, the one rule that matters, schema-change rules, stability policy
- [`CLAUDE.md`](CLAUDE.md) — engineering conventions
- [`SECURITY.md`](SECURITY.md) — trust boundaries, what counts as a vulnerability, private disclosure
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
- [`CHANGELOG.md`](CHANGELOG.md) — every entry says which promise a change affects

Found a bypass that affects a deployed system? Do not open a public issue — see [`SECURITY.md`](SECURITY.md).

## Why trust the author on this

I've built and operated multi-currency payment infrastructure moving real daily volume across NGN, GHS, KES and XOF: the fee logic, webhooks, and reconciliation underneath it. I've also shipped production agentic systems, voice agents and multi-step tool-using pipelines. Airlock is the library I kept wishing existed at the intersection.

## License

Apache-2.0
