# Changelog

Notable changes to Airlock. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [semantic versioning](https://semver.org/) under the stability policy in
[`CONTRIBUTING.md`](CONTRIBUTING.md).

Because Airlock's value is a small set of promises, every entry says which promise a change
affects.

## [Unreleased]

## [0.6.0]

Reach: other languages, other frameworks, and a policy the people who own the limits can read.

### Added

- **MCP server.** `serve(lock)` puts the guardrail behind the protocol, so the agent can be
  TypeScript, Go, Claude Desktop or anything else. Each tool gains an `intent` argument,
  because the guarantee depends on it and the protocol has nowhere else to put one.
- **LangChain / LangGraph adapter.** `as_langchain_tools(lock)`, using the run id as the
  intent: stable across a retry of a step, distinct across new ones.
- **Policy as data.** `Policy.from_file("policy.yaml")` with caps, approval rules and
  durations written as `4h`. Conditions are a small expression language, not `eval`: calls,
  imports, comprehensions and dunder attribute access are all refused at load, because a
  policy format that could execute code would give away the property being protected.
- **Rate limits** as `max_calls_per_window` / `call_window`, distinct from a spend budget and
  enforced in the same transaction, so the two cannot race each other.
- **A reference deployment.** `examples/deployment/` runs Postgres, two agent replicas and
  Prometheus under compose, so the exactly-once and cap guarantees are exercised across
  processes rather than asserted.

### Changed

- Results larger than 256 KiB are recorded as executed but not kept for replay. A
  reservation row is not a blob store, and one oversized result should not slow every future
  read of the table. A retry of such an intent is blocked rather than replayed.

## [0.5.0]

Who is acting, whether the record can be trusted, and tools that are awaited.

### Added

- **Agent identity.** Calls carry a `principal`; caps can partition by it
  (`scope_by="principal"`), approval rules and risk hooks can read it, and the audit log
  can be queried by it. An approved call keeps the principal that proposed it while
  recording the approving human as the actor.
- **Tamper-evident audit**, opt-in via `audit_chain=True`. Each entry carries the digest of
  its predecessor, and `lock.audit.verify()` names the first altered or removed record.
  Triggers prevent the application rewriting history; this detects a rewrite by anyone who
  gets past them. It costs one serialised write, so it is off by default.
- **Nested redaction.** `audit_redact` takes dotted paths with `*` wildcards, and a bare
  name now matches at any depth.
- **Async tools** via `airlock.aio.AsyncAirlock`. The decision comes from the same `prepare`
  function the synchronous pipeline uses, with a parity test that fails if the two ever
  disagree. A synchronous `Airlock` now refuses an async tool outright.
- Property tests for idempotency key derivation, generating the collisions rather than
  testing the ones someone thought of.

### Fixed

- **Approving an async call through the synchronous path marked the request approved before
  the runner rejected it**, consuming an approval nobody could retry. Anything that can
  refuse now refuses before the request is marked decided. *Affects: the
  approval-required promise.*

### Changed

- The pipeline splits into `prepare` / execute / `settle`, which is what lets sync and async
  share one decision. The `_Passthrough` machinery is gone: the tool call now sits outside
  the fail-closed guard rather than nested inside it.

## [0.4.0]

Runnable by people who did not write it.

### Added

- **Prometheus metrics.** `pip install 'agent-airlock[prometheus]'`, then
  `telemetry=PrometheusTelemetry()`. Emits `airlock_decisions_total{tool,outcome,layer}`
  and an `airlock_pipeline_seconds` histogram. `metrics.watch(lock)` adds
  `airlock_pending_approvals`, `airlock_oldest_pending_approval_seconds`,
  `airlock_stuck_intents` and `airlock_oldest_stuck_intent_seconds`, collected at scrape
  time because a request ages while nothing happens and an intent becomes stuck by a
  process disappearing, so neither can be counted as it occurs.
- **OpenTelemetry traces.** `pip install 'agent-airlock[otel]'`, then
  `telemetry=OpenTelemetry()`. One span per proposed action carrying the outcome, the
  deciding layer and the reason, with refusals marked as errors.
- `lock.snapshot()` for the same queue and stuck-intent state without a metrics backend.
- `Airlock(telemetry=...)` accepts one backend or a list. Every alert in the operations
  runbook now has a query next to it.

### Notes on design

- **The audit log fails closed; telemetry fails open.** A call that cannot be audited does
  not execute, because the audit log is the compliance record. A metrics backend having a
  bad day costs a point on a dashboard, so every telemetry call is wrapped and its
  exceptions swallowed. Backends are guarded individually, so one broken exporter cannot
  silence another.
- Telemetry hangs off the audit writer, the one place every outcome already flows through,
  so a counter cannot drift out of step with the audit trail.

## [0.3.0]

Adoptable without a big-bang cutover.

### Added

- **Shadow mode.** `Airlock(mode="shadow")` evaluates every layer and audits every verdict
  without blocking anything, so a policy can be soaked against production traffic before it
  enforces. `lock.shadow.report()` and `airlock shadow report` group what enforcing would
  have changed, by rule, with counts and example intents. `--strict` exits non-zero when
  anything would still be stopped, so a promotion can be gated in CI.
- **Per-tool graduation.** `@lock.tool(mode="enforce")` overrides the lock's mode for one
  tool, so a policy goes live one action at a time rather than all at once.
- `Decision` gained a `rule` field: a stable identity for the thing that fired, separate
  from the human-readable reason that names amounts and running totals. Without it a
  thousand breaches of one limit report as a thousand separate findings.

### Fixed

- **Postgres returned audit timestamps in the server's local timezone** while the other
  backends returned UTC, so the same log read differently depending on the store. The pool
  now pins the session to UTC. *Affects: reading the audit log, not any guarantee.*

### Changed

- **Window limits are no longer checked at layer 2.** They were being evaluated twice: once
  as an advisory read and again as the binding check inside the transaction that writes the
  spend. The advisory read cost a query per call, could never be authoritative anyway, and
  made shadow mode report every window breach twice. Layer 2 now covers only the rules that
  depend on the single call in front of it — `max_per_call`, currency, negative amounts —
  and windows are enforced solely where the spend is written. *No behaviour change when
  enforcing; a window breach is still blocked, with the same reason.*
- `Store.commit_spend` gained `enforce`. With `enforce=False` the spend is recorded whatever
  the checks say and the violation is returned for reporting, which is what lets shadow mode
  keep its windows truthful. *`airlock.core` is internal; see the stability policy.*

## [0.2.0]

Deployable across replicas, and recoverable when a call goes missing.

### Added

- **Postgres store**, the first backend safe across more than one host. Atomic reserve via
  `INSERT ... ON CONFLICT DO NOTHING`; cap commits serialised by a transaction-scoped
  advisory lock per `(tool, scope)`; connection pooling. Install with
  `pip install 'agent-airlock[postgres]'`.
- **Forward-only schema migrations** with a `schema_version` table, for both SQL dialects,
  guarded by an advisory lock so replicas booting together cannot both apply one.
- **Stuck-intent recovery.** `lock.intents.stuck()` lists intents whose real-world effect is
  unknown and which are therefore blocking retries; `lock.intents.resolve(key,
  executed=True|False, by=...)` settles one. `--executed` keeps the intent closed so retries
  replay; `--not-executed` releases the intent *and* the budget it reserved. Both are
  audit-logged against the named human as a new `resolved` outcome.
- **Approval TTLs.** `approval.when(..., ttl=timedelta(hours=4))`, or an `approval_ttl`
  default on `Airlock`. Expiry is audited as a new `expired` outcome, an expired request
  cannot be approved, and a later retry opens a fresh request.
- **Operator CLI** (`airlock`): `intents stuck|resolve`, `approvals pending|approve|reject`,
  `audit`, `migrate`. Intent keys can be abbreviated the way git takes a short commit hash.
- `Airlock(stuck_after=...)` to tune when a pending call is considered stuck.
- Postgres in the CI matrix, so all 282 tests run against all three backends.

### Fixed

- **A boot race that killed replicas starting together** (SQLite). `PRAGMA
  journal_mode=WAL` was issued before `busy_timeout`, and SQLite answers a journal-mode
  change with `SQLITE_BUSY` without ever consulting the busy handler. Enabling WAL now has
  its own bounded retry. *Affects: availability at startup, not any guarantee.*
- **`TRUNCATE` bypassed the append-only audit triggers** on Postgres, because a row-level
  trigger does not fire on it. Closed by migration 3. *Affects: the audit-is-complete
  promise.*
- **A retrying agent could be handed an approval request that was already past its
  deadline**, because expiry only ran when the queue was read. *Affects: the
  approval-required promise.*
- Cap spend is now released when an operator resolves a stuck intent as not executed.
  Previously the budget stayed consumed by an action that provably never happened.

### Changed

- `Store` gained `discard`, `stuck_reservations`, `resolve_reservation`,
  `find_pending_by_key` and `expire_requests`, and `record_spend` became `commit_spend`,
  which re-checks every window inside the same transaction that writes the spend. Custom
  backends must implement these. *`airlock.core` is internal; see the stability policy.*
- `sqlite://` is now documented as safe for any number of processes on **one host**, which
  is tested, and unsafe across hosts.

## [0.1.0]

First release. The five layers, and the promises they make.

### Added

- **The pipeline**: tool → caps → idempotency → risk hooks → approval gate, in a fixed
  order in one file, with no fail-open mode.
- **Typed tool registration.** `@lock.tool` validates arguments against the signature before
  any layer sees them, and rejects `*args`/`**kwargs` tools at registration.
- **Caps** per call, per rolling day, and per custom window, optionally partitioned by a
  scope key. Amounts are `Decimal` throughout, so boundaries are exact.
- **Idempotency** with keys derived deterministically from tool, canonicalised arguments and
  a mandatory caller-supplied `_intent`. Retries replay the original result. The same intent
  with mutated arguments is blocked. An attempt with an unknown outcome blocks every later
  attempt on that intent.
- **Risk hooks** returning allow, block or escalate. First non-allow wins; a hook that raises
  is a block.
- **Approval gate** with a pending queue, atomic approve/reject, and caps re-checked at
  approval time.
- **Append-only audit log**, enforced by database triggers, with argument redaction.
- **Stores**: `memory://` and `sqlite://`.
- **Adapters** for OpenAI and Anthropic tool calling, returning refusals as tool results the
  model can read rather than exceptions that crash the loop.
- **A 31-case adversarial benchmark** with two hard invariants: zero duplicate executions and
  zero fail-closed violations.

[Unreleased]: https://github.com/CodeKage25/airlock/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/CodeKage25/airlock/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/CodeKage25/airlock/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/CodeKage25/airlock/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/CodeKage25/airlock/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/CodeKage25/airlock/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/CodeKage25/airlock/releases/tag/v0.1.0
