# Changelog

Notable changes to Airlock. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [semantic versioning](https://semver.org/) under the stability policy in
[`CONTRIBUTING.md`](CONTRIBUTING.md).

Because Airlock's value is a small set of promises, every entry says which promise a change
affects.

## [Unreleased]

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

[Unreleased]: https://github.com/CodeKage25/airlock/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/CodeKage25/airlock/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/CodeKage25/airlock/releases/tag/v0.1.0
