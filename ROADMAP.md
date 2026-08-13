# From v0.1 to something companies deploy

Two separate problems. **Deployability** is whether it can run in a real environment at all.
**Adoptability** is whether a company will let it near production. Solving only the first is
how good infrastructure projects end up with fifty stars and no users.

Ordered by what blocks the most people.

---

## P0 — deployability blockers  ✅ shipped in v0.2

All four landed. The acceptance test was the existing suite passing unchanged against
Postgres, which it now does: 282 tests across memory, SQLite and Postgres.

### 1. Postgres store  ✅

Every company runs more than one replica. Today that is unsupported, so Airlock is a
single-host library. This is the single biggest blocker.

- Atomic reserve via `INSERT ... ON CONFLICT DO NOTHING RETURNING`
- `commit_spend` under `SERIALIZABLE`, or a transaction-scoped advisory lock per
  `(tool, scope)`, with retry on serialisation failure
- Connection pooling, statement timeouts, and a `busy`-equivalent policy
- The existing suite runs against it unchanged — that is the acceptance test, and it is
  already written
- CI service container so it runs on every PR

### 2. Schema migrations  ✅

Once a company has six months of audit history, the schema can never break. This has to
exist *before* anyone stores real data, not after.

- `schema_version` table, forward-only migrations, a documented upgrade path
- Migration tests that run against a database populated by the previous version
- A rule in `CLAUDE.md`: no PR may alter an existing audit column

### 3. Stuck-intent resolution  ✅

A process that dies mid-call blocks that intent permanently, by design. Right now there is
no way out except editing the database, which is the worst possible answer for the one
situation where someone is already panicking.

- Leases: a reservation carries a heartbeat, so "in flight" and "abandoned" are
  distinguishable rather than both being `PENDING`
- `lock.intents.stuck(older_than=...)` to list them with full audit context
- `lock.intents.resolve(intent, outcome="executed" | "not_executed", by=..., evidence=...)`,
  itself audit-logged and requiring a named human
- CLI: `airlock intents stuck`, `airlock intents resolve`

### 4. Approval lifecycle  ✅

A queue with no expiry rots, and someone eventually approves a three-week-old payment.

- Per-rule TTL, expiry audited as its own outcome
- Queue bounds, and reminders as a hook
- Indexed lookup by key, replacing the current linear scan of pending requests

---

## P1 — adoption blockers

These decide whether a company will *choose* it.

### 5. Shadow mode

The most important item on this list for real adoption. Nobody switches on a blocking
guardrail in a payment path on day one. They run it in observe-only for two weeks, read what
it *would* have stopped, tune the policy, then enforce.

- `Airlock(mode="shadow")`: every layer evaluates and audits its verdict, nothing is blocked
- A diff report: what shadow mode would have blocked, grouped by layer and reason
- Per-tool graduation, so `send_payment` can enforce while `issue_refund` still observes

### 6. Observability

Companies do not run components they cannot see.

- OpenTelemetry spans per pipeline layer, with the decision on the span
- Prometheus metrics: decisions by tool/layer/outcome, latency histogram, cap utilisation
  per scope, pending-approval age, stuck-intent gauge
- A reference Grafana dashboard in the repo

### 7. Async

Most modern Python agent stacks are async. `v0.3` is too late for something this basic; it
is closer to a blocker than a feature.

- Async pipeline and store interfaces, sync kept as the thin wrapper
- Async risk hooks, which the current `Policy` explicitly rejects

### 8. Agent identity

The README says autonomy is earned per action class, but there is no notion of *who* is
acting. One `Airlock` instance means one policy for every caller. Companies run a support
bot and a treasury bot and do not want them sharing a budget.

- `principal` as a first-class field on `Call`, alongside tool and scope
- Per-principal caps and rules, and per-principal audit queries
- Budget delegation: a parent task holds an allowance that sub-agents draw down

### 9. Policy as data

Policy is Python today. Companies want it version-controlled, reviewable by risk and
compliance people who do not write Python, and changeable without a deploy.

- YAML/JSON policy with a published schema, `Policy.from_file()`
- Predicates as a small safe expression language, not `eval`
- Hot reload with an audited policy-version stamp on every decision

---

## P2 — trust surface  ✅ shipped

What a company's security review actually asks for. Cheap to build, disproportionate in
effect.

- **CI** ✅ — GitHub Actions over 3.11–3.13 and all three store backends; lint, mypy, tests
  with coverage, the benchmark, the example, and a clean-install check that the built wheel
  still enforces a cap. A guard fails the run if any backend silently skips.
- **Release** ✅ — PyPI trusted publishing with build provenance attestation, a tag/version
  consistency check, full verification before publish, and a CHANGELOG whose every entry
  names the promise a change affects. Stability policy written, including the rule that
  idempotency key derivation is part of the public contract.
- **Security** ✅ — `SECURITY.md` with private disclosure, response targets, an explicit
  table of what does and does not count as a vulnerability, five stated trust boundaries,
  and a hardening checklist. Dependabot for pip and actions. A dedicated
  guardrail-bypass issue template.
- **Governance** ✅ — `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, DCO sign-off, `LICENSE`.
- **Docs site** ✅ — MkDocs Material on GitHub Pages, built from the canonical root markdown
  so the site cannot drift, plus a new operations runbook.
- **Reference deployment** — still to do: docker-compose with Postgres, a sample agent and a
  Grafana dashboard, once there are metrics to put on it.

---

## P3 — reach

### 10. MCP server

The answer to "does this work with any language". Airlock is an in-process Python library, so
today the agent must be Python. Exposing guarded tools over MCP makes them reachable from any
MCP client in any language, and turns Airlock into infrastructure rather than a dependency.
Highest-leverage item here by a distance.

### 11. Framework adapters

LangChain/LangGraph, Pydantic-AI, CrewAI. Adoption tracks integration surface.

### 12. Compliance features

The real differentiator in regulated industries.

- **Hash-chained audit log.** Each entry carries the digest of its predecessor, so tampering
  is detectable and not merely prevented by a trigger. Perhaps twenty lines, and it is what
  auditors actually ask for. Optional periodic anchoring for stronger guarantees.
- Retention and archival: audit exported to S3/Parquet, never deleted; the spend ledger
  rolled up rather than grown forever.
- Reports: who approved what, cap utilisation over time, every escalation and its outcome.

---

## P4 — hardening

- **Property-test the canonicaliser** with Hypothesis. It is the crown jewel and has only met
  the adversarial cases we thought of. The invariant: two argument sets canonicalise to the
  same key if and only if they are semantically identical.
- **Clock safety.** Rolling windows trust an injected clock; backwards skew on a host
  currently misbehaves. Prefer store-side time, guard against non-monotonic jumps.
- **Result size limits.** A tool returning 50MB currently JSON-encodes it into the
  reservation row.
- **Rate limits** as distinct from spend caps, plus circuit breaking on downstream failure.
- **Nested redaction**: path-based (`card.number`), detector-based (PAN, IBAN, JWT), and a
  redact-by-default allowlist mode for regulated deployments.
- **Load numbers.** Today's p50 of 0.19ms is the memory store with trivial tools. Publish
  real figures against Postgres under concurrency, or drop the performance claim.

---

## Suggested sequence

1. ~~**P0** — it can be deployed~~ ✅ v0.2
2. **P2 trust surface** — cheap, and it is what an evaluator sees first
3. **Shadow mode and observability** — it can be adopted without a scary cutover
4. **Async, MCP, identity** — it can be adopted by more than Python shops
5. **Compliance and hardening** — it can be adopted by the industries that need it most

### What P0 actually cost

Four bugs, all found by tests rather than by reading:

1. `PRAGMA journal_mode=WAL` ran before `busy_timeout` was set, and SQLite answers a
   journal-mode change with SQLITE_BUSY without ever consulting the busy handler. Replicas
   booting together killed each other before opening the database. Needed its own bounded
   retry, not just a reordering.
2. The CLI printed abbreviated keys and then refused them on input, which is the worst
   possible behaviour at 3am. Keys now expand from a prefix like a git short hash.
3. `Approvals.open` handed a retrying agent a request that was already past its deadline,
   because expiry only ran on read.
4. A row-level trigger does not fire on `TRUNCATE`, so the Postgres append-only guarantee
   had a one-statement hole until migration 3 closed it.
