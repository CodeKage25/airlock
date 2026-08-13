# Operations runbook

What to do when Airlock is the thing paging you. Written for whoever is on call, not for
whoever chose the library.

## What to alert on

| Signal | Query | Why it matters |
|---|---|---|
| **Stuck intents** | `lock.intents.stuck()` non-empty, or `airlock intents stuck` | Each one is an action whose real-world effect nobody knows. Money may have moved. This is the highest-priority signal Airlock produces. |
| **Fail-closed blocks** | audit `outcome=blocked`, `layer=fail-closed` | Your store is unreachable. The agent is doing nothing at all, safely, but doing nothing. |
| **Approval queue age** | oldest `pending` request | Work is silently not happening. If requests routinely age out, either the rule is too broad or nobody owns the queue. |
| **Expired approvals** | audit `outcome=expired` | Decisions nobody made. A steady rate means the queue has no owner. |
| **Cap saturation** | `blocked` with `layer=caps` rising | Either a runaway agent or a limit that no longer matches the business. Look at which before changing anything. |
| **Block rate by layer** | `blocked` grouped by `layer` | A sudden shift in *which* layer is refusing usually means an upstream change, not an agent change. |

There are no built-in metrics yet; these come from `lock.audit.query(...)`. OpenTelemetry and
Prometheus are the next track on the [roadmap](ROADMAP.md).

## Incident: a stuck intent

**Symptom.** `airlock intents stuck` lists an intent. Every retry of it is blocked with
"a previous attempt failed with an unknown outcome".

This is Airlock working. A call crashed, timed out, or is still in flight, so whether the
action landed is unknown, and it will not gamble on a second attempt.

```bash
$ airlock intents stuck
KEY               TOOL    INTENT  STATE   AGE
----------------  ------  ------  ------  -------
20e297dffb062b7e  settle  inv-80  failed  0:04:11
```

**1. Get the context.**

```bash
$ airlock audit --intent inv-80
```

You will see `proposed` and then `failed` with the exception, and no `executed`. That means
Airlock started the call. It does not tell you whether the downstream system finished it.

**2. Go and look at the downstream system.** This is the part nobody can automate. Check the
payment rail, the ledger, the provider dashboard. The question is only: *did the effect
actually land?*

**3. Record what you found.**

```bash
# The money moved. Keep the intent closed so a retry replays instead of paying twice.
$ airlock intents resolve 20e297dffb -- executed --by you@company.com \
    --note "found as txn_88121 in the rail"

# It did not. Release the intent and the budget it reserved so a retry can proceed.
$ airlock intents resolve 20e297dffb --not-executed --by you@company.com \
    --note "no record in the rail, checked 14:20 UTC"
```

Keys can be abbreviated. Both outcomes are audit-logged as `resolved`, against your name.

!!! warning "Do not guess"
    `--not-executed` releases the intent for retry. If you are wrong, the next retry pays
    twice, which is precisely the failure Airlock exists to prevent. If you cannot confirm,
    leave it stuck and escalate. A blocked payment is recoverable; a double payment is a
    phone call to a customer.

**4. If a pending intent is stuck because a pod died**, the reservation stays `pending`
forever, since Airlock cannot distinguish "in flight" from "the process is gone". Same
procedure: check downstream, then resolve.

## Incident: everything is blocked, layer is fail-closed

**Symptom.** Every call raises `Blocked` with `layer="fail-closed"`.

The store is unreachable. Airlock refuses to act rather than act unauditably. Nothing has
executed, so there is no reconciliation to do.

1. Check the store: `airlock migrate` will fail the same way if the database is down
2. Check connection pool exhaustion before assuming the database is down. `PostgresStore`
   defaults to `max_size=10` per process
3. Fix the store. Airlock recovers by itself, with no queue to drain and no state to repair

## Incident: the agent is blocked and shouldn't be

Read the reason. Every block carries one:

```bash
$ airlock audit --outcome blocked --limit 20
```

| Reason mentions | What is actually happening |
|---|---|
| `max_per_call` | A single call is over the limit. Either the model is wrong or the limit is |
| `max_per_day` / `max_per_window` | The window is exhausted. Windows are **rolling**, not calendar, so it frees up gradually |
| `already bound to a different set of arguments` | Same intent id, different arguments. The caller is generating intent ids wrongly, usually reusing one across distinct actions |
| `unknown outcome` | A stuck intent. See above |
| `currency` | A cap is denominated in one currency and the call is in another |
| `scope key ... missing from context` | A scoped cap with no scope supplied. The caller must pass `_context` |
| `fail-closed` | Store outage. See above |

**Never raise a cap to unblock an incident before you know which of the two cases you are
in.** If the model is wrong, raising the cap removes the only thing that caught it.

## Deploying

**More than one host requires Postgres.** SQLite is safe for any number of processes on one
host, and unsafe across hosts, because its locking does not survive a network filesystem.

**Migrations run at startup**, forward-only, guarded by an advisory lock so replicas booting
together cannot both apply one. A rolling deploy is safe: new columns are additive and old
code ignores them.

```bash
$ airlock migrate
postgresql://...
schema version 3 (latest 3)
```

**Lock down the audit table.** The append-only triggers stop the application from rewriting
history. They do not stop whoever owns the table.

```sql
GRANT INSERT, SELECT ON audit TO airlock_app;
REVOKE UPDATE, DELETE, TRUNCATE ON audit FROM airlock_app;
```

## Capacity and growth

Two tables grow without bound, and neither has automatic retention yet:

- **`audit`** — one row per proposed action plus one per outcome, so roughly two to three
  rows per agent call. Archive rather than delete; that is the compliance record.
- **`spend`** — one row per executed call. Only rows inside the longest cap window are ever
  read, so older rows are dead weight. Rolling them up is safe once they are outside every
  window in your policy.

Guardrail overhead is a handful of queries per call. Against any tool that touches a network
it is noise, but it is not zero, and every call takes at least one write.

## Tuning

**`stuck_after`** (default 5 minutes) only affects *classification*, never whether something
is blocked. Set it above your slowest tool's timeout, or healthy in-flight calls will show
up in `intents stuck` and train you to ignore the signal.

**Approval `ttl`** should match how fast a human really responds, not how fast you would
like them to. A TTL shorter than your on-call response time turns every escalation into a
silent expiry.

**Windows are rolling.** `max_per_day` means the last 24 hours, not "since midnight". If
finance expects a calendar day, say so before someone reconciles against the wrong number.

## Reconciliation

The audit log is designed to answer "what did the agent actually do" without access to the
agent:

```bash
$ airlock audit --tool send_payment --outcome executed --limit 100
$ airlock audit --outcome escalated        # everything that reached a human
$ airlock audit --outcome resolved         # every stuck intent and who settled it
```

An `executed` entry carries a `result_ref`, which is a digest of the result rather than the
result itself, so the log can be shared without leaking payloads. Arguments are recorded
canonicalised and with `audit_redact` applied — remember that redaction currently matches
top-level argument names only.

A `proposed` entry with no matching outcome means a process died mid-call. That is the same
signal as a stuck intent, visible from the log side.
