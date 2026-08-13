# Security policy

Airlock sits between an agent and things that cost money. A bug that lets an action through
is a security bug, not a correctness nit, and it is treated that way here.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private reporting on this repository:
[Security → Report a vulnerability](https://github.com/CodeKage25/airlock/security/advisories/new).

Please include:

- What guardrail you got past, and which layer should have stopped you
- A minimal reproduction, ideally as a failing test in the style of `tests/`
- The store backend and version, and the Airlock version
- Whether it needs a malicious model, a malicious caller, or neither

**Response targets.** Acknowledgement within 3 working days, an initial assessment within
7 days, and a fix or a public mitigation within 30 days for anything rated high or critical.
If we are going to miss one of those, we will say so rather than go quiet.

Credit is given in the advisory and the changelog unless you would rather stay anonymous.
There is no bounty programme.

## What counts as a vulnerability

Anything that breaks one of these, without needing direct database access:

| Guarantee | A break looks like |
|---|---|
| **At most once** | One intent producing two real side effects |
| **Caps bind** | Any path that executes past `max_per_call` or a window limit |
| **Fail closed** | Any execution while a store is unreachable or a layer errored |
| **Approval required** | A call matching an approval rule that executes without a decision |
| **Audit is complete** | An execution with no audit record, or a record that can be altered by the application |
| **Enforcement is outside the model** | Tool arguments or model output changing a limit or a verdict |

Also in scope: secrets reaching the audit log despite `audit_redact`, an idempotency key
collision between two semantically different calls, and privilege confusion between scopes.

## What does not count

- **Bad policy.** `Caps(max_per_call=1_000_000)` allowing a large payment is Airlock doing
  as it was told. Misconfiguration is not a vulnerability.
- **Bugs in your own tool implementations.** Airlock governs whether a tool runs, not what
  the tool does once it does.
- **Direct database access.** Someone with write access to the store can rewrite anything.
  Airlock governs the agent path, not your whole perimeter. See [Trust boundaries](#trust-boundaries).
- **Model output quality.** Airlock bounds actions; it does not make the model correct.
- **Denial of service by exhausting the store.** Real, but a capacity concern.

## Trust boundaries

Airlock assumes the following. If your deployment breaks one of these, Airlock's guarantees
do not hold, and that is a deployment problem rather than a library bug.

1. **The policy is trusted.** It is code, written by you, that the model never sees and
   cannot influence.
2. **The store is trusted and correct.** Its atomic conditional write must actually be
   atomic. On a network filesystem, SQLite's is not, which is why multi-host means Postgres.
3. **The audit table's owner is trusted.** The append-only triggers stop the *application*
   from rewriting history. They do not stop whoever can drop the triggers. Grant the
   application role `INSERT` and `SELECT` on `audit` and nothing more.
4. **The process is trusted.** Anything running in-process can call the underlying function
   directly and bypass the pipeline entirely. Airlock is a guardrail, not a sandbox.
5. **Tool arguments are hostile.** This one is *not* assumed to be safe: arguments are
   treated as attacker-controlled, validated against the signature, and never allowed to
   influence a limit.

## Hardening checklist

- Use Postgres for anything with more than one host
- Grant the application `INSERT`/`SELECT` on `audit`, nothing more
- Set `audit_redact` for every argument that can carry a secret, and remember it currently
  matches top-level argument names only
- Give consequential approval rules a `ttl` so the queue cannot rot
- Alert on `lock.intents.stuck()` being non-empty; a stuck intent is a payment nobody has
  reconciled
- Alert on `blocked` audit entries with `layer="fail-closed"`; that is a dependency outage
- Keep the store's credentials out of the same secret scope as the payment rail's

## Supported versions

Pre-1.0, only the latest minor version receives security fixes. Once 1.0 ships, the current
and previous minor will be supported. See the stability policy in
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## Disclosure

Fixes ship with a GitHub Security Advisory and a CHANGELOG entry describing the guarantee
that broke and the conditions required. Because Airlock's whole value is a small set of
promises, an advisory always states plainly which promise did not hold.
