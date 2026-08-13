# Contributing

Early contributors shape the architecture. This is the best time to get involved.

## Setup

```bash
git clone https://github.com/CodeKage25/airlock && cd airlock
uv sync --all-extras

uv run pytest                    # memory and sqlite
uv run ruff check && uv run ruff format --check
uv run mypy airlock/             # core/ is strict
uv run python bench/run.py       # the adversarial benchmark
```

To run the Postgres backend too, which CI always does:

```bash
createdb airlock_test
AIRLOCK_TEST_POSTGRES=postgresql:///airlock_test uv run pytest
```

## The one rule that matters

**Every guardrail change ships with a test proving it blocks what it should, not just that
it allows what it should.** A test that only checks the happy path tells you nothing about
a guardrail. If your change is a fix for a race, revert the fix locally and confirm the new
test actually goes red first — a concurrency test that has never failed is decoration.

## What good contributions look like

The most valuable thing you can send is **a way you broke a guardrail**. Adversarial issues
are genuinely gold, and a failing benchmark case is the ideal form:

```python
@case("what an agent did to someone", "caps")
def scenario(run: CaseRun) -> None:
    lock = run.airlock(Policy(caps={"send_payment": Caps(max_per_call=100)}))

    @lock.tool
    def send_payment(to: str, amount: float) -> str:
        run.executed()  # the only place a real side effect is counted
        return "txn"

    run.expect("one cent over", BLOCK, lambda: send_payment(to="a", amount=100.01, _intent="i-1"))
```

Other good first contributions: a framework adapter, a risk-hook example, a store backend,
or hardening the idempotency key canonicalisation.

## Conventions

Full engineering rules are in [`CLAUDE.md`](CLAUDE.md). The short version:

- **Fail closed.** Uncertainty means no execution. There is no fail-open mode and no flag
  that adds one.
- **Enforcement lives outside the model.** Nothing in a prompt, an argument, or model output
  may influence a limit.
- **Check and write in one step.** A guardrail that reads a total, decides, then writes can
  be raced. Enforcement belongs inside the store transaction that records the effect.
- **Money is `Decimal`.** Never compare or accumulate float amounts.
- **Tests run against every backend.** A difference between `memory://` and `sqlite://` and
  `postgres://` is a bug in whichever one is wrong.
- **Time is injected.** Never sleep in a test; use the `clock` fixture.
- **Clean code, no verbose comments.** A comment earns its place by explaining *why*,
  usually why the obvious approach is wrong.

## Schema changes

The audit log is the product. Once a deployment has history, its schema can never break.

- Add a new numbered migration in `airlock/core/stores/migrations.py` for every dialect
- **Never alter or drop an existing audit column.** Additive changes only
- Include a test that migrates a database populated at the previous version and asserts the
  old rows survive
- New backends must implement the whole `Store` interface and pass the existing suite
  unchanged. If a backend needs its own special-case test, the abstraction is leaking

## Pull requests

1. Fork, branch from `main`
2. Make sure `pytest`, `ruff`, `mypy` and `bench/run.py` are all green
3. Sign off your commits (`git commit -s`) to certify the [DCO](https://developercertificate.org/)
4. Open a PR describing the **behaviour** change: what now executes, or now does not, that
   did not before

Every PR runs the full matrix in CI: three Python versions, three store backends, lint,
types, the benchmark, and a clean-install check that the built wheel still enforces.

## Stability policy

Pre-1.0, minor versions may make breaking changes, and the CHANGELOG will say so plainly at
the top of the entry. Patch versions never break anything.

From 1.0:

- Public API is everything importable from `airlock` and `airlock.errors`. Anything under
  `airlock.core` is internal and may change in a minor release.
- Breaking changes need a major version, preceded by at least one minor release that emits a
  `DeprecationWarning`.
- **Idempotency key derivation is part of the public contract.** Changing canonicalisation
  changes every key, which would let a retry execute a second time across an upgrade. It
  requires a major version and a documented migration.
- Audit schema changes are additive within a major version.

## Repository setup

Two settings have to be enabled by hand once, because a workflow token cannot do either:

- **Pages**: Settings → Pages → Source → **GitHub Actions**. Without it the docs workflow
  builds fine and then fails at deploy with a 404.
- **PyPI trusted publishing**: create a `pypi` environment and register this repository as a
  trusted publisher on PyPI. Only needed when you cut a release tag.

## Reporting security issues

Do not open a public issue. See [`SECURITY.md`](SECURITY.md).
