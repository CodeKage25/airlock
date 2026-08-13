## What behaviour changes

What now executes, or now does not, that did not before. If nothing about behaviour changes,
say that.

## Why

## Checklist

- [ ] `uv run pytest` passes, including against Postgres
      (`AIRLOCK_TEST_POSTGRES=postgresql:///airlock_test`)
- [ ] `uv run ruff check` and `uv run ruff format --check` pass
- [ ] `uv run mypy airlock/` passes
- [ ] `uv run python bench/run.py` is green
- [ ] Commits are signed off (`git commit -s`) per the DCO

### If this touches a guardrail

- [ ] There is a test proving it **blocks** what it should, not only that it allows what it
      should
- [ ] If this fixes a race, I reverted the fix locally and confirmed the new test goes red

### If this touches the store or schema

- [ ] Additive migration only; no existing audit column altered or dropped
- [ ] A migration test covers upgrading a database populated at the previous version
- [ ] Every backend implements it, and the existing suite passes unchanged against each
