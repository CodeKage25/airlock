from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from airlock import Airlock, Policy
from airlock.core.stores.base import Store
from airlock.errors import StoreUnavailable


class Clock:
    """Injectable time, so window accounting is tested rather than waited on."""

    def __init__(self, start: datetime | None = None) -> None:
        self.now = start or datetime(2026, 1, 1, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **delta: float) -> None:
        self.now += timedelta(**delta)


class BrokenStore:
    """Wraps a store and fails the named methods, standing in for a downed dependency."""

    def __init__(self, inner: Store, *failing: str) -> None:
        self._inner = inner
        self._failing = set(failing)
        self.url = inner.url

    def __getattr__(self, name: str) -> Any:
        if name in self._failing:

            def boom(*_: Any, **__: Any) -> Any:
                raise StoreUnavailable(self.url, RuntimeError(f"{name} is down"))

            return boom
        return getattr(self._inner, name)


POSTGRES_URL = os.environ.get("AIRLOCK_TEST_POSTGRES")

_TABLES = "reservations, intents, spend, audit, approvals"


@pytest.fixture(scope="session")
def postgres_store() -> Any:
    """One pool for the whole session. Per-test isolation is a truncate, not a new pool."""
    if not POSTGRES_URL:
        pytest.skip("set AIRLOCK_TEST_POSTGRES to run the suite against Postgres")
    from airlock.core.stores.postgres import PostgresStore

    store = PostgresStore(POSTGRES_URL, max_size=4)
    yield store
    store.close()


@pytest.fixture(params=["memory", "sqlite", "postgres"])
def store_url(request: pytest.FixtureRequest, tmp_path: Any) -> Any:
    if request.param == "memory":
        return "memory://"
    if request.param == "sqlite":
        return f"sqlite:///{tmp_path / 'airlock.db'}"

    store = request.getfixturevalue("postgres_store")
    # The append-only triggers are doing their job, so clearing between tests has to
    # switch them off deliberately rather than find a way around them.
    with store._tx() as cur:
        cur.execute("ALTER TABLE audit DISABLE TRIGGER USER")
        cur.execute(f"TRUNCATE {_TABLES} RESTART IDENTITY")
        cur.execute("ALTER TABLE audit ENABLE TRIGGER USER")
    return store


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def calls() -> list[dict[str, Any]]:
    return []


def build_lock(
    store_url: Any, clock: Clock, policy: Policy | None = None, **kwargs: Any
) -> Airlock:
    return Airlock(policy=policy or Policy(), store=store_url, clock=clock, **kwargs)


def make_store(store_url: Any) -> Store:
    """The fixture yields a URL for the file-backed stores and a live store for Postgres."""
    from airlock.core.stores import from_url

    return store_url if isinstance(store_url, Store) else from_url(store_url)
