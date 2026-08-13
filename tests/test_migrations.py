from __future__ import annotations

import sqlite3
from typing import Any

from airlock import Airlock
from airlock.core.stores import migrations
from airlock.core.stores.sqlite import SqliteStore
from tests.conftest import make_store


def test_a_new_store_lands_on_the_latest_schema(store_url: Any) -> None:
    assert make_store(store_url).schema_version() == migrations.CURRENT


def test_opening_an_existing_store_is_idempotent(tmp_path: Any) -> None:
    path = str(tmp_path / "airlock.db")
    first = SqliteStore(path)
    version = first.schema_version()
    first.close()

    second = SqliteStore(path)
    assert second.schema_version() == version
    second.close()


def test_an_older_database_migrates_forward_without_losing_history(tmp_path: Any) -> None:
    """Audit history has to survive every upgrade, or the guarantee is worthless."""
    path = str(tmp_path / "airlock.db")

    conn = sqlite3.connect(path)
    conn.execute(migrations.VERSION_TABLE[migrations.SQLITE])
    initial = migrations.MIGRATIONS[migrations.SQLITE][0]
    for statement in initial.statements:
        conn.execute(statement)
    conn.execute(
        "INSERT INTO schema_version (version, name, applied_at) VALUES (?, ?, ?)",
        (initial.version, initial.name, "2026-01-01T00:00:00.000000+00:00"),
    )
    conn.execute(
        "INSERT INTO audit (id, at, tool, intent, key, outcome, args) "
        "VALUES ('old', '2026-01-01T00:00:00.000000+00:00', 'pay', 'inv-1', 'k', 'executed', '{}')"
    )
    conn.commit()
    conn.close()

    store = SqliteStore(path)
    assert store.schema_version() == migrations.latest(migrations.SQLITE)
    surviving = store.query_audit(intent="inv-1")
    assert [entry.id for entry in surviving] == ["old"]
    store.close()


def test_the_new_columns_are_usable_after_an_upgrade(tmp_path: Any) -> None:
    path = str(tmp_path / "airlock.db")

    conn = sqlite3.connect(path)
    conn.execute(migrations.VERSION_TABLE[migrations.SQLITE])
    for statement in migrations.MIGRATIONS[migrations.SQLITE][0].statements:
        conn.execute(statement)
    conn.execute(
        "INSERT INTO schema_version (version, name, applied_at) VALUES (1, 'initial', 'x')"
    )
    conn.commit()
    conn.close()

    lock = Airlock(store=f"sqlite:///{path}")

    @lock.tool
    def pay(amount: float) -> str:
        return "txn"

    assert pay(amount=1, _intent="i-1") == "txn"
    assert lock.intents.stuck() == []
    lock.close()
