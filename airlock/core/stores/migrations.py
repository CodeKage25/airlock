"""Forward-only schema migrations.

Once a deployment has audit history, its schema can never be broken. Every change ships
as a new numbered migration and no migration may alter or drop an existing audit column.
"""

from __future__ import annotations

from dataclasses import dataclass

SQLITE = "sqlite"
POSTGRES = "postgres"


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    statements: tuple[str, ...]


_SQLITE_INITIAL = (
    """
    CREATE TABLE IF NOT EXISTS reservations (
        key TEXT PRIMARY KEY,
        tool TEXT NOT NULL,
        intent TEXT NOT NULL,
        state TEXT NOT NULL,
        created_at TEXT NOT NULL,
        result_json TEXT,
        replayable INTEGER NOT NULL DEFAULT 0,
        reason TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS intents (
        tool TEXT NOT NULL,
        intent TEXT NOT NULL,
        key TEXT NOT NULL,
        PRIMARY KEY (tool, intent)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS spend (
        key TEXT PRIMARY KEY,
        tool TEXT NOT NULL,
        scope TEXT,
        amount TEXT NOT NULL,
        at TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS spend_window ON spend (tool, scope, at)",
    """
    CREATE TABLE IF NOT EXISTS audit (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        id TEXT NOT NULL,
        at TEXT NOT NULL,
        tool TEXT NOT NULL,
        intent TEXT NOT NULL,
        key TEXT NOT NULL,
        outcome TEXT NOT NULL,
        layer TEXT,
        reason TEXT,
        scope TEXT,
        args TEXT NOT NULL,
        result_ref TEXT,
        actor TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS audit_lookup ON audit (tool, outcome, at)",
    """
    CREATE TABLE IF NOT EXISTS approvals (
        id TEXT PRIMARY KEY,
        tool TEXT NOT NULL,
        intent TEXT NOT NULL,
        key TEXT NOT NULL,
        reason TEXT NOT NULL,
        created_at TEXT NOT NULL,
        args TEXT NOT NULL,
        context TEXT NOT NULL,
        scope TEXT,
        status TEXT NOT NULL,
        decided_at TEXT,
        decided_by TEXT,
        decision_reason TEXT
    )
    """,
    """
    CREATE TRIGGER IF NOT EXISTS audit_no_update
        BEFORE UPDATE ON audit
        BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS audit_no_delete
        BEFORE DELETE ON audit
        BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END
    """,
)

_SQLITE_OPERATIONS = (
    "ALTER TABLE reservations ADD COLUMN heartbeat_at TEXT",
    "ALTER TABLE approvals ADD COLUMN expires_at TEXT",
    "CREATE INDEX IF NOT EXISTS approvals_by_key ON approvals (key, status)",
    "CREATE INDEX IF NOT EXISTS reservations_by_state ON reservations (state, created_at)",
)

_POSTGRES_INITIAL = (
    """
    CREATE TABLE IF NOT EXISTS reservations (
        key TEXT PRIMARY KEY,
        tool TEXT NOT NULL,
        intent TEXT NOT NULL,
        state TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        result_json TEXT,
        replayable BOOLEAN NOT NULL DEFAULT FALSE,
        reason TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS intents (
        tool TEXT NOT NULL,
        intent TEXT NOT NULL,
        key TEXT NOT NULL,
        PRIMARY KEY (tool, intent)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS spend (
        key TEXT PRIMARY KEY,
        tool TEXT NOT NULL,
        scope TEXT,
        amount NUMERIC NOT NULL,
        at TIMESTAMPTZ NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS spend_window ON spend (tool, scope, at)",
    """
    CREATE TABLE IF NOT EXISTS audit (
        seq BIGSERIAL PRIMARY KEY,
        id TEXT NOT NULL,
        at TIMESTAMPTZ NOT NULL,
        tool TEXT NOT NULL,
        intent TEXT NOT NULL,
        key TEXT NOT NULL,
        outcome TEXT NOT NULL,
        layer TEXT,
        reason TEXT,
        scope TEXT,
        args JSONB NOT NULL,
        result_ref TEXT,
        actor TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS audit_lookup ON audit (tool, outcome, at)",
    """
    CREATE TABLE IF NOT EXISTS approvals (
        id TEXT PRIMARY KEY,
        tool TEXT NOT NULL,
        intent TEXT NOT NULL,
        key TEXT NOT NULL,
        reason TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        args JSONB NOT NULL,
        context JSONB NOT NULL,
        scope TEXT,
        status TEXT NOT NULL,
        decided_at TIMESTAMPTZ,
        decided_by TEXT,
        decision_reason TEXT
    )
    """,
    """
    CREATE OR REPLACE FUNCTION airlock_audit_append_only() RETURNS trigger AS $$
    BEGIN RAISE EXCEPTION 'audit log is append-only'; END;
    $$ LANGUAGE plpgsql
    """,
    "DROP TRIGGER IF EXISTS audit_immutable ON audit",
    """
    CREATE TRIGGER audit_immutable
        BEFORE UPDATE OR DELETE ON audit
        FOR EACH ROW EXECUTE FUNCTION airlock_audit_append_only()
    """,
)

_POSTGRES_OPERATIONS = (
    "ALTER TABLE reservations ADD COLUMN IF NOT EXISTS heartbeat_at TIMESTAMPTZ",
    "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ",
    "CREATE INDEX IF NOT EXISTS approvals_by_key ON approvals (key, status)",
    "CREATE INDEX IF NOT EXISTS reservations_by_state ON reservations (state, created_at)",
)

# A row-level trigger does not fire on TRUNCATE, so without this the append-only
# guarantee has a one-statement hole in it. SQLite has no TRUNCATE to close.
_POSTGRES_TRUNCATE_GUARD = (
    "DROP TRIGGER IF EXISTS audit_no_truncate ON audit",
    """
    CREATE TRIGGER audit_no_truncate
        BEFORE TRUNCATE ON audit
        FOR EACH STATEMENT EXECUTE FUNCTION airlock_audit_append_only()
    """,
)

MIGRATIONS: dict[str, tuple[Migration, ...]] = {
    SQLITE: (
        Migration(1, "initial schema", _SQLITE_INITIAL),
        Migration(2, "leases and approval expiry", _SQLITE_OPERATIONS),
        Migration(3, "audit truncate guard", ()),
    ),
    POSTGRES: (
        Migration(1, "initial schema", _POSTGRES_INITIAL),
        Migration(2, "leases and approval expiry", _POSTGRES_OPERATIONS),
        Migration(3, "audit truncate guard", _POSTGRES_TRUNCATE_GUARD),
    ),
}

VERSION_TABLE = {
    SQLITE: (
        "CREATE TABLE IF NOT EXISTS schema_version ("
        "version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
    ),
    POSTGRES: (
        "CREATE TABLE IF NOT EXISTS schema_version ("
        "version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TIMESTAMPTZ NOT NULL)"
    ),
}


def pending(dialect: str, current: int) -> tuple[Migration, ...]:
    return tuple(m for m in MIGRATIONS[dialect] if m.version > current)


def latest(dialect: str) -> int:
    return max(m.version for m in MIGRATIONS[dialect])


#: Dialects advance together, so an in-memory store is current by construction.
CURRENT = max(latest(dialect) for dialect in MIGRATIONS)
