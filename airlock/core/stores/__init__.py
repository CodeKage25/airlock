from __future__ import annotations

from airlock.core.stores.base import ReserveResult, SpendCheck, SpendViolation, Store
from airlock.core.stores.memory import MemoryStore
from airlock.core.stores.sqlite import SqliteStore
from airlock.errors import PolicyError

__all__ = [
    "MemoryStore",
    "ReserveResult",
    "SpendCheck",
    "SpendViolation",
    "SqliteStore",
    "Store",
    "from_url",
]


def from_url(url: str) -> Store:
    if url in ("memory://", "memory://:memory:"):
        return MemoryStore()
    if url.startswith("sqlite://"):
        # sqlite:///relative.db keeps one slash, sqlite:////abs/path.db keeps two.
        rest = url[len("sqlite://") :]
        path = rest[1:] if rest.startswith("/") else rest
        return SqliteStore(path or ":memory:")
    if url.startswith(("postgres://", "postgresql://")):
        from airlock.core.stores.postgres import PostgresStore

        return PostgresStore(url)
    raise PolicyError(f"unrecognised store url {url!r}")
