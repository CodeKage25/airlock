from __future__ import annotations

import hashlib
import json
import unicodedata
from collections.abc import Mapping
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any

_MAX_DEPTH = 32


def canonical(value: Any, _depth: int = 0) -> Any:
    """Reduce a value to a stable, JSON-encodable shape.

    Two arguments that mean the same thing must reduce to the same shape, or a retry
    silently becomes a second execution. Numbers go through normalised Decimal so
    ``40``, ``40.0`` and ``Decimal("40.00")`` agree; strings are NFC-normalised so
    visually identical unicode agrees.
    """
    if _depth > _MAX_DEPTH:
        raise ValueError("argument nesting too deep to canonicalise")

    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, Enum):
        return canonical(value.value, _depth + 1)
    if isinstance(value, (int, float, Decimal)):
        return _canonical_number(value)
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, bytes):
        return {"__bytes__": value.hex()}
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {
            unicodedata.normalize("NFC", str(k)): canonical(v, _depth + 1)
            for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))
        }
    if isinstance(value, (set, frozenset)):
        return sorted(json.dumps(canonical(v, _depth + 1), sort_keys=True) for v in value)
    if isinstance(value, (list, tuple)):
        return [canonical(v, _depth + 1) for v in value]
    raise TypeError(f"cannot canonicalise {type(value).__name__}")


def _canonical_number(value: int | float | Decimal) -> str:
    try:
        dec = Decimal(str(value))
    except InvalidOperation as exc:
        raise TypeError(f"cannot canonicalise number {value!r}") from exc
    if not dec.is_finite():
        raise TypeError(f"cannot canonicalise non-finite number {value!r}")
    normalised = dec.normalize()
    if normalised == 0:
        return "0"
    return format(normalised, "f")


def encode(value: Any) -> str:
    return json.dumps(canonical(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(*parts: Any) -> str:
    hasher = hashlib.sha256()
    for part in parts:
        hasher.update(encode(part).encode("utf-8"))
        hasher.update(b"\x1e")
    return hasher.hexdigest()


def idempotency_key(tool: str, args: Mapping[str, Any], intent: str) -> str:
    """Deterministic across retries, processes and restarts."""
    return digest(tool, args, intent)


def to_decimal(value: Any) -> Decimal:
    try:
        dec = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ValueError(f"{value!r} is not a number") from exc
    if not dec.is_finite():
        raise ValueError(f"{value!r} is not finite")
    return dec
