"""Keeping secrets out of the audit log.

Matching on top-level argument names alone is not enough: real tool arguments nest, and
the card number is usually two levels down inside a payload the tool author added later.
Paths are dotted, ``*`` matches one segment, and a bare name still matches at any depth so
existing configuration keeps working and gets stricter rather than looser.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

REDACTED = "***"


class Redactor:
    """Replaces matching values with ``***`` before anything is written down."""

    def __init__(self, patterns: Iterable[str] = ()) -> None:
        self._paths: list[tuple[str, ...]] = []
        self._names: set[str] = set()
        for pattern in patterns:
            if "." in pattern:
                self._paths.append(tuple(pattern.split(".")))
            else:
                # A bare name matches wherever it appears, because a secret does not stop
                # being a secret by being nested one level deeper.
                self._names.add(pattern)

    def __bool__(self) -> bool:
        return bool(self._paths or self._names)

    def apply(self, value: Any, path: tuple[str, ...] = ()) -> Any:
        if isinstance(value, Mapping):
            return {
                str(key): (
                    REDACTED
                    if self._matches((*path, str(key)), str(key))
                    else self.apply(item, (*path, str(key)))
                )
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [self.apply(item, (*path, "*")) for item in value]
        return value

    def _matches(self, path: tuple[str, ...], name: str) -> bool:
        if name in self._names:
            return True
        return any(_glob(pattern, path) for pattern in self._paths)


def _glob(pattern: Sequence[str], path: Sequence[str]) -> bool:
    if len(pattern) != len(path):
        return False
    return all(part in ("*", actual) for part, actual in zip(pattern, path, strict=True))
