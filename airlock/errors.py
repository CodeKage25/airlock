from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from airlock.core.types import Call


class AirlockError(Exception):
    """Base for every error Airlock raises."""


class Blocked(AirlockError):
    """A layer refused the call. Nothing executed."""

    def __init__(self, reason: str, layer: str, call: Call | None = None) -> None:
        super().__init__(f"[{layer}] {reason}")
        self.reason = reason
        self.layer = layer
        self.call = call


class PendingApproval(AirlockError):
    """An approval rule matched. The call is parked; nothing executed."""

    def __init__(self, request_id: str, reason: str, call: Call | None = None) -> None:
        super().__init__(f"approval required ({request_id}): {reason}")
        self.request_id = request_id
        self.reason = reason
        self.call = call


class DuplicateIntent(AirlockError):
    """Raised only under strict_idempotency. The default replays the original result."""

    def __init__(self, intent: str, original_result: Any) -> None:
        super().__init__(f"intent {intent!r} has already executed")
        self.intent = intent
        self.original_result = original_result


class StoreUnavailable(AirlockError):
    """A store dependency failed. Always surfaces to the caller as a fail-closed Blocked."""

    def __init__(self, store: str, cause: BaseException) -> None:
        super().__init__(f"store {store!r} unavailable: {cause}")
        self.store = store
        self.cause = cause


class PolicyError(AirlockError):
    """An invalid policy or tool registration. Raised at configuration time, not call time."""
