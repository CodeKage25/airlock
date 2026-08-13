"""The safety layer between your AI agent and the real world."""

from airlock import approval, errors
from airlock.core.policy import Caps, Policy
from airlock.core.risk import RiskHook
from airlock.core.types import ApprovalRecord, AuditEntry, Call, Decision, Outcome, Verdict
from airlock.errors import (
    AirlockError,
    Blocked,
    DuplicateIntent,
    PendingApproval,
    PolicyError,
    StoreUnavailable,
)
from airlock.lock import Airlock

__version__ = "0.2.0"

__all__ = [
    "Airlock",
    "AirlockError",
    "ApprovalRecord",
    "AuditEntry",
    "Blocked",
    "Call",
    "Caps",
    "Decision",
    "DuplicateIntent",
    "Outcome",
    "PendingApproval",
    "Policy",
    "PolicyError",
    "RiskHook",
    "StoreUnavailable",
    "Verdict",
    "approval",
    "errors",
]
