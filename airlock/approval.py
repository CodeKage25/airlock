"""Approval rules. ``approval.when(tool, predicate)`` routes matching calls to a human."""

from airlock.core.approvals import ApprovalRequest, ApprovalRule, when

__all__ = ["ApprovalRequest", "ApprovalRule", "when"]
