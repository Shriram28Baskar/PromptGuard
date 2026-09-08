"""
core/action_policy.py — Deterministic policy for critical actions.

This module is intentionally SEPARATE from the ML-based injection detector.
Security (did this prompt try to hijack the model?) and authorization (is this
action permitted by policy?) are different questions answered by different
components.

Rules here are hard-coded and deterministic.  No ML, no LLM, no external call.
A policy decision cannot be overridden by the LLM or by any frontend signal.

Policy check is the SECOND gate (after PromptGuard detection); both gates must
pass before ARGUS may be called.
"""
from dataclasses import dataclass
from typing import Set

from core.action_schema import ProposedAction

# ---------------------------------------------------------------------------
# Configuration — kept in this file to make it clear policy is deterministic.
# ---------------------------------------------------------------------------

#: Maximum monetary amount (inclusive) that approve_transaction may authorize.
TRANSACTION_LIMIT: float = 10_000.00

#: Principals that may authorize an authorize_access action.
KNOWN_PRINCIPALS: Set[str] = {"system", "admin", "ops_team"}


@dataclass(frozen=True)
class PolicyResult:
    """Outcome of a deterministic policy evaluation."""

    allowed: bool
    reason: str

    @property
    def verdict(self) -> str:
        return "ALLOW" if self.allowed else "DENY"


def validate(action: ProposedAction) -> PolicyResult:
    """Evaluate *action* against all deterministic policy rules.

    Evaluation is fail-safe: any failing rule returns DENY immediately
    without checking remaining rules (defence-in-depth order).

    Rules
    -----
    R1  recipient_id must be non-empty        (all action types)
    R2  authorized_by must be non-empty       (all action types)
    R3  request_id must be non-empty          (all action types)
    R4  approve_transaction: amount must be present AND ≤ TRANSACTION_LIMIT
    R5  authorize_access: authorized_by must be a known principal
    """
    # R1 — recipient_id (already enforced by Pydantic min_length=1, but
    #      policy must enforce independently of schema validation).
    if not action.recipient_id.strip():
        return PolicyResult(
            allowed=False,
            reason="Policy R1: recipient_id is empty or whitespace-only.",
        )

    # R2 — authorized_by
    if not action.authorized_by.strip():
        return PolicyResult(
            allowed=False,
            reason="Policy R2: authorized_by is empty or whitespace-only.",
        )

    # R3 — request_id
    if not action.request_id.strip():
        return PolicyResult(
            allowed=False,
            reason="Policy R3: request_id is empty or whitespace-only.",
        )

    # R4 — monetary limit for approve_transaction
    if action.action_type == "approve_transaction":
        if action.amount is None:
            # Should not reach here (schema enforces it) but fail closed.
            return PolicyResult(
                allowed=False,
                reason="Policy R4: approve_transaction requires an amount.",
            )
        if action.amount > TRANSACTION_LIMIT:
            return PolicyResult(
                allowed=False,
                reason=(
                    f"Policy R4: amount {action.currency} {action.amount:,.2f} "
                    f"exceeds the per-request limit of {action.currency} "
                    f"{TRANSACTION_LIMIT:,.2f}."
                ),
            )

    # R5 — known principals for approve_transaction and authorize_access
    if action.action_type in ("approve_transaction", "authorize_access"):
        if action.authorized_by.strip().lower() not in {p.lower() for p in KNOWN_PRINCIPALS}:
            return PolicyResult(
                allowed=False,
                reason=(
                    f"Policy R5: '{action.authorized_by}' is not a known "
                    f"authorized principal for {action.action_type}. "
                    f"Authorized principals: {sorted(KNOWN_PRINCIPALS)}."
                ),
            )

    # All rules passed.
    return PolicyResult(
        allowed=True,
        reason=f"All policy rules satisfied for action '{action.action_type}'.",
    )
