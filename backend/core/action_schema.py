"""
core/action_schema.py — Structured representation of a proposed critical action.

A ProposedAction is NOT free-form text.  It is a typed, validated record that
describes exactly what the ARGUS Critical Decision Simulator is being asked to
do.  Pydantic validation is the *first* gate — a structurally invalid action
cannot even be represented in the system, let alone executed.

Validation alone is NOT sufficient for security: a structurally valid action
still must pass the PromptGuard detection gate AND the deterministic policy
check before ARGUS may be called.
"""
from typing import Dict, Literal, Optional

from pydantic import BaseModel, Field, field_validator


class ProposedAction(BaseModel):
    """Structured representation of a critical decision to be validated and
    (if permitted) executed by the ARGUS Critical Decision Simulator.

    Fields
    ------
    action_type     : one of the three supported critical action types.
    amount          : monetary amount — REQUIRED for approve_transaction.
    currency        : ISO-4217 currency code (default USD).
    recipient_id    : non-empty identifier of the target account / resource.
    authorized_by   : claimed authority requesting the action.
    request_id      : reference back to the upstream prompt detection log ID.
    metadata        : optional free-form auxiliary data (read-only by ARGUS).
    """

    action_type: Literal[
        "approve_transaction",
        "reject_transaction",
        "authorize_access",
    ]
    amount: Optional[float] = Field(
        default=None,
        description="Required for approve_transaction; must be > 0.",
    )
    currency: str = Field(default="USD", max_length=3)
    recipient_id: str = Field(min_length=1)
    authorized_by: str = Field(min_length=1)
    request_id: str = Field(min_length=1)
    metadata: Dict[str, str] = Field(default_factory=dict)

    @field_validator("amount")
    @classmethod
    def amount_positive(cls, v: Optional[float]) -> Optional[float]:
        if v is not None and v <= 0:
            raise ValueError("amount must be greater than zero")
        return v

    @field_validator("currency")
    @classmethod
    def currency_upper(cls, v: str) -> str:
        return v.upper()

    def model_post_init(self, __context) -> None:  # noqa: D401
        """Enforce that approve_transaction always carries an amount."""
        if self.action_type == "approve_transaction" and self.amount is None:
            raise ValueError(
                "amount is required for approve_transaction"
            )
