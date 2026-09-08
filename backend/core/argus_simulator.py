"""
core/argus_simulator.py — ARGUS Critical Decision Simulator.

This is a DEMONSTRATION / TEST EXECUTOR ONLY.  It simulates what a real
critical-decision executor would do without connecting to any real financial,
identity, or operational system.

ARGUS is intentionally inaccessible from any path that has not first cleared:
  1. Pydantic schema validation   (action_schema.ProposedAction)
  2. PromptGuard detection gate   (core.pipeline.detect → action != "block")
  3. Degraded-state check         (classifier model present; fail-closed if not)
  4. Deterministic policy check   (action_policy.validate → allowed)

This function must ONLY be called from api/argus.py after all four gates pass.
Any other call site is a security defect.
"""
import hashlib
import time
from dataclasses import dataclass

from core.action_schema import ProposedAction


@dataclass(frozen=True)
class ArgusResult:
    """Outcome returned by the ARGUS Critical Decision Simulator."""

    executed: bool
    receipt_id: str
    detail: str


def execute(action: ProposedAction) -> ArgusResult:
    """Simulate execution of *action*.

    This function assumes ALL security and policy gates have already been
    satisfied by the caller.  It does NOT re-check gates — that is the
    caller's (api/argus.py) responsibility.

    Returns a deterministic mock receipt derived from the action fields so
    that repeated demo runs with the same inputs produce the same receipt ID
    (useful for reproducibility in presentations).
    """
    # Deterministic receipt: SHA-256 of action_type + recipient_id + request_id + timestamp-bucket
    # The timestamp bucket (10-second window) ensures receipts differ across
    # separate runs while remaining stable for tests that mock time.
    ts_bucket = str(int(time.time()) // 10)
    raw = f"{action.action_type}|{action.recipient_id}|{action.request_id}|{ts_bucket}"
    receipt_id = "RCP-" + hashlib.sha256(raw.encode()).hexdigest()[:12].upper()

    if action.action_type == "approve_transaction":
        detail = (
            f"[SIMULATOR] Approved {action.currency} {action.amount:,.2f} "
            f"to recipient '{action.recipient_id}'. "
            f"Receipt: {receipt_id}."
        )

    elif action.action_type == "reject_transaction":
        detail = (
            f"[SIMULATOR] Transaction rejected for recipient '{action.recipient_id}'. "
            f"Receipt: {receipt_id}."
        )

    elif action.action_type == "authorize_access":
        detail = (
            f"[SIMULATOR] Access authorized for '{action.recipient_id}' "
            f"by '{action.authorized_by}'. "
            f"Receipt: {receipt_id}."
        )

    else:
        # Unreachable due to Pydantic Literal constraint, but fail closed.
        return ArgusResult(
            executed=False,
            receipt_id="",
            detail=f"[SIMULATOR] Unknown action type '{action.action_type}'. NOT executed.",
        )

    return ArgusResult(executed=True, receipt_id=receipt_id, detail=detail)
