"""Public-safe response-contract diagnostics for evaluator preflight."""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .attorney_models import EvaluationPreflightIssue


class ResponseContractCode(StrEnum):
    SEMANTIC_INVALID = "EVALUATION_RESPONSE_SEMANTIC_INVALID"
    RESPONSE_INCOMPLETE = "EVALUATION_RESPONSE_INCOMPLETE"
    AUDIT_INCOMPLETE = "EVALUATION_AUDIT_INCOMPLETE"
    AUDIT_RATIONALE_INSUFFICIENT = "EVALUATION_AUDIT_RATIONALE_INSUFFICIENT"
    AUDIT_ACTION_INVALID = "EVALUATION_AUDIT_ACTION_INVALID"
    AUDIT_TARGET_UNKNOWN = "EVALUATION_AUDIT_TARGET_UNKNOWN"
    SOURCE_BINDING_INVALID = "EVALUATION_SOURCE_BINDING_INVALID"
    PROPOSED_ENTRY_INVALID = "EVALUATION_PROPOSED_ENTRY_INVALID"


PREFLIGHT_ISSUE_MESSAGES: dict[str, str] = {
    "EVALUATION_NO_PENDING_REQUEST": "The evaluation run has no pending request.",
    "EVALUATION_RESPONSE_REQUEST_MISMATCH": "The response does not bind the pending request.",
    "EVALUATION_RESPONSE_SCHEMA_INVALID": (
        "The response does not satisfy the canonical response schema."
    ),
    ResponseContractCode.SEMANTIC_INVALID: (
        "The response does not satisfy the pending operation contract."
    ),
    ResponseContractCode.RESPONSE_INCOMPLETE: (
        "The response is incomplete for the pending operation."
    ),
    ResponseContractCode.AUDIT_INCOMPLETE: "The ledger audit is incomplete.",
    ResponseContractCode.AUDIT_RATIONALE_INSUFFICIENT: (
        "The ledger audit rationale is insufficient."
    ),
    ResponseContractCode.AUDIT_ACTION_INVALID: "The ledger audit action is invalid.",
    ResponseContractCode.AUDIT_TARGET_UNKNOWN: "The ledger audit target is unknown.",
    ResponseContractCode.SOURCE_BINDING_INVALID: "The source binding is invalid.",
    ResponseContractCode.PROPOSED_ENTRY_INVALID: "The audit proposed entry is invalid.",
}


class ResponseContractError(ValueError):
    """A deterministic response defect that can be reported without private details."""

    def __init__(
        self,
        message: str,
        *,
        code: ResponseContractCode = ResponseContractCode.SEMANTIC_INVALID,
        related_ids: Sequence[str] = (),
    ) -> None:
        super().__init__(message)
        self.code = code
        self.related_ids = tuple(sorted(set(related_ids)))


def preflight_issue_message(code: str | ResponseContractCode) -> str:
    """Return the sole public message assigned to one preflight diagnostic code."""
    return PREFLIGHT_ISSUE_MESSAGES[str(code)]


def safe_preflight_issue(error: Exception) -> EvaluationPreflightIssue:
    """Convert a response error into a fixed, public-safe preflight issue."""
    from .attorney_models import EvaluationPreflightIssue

    if isinstance(error, ResponseContractError):
        code = error.code
        related_ids = list(error.related_ids)
    else:
        code = ResponseContractCode.SEMANTIC_INVALID
        related_ids = []
    return EvaluationPreflightIssue(
        code=code,
        message=preflight_issue_message(code),
        related_ids=related_ids,
    )
