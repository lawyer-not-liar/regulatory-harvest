"""Tests for the report-blind evaluation-baseline-v1 model boundary."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from pydantic import ValidationError

from regulatory_harvest.evaluation.attorney_baseline_models import (
    BaselineImportanceV1,
    BaselineInputV1,
    BaselineProposalV1,
    ImportanceBasisV1,
)

HASH = "a" * 64
ROOT = Path(__file__).resolve().parents[2]
EXPECTED_POLICY_BYTES = (
    b'{"definitions":{"critical":"omission or material misstatement could change the legal '
    b'bottom line, applicability, operative status, core duty or prohibition, enforcement '
    b'exposure, remedy, or a dispositive deadline.","material":"necessary for a competent '
    b'attorney briefing or implementation decision but not independently outcome-determinative '
    b'under the current scoped question.","supporting":"useful explanatory, contextual, or '
    b'implementation detail whose absence does not materially change the legal answer or required '
    b'next action."},"importance_policy_version":"importance-policy-v1"}'
)


@pytest.fixture
def policy_bytes() -> bytes:
    return (ROOT / "assets" / "evaluation-baseline-policy-v1.json").read_bytes()


@pytest.fixture
def valid_input() -> dict[str, object]:
    source_text = "A covered operator must file a notice."
    client_facts = "The operator is covered."
    client_facts_digest = hashlib.sha256(client_facts.encode("utf-8")).hexdigest()
    return {
        "schema_version": "baseline-input-v1",
        "sources": (
            {
                "source_id": "rule-1",
                "title": "Rule 1",
                "normalized_text": source_text,
                "content_hash": hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
                "jurisdiction": "Example",
                "authority_type": "regulation",
                "source_role": "official_primary",
                "source_quality": "primary",
                "completeness": "complete",
                "language": "en",
            },
        ),
        "source_record_fingerprint": HASH,
        "question": "What must a covered operator do?",
        "jurisdiction": "Example",
        "as_of": "2026-08-24",
        "requested_authorities": (
            {
                "authority_id": "rule-1",
                "title": "Rule 1",
                "jurisdiction": "Example",
                "authority_type": "regulation",
                "source_ids": ["rule-1"],
            },
        ),
        "client_facts": client_facts,
        "client_facts_binding": f"sha256:{client_facts_digest}",
        "qualification_root": "b" * 64,
        "qualification_receipt_fingerprint": "c" * 64,
        "qualification_readiness": "ADMITTED",
        "compiler_contract": {"version": "baseline-compiler-contract-v1"},
        "compiler_contract_fingerprint": "d" * 64,
        "evaluation_rubric_version": "attorney-eval-v2.2",
        "evaluation_rubric_bytes": b'{"version":"attorney-eval-v2.2"}',
        "evaluation_rubric_fingerprint": "e" * 64,
        "importance_policy_version": "importance-policy-v1",
        "importance_policy_bytes": (
            b'{"definitions":{},"importance_policy_version":"importance-policy-v1"}'
        ),
        "importance_policy_fingerprint": "f" * 64,
        "legal_input_fingerprint": "0" * 64,
    }


def _proposal(
    *,
    importance: str = "critical",
    basis: tuple[str, ...] = ("legal_bottom_line",),
    rationale: str = "Omission could change the legal bottom line.",
) -> dict[str, object]:
    return {
        "statement": "A covered operator must file a notice.",
        "kind": "obligation",
        "importance": importance,
        "importance_basis": basis,
        "importance_rationale": rationale,
        "passages": ({"source_id": "rule-1", "quote": "must file a notice"},),
        "confidence": "clear",
        "substantive_rationale": "The source uses mandatory language.",
    }


def test_importance_policy_definitions_are_exact(policy_bytes: bytes) -> None:
    assert policy_bytes == EXPECTED_POLICY_BYTES


def test_importance_enums_are_closed() -> None:
    assert {item.value for item in BaselineImportanceV1} == {
        "critical",
        "material",
        "supporting",
    }
    assert {item.value for item in ImportanceBasisV1} == {
        "legal_bottom_line",
        "applicability",
        "operative_status",
        "core_duty_or_prohibition",
        "enforcement_exposure",
        "remedy",
        "dispositive_deadline",
        "attorney_briefing",
        "implementation_decision",
        "explanatory_context",
        "implementation_detail",
    }
    with pytest.raises(ValidationError):
        BaselineProposalV1.model_validate({**_proposal(), "importance": "urgent"})


@pytest.mark.parametrize(
    "forbidden",
    [
        "candidate_id",
        "report_text",
        "report_hash",
        "anonymous_label",
        "generation_metadata",
        "grader_responses",
        "run_seed",
        "case_fingerprint",
    ],
)
def test_baseline_input_rejects_report_bound_fields(
    valid_input: dict[str, object], forbidden: str
) -> None:
    with pytest.raises(ValidationError):
        BaselineInputV1.model_validate({**valid_input, forbidden: "forbidden"})


def test_baseline_input_rejects_extra_object_keys(valid_input: dict[str, object]) -> None:
    source = valid_input["sources"]
    assert isinstance(source, tuple)
    first_source = source[0]
    assert isinstance(first_source, dict)
    with pytest.raises(ValidationError):
        BaselineInputV1.model_validate(
            {**valid_input, "sources": ({**first_source, "report_text": "forbidden"},)}
        )


@pytest.mark.parametrize(
    "forbidden",
    [
        "candidate_id",
        "report_text",
        "report_hash",
        "anonymous_label",
        "generation_metadata",
        "grader_responses",
        "run_seed",
        "case_fingerprint",
    ],
)
def test_baseline_input_recursively_rejects_report_bound_compiler_contract_keys(
    valid_input: dict[str, object], forbidden: str
) -> None:
    with pytest.raises(ValidationError, match="report-bound"):
        BaselineInputV1.model_validate(
            {
                **valid_input,
                "compiler_contract": {
                    "version": "baseline-compiler-contract-v1",
                    "nested": {forbidden: "forbidden"},
                },
            }
        )


@pytest.mark.parametrize("non_wire", [("tuple",), object()])
def test_baseline_input_rejects_non_wire_compiler_contract_values(
    valid_input: dict[str, object], non_wire: object
) -> None:
    with pytest.raises(ValidationError, match="compiler contract"):
        BaselineInputV1.model_validate(
            {
                **valid_input,
                "compiler_contract": {
                    "version": "baseline-compiler-contract-v1",
                    "nested": non_wire,
                },
            }
        )


def test_baseline_input_binds_explicit_null_client_facts(valid_input: dict[str, object]) -> None:
    accepted = BaselineInputV1.model_validate(
        {**valid_input, "client_facts": None, "client_facts_binding": "explicit-null"}
    )
    assert accepted.client_facts is None
    with pytest.raises(ValidationError, match="client facts"):
        BaselineInputV1.model_validate(
            {**valid_input, "client_facts": None, "client_facts_binding": "sha256:" + HASH}
        )


def test_baseline_input_binds_present_client_facts_to_the_exact_digest(
    valid_input: dict[str, object],
) -> None:
    with pytest.raises(ValidationError, match="client facts"):
        BaselineInputV1.model_validate({**valid_input, "client_facts_binding": "sha256:" + HASH})


@pytest.mark.parametrize(
    "rationale", ["", "   ", "critical", "important", "self evident", "as labeled"]
)
def test_baseline_proposal_rejects_blank_or_generic_importance_rationale(rationale: str) -> None:
    with pytest.raises(ValidationError):
        BaselineProposalV1.model_validate({**_proposal(), "importance_rationale": rationale})


def test_baseline_proposal_rejects_basis_from_another_definition() -> None:
    with pytest.raises(ValidationError, match="importance basis"):
        BaselineProposalV1.model_validate(
            {**_proposal(importance="material", basis=("legal_bottom_line",))}
        )


def test_model_validate_rejects_raw_pydantic_construction_bypass() -> None:
    forged = BaselineProposalV1.model_construct(**_proposal(rationale="critical"))
    with pytest.raises(ValidationError, match="importance rationale"):
        BaselineProposalV1.model_validate(forged)
