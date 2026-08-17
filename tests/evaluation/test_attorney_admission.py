from __future__ import annotations

import hashlib
import json
from datetime import date

import pytest
from pydantic import ValidationError

from regulatory_harvest.evaluation.attorney_admission import (
    adjudicate_admission,
    build_admission_packet,
    freeze_case,
)
from regulatory_harvest.evaluation.attorney_models import (
    AdmissionCheck,
    AttorneyEvaluationCase,
    CandidateReport,
    CandidateRole,
    CaseAdmissionJudgment,
    CaseEnvelope,
    EvaluationIssue,
    EvaluationMode,
    EvaluationSource,
    IssueSeverity,
    ReadinessStatus,
    RequestedAuthority,
    model_fingerprint,
)
from regulatory_harvest.models import SourceQuality, SourceRole


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _parity_receipt(
    source_hashes: dict[str, str], client_facts: str | None = None
) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "source_hashes": source_hashes,
        "client_facts_hash": _sha256(client_facts or ""),
    }


def synthetic_case() -> AttorneyEvaluationCase:
    source_text = "Section 1. A controller shall document its processing activities."
    candidate_text = "The controller must document its processing activities."
    comparator_text = "Documentation is required for processing activities."
    return AttorneyEvaluationCase(
        case_id="synthetic-case",
        mode=EvaluationMode.CLOSED_UNIVERSE,
        question="What documentation is required?",
        jurisdiction="Example State",
        as_of=date(2026, 8, 11),
        requested_authorities=[
            RequestedAuthority(
                authority_id="example-statute",
                title="Example Privacy Act",
                jurisdiction="Example State",
                authority_type="statute",
                source_ids=["example-statute-1"],
            )
        ],
        sources=[
            EvaluationSource(
                source_id="example-statute-1",
                title="Example Privacy Act",
                normalized_text=source_text,
                content_hash=_sha256(source_text),
                jurisdiction="Example State",
                authority_type="statute",
                source_role=SourceRole.OFFICIAL_PRIMARY,
                source_quality=SourceQuality.PRIMARY,
                completeness="complete",
                language="en",
            )
        ],
        candidates=[
            CandidateReport(
                candidate_id="harvest",
                role=CandidateRole.CANDIDATE,
                report_text=candidate_text,
                report_hash=_sha256(candidate_text),
                validation_receipt=_parity_receipt(
                    {"example-statute-1": _sha256(source_text)}
                ),
            ),
            CandidateReport(
                candidate_id="comparison",
                role=CandidateRole.COMPARATOR,
                report_text=comparator_text,
                report_hash=_sha256(comparator_text),
                validation_receipt=_parity_receipt(
                    {"example-statute-1": _sha256(source_text)}
                ),
            ),
        ],
    )


def admission_judgment(
    envelope: CaseEnvelope,
    *,
    issue_codes: list[str] | None = None,
    common_record_proven: bool = True,
) -> CaseAdmissionJudgment:
    checks = [
        AdmissionCheck(
            code="AUTHORITY_ALIGNMENT",
            satisfied=True,
            material=True,
            rationale="Requested authorities match the retained sources.",
            source_ids=["example-statute-1"],
        ),
        AdmissionCheck(
            code="OPERATIVE_TEXT",
            satisfied=True,
            material=True,
            rationale="Primary operative text is retained.",
            source_ids=["example-statute-1"],
        ),
        AdmissionCheck(
            code="CURRENTNESS_EVIDENCE",
            satisfied=True,
            material=True,
            rationale="Currentness evidence is sufficient for this record.",
            source_ids=["example-statute-1"],
        ),
        AdmissionCheck(
            code="LANGUAGE_RESOLUTION",
            satisfied=True,
            material=True,
            rationale="The source language is resolved.",
            source_ids=["example-statute-1"],
        ),
        AdmissionCheck(
            code="SOURCE_PARITY",
            satisfied=common_record_proven,
            material=True,
            rationale="Both reports were evaluated against the retained source record.",
            source_ids=["example-statute-1"],
        ),
    ]
    return CaseAdmissionJudgment(
        request_fingerprint=build_admission_packet(envelope).request_fingerprint,
        checks=checks,
        issues=[
            EvaluationIssue(
                code=code,
                severity=IssueSeverity.ERROR,
                message="A material admission defect was found.",
            )
            for code in issue_codes or []
        ],
    )


@pytest.mark.parametrize(
    ("issue_code", "expected"),
    [
        ("AUTHORITY_MISMATCH", ReadinessStatus.CASE_INVALID),
        ("OPERATIVE_TEXT_MISSING", ReadinessStatus.CASE_INVALID),
        ("CURRENTNESS_EVIDENCE_INSUFFICIENT", ReadinessStatus.CASE_INVALID),
        ("LANGUAGE_UNRESOLVED", ReadinessStatus.CASE_INVALID),
        ("SOURCE_PARITY_UNPROVEN", ReadinessStatus.CASE_INVALID),
    ],
)
def test_material_admission_issue_invalidates_case(
    issue_code: str, expected: ReadinessStatus
) -> None:
    envelope = freeze_case(synthetic_case(), seed_hex="1" * 64)

    readiness = adjudicate_admission(
        envelope,
        admission_judgment(envelope, issue_codes=[issue_code]),
    )

    assert readiness.status is expected
    assert readiness.issue_codes == [issue_code]


def test_export_presence_cannot_prove_case_source_parity() -> None:
    case = synthetic_case_with_export_metadata_but_no_parity_receipts()
    envelope = freeze_case(case, seed_hex="2" * 64)

    readiness = adjudicate_admission(envelope, admission_judgment(envelope))

    assert readiness.status is ReadinessStatus.CASE_INVALID
    assert "SOURCE_PARITY_UNPROVEN" in readiness.issue_codes


def test_freeze_is_seed_deterministic_and_binds_every_envelope_fingerprint() -> None:
    case = synthetic_case()

    first = freeze_case(case, seed_hex="3" * 64)
    second = freeze_case(case, seed_hex="3" * 64)

    assert first == second
    assert first.case_fingerprint == hashlib.sha256(
        json.dumps(
            case.model_dump(mode="json"), ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
    ).hexdigest()
    assert first.seed_fingerprint == _sha256("3" * 64)
    assert {assignment.candidate_id for assignment in first.assignments} == {
        candidate.candidate_id for candidate in case.candidates
    }


def test_freeze_rejects_noncanonical_seed() -> None:
    with pytest.raises(ValueError, match="64 lowercase hexadecimal"):
        freeze_case(synthetic_case(), seed_hex="not-a-seed")


def test_freeze_copies_a_strict_snapshot_before_caller_mutation() -> None:
    case = synthetic_case()
    envelope = freeze_case(case, seed_hex="f" * 64)
    case.candidates.append(case.candidates[0])
    case.sources[0].content_hash = "0" * 64

    packet = build_admission_packet(envelope)

    assert len(envelope.case.candidates) == 2
    assert packet.payload["sources"][0]["content_hash"] != "0" * 64


def test_public_entries_reject_post_validation_invalid_case_cardinality() -> None:
    envelope = freeze_case(synthetic_case(), seed_hex="0" * 64)
    envelope.case.candidates.append(envelope.case.candidates[0])

    with pytest.raises(ValueError, match=r"at most 2 items|at most one comparator"):
        build_admission_packet(envelope)


@pytest.mark.parametrize("field_name", ["content_hash", "report_hash"])
def test_public_entries_revalidate_hashes_after_mechanical_rebinding(field_name: str) -> None:
    envelope = freeze_case(synthetic_case(), seed_hex="0" * 64)
    if field_name == "content_hash":
        envelope.case.sources[0].content_hash = "0" * 64
    else:
        envelope.case.candidates[0].report_hash = "0" * 64
    envelope.case_fingerprint = model_fingerprint(envelope.case)

    with pytest.raises(ValueError, match=f"{field_name} must match"):
        build_admission_packet(envelope)


def test_adjudication_rejects_post_validation_nonboolean_judge_check() -> None:
    envelope = freeze_case(synthetic_case(), seed_hex="1" * 64)
    judgment = admission_judgment(envelope)
    judgment.checks[0].satisfied = "false"

    with pytest.raises(ValueError, match="boolean"):
        adjudicate_admission(envelope, judgment)


def test_admission_packet_is_source_only_and_blind() -> None:
    case = synthetic_case()
    envelope = freeze_case(case, seed_hex="4" * 64)

    packet = build_admission_packet(envelope)
    packet_json = str(packet.model_dump(mode="json"))

    assert packet.operation.value == "admit_case"
    assert "report_text" not in packet_json
    assert "candidate_id" not in packet_json
    assert "harvest" not in packet_json
    assert "comparison" not in packet_json
    assert case.case_id not in packet_json
    assert packet.payload["sources"] == [source.model_dump(mode="json") for source in case.sources]


def test_admission_packet_discloses_the_complete_required_decision_contract() -> None:
    """A fresh packet-only judge cannot guess runner-private admission code names."""
    packet = build_admission_packet(freeze_case(synthetic_case(), seed_hex="4" * 64))
    required_codes = {
        "AUTHORITY_ALIGNMENT",
        "OPERATIVE_TEXT",
        "CURRENTNESS_EVIDENCE",
        "LANGUAGE_RESOLUTION",
        "SOURCE_PARITY",
    }
    admission_check = packet.json_schema["$defs"]["AdmissionCheck"]
    code_schema = admission_check["properties"]["code"]

    assert set(code_schema["enum"]) == required_codes
    for code in required_codes:
        assert code in packet.system_instructions
    assert "exactly once" in packet.system_instructions
    assert "material=true" in packet.system_instructions
    assert "request_fingerprint" in packet.system_instructions


def test_semantically_plausible_admission_check_alias_is_rejected() -> None:
    """Aliases must not silently replace an exact check required by the runner."""
    with pytest.raises(ValidationError, match="AUTHORITY_ALIGNMENT"):
        AdmissionCheck(
            code="REQUESTED_AUTHORITY_COVERAGE",
            satisfied=True,
            material=True,
            rationale="The requested authority is present.",
            source_ids=["source-1"],
        )


def test_judgment_must_bind_the_exact_admission_packet() -> None:
    envelope = freeze_case(synthetic_case(), seed_hex="5" * 64)
    judgment = admission_judgment(envelope)
    judgment.request_fingerprint = "0" * 64

    with pytest.raises(ValueError, match="does not bind"):
        adjudicate_admission(envelope, judgment)


@pytest.mark.parametrize("candidate_index", [0, 1])
def test_missing_parity_receipt_for_either_report_invalidates_case(candidate_index: int) -> None:
    case = synthetic_case()
    case.candidates[candidate_index].validation_receipt = None
    envelope = freeze_case(case, seed_hex="6" * 64)

    readiness = adjudicate_admission(envelope, admission_judgment(envelope))

    assert readiness.status is ReadinessStatus.CASE_INVALID
    assert "SOURCE_PARITY_UNPROVEN" in readiness.issue_codes


@pytest.mark.parametrize(
    "receipt",
    [
        {"source_hashes": "not-a-mapping", "client_facts_hash": _sha256("")},
        {"source_hashes": {}, "client_facts_hash": _sha256("")},
        {
            "source_hashes": {"example-statute-1": "0" * 64, "extra": "1" * 64},
            "client_facts_hash": _sha256(""),
        },
        {
            "source_hashes": {"example-statute-1": "0" * 64},
            "client_facts_hash": "0" * 64,
        },
        {
            "source_hashes": {"example-statute-1": "0" * 64},
            "client_facts_hash": _sha256(""),
            "unexpected_commitment": "not-allowlisted",
        },
    ],
)
@pytest.mark.parametrize("candidate_index", [0, 1])
def test_malformed_or_mismatched_parity_receipt_invalidates_case(
    receipt: dict[str, object], candidate_index: int
) -> None:
    case = synthetic_case()
    case.candidates[candidate_index].validation_receipt = receipt
    envelope = freeze_case(case, seed_hex="7" * 64)

    readiness = adjudicate_admission(envelope, admission_judgment(envelope))

    assert readiness.status is ReadinessStatus.CASE_INVALID
    assert "SOURCE_PARITY_UNPROVEN" in readiness.issue_codes
    if candidate_index == 1:
        assert "COMPARATOR_ACCESS_MISMATCH" in readiness.issue_codes


def test_valid_parity_receipts_admit_the_case() -> None:
    envelope = freeze_case(synthetic_case(), seed_hex="8" * 64)

    readiness = adjudicate_admission(envelope, admission_judgment(envelope))

    assert readiness.status is ReadinessStatus.ADMITTED


def test_resolved_non_english_source_can_be_admitted() -> None:
    """Language resolution belongs to the mandatory fresh admission judgment."""
    case = synthetic_case()
    case.sources[0].language = "fr"
    envelope = freeze_case(case, seed_hex="8" * 64)

    readiness = adjudicate_admission(envelope, admission_judgment(envelope))

    assert readiness.status is ReadinessStatus.ADMITTED
    assert "LANGUAGE_UNRESOLVED" not in readiness.issue_codes


def test_non_english_source_with_failed_language_resolution_is_invalid() -> None:
    case = synthetic_case()
    case.sources[0].language = "fr"
    envelope = freeze_case(case, seed_hex="8" * 64)
    judgment = admission_judgment(envelope)
    language_check = next(
        check for check in judgment.checks if check.code == "LANGUAGE_RESOLUTION"
    )
    language_check.satisfied = False

    readiness = adjudicate_admission(envelope, judgment)

    assert readiness.status is ReadinessStatus.CASE_INVALID
    assert readiness.issue_codes == ["LANGUAGE_UNRESOLVED"]


@pytest.mark.parametrize("source_ids", [[], ["invented-source"]])
def test_satisfied_material_admission_check_requires_known_source_support(
    source_ids: list[str],
) -> None:
    """Empty or invented support must not admit a model-asserted material check."""
    envelope = freeze_case(synthetic_case(), seed_hex="8" * 64)
    judgment = admission_judgment(envelope)
    judgment.checks[0].source_ids = source_ids

    with pytest.raises(ValueError, match="supporting source_ids"):
        adjudicate_admission(envelope, judgment)


@pytest.mark.parametrize("required_check", ["AUTHORITY_ALIGNMENT", "SOURCE_PARITY"])
def test_required_check_cannot_be_downgraded_to_nonmaterial(required_check: str) -> None:
    envelope = freeze_case(synthetic_case(), seed_hex="9" * 64)
    judgment = admission_judgment(envelope)
    check = next(check for check in judgment.checks if check.code == required_check)
    check.material = False

    with pytest.raises(ValueError, match=r"required.*material"):
        adjudicate_admission(envelope, judgment)


@pytest.mark.parametrize(
    "issue_code",
    [
        "AUTHORITY_MISMATCH",
        "OPERATIVE_TEXT_MISSING",
        "CURRENTNESS_EVIDENCE_INSUFFICIENT",
        "LANGUAGE_UNRESOLVED",
        "SOURCE_PARITY_UNPROVEN",
    ],
)
def test_known_fatal_judge_issue_cannot_be_downgraded_to_warning(issue_code: str) -> None:
    envelope = freeze_case(synthetic_case(), seed_hex="a" * 64)
    judgment = admission_judgment(envelope)
    judgment.issues = [
        EvaluationIssue(
            code=issue_code,
            severity=IssueSeverity.WARNING,
            message="The judge attempted to downgrade a fatal defect.",
        )
    ]

    readiness = adjudicate_admission(envelope, judgment)

    assert readiness.status is ReadinessStatus.CASE_INVALID
    assert readiness.issue_codes == [issue_code]


@pytest.mark.parametrize("issue_code", ["authority_mismatch", "AUTHORITY-MISMATCH"])
def test_fatal_judge_issue_aliases_are_canonicalized(issue_code: str) -> None:
    envelope = freeze_case(synthetic_case(), seed_hex="2" * 64)
    judgment = admission_judgment(envelope)
    judgment.issues = [
        EvaluationIssue(
            code=issue_code,
            severity=IssueSeverity.WARNING,
            message="Format variant of a fatal defect.",
        )
    ]

    readiness = adjudicate_admission(envelope, judgment)

    assert readiness.status is ReadinessStatus.CASE_INVALID
    assert readiness.issue_codes == ["AUTHORITY_MISMATCH"]


def test_unknown_judge_warning_remains_nonfatal() -> None:
    envelope = freeze_case(synthetic_case(), seed_hex="e" * 64)
    judgment = admission_judgment(envelope)
    judgment.issues = [
        EvaluationIssue(
            code="MODEL_NOTE",
            severity=IssueSeverity.WARNING,
            message="Nonblocking model note.",
        )
    ]

    readiness = adjudicate_admission(envelope, judgment)

    assert readiness.status is ReadinessStatus.ADMITTED


def test_source_record_can_contain_a_common_candidate_identifier_without_censorship() -> None:
    case = synthetic_case()
    case.candidates[0].candidate_id = "act"
    case.question = "What act creates the duty?"
    case.sources[0].canonical_url = "https://example.test/act-rule"
    case.sources[0].publisher = "Acting Authority"
    envelope = freeze_case(case, seed_hex="b" * 64)

    packet = build_admission_packet(envelope)

    assert packet.payload["question"] == case.question
    assert packet.payload["sources"][0]["canonical_url"] == case.sources[0].canonical_url


def test_admission_projection_does_not_depend_on_candidate_content() -> None:
    first_case = synthetic_case()
    second_case = synthetic_case()
    second_case.candidates[0].candidate_id = "other-candidate"
    second_case.candidates[0].report_text = "Entirely different candidate report."
    second_case.candidates[0].report_hash = _sha256(second_case.candidates[0].report_text)
    second_case.candidates[0].bundle_json = {"private": "metadata"}
    second_case.candidates[0].coverage_review = {"private": "coverage"}
    second_case.candidates[0].validation_receipt = first_case.candidates[0].validation_receipt
    second_case.candidates[1].candidate_id = "different-comparator"
    second_case.candidates[1].report_text = "Entirely different comparator report."
    second_case.candidates[1].report_hash = _sha256(second_case.candidates[1].report_text)
    second_case.candidates[1].validation_receipt = first_case.candidates[1].validation_receipt
    first = build_admission_packet(freeze_case(first_case, seed_hex="c" * 64))
    second = build_admission_packet(freeze_case(second_case, seed_hex="d" * 64))
    first_json = json.dumps(first.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    second_json = json.dumps(second.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))

    assert first_json == second_json
    assert "case_fingerprint" not in first_json
    assert "other-candidate" not in first_json
    assert "different-comparator" not in first_json
    assert "source_record_fingerprint" in first_json


def test_source_side_change_changes_the_admission_request_fingerprint() -> None:
    first_case = synthetic_case()
    second_case = synthetic_case()
    second_case.question = "What records must a controller retain?"

    first = build_admission_packet(freeze_case(first_case, seed_hex="e" * 64))
    second = build_admission_packet(freeze_case(second_case, seed_hex="f" * 64))

    assert first.payload["source_record_fingerprint"] != second.payload["source_record_fingerprint"]
    assert first.request_fingerprint != second.request_fingerprint


def test_packet_serializes_only_allowlisted_source_record_fields() -> None:
    envelope = freeze_case(synthetic_case(), seed_hex="c" * 64)

    packet = build_admission_packet(envelope)

    assert set(packet.payload) == {
        "schema_version",
        "source_record_fingerprint",
        "mode",
        "question",
        "jurisdiction",
        "as_of",
        "requested_authorities",
        "sources",
    }
    assert "candidates" not in packet.payload
    assert "assignments" not in packet.payload
    assert "report_text" not in json.dumps(packet.model_dump(mode="json"))


def test_packet_and_adjudication_reject_tampered_blind_assignments() -> None:
    envelope = freeze_case(synthetic_case(), seed_hex="d" * 64)
    envelope.assignments.reverse()
    judgment = admission_judgment(freeze_case(synthetic_case(), seed_hex="d" * 64))

    with pytest.raises(ValueError, match="assignments"):
        build_admission_packet(envelope)
    with pytest.raises(ValueError, match="assignments"):
        adjudicate_admission(envelope, judgment)


def synthetic_case_with_export_metadata_but_no_parity_receipts() -> AttorneyEvaluationCase:
    case = synthetic_case()
    for candidate in case.candidates:
        candidate.validation_receipt = None
    case.candidates[1].bundle_json = {
        "fulltext_export": {"example-statute-1": case.sources[0].content_hash}
    }
    return case
