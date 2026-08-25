"""Controller-owned request packets for delivery-readiness-v1."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_attorney_baseline_artifacts import _complete_graph
from test_attorney_baseline_projection import _resealed_context

from regulatory_harvest.evaluation.attorney_baseline_artifacts import (
    initialize_baseline_storage_v1,
    load_verified_baseline_run,
)
from regulatory_harvest.evaluation.attorney_baseline_models import (
    BaselineRequirementV1,
    ContestedBaselineRequirementV1,
)
from regulatory_harvest.evaluation.attorney_baseline_projection import (
    project_gradeable_baseline_v1,
    verify_gradeable_baseline_projection_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_inputs import (
    GenerationCapsuleBindingV1,
    QualificationReadinessBindingV1,
    VerifiedReadinessInputsV1,
)
from regulatory_harvest.evaluation.attorney_readiness_models import (
    BaselineLockedContestedGradeV1,
    BaselineLockedGradeFragmentV1,
    BaselineLockedGraderAggregateV1,
    GenerationValidationBindingV1,
    HistoricalV22CrossCheckV1,
    ReadinessInputV1,
    SafetyFindingProposalV1,
    SafetyGapAssessmentV1,
    SafetyGapCandidateV1,
    SafetyLaneResponseV1,
    load_readiness_rubric_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_requests import (
    READINESS_COMPILER_CONTRACT_FINGERPRINT_V1,
    READINESS_COMPILER_CONTRACT_V1,
    READINESS_CONSERVATIVE_DISPOSITION_ORDER_V1,
    READINESS_STRICT_EQUIVALENT_SCORING_DESCRIPTOR_V1,
    READINESS_STRICT_EQUIVALENT_SCORING_FINGERPRINT_V1,
    build_baseline_locked_contested_grade_request_v1,
    build_baseline_locked_grade_batches_v1,
    build_baseline_locked_grade_request_v1,
    build_gap_candidate_inventory_v1,
    build_safety_disputes_v1,
    build_safety_lane_request_v1,
    build_safety_referee_request_v1,
)
from regulatory_harvest.evaluation.attorney_v2_models import RequirementGradeV2
from regulatory_harvest.evaluation.attorney_v22_compiler import RUBRIC_V22
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

REPORT_TEXT = (
    "# Fictional Rule Report\n\n"
    "## Executive Summary\n\n"
    "The report addresses the notice duty.\n\n"
    "The report partially addresses operator identification.\n\n"
    "## Limitations\n\n"
    "Currentness remains to be confirmed.\n"
)


def _digest(label: str) -> str:
    return sha256_digest(label.encode("utf-8"))


def _request_fingerprint(request: object) -> str:
    raw = request.model_dump(mode="json")  # type: ignore[union-attr]
    raw.pop("request_fingerprint")
    return sha256_digest(canonical_json_bytes(raw))


def _requirement(
    index: int,
    *,
    kind: str = "obligation",
    importance: str = "material",
) -> BaselineRequirementV1:
    quote = "must file a notice" if index % 2 else "must identify the operator"
    start_char = 30 if index % 2 else 72
    return BaselineRequirementV1(
        requirement_id=f"REQ-{index:04d}",
        canonical_order=index - 1,
        statement=f"Fictional requirement {index} must be addressed.",
        kind=kind,
        importance=importance,
        importance_basis=(
            ("legal_bottom_line",) if importance == "critical" else ("attorney_briefing",)
        ),
        importance_rationale=(
            "Omission could change the legal bottom line."
            if importance == "critical"
            else "The point is necessary for a competent attorney briefing."
        ),
        passages=(
            {
                "source_id": "rule-1",
                "start_char": start_char,
                "end_char": start_char + len(quote),
                "quote": quote,
            },
        ),
        dependency=None,
        confidence="clear",
        substantive_rationale="The exact source passage supplies the requirement.",
    )


def _contest() -> ContestedBaselineRequirementV1:
    reviewer = _requirement(8, importance="critical")
    auditor = BaselineRequirementV1(
        **{
            **reviewer.model_dump(mode="python"),
            "statement": "The fictional duty may require a narrower filing.",
            "confidence": "ambiguous",
            "substantive_rationale": "The source permits the narrower reading.",
        }
    )
    return ContestedBaselineRequirementV1(
        contested_requirement_id="CONT-0001",
        reviewer_alternative=reviewer,
        auditor_alternative=auditor,
        unresolved_reason="SOURCE_AMBIGUITY",
        importance="critical",
        importance_basis=("legal_bottom_line",),
        importance_rationale="Either reading could change the legal bottom line.",
        substantive_rationale="The sealed source leaves both readings plausible.",
        referee_fragment_fingerprint=_digest("referee"),
    )


@pytest.fixture
def inputs(tmp_path: Path) -> VerifiedReadinessInputsV1:
    _, files, manifest = _complete_graph()
    run_dir = tmp_path / "baseline"
    initialize_baseline_storage_v1(run_dir, manifest, files)
    context = load_verified_baseline_run(run_dir)
    requirements = tuple(
        _requirement(
            index,
            kind="gap" if index == 2 else "obligation",
            importance="critical" if index in {2, 5} else "material",
        )
        for index in range(1, 8)
    )
    context = _resealed_context(
        context,
        baseline_mutation={
            "requirements": requirements,
            "relationships": (),
            "contested_requirements": (_contest(),),
        },
    )
    projection = verify_gradeable_baseline_projection_v1(
        context,
        project_gradeable_baseline_v1(context),
    )
    report_hash = sha256_digest(REPORT_TEXT.encode("utf-8"))
    validation = GenerationValidationBindingV1(
        receipt_hash=_digest("receipt"),
        report_hash=report_hash,
        bundle_hash=_digest("bundle"),
        coverage_review_hash=_digest("coverage"),
        status="completed",
        evidence_precision_valid=True,
        proposition_coverage_valid=True,
        provision_recall_valid=True,
    )
    rubric = load_readiness_rubric_v1()
    rubric_bytes = Path("src/regulatory_harvest/evaluation/readiness-rubric-v1.json").read_bytes()
    scoring_bytes = projection.baseline_input.evaluation_rubric_bytes
    readiness_input = ReadinessInputV1(
        protocol_version="delivery-readiness-v1",
        gradeable_baseline=projection,
        grade_target_fingerprint=projection.binding.grade_target_fingerprint,
        report_text=REPORT_TEXT,
        report_hash=report_hash,
        generation_capsule_root=_digest("capsule"),
        generation_validation=validation,
        readiness_rubric_fingerprint=sha256_digest(rubric_bytes),
        strict_equivalent_scoring_contract_fingerprint=sha256_digest(scoring_bytes),
        historical_v22_cross_check=None,
    )
    source = projection.baseline_input.sources[0]
    client_facts = projection.baseline_input.client_facts
    return VerifiedReadinessInputsV1(
        readiness_input=readiness_input,
        baseline_context=context,
        gradeable_baseline=projection,
        report_text=REPORT_TEXT,
        report_hash=report_hash,
        source_record=projection.baseline_input.sources,
        qualification_binding=QualificationReadinessBindingV1(
            qualification_root=projection.baseline_input.qualification_root,
            qualification_receipt_fingerprint=(
                projection.baseline_input.qualification_receipt_fingerprint
            ),
            qualification_readiness="ADMITTED",
        ),
        generation_binding=GenerationCapsuleBindingV1(
            capsule_root=_digest("capsule"),
            capture_fingerprint=_digest("capture"),
            request_fingerprint=_digest("generation-request"),
            response_fingerprint=_digest("generation-response"),
            report_hash=report_hash,
            source_hashes=((source.source_id, source.content_hash),),
            client_facts_hash=(
                None if client_facts is None else sha256_digest(client_facts.encode("utf-8"))
            ),
            generator_artifact_hashes=(("generator", _digest("generator")),),
        ),
        generation_validation=validation,
        readiness_rubric=rubric,
        readiness_rubric_bytes=rubric_bytes,
        strict_equivalent_scoring_contract_bytes=scoring_bytes,
        historical_v22=None,
    )


def _with_history(inputs: VerifiedReadinessInputsV1) -> VerifiedReadinessInputsV1:
    historical = HistoricalV22CrossCheckV1(
        report_hash=inputs.report_hash,
        strict_disposition="FAIL",
        result_fingerprint=_digest("historical-result"),
        manifest_fingerprint=_digest("historical-manifest"),
        baseline_fingerprint=_digest("historical-baseline"),
        grader_aggregate_fingerprints=(
            _digest("historical-grade-1"),
            _digest("historical-grade-2"),
        ),
        reason_codes=("CRITICAL_RECALL_BELOW_FLOOR",),
        baseline_comparable=False,
        report_comparable=True,
    )
    raw = inputs.readiness_input.model_dump(
        mode="python", exclude={"gradeable_baseline", "historical_v22_cross_check"}
    )
    readiness_input = ReadinessInputV1(
        **raw,
        gradeable_baseline=inputs.gradeable_baseline,
        historical_v22_cross_check=historical,
    )
    return replace(inputs, readiness_input=readiness_input, historical_v22=historical)


def _grade(requirement_id: str, disposition: str) -> RequirementGradeV2:
    present = disposition in {"met", "partially_met"}
    return RequirementGradeV2(
        requirement_id=requirement_id,
        disposition=disposition,
        report_passages=(["The report addresses the notice duty."] if present else []),
        rationale=f"The report is {disposition} for this exact requirement.",
        omission=(
            None
            if disposition == "met"
            else "The report does not supply the complete required treatment."
        ),
    )


def _grader_aggregate(
    inputs: VerifiedReadinessInputsV1,
    *,
    lane: int,
    dispositions: tuple[str, ...],
    contested: tuple[str, str] = ("partially_met", "met"),
) -> BaselineLockedGraderAggregateV1:
    baseline_fingerprint = inputs.gradeable_baseline.binding.baseline_fingerprint
    scoring_fingerprint = inputs.readiness_input.strict_equivalent_scoring_contract_fingerprint
    grades = tuple(
        _grade(f"REQ-{index:04d}", disposition) for index, disposition in enumerate(dispositions, 1)
    )
    fragments = tuple(
        BaselineLockedGradeFragmentV1(
            lane=cast(int, lane),
            batch_ref=f"GB-{lane}-{batch_index:04d}",
            grade_target_fingerprint=inputs.readiness_input.grade_target_fingerprint,
            baseline_fingerprint=baseline_fingerprint,
            report_hash=inputs.report_hash,
            strict_equivalent_scoring_contract_fingerprint=scoring_fingerprint,
            requirement_grades=tuple(
                item.model_dump(mode="json") for item in grades[offset : offset + 5]
            ),
            rationale="The exact controller batch was graded.",
            fragment_fingerprint=_digest(f"fragment-{lane}-{batch_index}"),
        )
        for batch_index, offset in enumerate(range(0, len(grades), 5), 1)
    )
    contest = BaselineLockedContestedGradeV1(
        lane=cast(int, lane),
        contested_requirement_id="CONT-0001",
        grade_target_fingerprint=inputs.readiness_input.grade_target_fingerprint,
        baseline_fingerprint=baseline_fingerprint,
        report_hash=inputs.report_hash,
        strict_equivalent_scoring_contract_fingerprint=scoring_fingerprint,
        reviewer_alternative_disposition=contested[0],
        auditor_alternative_disposition=contested[1],
        reviewer_report_passages=("The report addresses the notice duty.",),
        auditor_report_passages=("The report addresses the notice duty.",),
        reviewer_rationale="The reviewer alternative is graded against the report.",
        auditor_rationale="The auditor alternative is graded against the report.",
        ambiguity_disposition="both_plausible",
        rationale="Both sealed alternatives remain plausible.",
        grade_fingerprint=_digest(f"contest-{lane}"),
    )
    return BaselineLockedGraderAggregateV1(
        lane=cast(int, lane),
        grade_target_fingerprint=inputs.readiness_input.grade_target_fingerprint,
        baseline_fingerprint=baseline_fingerprint,
        report_hash=inputs.report_hash,
        strict_equivalent_scoring_contract_fingerprint=scoring_fingerprint,
        ordinary_fragments=tuple(item.model_dump(mode="json") for item in fragments),
        contested_grades=(contest.model_dump(mode="json"),),
        requirement_grades=tuple(item.model_dump(mode="json") for item in grades),
        aggregate_fingerprint=_digest(f"aggregate-{lane}"),
    )


def _grader_lanes(
    inputs: VerifiedReadinessInputsV1,
) -> tuple[BaselineLockedGraderAggregateV1, BaselineLockedGraderAggregateV1]:
    return (
        _grader_aggregate(
            inputs,
            lane=1,
            dispositions=(
                "met",
                "met",
                "partially_met",
                "met",
                "uncertain",
                "met",
                "met",
            ),
            contested=("partially_met", "met"),
        ),
        _grader_aggregate(
            inputs,
            lane=2,
            dispositions=("met", "met", "met", "not_met", "met", "met", "met"),
            contested=("met", "met"),
        ),
    )


def _assessment(
    candidate: SafetyGapCandidateV1,
    *,
    owner: str = "reviewing_attorney",
) -> SafetyGapAssessmentV1:
    if candidate.origin.value == "prerequisite":
        rationale_kind = "CURRENTNESS_NOT_ESTABLISHED"
        follow_up = "CONFIRM_CURRENTNESS"
        resolution = "Verify operative status and currentness against official evidence."
    elif candidate.origin.value == "contested_requirement":
        rationale_kind = "CONTESTED_INTERPRETATION"
        follow_up = "RESOLVE_CONTESTED_INTERPRETATION"
        resolution = "Obtain a legal judgment resolving the sealed alternatives."
    elif candidate.origin.value == "baseline_gap":
        rationale_kind = "SOURCE_ABSENT"
        follow_up = "VERIFY_PRIMARY_AUTHORITY"
        resolution = "Obtain primary evidence that resolves the baseline gap."
    else:
        rationale_kind = "REPORT_PARTIAL_TREATMENT"
        follow_up = "EXPAND_REQUIREMENT_ANALYSIS"
        resolution = "Correct the report and verify the complete requirement treatment."
    return SafetyGapAssessmentV1(
        candidate_id=candidate.candidate_id,
        shortfall_description=f"The shortfall for {candidate.subject_id} remains open.",
        rationale_kind=rationale_kind,
        why_unresolved=f"The evidence bound to {candidate.subject_id} does not close the gap.",
        why_it_matters=(
            f"The {candidate.subject_id} shortfall affects the scoped legal conclusion."
        ),
        evidence_refs=candidate.evidence_refs,
        report_passages=("Currentness remains to be confirmed.",),
        disclosure_location="Limitations",
        visibility="prominent" if candidate.importance.value == "critical" else "visible",
        blocking_code=None,
        follow_up_code=follow_up,
        resolution_test=resolution,
        owner_role=owner,
    )


def _finding(
    *,
    rationale: str,
    subject_id: str = "REQ-0003",
    kind: str = "MATERIAL_UNSUPPORTED_ASSERTION",
) -> SafetyFindingProposalV1:
    return SafetyFindingProposalV1(
        finding_kind=kind,
        subject_id=subject_id,
        report_passages=("The report partially addresses operator identification.",),
        shortfall_description="The report overstates the evidence.",
        rationale_kind="UNSUPPORTED_ASSERTION",
        why_unresolved=rationale,
        why_it_matters="The assertion could change the scoped legal conclusion.",
        evidence_refs=("BASELINE-REQ-0003", "SOURCE-000001"),
        disclosure_location="Limitations",
        visibility="prominent",
        blocking_code="MATERIAL_UNSUPPORTED_ASSERTION",
        follow_up_code="CORRECT_UNSUPPORTED_ASSERTION",
        resolution_test="Correct the report or add exact supporting evidence.",
        owner_role="reviewing_attorney",
    )


def test_contract_fingerprints_bind_public_v22_semantics_without_private_replay() -> None:
    strict = READINESS_STRICT_EQUIVALENT_SCORING_DESCRIPTOR_V1
    assert strict["retained_semantics"] == "attorney-eval-v2.2"
    assert strict["importance_weights"] == {
        key.value: value for key, value in RUBRIC_V22.importance_weights.items()
    }
    assert strict["critical_recall_floor"] == RUBRIC_V22.critical_recall_floor == 1.0
    assert strict["weighted_coverage_floor"] == RUBRIC_V22.weighted_coverage_floor == 0.9
    assert strict["uncertain_first"] == {
        "disposition": "INCONCLUSIVE",
        "reason_code": "GRADE_UNCERTAIN",
    }
    assert strict["lane_disagreement"] == {
        "disposition": "INCONCLUSIVE",
        "reason_code": "GRADER_DISAGREEMENT",
    }
    assert strict["contested_sensitivity_reason_codes"] == [
        "BASELINE_EVIDENCE_INSUFFICIENT",
        "OUTCOME_SENSITIVE_BASELINE_DISPUTE",
    ]
    assert READINESS_CONSERVATIVE_DISPOSITION_ORDER_V1 == (
        "uncertain",
        "not_met",
        "partially_met",
        "met",
    )
    assert (
        sha256_digest(canonical_json_bytes(strict))
        == READINESS_STRICT_EQUIVALENT_SCORING_FINGERPRINT_V1
    )
    assert (
        sha256_digest(canonical_json_bytes(READINESS_COMPILER_CONTRACT_V1))
        == READINESS_COMPILER_CONTRACT_FINGERPRINT_V1
    )
    assert READINESS_COMPILER_CONTRACT_FINGERPRINT_V1 != (
        READINESS_STRICT_EQUIVALENT_SCORING_FINGERPRINT_V1
    )
    with pytest.raises(TypeError):
        cast(dict[str, object], strict)["weighted_coverage_floor"] = 0.0


def test_grade_batches_are_exact_five_item_lane_specific_inventories(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    lane_1 = build_baseline_locked_grade_batches_v1(inputs.gradeable_baseline, lane=1)
    lane_2 = build_baseline_locked_grade_batches_v1(inputs.gradeable_baseline, lane=2)
    assert [item.model_dump(mode="json") for item in lane_1] == [
        {
            "batch_ref": "GB-1-0001",
            "lane": 1,
            "requirement_ids": [f"REQ-{index:04d}" for index in range(1, 6)],
        },
        {
            "batch_ref": "GB-1-0002",
            "lane": 1,
            "requirement_ids": ["REQ-0006", "REQ-0007"],
        },
    ]
    assert [item.batch_ref for item in lane_2] == ["GB-2-0001", "GB-2-0002"]
    assert [item.requirement_ids for item in lane_2] == [item.requirement_ids for item in lane_1]
    with pytest.raises(ValueError, match="lane"):
        build_baseline_locked_grade_batches_v1(
            inputs.gradeable_baseline,
            lane=cast(int, True),
        )


def test_fresh_grade_requests_preserve_exact_evidence_and_omit_history(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    historical_inputs = _with_history(inputs)
    batch_1 = build_baseline_locked_grade_batches_v1(
        historical_inputs.gradeable_baseline,
        lane=1,
    )[0]
    batch_2 = build_baseline_locked_grade_batches_v1(
        historical_inputs.gradeable_baseline,
        lane=2,
    )[0]
    request_1 = build_baseline_locked_grade_request_v1(historical_inputs, batch_1)
    request_2 = build_baseline_locked_grade_request_v1(historical_inputs, batch_2)
    assert request_1.request_fingerprint == _request_fingerprint(request_1)
    assert build_baseline_locked_grade_request_v1(historical_inputs, batch_1) == request_1
    assert request_1.payload["stable_baseline"] == (
        historical_inputs.gradeable_baseline.model_dump(mode="json")
    )
    assert request_1.payload["report_text"] == REPORT_TEXT
    assert request_1.payload["report_hash"] == historical_inputs.report_hash
    assert request_1.payload["report_passage_allowlist"][-1] == REPORT_TEXT
    assert request_1.payload["strict_equivalent_scoring_fingerprint"] == (
        READINESS_STRICT_EQUIVALENT_SCORING_FINGERPRINT_V1
    )
    requirements = cast(list[dict[str, object]], request_1.payload["requirements"])
    assert requirements[1]["requirement"]["importance_basis"] == ["legal_bottom_line"]
    assert requirements[1]["requirement"]["importance_rationale"] == (
        "Omission could change the legal bottom line."
    )
    assert request_1.payload["controller_lane_id"] == "grade-lane-1-GB-1-0001"
    assert request_2.payload["controller_lane_id"] == "grade-lane-2-GB-2-0001"
    assert request_1.request_fingerprint != request_2.request_fingerprint
    evidence_1 = dict(request_1.payload)
    evidence_2 = dict(request_2.payload)
    for evidence in (evidence_1, evidence_2):
        evidence.pop("controller_lane_id")
        evidence.pop("lane")
        evidence.pop("batch_ref")
    assert evidence_1 == evidence_2
    wire = canonical_json_bytes(request_1).decode("utf-8")
    for forbidden in (
        "historical_v22",
        "historical-result",
        "CRITICAL_RECALL_BELOW_FLOOR",
        '"FAIL"',
        "anonymous_label",
        "candidate_id",
        "generation_binding",
    ):
        assert forbidden not in wire


def test_contested_grade_request_is_one_exact_stable_contest_per_lane(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    first = build_baseline_locked_contested_grade_request_v1(
        inputs, lane=1, contested_requirement_id="CONT-0001"
    )
    second = build_baseline_locked_contested_grade_request_v1(
        inputs, lane=2, contested_requirement_id="CONT-0001"
    )
    contest = inputs.gradeable_baseline.contested_requirements[0]
    assert first.payload["contested_requirement"] == contest.model_dump(mode="json")
    assert first.payload["controller_lane_id"] == ("contested-grade-lane-1-CONT-0001")
    assert second.payload["controller_lane_id"] == ("contested-grade-lane-2-CONT-0001")
    assert first.request_fingerprint != second.request_fingerprint
    assert first.payload["stable_baseline"] == second.payload["stable_baseline"]
    assert first.payload["report_text"] == second.payload["report_text"] == REPORT_TEXT
    schema = canonical_json_bytes(first.json_schema).decode("utf-8")
    assert all(
        value in schema
        for value in (
            "reviewer_supported",
            "auditor_supported",
            "both_plausible",
            "neither_supported",
        )
    )
    with pytest.raises(ValueError, match="contested"):
        build_baseline_locked_contested_grade_request_v1(
            inputs, lane=1, contested_requirement_id="CONT-9999"
        )


def test_gap_candidate_inventory_is_complete_conservative_and_canonical(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    lanes = _grader_lanes(inputs)
    candidates = build_gap_candidate_inventory_v1(inputs, lanes)
    assert [item.candidate_id for item in candidates] == [
        f"GC-{index:04d}" for index in range(1, 7)
    ]
    assert [(item.origin.value, item.subject_id) for item in candidates] == [
        ("baseline_gap", "REQ-0002"),
        ("requirement", "REQ-0003"),
        ("requirement", "REQ-0004"),
        ("requirement", "REQ-0005"),
        ("contested_requirement", "CONT-0001"),
        ("prerequisite", "CURRENTNESS:rule-1"),
    ]
    by_subject = {item.subject_id: item for item in candidates}
    assert (
        by_subject["REQ-0003"].lane_1_disposition.value,
        by_subject["REQ-0003"].lane_2_disposition.value,
    ) == ("partially_met", "met")
    assert (
        by_subject["REQ-0005"].lane_1_disposition.value,
        by_subject["REQ-0005"].lane_2_disposition.value,
    ) == ("uncertain", "met")
    assert (
        by_subject["CONT-0001"].lane_1_disposition.value,
        by_subject["CONT-0001"].lane_2_disposition.value,
    ) == ("partially_met", "met")
    assert by_subject["CURRENTNESS:rule-1"].lane_1_disposition is None
    assert by_subject["CURRENTNESS:rule-1"].lane_2_disposition is None
    for candidate in candidates:
        expected = {
            "origin": candidate.origin.value,
            "subject_id": candidate.subject_id,
            "lane_1_disposition": (
                None if candidate.lane_1_disposition is None else candidate.lane_1_disposition.value
            ),
            "lane_2_disposition": (
                None if candidate.lane_2_disposition is None else candidate.lane_2_disposition.value
            ),
            "baseline_fingerprint": candidate.baseline_fingerprint,
            "report_hash": candidate.report_hash,
            "evidence_refs": list(candidate.evidence_refs),
        }
        assert candidate.candidate_fingerprint == sha256_digest(canonical_json_bytes(expected))
    assert "evaluator" not in canonical_json_bytes(candidates).decode("utf-8")


def test_safety_lane_packets_are_evidence_identical_blind_and_no_advice(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    historical_inputs = _with_history(inputs)
    lanes = _grader_lanes(historical_inputs)
    candidates = build_gap_candidate_inventory_v1(historical_inputs, lanes)
    first = build_safety_lane_request_v1(historical_inputs, lanes, candidates, lane=1)
    second = build_safety_lane_request_v1(historical_inputs, lanes, candidates, lane=2)
    assert first.request_fingerprint == _request_fingerprint(first)
    assert first.request_fingerprint != second.request_fingerprint
    assert first.payload["controller_safety_lane_id"] == "safety-lane-1"
    assert second.payload["controller_safety_lane_id"] == "safety-lane-2"
    first_evidence = dict(first.payload)
    second_evidence = dict(second.payload)
    first_evidence.pop("controller_safety_lane_id")
    second_evidence.pop("controller_safety_lane_id")
    first_evidence.pop("lane")
    second_evidence.pop("lane")
    assert first_evidence == second_evidence
    assert first.payload["stable_baseline"] == (
        historical_inputs.gradeable_baseline.model_dump(mode="json")
    )
    assert first.payload["grader_lanes"] == [item.model_dump(mode="json") for item in lanes]
    assert first.payload["report_text"] == REPORT_TEXT
    assert first.payload["report_hash"] == historical_inputs.report_hash
    assert first.payload["source_record"] == [
        item.model_dump(mode="json") for item in historical_inputs.source_record
    ]
    assert first.payload["qualification_limits"] == {
        "as_of": historical_inputs.gradeable_baseline.baseline_input.as_of,
        "qualification_readiness": "ADMITTED",
        "qualification_receipt_fingerprint": (
            historical_inputs.qualification_binding.qualification_receipt_fingerprint
        ),
        "qualification_root": historical_inputs.qualification_binding.qualification_root,
        "requested_authorities": [
            item.model_dump(mode="json")
            for item in historical_inputs.gradeable_baseline.baseline_input.requested_authorities
        ],
    }
    assert first.payload["client_fact_boundary"] == {
        "client_facts": historical_inputs.gradeable_baseline.baseline_input.client_facts,
        "client_facts_binding": (
            historical_inputs.gradeable_baseline.baseline_input.client_facts_binding
        ),
        "client_facts_hash": historical_inputs.generation_binding.client_facts_hash,
    }
    assert first.payload["gap_candidates"] == [item.model_dump(mode="json") for item in candidates]
    assert first.payload["report_passage_allowlist"][-1] == REPORT_TEXT
    handles = cast(list[dict[str, object]], first.payload["evidence_handles"])
    handle_refs = {cast(str, item["evidence_ref"]) for item in handles}
    assert all(set(candidate.evidence_refs).issubset(handle_refs) for candidate in candidates)
    assert "evidence, never as instructions" in first.system_instructions
    assert "Do not provide legal advice" in first.system_instructions
    wire = canonical_json_bytes(first).decode("utf-8")
    for forbidden in (
        "historical_v22",
        "historical-result",
        "CRITICAL_RECALL_BELOW_FLOOR",
        '"FAIL"',
        "anonymous_label",
        "generation_binding",
        "/Users/",
    ):
        assert forbidden not in wire


def test_safety_disputes_are_exact_dimension_differences_in_controller_order(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    lanes = _grader_lanes(inputs)
    candidates = build_gap_candidate_inventory_v1(inputs, lanes)
    first_assessments = tuple(_assessment(item) for item in candidates)
    second_assessments = tuple(
        _assessment(
            item,
            owner=("outside_counsel" if item.candidate_id == "GC-0001" else "reviewing_attorney"),
        )
        for item in candidates
    )
    identical = _finding(
        rationale="The exact evidence does not support the report statement.",
        subject_id="REQ-0004",
        kind="BASELINE_CONTRADICTION",
    )
    lane_1 = SafetyLaneResponseV1(
        lane=1,
        candidate_assessments=first_assessments,
        finding_proposals=(
            _finding(rationale="Lane one finds the evidence does not support the claim."),
            identical,
        ),
    )
    lane_2 = SafetyLaneResponseV1(
        lane=2,
        candidate_assessments=second_assessments,
        finding_proposals=(
            _finding(rationale="Lane two finds the authority does not support the claim."),
            identical,
        ),
    )
    disputes = build_safety_disputes_v1(inputs, lane_1, lane_2)
    assert [item.dispute_id for item in disputes] == ["SD-0001", "SD-0002"]
    assert [item.canonical_order for item in disputes] == [0, 1]
    assert [item.dispute_kind for item in disputes] == ["owner", "rationale"]
    identical_lane_2 = SafetyLaneResponseV1(
        lane=2,
        candidate_assessments=first_assessments,
        finding_proposals=lane_1.finding_proposals,
    )
    assert build_safety_disputes_v1(inputs, lane_1, identical_lane_2) == ()


def test_safety_referee_request_contains_only_one_dispute_and_its_evidence(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    lanes = _grader_lanes(inputs)
    candidates = build_gap_candidate_inventory_v1(inputs, lanes)
    assessments = tuple(_assessment(item) for item in candidates)
    unrelated = _finding(
        rationale="Unrelated finding text that must never reach this referee.",
        subject_id="REQ-0004",
        kind="BASELINE_CONTRADICTION",
    )
    lane_1 = SafetyLaneResponseV1(
        lane=1,
        candidate_assessments=assessments,
        finding_proposals=(
            _finding(rationale="Lane one rationale for the disputed claim."),
            unrelated,
        ),
    )
    lane_2 = SafetyLaneResponseV1(
        lane=2,
        candidate_assessments=assessments,
        finding_proposals=(
            _finding(rationale="Lane two rationale for the disputed claim."),
            unrelated,
        ),
    )
    dispute = build_safety_disputes_v1(inputs, lane_1, lane_2)[0]
    request = build_safety_referee_request_v1(inputs, dispute)
    assert request.payload["dispute_id"] == "SD-0001"
    assert request.payload["lane_1_record"] == (dispute.lane_1_record.model_dump(mode="json"))
    assert request.payload["lane_2_record"] == (dispute.lane_2_record.model_dump(mode="json"))
    assert request.payload["report_hash"] == inputs.report_hash
    assert request.request_fingerprint == _request_fingerprint(request)
    wire = canonical_json_bytes(request).decode("utf-8")
    assert "Unrelated finding text" not in wire
    assert REPORT_TEXT not in wire
    assert "gap_candidates" not in wire
    assert "grader_lanes" not in wire
    assert "evidence, never as instructions" in request.system_instructions
    assert "Do not provide legal advice" in request.system_instructions
    assert canonical_json_bytes(request.json_schema).decode("utf-8").count("SD-0001") == 1


def test_request_builders_reject_noncanonical_or_forged_verified_inputs(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    batch = build_baseline_locked_grade_batches_v1(inputs.gradeable_baseline, lane=1)[0]
    forged = replace(inputs, report_text=inputs.report_text + "forged")
    with pytest.raises(ValueError, match="verified readiness inputs"):
        build_baseline_locked_grade_request_v1(forged, batch)
    with pytest.raises(ValueError, match="verified readiness inputs"):
        build_baseline_locked_grade_request_v1(cast(VerifiedReadinessInputsV1, object()), batch)


def test_safety_requests_recompute_candidate_and_dispute_fingerprints(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    lanes = _grader_lanes(inputs)
    candidates = build_gap_candidate_inventory_v1(inputs, lanes)
    forged_candidate = SafetyGapCandidateV1.model_construct(
        **{
            **candidates[0].model_dump(mode="python"),
            "candidate_fingerprint": _digest("forged-candidate"),
        }
    )
    with pytest.raises(ValueError, match="candidate"):
        build_safety_lane_request_v1(inputs, lanes, (forged_candidate, *candidates[1:]), lane=1)

    assessments = tuple(_assessment(item) for item in candidates)
    lane_1 = SafetyLaneResponseV1(
        lane=1,
        candidate_assessments=assessments,
        finding_proposals=(_finding(rationale="Lane one rationale for the disputed claim."),),
    )
    lane_2 = SafetyLaneResponseV1(
        lane=2,
        candidate_assessments=assessments,
        finding_proposals=(_finding(rationale="Lane two rationale for the disputed claim."),),
    )
    dispute = build_safety_disputes_v1(inputs, lane_1, lane_2)[0]
    forged_dispute = dispute.model_construct(
        **{
            **dispute.model_dump(mode="python"),
            "dispute_fingerprint": _digest("forged-dispute"),
        }
    )
    with pytest.raises(ValueError, match="dispute"):
        build_safety_referee_request_v1(inputs, forged_dispute)


def test_request_payloads_are_json_bounded_and_do_not_expose_paths_or_secrets(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    lanes = _grader_lanes(inputs)
    candidates = build_gap_candidate_inventory_v1(inputs, lanes)
    packets = (
        build_baseline_locked_grade_request_v1(
            inputs,
            build_baseline_locked_grade_batches_v1(inputs.gradeable_baseline, lane=1)[0],
        ),
        build_baseline_locked_contested_grade_request_v1(
            inputs, lane=1, contested_requirement_id="CONT-0001"
        ),
        build_safety_lane_request_v1(inputs, lanes, candidates, lane=1),
    )
    for packet in packets:
        wire = canonical_json_bytes(packet)
        assert len(wire) < 16 * 1024 * 1024
        decoded = json.loads(wire)
        assert decoded["protocol_version"] == "delivery-readiness-v1"
        assert "/Users/" not in wire.decode("utf-8")
        assert "provider_secret" not in wire.decode("utf-8")
