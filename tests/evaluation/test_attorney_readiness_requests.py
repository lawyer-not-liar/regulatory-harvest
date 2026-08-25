"""Controller-owned request packets for delivery-readiness-v1."""

from __future__ import annotations

import json
from dataclasses import asdict, replace
from pathlib import Path
from typing import cast

import pytest
from test_attorney_baseline_artifacts import _complete_graph
from test_attorney_baseline_projection import _resealed_context
from test_attorney_readiness_inputs import _make_verified_inputs

from regulatory_harvest.evaluation import attorney_readiness_requests as requests_module
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
    QualificationAdmissionCheckV1,
    QualificationAdmissionIssueV1,
    QualificationLanguageSourceV1,
    QualificationLanguageTreatmentV1,
    QualificationLimitsV1,
    QualificationReadinessBindingV1,
    QualificationReceiptReadinessV1,
    QualificationRequestedAuthorityV1,
    VerifiedReadinessInputsV1,
    build_verified_readiness_input_v1,
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
    build_readiness_compiler_contract_v1,
    build_safety_disputes_v1,
    build_safety_lane_request_v1,
    build_safety_referee_request_v1,
    readiness_compiler_contract_fingerprint_v1,
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


def _sealed_model(model_type: object, fingerprint_field: str, **values: object) -> object:
    provisional = model_type(  # type: ignore[operator]
        **values,
        **{fingerprint_field: _digest(f"provisional-{fingerprint_field}")},
    )
    descriptor = provisional.model_dump(mode="json", exclude={fingerprint_field})
    return model_type(  # type: ignore[operator]
        **descriptor,
        **{fingerprint_field: sha256_digest(canonical_json_bytes(descriptor))},
    )


def _reseal_model(value: object, fingerprint_field: str) -> object:
    descriptor = value.model_dump(  # type: ignore[union-attr]
        mode="json", exclude={fingerprint_field}
    )
    return type(value).model_validate(  # type: ignore[union-attr]
        {
            **descriptor,
            fingerprint_field: sha256_digest(canonical_json_bytes(descriptor)),
        }
    )


def _with_report(inputs: VerifiedReadinessInputsV1, report_text: str) -> VerifiedReadinessInputsV1:
    report_hash = sha256_digest(report_text.encode("utf-8"))
    validation = inputs.generation_validation.model_copy(update={"report_hash": report_hash})
    readiness = inputs.readiness_input.model_copy(
        update={
            "report_text": report_text,
            "report_hash": report_hash,
            "generation_validation": validation,
        }
    )
    return replace(
        inputs,
        readiness_input=readiness,
        report_text=report_text,
        report_hash=report_hash,
        generation_binding=replace(inputs.generation_binding, report_hash=report_hash),
        generation_validation=validation,
    )


def _with_clean_qualification(
    inputs: VerifiedReadinessInputsV1,
    *,
    declared_language_limit: str | None = None,
) -> VerifiedReadinessInputsV1:
    treatment = inputs.qualification_limits.language_treatments[0]
    limits = replace(
        inputs.qualification_limits,
        admission_checks=tuple(
            replace(item, satisfied=True) for item in inputs.qualification_limits.admission_checks
        ),
        admission_issues=(),
        receipt_readiness=QualificationReceiptReadinessV1(
            status="ADMITTED",
            issue_codes=(),
            rationale="All exact admission checks are satisfied.",
        ),
        language_treatments=(
            replace(
                treatment,
                limitation_status=(
                    "NOT_DECLARED" if declared_language_limit is None else "DECLARED"
                ),
                limitation_text=declared_language_limit,
            ),
        ),
    )
    return replace(inputs, qualification_limits=limits)


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
    qualification_limits = QualificationLimitsV1(
        case_schema_version="1.1",
        admission_status="qualified",
        qualification_readiness="ADMITTED",
        qualification_root=projection.baseline_input.qualification_root,
        qualification_receipt_fingerprint=(
            projection.baseline_input.qualification_receipt_fingerprint
        ),
        case_fingerprint=_digest("qualification-case"),
        source_record_fingerprint=projection.baseline_input.source_record_fingerprint,
        request_fingerprint=_digest("qualification-request"),
        judgment_fingerprint=_digest("qualification-judgment"),
        requested_authorities=tuple(
            QualificationRequestedAuthorityV1(
                authority_id=item.authority_id,
                title=item.title,
                jurisdiction=item.jurisdiction,
                authority_type=item.authority_type,
                source_ids=tuple(item.source_ids),
            )
            for item in projection.baseline_input.requested_authorities
        ),
        admission_checks=tuple(
            QualificationAdmissionCheckV1(
                code=cast(
                    object,
                    code,
                ),
                satisfied=code != "CURRENTNESS_EVIDENCE",
                material=True,
                rationale=(
                    "The source record does not establish currentness."
                    if code == "CURRENTNESS_EVIDENCE"
                    else f"The exact qualification evidence satisfies {code}."
                ),
                source_ids=(source.source_id,),
            )
            for code in (
                "AUTHORITY_ALIGNMENT",
                "OPERATIVE_TEXT",
                "CURRENTNESS_EVIDENCE",
                "LANGUAGE_RESOLUTION",
                "SOURCE_PARITY",
            )
        ),
        admission_issues=(
            QualificationAdmissionIssueV1(
                code="CURRENTNESS_REVIEW_REQUIRED",
                severity="warning",
                message="Currentness remains open for attorney review.",
                related_ids=(source.source_id,),
            ),
        ),
        receipt_readiness=QualificationReceiptReadinessV1(
            status="ADMITTED",
            issue_codes=("CURRENTNESS_REVIEW_REQUIRED",),
            rationale="The source record is admitted with a disclosed currentness issue.",
        ),
        language_treatments=(
            QualificationLanguageTreatmentV1(
                sources=(
                    QualificationLanguageSourceV1(
                        source_id=source.source_id,
                        content_hash=source.content_hash,
                        language=source.language,
                    ),
                ),
                method="Original-language review of the fictional source.",
                rationale="The retained source declares its language exactly.",
                limitation_status="NOT_DECLARED",
                limitation_text=None,
            ),
        ),
    )
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
        qualification_limits=qualification_limits,
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
        cast(
            BaselineLockedGradeFragmentV1,
            _sealed_model(
                BaselineLockedGradeFragmentV1,
                "fragment_fingerprint",
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
            ),
        )
        for batch_index, offset in enumerate(range(0, len(grades), 5), 1)
    )
    contest = cast(
        BaselineLockedContestedGradeV1,
        _sealed_model(
            BaselineLockedContestedGradeV1,
            "grade_fingerprint",
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
            ambiguity_disposition="acknowledged",
            rationale="Both sealed alternatives remain plausible.",
        ),
    )
    return cast(
        BaselineLockedGraderAggregateV1,
        _sealed_model(
            BaselineLockedGraderAggregateV1,
            "aggregate_fingerprint",
            lane=cast(int, lane),
            grade_target_fingerprint=inputs.readiness_input.grade_target_fingerprint,
            baseline_fingerprint=baseline_fingerprint,
            report_hash=inputs.report_hash,
            strict_equivalent_scoring_contract_fingerprint=scoring_fingerprint,
            ordinary_fragments=tuple(item.model_dump(mode="json") for item in fragments),
            contested_grades=(contest.model_dump(mode="json"),),
            requirement_grades=tuple(item.model_dump(mode="json") for item in grades),
        ),
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


def _all_met_grader_lanes(
    inputs: VerifiedReadinessInputsV1,
) -> tuple[BaselineLockedGraderAggregateV1, BaselineLockedGraderAggregateV1]:
    passage = next(line.strip() for line in inputs.report_text.splitlines() if line.strip())

    def one(lane: int) -> BaselineLockedGraderAggregateV1:
        bindings = {
            "lane": lane,
            "grade_target_fingerprint": inputs.readiness_input.grade_target_fingerprint,
            "baseline_fingerprint": inputs.gradeable_baseline.binding.baseline_fingerprint,
            "report_hash": inputs.report_hash,
            "strict_equivalent_scoring_contract_fingerprint": (
                inputs.readiness_input.strict_equivalent_scoring_contract_fingerprint
            ),
        }
        grades = tuple(
            RequirementGradeV2(
                requirement_id=item.requirement.requirement_id,
                disposition="met",
                report_passages=(passage,),
                rationale="The exact report passage supplies the treatment.",
                omission=None,
            )
            for item in inputs.gradeable_baseline.requirements
        )
        fragments = tuple(
            cast(
                BaselineLockedGradeFragmentV1,
                _sealed_model(
                    BaselineLockedGradeFragmentV1,
                    "fragment_fingerprint",
                    **bindings,
                    batch_ref=f"GB-{lane}-{ordinal:04d}",
                    requirement_grades=tuple(
                        grade.model_dump(mode="json") for grade in grades[offset : offset + 5]
                    ),
                    rationale="The exact controller batch was graded.",
                ),
            )
            for ordinal, offset in enumerate(range(0, len(grades), 5), 1)
        )
        contests = tuple(
            cast(
                BaselineLockedContestedGradeV1,
                _sealed_model(
                    BaselineLockedContestedGradeV1,
                    "grade_fingerprint",
                    **bindings,
                    contested_requirement_id=(item.contested_requirement.contested_requirement_id),
                    reviewer_alternative_disposition="met",
                    auditor_alternative_disposition="met",
                    reviewer_report_passages=(passage,),
                    auditor_report_passages=(passage,),
                    reviewer_rationale="The reviewer alternative is addressed.",
                    auditor_rationale="The auditor alternative is addressed.",
                    ambiguity_disposition="acknowledged",
                    rationale="The ambiguity is disclosed.",
                ),
            )
            for item in inputs.gradeable_baseline.contested_requirements
        )
        return cast(
            BaselineLockedGraderAggregateV1,
            _sealed_model(
                BaselineLockedGraderAggregateV1,
                "aggregate_fingerprint",
                **bindings,
                ordinary_fragments=tuple(item.model_dump(mode="json") for item in fragments),
                contested_grades=tuple(item.model_dump(mode="json") for item in contests),
                requirement_grades=tuple(item.model_dump(mode="json") for item in grades),
            ),
        )

    return one(1), one(2)


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


def _changed_assessment(
    assessment: SafetyGapAssessmentV1,
    **updates: object,
) -> SafetyGapAssessmentV1:
    raw = assessment.model_dump(mode="json")
    raw.update(cast(dict[str, object], json.loads(canonical_json_bytes(updates))))
    return SafetyGapAssessmentV1.model_validate(raw)


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


def test_contract_fingerprints_bind_public_v22_semantics_without_private_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
    assert strict["contested_sensitivity_reason_codes"] == (
        "BASELINE_EVIDENCE_INSUFFICIENT",
        "OUTCOME_SENSITIVE_BASELINE_DISPUTE",
    )
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
    assert build_readiness_compiler_contract_v1() == READINESS_COMPILER_CONTRACT_V1
    assert (
        readiness_compiler_contract_fingerprint_v1() == READINESS_COMPILER_CONTRACT_FINGERPRINT_V1
    )
    response_contracts = cast(
        dict[str, object], READINESS_COMPILER_CONTRACT_V1["response_contracts"]
    )
    assert set(response_contracts) == {
        "ordinary_grade",
        "contested_grade",
        "safety_lane",
        "safety_referee:blocker",
        "safety_referee:evidence_binding",
        "safety_referee:finding_existence",
        "safety_referee:follow_up",
        "safety_referee:owner",
        "safety_referee:rationale",
        "safety_referee:resolution_test",
        "safety_referee:visibility",
    }
    instructions = cast(dict[str, object], READINESS_COMPILER_CONTRACT_V1["instructions"])
    assert set(instructions) == set(response_contracts)
    assert READINESS_COMPILER_CONTRACT_FINGERPRINT_V1 != (
        READINESS_STRICT_EQUIVALENT_SCORING_FINGERPRINT_V1
    )
    with pytest.raises(TypeError):
        cast(dict[str, object], strict)["weighted_coverage_floor"] = 0.0
    with pytest.raises(TypeError):
        ordinary_contract = cast(dict[str, object], response_contracts["ordinary_grade"])
        cast(list[object], ordinary_contract["required"])[0] = "mutated"
    with pytest.raises(TypeError):
        cast(
            dict[str, object],
            cast(dict[str, object], response_contracts["ordinary_grade"])["properties"],
        )["mutated"] = True
    with pytest.raises(TypeError):
        dict.__setitem__(response_contracts, "mutated", True)

    monkeypatch.setattr(
        requests_module,
        "_ORDINARY_GRADE_SYSTEM",
        "mutated exact instruction",
    )
    assert (
        readiness_compiler_contract_fingerprint_v1() != READINESS_COMPILER_CONTRACT_FINGERPRINT_V1
    )


def test_compiler_descriptor_rejects_direct_base_class_mutation() -> None:
    descriptor = build_readiness_compiler_contract_v1()
    original = canonical_json_bytes(descriptor)
    response_contracts = cast(dict[str, object], descriptor["response_contracts"])
    ordinary = cast(dict[str, object], response_contracts["ordinary_grade"])
    required = cast(list[object], ordinary["required"])
    with pytest.raises(TypeError):
        dict.__setitem__(cast(dict[str, object], descriptor), "mutated", True)
    with pytest.raises(TypeError):
        list.__setitem__(required, 0, "mutated")
    object.__setattr__(descriptor, "data", {"mutated": True})
    descriptor.__dict__["data"] = {"mutated_again": True}
    assert canonical_json_bytes(descriptor) == original
    assert dict(descriptor) != {"mutated": True}
    assert dict(descriptor) != {"mutated_again": True}


def test_compiler_fingerprint_binds_safety_assessment_prefix_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = requests_module._scope_safety_schema

    def mutated(
        schema: dict[str, object],
        *,
        evidence_refs: object,
        allowlist: object,
    ) -> dict[str, object]:
        scoped = original(  # type: ignore[arg-type]
            schema,
            evidence_refs=evidence_refs,
            allowlist=allowlist,
        )
        if schema.get("title") == "SafetyGapAssessmentV1":
            return {**scoped, "description": "assessment-only schema mutation"}
        return scoped

    monkeypatch.setattr(requests_module, "_scope_safety_schema", mutated)
    assert (
        readiness_compiler_contract_fingerprint_v1() != READINESS_COMPILER_CONTRACT_FINGERPRINT_V1
    )


@pytest.mark.parametrize(
    "factory_name",
    (
        "_grade_response_schema_for_ids",
        "_contested_response_schema",
        "_safety_response_schema",
        "_referee_response_schema",
    ),
)
def test_compiler_fingerprint_changes_with_each_actual_schema_factory(
    monkeypatch: pytest.MonkeyPatch,
    factory_name: str,
) -> None:
    original = getattr(requests_module, factory_name)

    def mutated(*args: object) -> dict[str, object]:
        schema = original(*args)
        return {**schema, "description": "mutation-sensitive schema marker"}

    monkeypatch.setattr(requests_module, factory_name, mutated)
    assert (
        readiness_compiler_contract_fingerprint_v1() != READINESS_COMPILER_CONTRACT_FINGERPRINT_V1
    )


@pytest.mark.parametrize(
    "instruction_name",
    (
        "_ORDINARY_GRADE_SYSTEM",
        "_CONTESTED_GRADE_SYSTEM",
        "_SAFETY_SYSTEM",
    ),
)
def test_compiler_fingerprint_changes_with_each_exact_operation_instruction(
    monkeypatch: pytest.MonkeyPatch,
    instruction_name: str,
) -> None:
    monkeypatch.setattr(requests_module, instruction_name, "mutated exact instruction")
    assert (
        readiness_compiler_contract_fingerprint_v1() != READINESS_COMPILER_CONTRACT_FINGERPRINT_V1
    )


def test_compiler_fingerprint_changes_with_referee_instruction_factory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        requests_module,
        "_referee_system",
        lambda kind: f"mutated exact {kind} referee instruction",
    )
    assert (
        readiness_compiler_contract_fingerprint_v1() != READINESS_COMPILER_CONTRACT_FINGERPRINT_V1
    )


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
            "acknowledged",
            "overstated",
            "omitted",
            "uncertain",
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


def test_prerequisites_come_only_from_explicit_qualification_evidence(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    lanes = _grader_lanes(inputs)
    clean_inputs = _with_clean_qualification(inputs)
    clean = build_gap_candidate_inventory_v1(clean_inputs, lanes)
    assert all(item.origin.value != "prerequisite" for item in clean)

    declared_inputs = _with_clean_qualification(
        inputs,
        declared_language_limit="The qualification records a material translation limit.",
    )
    declared = build_gap_candidate_inventory_v1(declared_inputs, lanes)
    prerequisites = [item for item in declared if item.origin.value == "prerequisite"]
    assert [(item.subject_id, item.evidence_refs) for item in prerequisites] == [
        (
            "LANGUAGE:rule-1",
            ("SOURCE-000001", "PREREQUISITE-LANGUAGE-rule-1"),
        )
    ]
    request = build_safety_lane_request_v1(declared_inputs, lanes, declared, lane=1)
    handles = {
        cast(str, item["evidence_ref"]): item
        for item in cast(list[dict[str, object]], request.payload["evidence_handles"])
    }
    assert handles["PREREQUISITE-LANGUAGE-rule-1"]["evidence"] == json.loads(
        canonical_json_bytes(asdict(declared_inputs.qualification_limits.language_treatments[0]))
    )
    assert "PREREQUISITE-CURRENTNESS-rule-1" not in handles
    assert "PREREQUISITE-COMPLETENESS-rule-1" not in handles


def test_non_english_not_declared_treatment_does_not_invent_language_limit(
    tmp_path: Path,
) -> None:
    fixture = _make_verified_inputs(tmp_path, language="fr", limitations=None)
    admitted = build_verified_readiness_input_v1(**fixture.without_history())
    assert admitted.qualification_limits.language_treatments[0].limitation_status == (
        "NOT_DECLARED"
    )
    assert admitted.qualification_limits.language_treatments[0].sources[0].language == "fr"
    candidates = build_gap_candidate_inventory_v1(
        admitted,
        _all_met_grader_lanes(admitted),
    )
    assert all(item.subject_id != "LANGUAGE:rule-1" for item in candidates)


@pytest.mark.parametrize(
    "unsafe_rationale",
    (
        "Private path /Users/client/secret.txt",
        REPORT_TEXT,
    ),
)
def test_qualification_public_text_is_rechecked_before_any_request(
    inputs: VerifiedReadinessInputsV1,
    unsafe_rationale: str,
) -> None:
    first_check = replace(
        inputs.qualification_limits.admission_checks[0],
        rationale=unsafe_rationale,
    )
    forged = replace(
        inputs,
        qualification_limits=replace(
            inputs.qualification_limits,
            admission_checks=(
                first_check,
                *inputs.qualification_limits.admission_checks[1:],
            ),
        ),
    )
    batch = build_baseline_locked_grade_batches_v1(inputs.gradeable_baseline, lane=1)[0]
    with pytest.raises(ValueError, match="verified readiness inputs"):
        build_baseline_locked_grade_request_v1(forged, batch)


def test_qualification_public_text_cannot_copy_normalized_source_bytes(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    first_check = replace(
        inputs.qualification_limits.admission_checks[0],
        rationale=inputs.source_record[0].normalized_text,
    )
    forged = replace(
        inputs,
        qualification_limits=replace(
            inputs.qualification_limits,
            admission_checks=(
                first_check,
                *inputs.qualification_limits.admission_checks[1:],
            ),
        ),
    )
    batch = build_baseline_locked_grade_batches_v1(inputs.gradeable_baseline, lane=1)[0]
    with pytest.raises(ValueError, match="verified readiness inputs"):
        build_baseline_locked_grade_request_v1(forged, batch)


def test_unsatisfied_source_scoped_check_cannot_invent_source_bindings(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    checks = tuple(
        replace(item, source_ids=()) if item.code == "CURRENTNESS_EVIDENCE" else item
        for item in inputs.qualification_limits.admission_checks
    )
    forged = replace(
        inputs,
        qualification_limits=replace(inputs.qualification_limits, admission_checks=checks),
    )
    with pytest.raises(ValueError, match="verified readiness inputs"):
        build_gap_candidate_inventory_v1(forged, _grader_lanes(inputs))


@pytest.mark.parametrize(
    ("field_name", "unsafe_value"),
    (
        ("capture_fingerprint", "not-a-hash"),
        ("request_fingerprint", "not-a-hash"),
        ("response_fingerprint", "not-a-hash"),
        ("source_hashes", (("rule-1", "not-a-hash"),)),
        ("client_facts_hash", "Private /Users/client/facts.txt"),
        (
            "generator_artifact_hashes",
            (("generator", _digest("generator")), ("generator", _digest("generator"))),
        ),
        (
            "generator_artifact_hashes",
            (("/Users/client/private-generator.py", _digest("generator")),),
        ),
    ),
)
def test_generation_binding_is_strictly_reverified_before_any_request(
    inputs: VerifiedReadinessInputsV1,
    field_name: str,
    unsafe_value: object,
) -> None:
    forged = replace(
        inputs,
        generation_binding=replace(
            inputs.generation_binding,
            **{field_name: unsafe_value},
        ),
    )
    batch = build_baseline_locked_grade_batches_v1(inputs.gradeable_baseline, lane=1)[0]
    with pytest.raises(ValueError, match="verified readiness inputs"):
        build_baseline_locked_grade_request_v1(forged, batch)


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
    assert first.payload["qualification_limits"] == json.loads(
        canonical_json_bytes(asdict(historical_inputs.qualification_limits))
    )
    qualification = cast(dict[str, object], first.payload["qualification_limits"])
    assert qualification["admission_checks"] == [
        json.loads(canonical_json_bytes(asdict(item)))
        for item in historical_inputs.qualification_limits.admission_checks
    ]
    assert qualification["admission_issues"] == [
        json.loads(canonical_json_bytes(asdict(item)))
        for item in historical_inputs.qualification_limits.admission_issues
    ]
    assert qualification["receipt_readiness"] == json.loads(
        canonical_json_bytes(asdict(historical_inputs.qualification_limits.receipt_readiness))
    )
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
    assert disputes[0].subject_identity == "candidate:GC-0001"
    assert disputes[0].lane_1_choice == {"owner_role": "reviewing_attorney"}
    assert disputes[0].lane_2_choice == {"owner_role": "outside_counsel"}
    assert disputes[1].subject_identity == ("finding:MATERIAL_UNSUPPORTED_ASSERTION:REQ-0003")
    for dispute in disputes:
        expected = dispute.model_dump(mode="json", exclude={"dispute_fingerprint"})
        assert dispute.dispute_fingerprint == sha256_digest(canonical_json_bytes(expected))
    identical_lane_2 = SafetyLaneResponseV1(
        lane=2,
        candidate_assessments=first_assessments,
        finding_proposals=lane_1.finding_proposals,
    )
    assert build_safety_disputes_v1(inputs, lane_1, identical_lane_2) == ()


@pytest.mark.parametrize(
    ("kind", "updates", "choice_keys"),
    (
        (
            "rationale",
            {"why_unresolved": "Lane two gives a different scoped rationale."},
            {
                "shortfall_description",
                "rationale_kind",
                "why_unresolved",
                "why_it_matters",
            },
        ),
        (
            "evidence_binding",
            {"evidence_refs": ("SOURCE-000001",)},
            {"evidence_refs", "report_passages"},
        ),
        (
            "visibility",
            {"visibility": "visible"},
            {"disclosure_location", "visibility"},
        ),
        ("blocker", {"blocking_code": "SOURCE_REVIEW_REQUIRED"}, {"blocking_code"}),
        ("follow_up", {"follow_up_code": "CONFIRM_CURRENTNESS"}, {"follow_up_code"}),
        ("owner", {"owner_role": "outside_counsel"}, {"owner_role"}),
        (
            "resolution_test",
            {"resolution_test": "Apply a different exact resolution test."},
            {"resolution_test"},
        ),
    ),
)
def test_each_nonexistence_dispute_is_dimension_only(
    inputs: VerifiedReadinessInputsV1,
    kind: str,
    updates: dict[str, object],
    choice_keys: set[str],
) -> None:
    candidates = build_gap_candidate_inventory_v1(inputs, _grader_lanes(inputs))
    assessments = tuple(_assessment(item) for item in candidates)
    changed = (_changed_assessment(assessments[0], **updates), *assessments[1:])
    lane_1 = SafetyLaneResponseV1(
        lane=1,
        candidate_assessments=assessments,
        finding_proposals=(),
    )
    lane_2 = SafetyLaneResponseV1(
        lane=2,
        candidate_assessments=changed,
        finding_proposals=(),
    )
    disputes = build_safety_disputes_v1(inputs, lane_1, lane_2)
    assert len(disputes) == 1
    dispute = disputes[0]
    assert dispute.dispute_kind == kind
    assert set(cast(dict[str, object], dispute.lane_1_choice)) == choice_keys
    assert set(cast(dict[str, object], dispute.lane_2_choice)) == choice_keys
    assert dispute.subject_identity == "candidate:GC-0001"
    assert dispute.evidence_refs == tuple(
        dict.fromkeys((*assessments[0].evidence_refs, *changed[0].evidence_refs))
    )
    assert dispute.report_passages == tuple(
        dict.fromkeys((*assessments[0].report_passages, *changed[0].report_passages))
    )


def test_finding_existence_dispute_contains_only_presence_choice(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    candidates = build_gap_candidate_inventory_v1(inputs, _grader_lanes(inputs))
    assessments = tuple(_assessment(item) for item in candidates)
    finding = _finding(rationale="Only lane one proposes this exact finding.")
    lane_1 = SafetyLaneResponseV1(
        lane=1,
        candidate_assessments=assessments,
        finding_proposals=(finding,),
    )
    lane_2 = SafetyLaneResponseV1(
        lane=2,
        candidate_assessments=assessments,
        finding_proposals=(),
    )
    dispute = build_safety_disputes_v1(inputs, lane_1, lane_2)[0]
    assert dispute.dispute_kind == "finding_existence"
    assert dispute.subject_identity == "finding:MATERIAL_UNSUPPORTED_ASSERTION:REQ-0003"
    assert dispute.lane_1_choice == {"present": True}
    assert dispute.lane_2_choice is None
    assert dispute.evidence_refs == finding.evidence_refs
    assert dispute.report_passages == finding.report_passages


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
    assert request.payload["subject_identity"] == dispute.subject_identity
    assert request.payload["lane_1_choice"] == dispute.lane_1_choice
    assert request.payload["lane_2_choice"] == dispute.lane_2_choice
    assert request.payload["evidence_refs"] == list(dispute.evidence_refs)
    assert request.payload["disputed_report_passages"] == list(dispute.report_passages)
    assert request.payload["report_hash"] == inputs.report_hash
    assert request.request_fingerprint == _request_fingerprint(request)
    wire = canonical_json_bytes(request).decode("utf-8")
    assert "Unrelated finding text" not in wire
    assert REPORT_TEXT not in wire
    assert "gap_candidates" not in wire
    assert "grader_lanes" not in wire
    assert "lane_1_record" not in wire
    assert "lane_2_record" not in wire
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


def test_safety_request_resolves_every_candidate_ref_against_controller_handles(
    inputs: VerifiedReadinessInputsV1,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lanes = _grader_lanes(inputs)
    candidates = build_gap_candidate_inventory_v1(inputs, lanes)
    missing_ref = candidates[0].evidence_refs[0]
    original = requests_module._evidence_handles

    def missing_handle(value: VerifiedReadinessInputsV1) -> list[dict[str, object]]:
        return [item for item in original(value) if item["evidence_ref"] != missing_ref]

    monkeypatch.setattr(requests_module, "_evidence_handles", missing_handle)
    with pytest.raises(ValueError, match="candidate evidence"):
        build_safety_lane_request_v1(inputs, lanes, candidates, lane=1)


def test_dispute_fingerprint_independently_binds_id_and_canonical_order(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    lanes = _grader_lanes(inputs)
    candidates = build_gap_candidate_inventory_v1(inputs, lanes)
    assessments = tuple(_assessment(item) for item in candidates)
    lane_1 = SafetyLaneResponseV1(
        lane=1,
        candidate_assessments=assessments,
        finding_proposals=(_finding(rationale="Lane one scoped rationale."),),
    )
    lane_2 = SafetyLaneResponseV1(
        lane=2,
        candidate_assessments=assessments,
        finding_proposals=(_finding(rationale="Lane two scoped rationale."),),
    )
    dispute = build_safety_disputes_v1(inputs, lane_1, lane_2)[0]
    raw = dispute.model_dump(mode="json")
    raw.update({"dispute_id": "SD-0002", "canonical_order": 1})
    stale = type(dispute).model_validate(raw)
    with pytest.raises(ValueError, match="dispute"):
        build_safety_referee_request_v1(inputs, stale)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("evidence_refs", ["SOURCE-999999"]),
        ("report_passages", ["Not an exact report passage."]),
    ),
)
def test_referee_rejects_resealed_unknown_controller_scope(
    inputs: VerifiedReadinessInputsV1,
    field: str,
    value: list[str],
) -> None:
    lanes = _grader_lanes(inputs)
    candidates = build_gap_candidate_inventory_v1(inputs, lanes)
    assessments = tuple(_assessment(item) for item in candidates)
    lane_1 = SafetyLaneResponseV1(
        lane=1,
        candidate_assessments=assessments,
        finding_proposals=(_finding(rationale="Lane one scoped rationale."),),
    )
    lane_2 = SafetyLaneResponseV1(
        lane=2,
        candidate_assessments=assessments,
        finding_proposals=(_finding(rationale="Lane two scoped rationale."),),
    )
    dispute = build_safety_disputes_v1(inputs, lane_1, lane_2)[0]
    raw = dispute.model_dump(mode="json", exclude={"dispute_fingerprint"})
    raw[field] = value
    raw["dispute_fingerprint"] = sha256_digest(canonical_json_bytes(raw))
    forged = type(dispute).model_validate(raw)
    with pytest.raises(ValueError, match="dispute"):
        build_safety_referee_request_v1(inputs, forged)


def test_controller_recomputes_every_grader_fingerprint_before_use(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    first, second = _grader_lanes(inputs)

    with pytest.raises(ValueError, match="grader lanes"):
        build_gap_candidate_inventory_v1(inputs, (second, first))

    fragment = first.ordinary_fragments[0].model_copy(
        update={"rationale": "A stale fragment fingerprint must fail closed."}
    )
    fragment_outer = first.model_copy(
        update={"ordinary_fragments": (fragment, *first.ordinary_fragments[1:])}
    )
    fragment_outer = cast(
        BaselineLockedGraderAggregateV1,
        _reseal_model(fragment_outer, "aggregate_fingerprint"),
    )
    with pytest.raises(ValueError, match="grader lanes"):
        build_gap_candidate_inventory_v1(inputs, (fragment_outer, second))

    contested = first.contested_grades[0].model_copy(
        update={"rationale": "A stale contested fingerprint must fail closed."}
    )
    contested_outer = first.model_copy(update={"contested_grades": (contested,)})
    contested_outer = cast(
        BaselineLockedGraderAggregateV1,
        _reseal_model(contested_outer, "aggregate_fingerprint"),
    )
    with pytest.raises(ValueError, match="grader lanes"):
        build_gap_candidate_inventory_v1(inputs, (contested_outer, second))

    aggregate = first.model_copy(update={"aggregate_fingerprint": _digest("stale-aggregate")})
    with pytest.raises(ValueError, match="grader lanes"):
        build_gap_candidate_inventory_v1(inputs, (aggregate, second))


def test_report_allowlist_rejects_ambiguous_excessive_and_unknown_passages(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    batch = build_baseline_locked_grade_batches_v1(inputs.gradeable_baseline, lane=1)[0]
    duplicate = _with_report(inputs, "# Report\n\nRepeated passage.\n\nRepeated passage.\n")
    with pytest.raises(ValueError, match="ambiguous"):
        build_baseline_locked_grade_request_v1(duplicate, batch)

    excessive_text = "\n".join(f"unique passage {index}" for index in range(641))
    excessive = _with_report(inputs, excessive_text)
    with pytest.raises(ValueError, match="allowlist exceeds limit"):
        build_baseline_locked_grade_request_v1(excessive, batch)

    first, second = _grader_lanes(inputs)
    changed_grade_raw = first.requirement_grades[0].model_dump(mode="json")
    changed_grade_raw["report_passages"] = ["Not an exact report passage."]
    changed_grade = RequirementGradeV2.model_validate(changed_grade_raw)
    changed_fragment = first.ordinary_fragments[0].model_copy(
        update={
            "requirement_grades": (
                changed_grade,
                *first.ordinary_fragments[0].requirement_grades[1:],
            )
        }
    )
    changed_fragment = cast(
        BaselineLockedGradeFragmentV1,
        _reseal_model(changed_fragment, "fragment_fingerprint"),
    )
    changed_aggregate = first.model_copy(
        update={
            "ordinary_fragments": (changed_fragment, *first.ordinary_fragments[1:]),
            "requirement_grades": (
                changed_grade,
                *first.requirement_grades[1:],
            ),
        }
    )
    changed_aggregate = cast(
        BaselineLockedGraderAggregateV1,
        _reseal_model(changed_aggregate, "aggregate_fingerprint"),
    )
    with pytest.raises(ValueError, match="grader lanes"):
        build_gap_candidate_inventory_v1(inputs, (changed_aggregate, second))

    changed_contest_raw = first.contested_grades[0].model_dump(
        mode="json", exclude={"grade_fingerprint"}
    )
    changed_contest_raw["reviewer_report_passages"] = ["Not an exact contested report passage."]
    changed_contest_raw["grade_fingerprint"] = sha256_digest(
        canonical_json_bytes(changed_contest_raw)
    )
    changed_contest = BaselineLockedContestedGradeV1.model_validate(changed_contest_raw)
    contested_aggregate = first.model_copy(update={"contested_grades": (changed_contest,)})
    contested_aggregate = cast(
        BaselineLockedGraderAggregateV1,
        _reseal_model(contested_aggregate, "aggregate_fingerprint"),
    )
    with pytest.raises(ValueError, match="grader lanes"):
        build_gap_candidate_inventory_v1(inputs, (contested_aggregate, second))


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("evidence_refs", ("SOURCE-999999",)),
        ("report_passages", ("Not an exact report passage.",)),
    ),
)
def test_safety_lanes_reject_unknown_controller_scope_before_dispute(
    inputs: VerifiedReadinessInputsV1,
    field: str,
    value: tuple[str, ...],
) -> None:
    lanes = _grader_lanes(inputs)
    candidates = build_gap_candidate_inventory_v1(inputs, lanes)
    assessments = list(_assessment(item) for item in candidates)
    assessment_raw = assessments[0].model_dump(mode="json")
    assessment_raw[field] = list(value)
    assessments[0] = SafetyGapAssessmentV1.model_validate(assessment_raw)
    lane_1 = SafetyLaneResponseV1(
        lane=1,
        candidate_assessments=tuple(assessments),
        finding_proposals=(),
    )
    lane_2 = SafetyLaneResponseV1(
        lane=2,
        candidate_assessments=tuple(_assessment(item) for item in candidates),
        finding_proposals=(),
    )
    with pytest.raises(ValueError, match="safety lane"):
        build_safety_disputes_v1(inputs, lane_1, lane_2)


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
