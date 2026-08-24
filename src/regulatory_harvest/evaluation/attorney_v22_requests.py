"""Controller-issued Protocol 2.2 evaluator requests and contract binding."""
# ruff: noqa: E501

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Literal, cast

from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from .attorney_admission import _validate_envelope_binding, build_source_record
from .attorney_models import CaseEnvelope
from .attorney_v22_drafts import (
    _ENUM_ALIASES,
    _ContestedGradeDraftV22,
    _OrdinaryGradeDraftV22,
    _RefereeDraftV22,
    _SourceAuditDraftV22,
    _SourceReviewDraftV22,
)
from .attorney_v22_models import (
    AcceptedSourceAuditFragmentV22,
    AcceptedSourceReviewFragmentV22,
    CanonicalBaselineV22,
    ContestedGradeFragmentV22,
    ContestedRequirementV22,
    EvaluatorOperationV22,
    EvaluatorRequestV22,
    OrdinaryGradeBatchV22,
    OrdinaryGradeFragmentV22,
    RefereeDecisionV22,
    RefereeDisputeV22,
    RubricV22,
    SourceAuditFragmentV22,
    SourceReviewAggregateV22,
    SourceReviewFragmentV22,
    _strict_fragment_ordinal_v22,
    _strict_grade_coordinate_v22,
    _strict_rehydrate_v22,
    _strict_source_context_v22,
)

_INNER = " Return only the inner payload as one canonical JSON object conforming exactly to json_schema. Do not author the outer response envelope; the controller supplies operation, request_fingerprint, provider_name, model_name, judge_isolation, and the outer schema_version."
_EVIDENCE_HANDLE_RULE = (
    "Select only controller-issued evidence_handle values from the evidence_handles "
    "inventory. Each handle resolves immutably to the complete frozen normalized_text "
    "of exactly one source."
)
_AUDIT_SHAPE_RULE = (
    " Concern shapes are fixed: omission requires no target and a correction; "
    "ambiguity requires a target and no correction; incorrect_statement, "
    "incorrect_evidence, and incorrect_relationship each require both a target and "
    "a correction."
)
_GRADE_ORDINAL_RULE = (
    " Return exactly one grade for each allowed ordinal. The ordinal is the "
    "1-based position of the requirement in the supplied requirements array."
)
_INSTRUCTIONS = {
    EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT: "Review the supplied frozen source record and accepted inventory. Identify only new source-grounded semantic proposals.",
    EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT: "Audit the supplied source record and controller-indexed proposal inventory. Identify only new source-grounded concerns.",
    EvaluatorOperationV22.SOURCE_REFEREE_FRAGMENT: "Resolve one supplied material dispute using only controller-resolved source evidence.",
    EvaluatorOperationV22.ORDINARY_GRADE_FRAGMENT: "Grade only the supplied canonical requirement subset against the supplied report and source context.",
    EvaluatorOperationV22.CONTESTED_GRADE_FRAGMENT: "Grade both supplied alternatives for exactly one contested requirement against the supplied report and source context.",
}


def _schema_hash(value: object) -> str:
    return sha256_digest(canonical_json_bytes(value))


_SOURCE_REVIEW_DRAFT_SCHEMA_V22 = _SourceReviewDraftV22.model_json_schema()
_SOURCE_AUDIT_DRAFT_SCHEMA_V22 = _SourceAuditDraftV22.model_json_schema()


COMPILER_CONTRACT_V22: dict[str, object] = {
    "protocol": "2.2",
    "operations": [item.value for item in EvaluatorOperationV22],
    "strict_schema_hashes": {
        "source_review": _schema_hash(SourceReviewFragmentV22.model_json_schema()),
        "source_audit": _schema_hash(SourceAuditFragmentV22.model_json_schema()),
        "referee": _schema_hash(RefereeDecisionV22.model_json_schema()),
        "ordinary_grade": _schema_hash(OrdinaryGradeFragmentV22.model_json_schema()),
        "contested_grade": _schema_hash(ContestedGradeFragmentV22.model_json_schema()),
        "rubric": _schema_hash(RubricV22.model_json_schema()),
    },
    "draft_schema_hashes": {
        "source_review": _schema_hash(_SOURCE_REVIEW_DRAFT_SCHEMA_V22),
        "source_audit": _schema_hash(_SOURCE_AUDIT_DRAFT_SCHEMA_V22),
        "referee": _schema_hash(_RefereeDraftV22.model_json_schema()),
        "ordinary_grade": _schema_hash(_OrdinaryGradeDraftV22.model_json_schema()),
        "contested_grade": _schema_hash(_ContestedGradeDraftV22.model_json_schema()),
    },
    "enum_aliases": {key: sorted(values) for key, values in sorted(_ENUM_ALIASES.items())},
    "evidence_normalization_version": "source-whitespace-unique-v1",
    "fragment_maximum": 5,
    "fragments_per_operation_maximum": 128,
    "items_per_operation_maximum": 640,
    "request_contract_version": "self-describing-reference-constraints-v2",
    "ordering_version": "controller-fragment-order-v1",
    "compiler_version": "semantic-compiler-v2.2",
    "aggregate_version": "fragment-aggregate-v2.2",
    "rubric_version": "attorney-eval-v2.2",
}


def compiler_contract_fingerprint_v22(contract: object) -> str:
    return sha256_digest(canonical_json_bytes(contract))


COMPILER_CONTRACT_FINGERPRINT_V22 = compiler_contract_fingerprint_v22(COMPILER_CONTRACT_V22)


def _snapshot(value: object, location: str) -> dict[str, object]:
    try:
        result = json.loads(canonical_json_bytes(value))
    except (TypeError, ValueError, RecursionError) as error:
        raise ValueError(f"{location} is invalid") from error
    if type(result) is not dict:
        raise ValueError(f"{location} must be an object")
    return cast(dict[str, object], result)


def _fingerprint(request: EvaluatorRequestV22) -> str:
    digest = hashlib.sha256(
        canonical_json_bytes(request.model_dump(mode="json", exclude={"request_fingerprint"}))
    )
    return digest.hexdigest()


def _new_request_v22(
    operation: EvaluatorOperationV22,
    *,
    json_schema: dict[str, object],
    payload: dict[str, object],
    safe_metadata: dict[str, str],
    system_instructions: str | None = None,
) -> EvaluatorRequestV22:
    provisional = EvaluatorRequestV22(
        schema_version="2.2",
        operation=operation,
        request_fingerprint="0" * 64,
        system_instructions=system_instructions or (_INSTRUCTIONS[operation] + _INNER),
        json_schema=_snapshot(json_schema, "schema"),
        payload=_snapshot(payload, "payload"),
        safe_metadata={
            **safe_metadata,
            "compiler_contract_fingerprint": COMPILER_CONTRACT_FINGERPRINT_V22,
        },
    )
    # Legitimate post-validation conversion: the strict provisional request is
    # serialized only to replace its controller-owned fingerprint.
    raw = provisional.model_dump(mode="json")
    raw["request_fingerprint"] = _fingerprint(provisional)
    return _strict_rehydrate_v22(
        EvaluatorRequestV22,
        raw,
        location="evaluator request",
    )


def _ordinary_grade_request_contract_v22(
    requirement_count: int,
) -> tuple[dict[str, object], str]:
    if not 1 <= requirement_count <= 5:
        raise ValueError("ordinary-grade requirement inventory is invalid")
    schema = _snapshot(
        _OrdinaryGradeDraftV22.model_json_schema(), "ordinary-grade draft schema"
    )
    definitions = cast(dict[str, object], schema["$defs"])
    grade = cast(dict[str, object], definitions["_RequirementGradeDraftV22"])
    grade_properties = cast(dict[str, object], grade["properties"])
    ordinal = cast(dict[str, object], grade_properties["requirement_ordinal"])
    allowed = list(range(1, requirement_count + 1))
    ordinal["enum"] = allowed
    properties = cast(dict[str, object], schema["properties"])
    grades = cast(dict[str, object], properties["requirement_grades"])
    grades["minItems"] = requirement_count
    grades["maxItems"] = requirement_count
    encoded = json.dumps(allowed, separators=(",", ":"))
    instructions = (
        _INSTRUCTIONS[EvaluatorOperationV22.ORDINARY_GRADE_FRAGMENT]
        + f" Allowed requirement_ordinal values: {encoded}."
        + _GRADE_ORDINAL_RULE
        + _INNER
    )
    return schema, instructions


@dataclass(frozen=True)
class _VerifiedSourceRequestContextV22:
    envelope: CaseEnvelope
    source_record_json: bytes
    source_record_fingerprint: str
    safe_metadata: tuple[tuple[str, str], ...]


def _verified_source_request_context_v22(
    envelope: CaseEnvelope,
) -> _VerifiedSourceRequestContextV22:
    try:
        checked = _strict_rehydrate_v22(
            CaseEnvelope, envelope, location="frozen case envelope"
        )
        _validate_envelope_binding(checked)
    except Exception as error:
        raise ValueError("frozen case envelope is invalid") from error
    record = _snapshot(build_source_record(checked.case), "source record")
    record_json = canonical_json_bytes(record)
    fingerprint = sha256_digest(record_json)
    return _VerifiedSourceRequestContextV22(
        envelope=checked,
        source_record_json=record_json,
        source_record_fingerprint=fingerprint,
        safe_metadata=(
            ("record_scope", "source-only"),
            ("case_fingerprint", checked.case_fingerprint),
            ("source_record_fingerprint", fingerprint),
        ),
    )


def _context_source_record_v22(
    context: _VerifiedSourceRequestContextV22,
) -> dict[str, object]:
    return cast(dict[str, object], json.loads(context.source_record_json))


def _context_source_metadata_v22(
    context: _VerifiedSourceRequestContextV22,
) -> dict[str, str]:
    return dict(context.safe_metadata)


def _source_ids_v22(source_record: dict[str, object]) -> list[str]:
    sources = cast(list[dict[str, object]], source_record["sources"])
    return [cast(str, source["source_id"]) for source in sources]


def _source_evidence_handles_v22(
    source_record: dict[str, object],
) -> list[dict[str, str]]:
    return [
        {"evidence_handle": f"SOURCE-{ordinal:06d}", "source_id": source_id}
        for ordinal, source_id in enumerate(_source_ids_v22(source_record), 1)
    ]


def _source_fragment_contract_v22(
    operation: EvaluatorOperationV22,
    *,
    source_record: dict[str, object],
    proposal_count: int,
) -> tuple[dict[str, object], str]:
    if operation is EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT:
        schema = _snapshot(_SOURCE_REVIEW_DRAFT_SCHEMA_V22, "schema")
    elif operation is EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT:
        schema = _snapshot(_SOURCE_AUDIT_DRAFT_SCHEMA_V22, "schema")
    else:  # pragma: no cover - private helper has two fixed call sites
        raise ValueError("source-fragment operation is invalid")
    definitions = cast(dict[str, dict[str, object]], schema["$defs"])
    handles = _source_evidence_handles_v22(source_record)
    handle_values = [item["evidence_handle"] for item in handles]
    handle = cast(
        dict[str, dict[str, object]],
        definitions["_EvidenceHandleDraftV22"]["properties"],
    )
    handle_field = handle["evidence_handle"]
    handle_field["enum"] = handle_values

    proposal = cast(
        dict[str, dict[str, object]], definitions["_ProposalDraftV22"]["properties"]
    )
    proposal_passages = proposal["passages"]
    proposal_passages["items"] = {
        "$ref": "#/$defs/_EvidenceHandleDraftV22"
    }
    concern: dict[str, dict[str, object]] | None = None
    if "_AuditConcernDraftV22" in definitions:
        concern = cast(
            dict[str, dict[str, object]],
            definitions["_AuditConcernDraftV22"]["properties"],
        )
        concern_passages = concern["passages"]
        concern_passages["items"] = {
            "$ref": "#/$defs/_EvidenceHandleDraftV22"
        }
    if proposal_count == 0:
        proposal["dependency"] = {"default": None, "type": "null"}
    else:
        dependency = cast(
            dict[str, dict[str, object]],
            definitions["_DependencyDraftV22"]["properties"],
        )
        dependency_target_schema = dependency["target_ordinal"]
        dependency_target_schema["maximum"] = proposal_count

    handle_list = json.dumps(handle_values, ensure_ascii=False, separators=(",", ":"))
    instructions = (
        _INSTRUCTIONS[operation]
        + f" Allowed evidence_handle values: {handle_list}. {_EVIDENCE_HANDLE_RULE}"
    )
    if operation is EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT:
        if proposal_count == 0:
            instructions += (
                " No accepted proposal ordinals exist; dependency must be null."
            )
        else:
            instructions += (
                " Allowed dependency target_ordinal values: 1 through "
                f"{proposal_count}."
            )
    else:
        if concern is None:  # pragma: no cover - schema provenance invariant
            raise ValueError("source-audit schema is invalid")
        if proposal_count == 0:
            concern["target_proposal_ordinal"] = {"default": None, "type": "null"}
            instructions += (
                " No target proposal ordinals exist; target_proposal_ordinal must be "
                "null and correction dependencies must be null."
            )
        else:
            target = cast(
                list[dict[str, object]],
                concern["target_proposal_ordinal"]["anyOf"],
            )[0]
            target["maximum"] = proposal_count
            instructions += f" Allowed target proposal ordinals: 1 through {proposal_count}."
            instructions += (
                " Allowed correction dependency target_ordinal values: 1 through "
                f"{proposal_count}."
            )
        instructions += _AUDIT_SHAPE_RULE
    return schema, instructions + _INNER


def _frozen_source_record_v22(envelope: CaseEnvelope) -> tuple[dict[str, object], str]:
    context = _verified_source_request_context_v22(envelope)
    return _context_source_record_v22(context), context.source_record_fingerprint


def _source_metadata(envelope: CaseEnvelope, fingerprint: str) -> dict[str, str]:
    envelope = _strict_rehydrate_v22(
        CaseEnvelope, envelope, location="frozen case envelope"
    )
    return {
        "record_scope": "source-only",
        "case_fingerprint": envelope.case_fingerprint,
        "source_record_fingerprint": fingerprint,
    }


def _source_review_request_from_context_v22(
    context: _VerifiedSourceRequestContextV22,
    accepted_proposals: list[dict[str, object]],
    fragment_ordinal: int,
) -> EvaluatorRequestV22:
    source_record = _context_source_record_v22(context)
    schema, instructions = _source_fragment_contract_v22(
        EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT,
        source_record=source_record,
        proposal_count=len(accepted_proposals),
    )
    return _new_request_v22(
        EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT,
        json_schema=schema,
        payload={
            "source_record": source_record,
            "evidence_handles": _source_evidence_handles_v22(source_record),
            "accepted_proposals": accepted_proposals,
            "fragment_ordinal": fragment_ordinal,
            "max_new_proposals": 5,
        },
        safe_metadata=_context_source_metadata_v22(context),
        system_instructions=instructions,
    )


def _source_audit_request_from_context_v22(
    context: _VerifiedSourceRequestContextV22,
    review: SourceReviewAggregateV22,
    accepted_concerns: list[dict[str, object]],
    fragment_ordinal: int,
) -> EvaluatorRequestV22:
    source_record = _context_source_record_v22(context)
    schema, instructions = _source_fragment_contract_v22(
        EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT,
        source_record=source_record,
        proposal_count=len(review.proposals),
    )
    return _new_request_v22(
        EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT,
        json_schema=schema,
        payload={
            "source_record": source_record,
            "evidence_handles": _source_evidence_handles_v22(source_record),
            "indexed_proposals": [
                proposal.model_dump(mode="json") for proposal in review.proposals
            ],
            "accepted_concerns": accepted_concerns,
            "fragment_ordinal": fragment_ordinal,
            "max_new_concerns": 5,
        },
        safe_metadata=_context_source_metadata_v22(context),
        system_instructions=instructions,
    )


def _review_history(
    context: _VerifiedSourceRequestContextV22,
    value: tuple[AcceptedSourceReviewFragmentV22, ...],
    *,
    complete: bool,
) -> tuple[AcceptedSourceReviewFragmentV22, ...]:
    try:
        if not isinstance(value, tuple):
            raise ValueError
        checked = tuple(
            _strict_rehydrate_v22(
                AcceptedSourceReviewFragmentV22,
                item,
                location="accepted source-review history",
            )
            for item in tuple.__iter__(value)
        )
    except Exception as error:
        raise ValueError("accepted source-review history is invalid") from error
    if [item.fragment_ordinal for item in checked] != list(range(1, len(checked) + 1)):
        raise ValueError("accepted source-review history has invalid ordinal or finality")
    if complete:
        if (
            not checked
            or not checked[-1].payload.review_complete
            or any(item.payload.review_complete for item in checked[:-1])
        ):
            raise ValueError("accepted source-review history has invalid ordinal or finality")
    elif any(item.payload.review_complete for item in checked):
        raise ValueError("accepted source-review history has invalid ordinal or finality")
    if (
        len(checked) > 128
        or len({item.response_fingerprint for item in checked}) != len(checked)
        or sum(len(item.payload.proposals) for item in checked) > 640
    ):
        raise ValueError("accepted source-review history is invalid")
    accepted_proposals: list[dict[str, object]] = []
    for item in checked:
        expected = _source_review_request_from_context_v22(
            context, accepted_proposals, item.fragment_ordinal
        )
        if item.request_fingerprint != expected.request_fingerprint:
            raise ValueError("accepted source-review history is bound to another request sequence")
        accepted_proposals.extend(
            proposal.model_dump(mode="json") for proposal in item.payload.proposals
        )
    return checked


def _audit_history(
    context: _VerifiedSourceRequestContextV22,
    review: SourceReviewAggregateV22,
    value: tuple[AcceptedSourceAuditFragmentV22, ...],
    *,
    complete: bool,
) -> tuple[AcceptedSourceAuditFragmentV22, ...]:
    try:
        if not isinstance(value, tuple):
            raise ValueError
        checked = tuple(
            _strict_rehydrate_v22(
                AcceptedSourceAuditFragmentV22,
                item,
                location="accepted source-audit history",
            )
            for item in tuple.__iter__(value)
        )
    except Exception as error:
        raise ValueError("accepted source-audit history is invalid") from error
    if [item.fragment_ordinal for item in checked] != list(range(1, len(checked) + 1)):
        raise ValueError("accepted source-audit history has invalid ordinal or finality")
    if complete:
        if (
            not checked
            or not checked[-1].payload.audit_complete
            or any(item.payload.audit_complete for item in checked[:-1])
        ):
            raise ValueError("accepted source-audit history has invalid ordinal or finality")
    elif any(item.payload.audit_complete for item in checked):
        raise ValueError("accepted source-audit history has invalid ordinal or finality")
    if (
        len(checked) > 128
        or len({item.response_fingerprint for item in checked}) != len(checked)
        or sum(len(item.payload.concerns) for item in checked) > 640
    ):
        raise ValueError("accepted source-audit history is invalid")
    accepted_concerns: list[dict[str, object]] = []
    for item in checked:
        expected = _source_audit_request_from_context_v22(
            context, review, accepted_concerns, item.fragment_ordinal
        )
        if item.request_fingerprint != expected.request_fingerprint:
            raise ValueError("accepted source-audit history is bound to another request sequence")
        accepted_concerns.extend(
            concern.model_dump(mode="json") for concern in item.payload.concerns
        )
    return checked


def build_source_review_fragment_request_v22(
    envelope: CaseEnvelope,
    accepted: tuple[AcceptedSourceReviewFragmentV22, ...],
    *,
    fragment_ordinal: int,
) -> EvaluatorRequestV22:
    context = _verified_source_request_context_v22(envelope)
    accepted = _review_history(context, accepted, complete=False)
    fragment_ordinal = _strict_fragment_ordinal_v22(fragment_ordinal)
    if fragment_ordinal != len(accepted) + 1 or fragment_ordinal > 128:
        raise ValueError("source-review fragment ordinal is invalid")
    return _source_review_request_from_context_v22(
        context,
        [
            proposal.model_dump(mode="json")
            for fragment in accepted
            for proposal in fragment.payload.proposals
        ],
        fragment_ordinal,
    )


def build_source_audit_fragment_request_v22(
    envelope: CaseEnvelope,
    review: SourceReviewAggregateV22,
    accepted: tuple[AcceptedSourceAuditFragmentV22, ...],
    *,
    fragment_ordinal: int,
) -> EvaluatorRequestV22:
    try:
        from .attorney_v22_compiler import _verify_source_review_aggregate_with_context_v22

        context = _verified_source_request_context_v22(envelope)
        review = _verify_source_review_aggregate_with_context_v22(context, review)
    except Exception as error:
        raise ValueError("source-review aggregate is invalid") from error
    accepted = _audit_history(context, review, accepted, complete=False)
    fragment_ordinal = _strict_fragment_ordinal_v22(fragment_ordinal)
    if fragment_ordinal != len(accepted) + 1 or fragment_ordinal > 128:
        raise ValueError("source-audit fragment ordinal is invalid")
    return _source_audit_request_from_context_v22(
        context,
        review,
        [
            concern.model_dump(mode="json")
            for fragment in accepted
            for concern in fragment.payload.concerns
        ],
        fragment_ordinal,
    )


def build_source_referee_fragment_request_v22(
    envelope: CaseEnvelope,
    dispute: RefereeDisputeV22,
    *,
    controller_disputes: tuple[RefereeDisputeV22, ...],
) -> EvaluatorRequestV22:
    from .attorney_v22_compiler import canonical_referee_disputes_v22

    checked_envelope = _strict_rehydrate_v22(
        CaseEnvelope, envelope, location="frozen case envelope"
    )
    checked = _strict_rehydrate_v22(
        RefereeDisputeV22, dispute, location="referee dispute"
    )
    inventory = tuple(
        _strict_rehydrate_v22(
            RefereeDisputeV22, item, location="controller dispute inventory"
        )
        for item in controller_disputes
    )
    if (
        checked.case_fingerprint != checked_envelope.case_fingerprint
        or [item.dispute_id for item in inventory]
        != [f"D{i:04d}" for i in range(1, len(inventory) + 1)]
        or sum(item == checked for item in inventory) != 1
        or len(inventory) > 128
        or any(item.case_fingerprint != checked_envelope.case_fingerprint for item in inventory)
    ):
        raise ValueError("controller dispute inventory is invalid")
    try:
        expected = canonical_referee_disputes_v22(
            checked_envelope, tuple(item.material_dispute for item in inventory)
        )
    except Exception as error:
        raise ValueError("controller dispute inventory is invalid") from error
    if inventory != expected:
        raise ValueError("controller dispute inventory is invalid")
    return _new_request_v22(
        EvaluatorOperationV22.SOURCE_REFEREE_FRAGMENT,
        json_schema=_RefereeDraftV22.model_json_schema(),
        payload={"material_disputes": [checked.model_dump(mode="json")]},
        safe_metadata={
            "record_scope": "one-source-referee-dispute",
            "case_fingerprint": checked.case_fingerprint,
            "dispute_id": checked.dispute_id,
            "dispute_fingerprint": checked.dispute_fingerprint,
        },
    )


def _grade_context(
    report_text: str, source_context: dict[str, str], rubric: object
) -> dict[str, object]:
    if not isinstance(report_text, str) or not report_text.strip():
        raise ValueError("report text is invalid")
    try:
        from .attorney_v22_compiler import _strict_rubric

        checked_rubric = _strict_rubric(rubric)
    except Exception as error:
        raise ValueError("rubric is invalid") from error
    checked_source_context = _strict_source_context_v22(source_context)
    report_digest = hashlib.sha256(report_text.encode())
    return {
        "report_text": report_text,
        "report_fingerprint": report_digest.hexdigest(),
        "source_context": checked_source_context,
        "rubric": checked_rubric.model_dump(mode="json"),
    }


def build_ordinary_grade_request_v22(
    baseline: CanonicalBaselineV22,
    batch: OrdinaryGradeBatchV22,
    anonymous_label: Literal["A", "B"],
    grader_lane: Literal[1, 2],
    report_text: str,
    source_context: dict[str, str],
    rubric: object = None,
) -> EvaluatorRequestV22:
    from .attorney_v22_compiler import (
        RUBRIC_V22,
        ordinary_grade_batches_v22,
        verify_canonical_baseline_v22,
    )

    try:
        sealed = verify_canonical_baseline_v22(baseline)
    except Exception as error:
        raise ValueError("canonical baseline is invalid") from error
    anonymous_label, grader_lane = _strict_grade_coordinate_v22(
        anonymous_label, grader_lane
    )
    checked = _strict_rehydrate_v22(
        OrdinaryGradeBatchV22, batch, location="ordinary grade batch"
    )
    rubric = RUBRIC_V22 if rubric is None else rubric
    if checked not in ordinary_grade_batches_v22(sealed, anonymous_label, grader_lane):
        raise ValueError("ordinary grade batch is absent from inventory")
    requirements = {item.requirement_id: item for item in sealed.requirements}
    serialized_requirements: list[dict[str, object]] = []
    for requirement_id in checked.requirement_ids:
        requirement = requirements[requirement_id]
        serialized_requirements += [requirement.model_dump(mode="json")]
    schema, instructions = _ordinary_grade_request_contract_v22(
        len(serialized_requirements)
    )
    return _new_request_v22(
        EvaluatorOperationV22.ORDINARY_GRADE_FRAGMENT,
        json_schema=schema,
        payload={
            "anonymous_label": anonymous_label,
            "grader_lane": grader_lane,
            "batch_ref": checked.batch_ref,
            "baseline_fingerprint": sealed.baseline_fingerprint,
            "requirements": serialized_requirements,
            **_grade_context(report_text, source_context, rubric),
        },
        safe_metadata={
            "record_scope": "one-ordinary-grade-batch",
            "baseline_fingerprint": sealed.baseline_fingerprint,
            "batch_ref": checked.batch_ref,
        },
        system_instructions=instructions,
    )


def build_contested_grade_request_v22(
    baseline: CanonicalBaselineV22,
    contested_requirement: ContestedRequirementV22,
    anonymous_label: Literal["A", "B"],
    grader_lane: Literal[1, 2],
    report_text: str,
    source_context: dict[str, str],
    rubric: object = None,
) -> EvaluatorRequestV22:
    from .attorney_v22_compiler import RUBRIC_V22, verify_canonical_baseline_v22

    try:
        sealed = verify_canonical_baseline_v22(baseline)
    except Exception as error:
        raise ValueError("canonical baseline is invalid") from error
    anonymous_label, grader_lane = _strict_grade_coordinate_v22(
        anonymous_label, grader_lane
    )
    checked = _strict_rehydrate_v22(
        ContestedRequirementV22,
        contested_requirement,
        location="contested requirement",
    )
    rubric = RUBRIC_V22 if rubric is None else rubric
    if sum(item == checked for item in sealed.contested_requirements) != 1:
        raise ValueError("contested requirement is absent from inventory")
    if len(sealed.contested_requirements) > 128:
        raise ValueError("contested grade inventory exceeds 128 fragments")
    return _new_request_v22(
        EvaluatorOperationV22.CONTESTED_GRADE_FRAGMENT,
        json_schema=_ContestedGradeDraftV22.model_json_schema(),
        payload={
            "anonymous_label": anonymous_label,
            "grader_lane": grader_lane,
            "baseline_fingerprint": sealed.baseline_fingerprint,
            "contested_requirement": checked.model_dump(mode="json"),
            **_grade_context(report_text, source_context, rubric),
        },
        safe_metadata={
            "record_scope": "one-contested-grade-requirement",
            "baseline_fingerprint": sealed.baseline_fingerprint,
            "contested_requirement_id": checked.contested_requirement_id,
        },
    )
