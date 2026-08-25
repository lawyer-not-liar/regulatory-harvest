"""Deterministic conservative compilation for ``delivery-readiness-v1``.

This module owns current scoring, safety reconciliation, matrices, and the
orthogonal attorney-review tier.  Historical Protocol 2.2 evidence is attached
only after the current tier is fixed and never participates in a tier branch.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Mapping, Sequence
from enum import Enum
from typing import Literal, TypeVar, cast

from pydantic import BaseModel, ValidationError

from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from . import attorney_baseline_models as _baseline_models
from . import attorney_readiness_models as _models
from . import attorney_readiness_requests as _requests
from .attorney_baseline_models import (
    BaselineImportanceV1,
    GradeableBaselineProjectionV1,
    ImportanceBasisV1,
)
from .attorney_readiness_inputs import VerifiedReadinessInputsV1
from .attorney_readiness_models import (
    BaselineLockedContestedGradeV1,
    BaselineLockedGradeFragmentV1,
    BaselineLockedGraderAggregateV1,
    BaselineLockedStrictEquivalentV1,
    DeliveryReadinessResultV1,
    DeliveryReadinessTierV1,
    GapFollowUpMatrixV1,
    GapFollowUpRowV1,
    GapOriginV1,
    GapVisibilityV1,
    HistoricalV22CrossCheckStatusV1,
    OwnerRoleV1,
    ReadinessRubricV1,
    ReconciledSafetyReviewV1,
    RequirementDispositionV1,
    RequirementMatrixRowV1,
    RequirementMatrixV1,
    SafetyDisputeV1,
    SafetyFindingKindV1,
    SafetyFindingProposalV1,
    SafetyGapAssessmentV1,
    SafetyGapCandidateV1,
    SafetyLaneResponseV1,
    SafetyRefereeDecisionV1,
    load_readiness_rubric_v1,
)
from .attorney_readiness_requests import (
    READINESS_CONSERVATIVE_DISPOSITION_ORDER_V1,
    READINESS_STRICT_EQUIVALENT_SCORING_DESCRIPTOR_V1,
    READINESS_STRICT_EQUIVALENT_SCORING_FINGERPRINT_V1,
    build_baseline_locked_grade_batches_v1,
    build_safety_disputes_v1,
)
from .attorney_v2_models import AbsoluteDispositionV2

_MAX_DEPTH = 64
_MAX_NODES = 100_000
_MAX_BYTES = 16 * 1024 * 1024
_MODEL_TYPE = TypeVar("_MODEL_TYPE", bound=BaseModel)

_DISPOSITION_HALF_UNITS = {
    RequirementDispositionV1.MET: 2,
    RequirementDispositionV1.PARTIALLY_MET: 1,
    RequirementDispositionV1.NOT_MET: 0,
    RequirementDispositionV1.UNCERTAIN: 0,
}
_DISPOSITION_RANK = {
    RequirementDispositionV1(value): index
    for index, value in enumerate(READINESS_CONSERVATIVE_DISPOSITION_ORDER_V1)
}
_ORIGIN_PRIORITY = {
    GapOriginV1.REQUIREMENT: 0,
    GapOriginV1.BASELINE_GAP: 1,
    GapOriginV1.CONTESTED_REQUIREMENT: 2,
    GapOriginV1.PREREQUISITE: 3,
    GapOriginV1.SAFETY_FINDING: 4,
}
_FINDING_BLOCKER = {
    SafetyFindingKindV1.MATERIAL_UNSUPPORTED_ASSERTION: "MATERIAL_UNSUPPORTED_ASSERTION",
    SafetyFindingKindV1.BASELINE_CONTRADICTION: "BASELINE_CONTRADICTION",
    SafetyFindingKindV1.HIDDEN_OR_UNDERSTATED_LIMITATION: "HIDDEN_MATERIAL_GAP",
    SafetyFindingKindV1.UNDISCLOSED_DISPOSITIVE_CLIENT_FACT: (
        "UNDISCLOSED_DISPOSITIVE_CLIENT_FACT"
    ),
    SafetyFindingKindV1.MISLEADING_CURRENTNESS_OR_AUTHORITY: (
        "MISLEADING_CURRENTNESS_OR_AUTHORITY"
    ),
    SafetyFindingKindV1.UNDISCLOSED_GRADER_GAP: "HIDDEN_MATERIAL_GAP",
}
_DISPUTE_FIELDS: dict[str, tuple[str, ...]] = {
    "rationale": (
        "shortfall_description",
        "rationale_kind",
        "why_unresolved",
        "why_it_matters",
    ),
    "evidence_binding": ("evidence_refs", "report_passages"),
    "visibility": ("disclosure_location", "visibility"),
    "blocker": ("blocking_code",),
    "follow_up": ("follow_up_code",),
    "owner": ("owner_role",),
    "resolution_test": ("resolution_test",),
}
_GENERIC_ONLY = re.compile(
    r"^(?:more research (?:is )?needed|insufficient information|requirement partially met|"
    r"partially met|partially_met|not met|not_met|uncertain|met|[01](?:\.0|\.5)?)$"
)
_COMPLETENESS_CLAIM = re.compile(
    r"\b(?:no (?:material )?(?:gaps|limitations)|fully comprehensive|complete and "
    r"(?:accurate|current)|all issues (?:are )?resolved)\b",
    re.IGNORECASE,
)
_TRUSTED_CONTAINER_TYPES = frozenset(
    {
        tuple,
        list,
        dict,
        _models._FrozenWireTuple,
        _models._FrozenJsonList,
        _models._FrozenDict,
        _baseline_models._FrozenStringList,
        _baseline_models._FrozenDict,
    }
)
_BLOCKING_CODES = frozenset(load_readiness_rubric_v1().blocking_codes)


def _fingerprint(value: object) -> str:
    return sha256_digest(canonical_json_bytes(value))


def _accepted_container(value: object) -> bool:
    return type(value) in _TRUSTED_CONTAINER_TYPES


def _preflight_model(value: BaseModel) -> None:
    """Bound trusted model state before any recursive dump or serialization."""
    budget = [0, 0]
    active: set[int] = set()

    def add(*, nodes: int = 1, bytes_: int = 0) -> None:
        budget[0] += nodes
        budget[1] += bytes_
        if budget[0] > _MAX_NODES or budget[1] > _MAX_BYTES:
            raise ValueError("readiness compiler input exceeds its budget")

    def text_cost(item: str) -> int:
        if len(item) > _MAX_BYTES:
            raise ValueError("readiness compiler text exceeds its budget")
        return sum(
            1 if code < 0x80 else 2 if code < 0x800 else 3 if code < 0x10000 else 4
            for code in map(ord, item)
        )

    def visit(item: object, depth: int) -> None:
        if depth > _MAX_DEPTH:
            raise ValueError("readiness compiler input exceeds its depth budget")
        if item is None or type(item) in {bool, int, float}:
            add()
            return
        if type(item) is str:
            add(bytes_=text_cost(item))
            return
        if type(item) is bytes:
            add(bytes_=len(item))
            return
        if isinstance(item, Enum):
            visit(item.value, depth + 1)
            return
        if isinstance(item, BaseModel):
            identity = id(item)
            if identity in active:
                raise ValueError("readiness compiler input contains a cycle")
            active.add(identity)
            add(nodes=len(type(item).model_fields) + 1)
            for name in type(item).model_fields:
                visit(getattr(item, name), depth + 1)
            active.remove(identity)
            return
        if _accepted_container(item):
            identity = id(item)
            if identity in active:
                raise ValueError("readiness compiler input contains a cycle")
            active.add(identity)
            add()
            if isinstance(item, Mapping):
                for key, nested in item.items():
                    if type(key) is not str and not isinstance(key, Enum):
                        raise ValueError("readiness compiler mappings require native string keys")
                    visit(key, depth + 1)
                    visit(nested, depth + 1)
            else:
                for nested in cast(Sequence[object], item):
                    visit(nested, depth + 1)
            active.remove(identity)
            return
        raise ValueError("readiness compiler input contains an unsafe native value")

    visit(value, 0)


def _strict_model(model_type: type[_MODEL_TYPE], value: object, *, label: str) -> _MODEL_TYPE:
    try:
        if type(value) is not model_type:
            raise TypeError
        checked_value = value
        _preflight_model(checked_value)
        if getattr(checked_value, "__pydantic_extra__", None):
            raise ValueError
        raw = checked_value.model_dump(mode="python", warnings="error")
        checked = model_type.model_validate(raw)
        if canonical_json_bytes(checked) != canonical_json_bytes(raw):
            raise ValueError
        return checked
    except (
        AttributeError,
        RecursionError,
        TypeError,
        UnicodeError,
        ValidationError,
        ValueError,
    ) as error:
        raise ValueError(f"{label} is invalid") from error


def _strict_inputs(value: object) -> VerifiedReadinessInputsV1:
    return _requests._verified_inputs(value)


def _strict_rubric(value: object) -> ReadinessRubricV1:
    checked = _strict_model(ReadinessRubricV1, value, label="readiness rubric")
    if checked != load_readiness_rubric_v1():
        raise ValueError("readiness rubric is invalid")
    descriptor = READINESS_STRICT_EQUIVALENT_SCORING_DESCRIPTOR_V1
    if (
        descriptor["retained_semantics"] != checked.strict_equivalent_scoring_semantics
        or dict(cast(Mapping[str, int], descriptor["importance_weights"]))
        != {key.value: value for key, value in checked.strict_importance_weights.items()}
        or dict(cast(Mapping[str, float], descriptor["disposition_credit"]))
        != {key.value: value for key, value in checked.disposition_credit.items()}
        or descriptor["critical_recall_floor"] != checked.high_assurance_critical_recall_floor
        or descriptor["weighted_coverage_floor"] != checked.high_assurance_weighted_coverage_floor
        or _fingerprint(READINESS_STRICT_EQUIVALENT_SCORING_DESCRIPTOR_V1)
        != READINESS_STRICT_EQUIVALENT_SCORING_FINGERPRINT_V1
    ):
        raise ValueError("readiness rubric is invalid")
    return checked


def _strict_projection(value: object) -> GradeableBaselineProjectionV1:
    try:
        if type(value) is not GradeableBaselineProjectionV1:
            raise TypeError
        projection = value
        _preflight_model(projection)
        serialized = projection.model_dump(mode="json", warnings="error")
        raw = dict(serialized)
        baseline_value = raw.get("baseline_input")
        if type(baseline_value) is not dict:
            raise ValueError
        baseline_raw = dict(cast(dict[str, object], baseline_value))
        baseline_raw["compiler_contract"] = json.loads(
            canonical_json_bytes(baseline_raw.get("compiler_contract"))
        )
        for field_name in ("evaluation_rubric_bytes", "importance_policy_bytes"):
            field_value = baseline_raw.get(field_name)
            if type(field_value) is not str:
                raise ValueError
            baseline_raw[field_name] = field_value.encode("utf-8")
        raw["baseline_input"] = baseline_raw
        checked = GradeableBaselineProjectionV1.model_validate(raw)
        if canonical_json_bytes(checked.model_dump(mode="json", warnings="error")) != (
            canonical_json_bytes(serialized)
        ):
            raise ValueError
        return checked
    except (
        AttributeError,
        RecursionError,
        TypeError,
        UnicodeError,
        ValidationError,
        ValueError,
    ) as error:
        raise ValueError("gradeable baseline projection is invalid") from error


def _seal_model(
    model_type: type[_MODEL_TYPE], fingerprint_field: str, **values: object
) -> _MODEL_TYPE:
    provisional = model_type(
        **values,
        **{fingerprint_field: "0" * 64},
    )
    descriptor = provisional.model_dump(mode="json", exclude={fingerprint_field})
    return model_type.model_validate({**descriptor, fingerprint_field: _fingerprint(descriptor)})


def _fragment_bindings(
    inputs: VerifiedReadinessInputsV1, lane: Literal[1, 2]
) -> tuple[object, ...]:
    return (
        lane,
        inputs.readiness_input.grade_target_fingerprint,
        inputs.gradeable_baseline.binding.baseline_fingerprint,
        inputs.report_hash,
        inputs.readiness_input.strict_equivalent_scoring_contract_fingerprint,
    )


def _item_bindings(
    item: BaselineLockedGradeFragmentV1 | BaselineLockedContestedGradeV1,
) -> tuple[object, ...]:
    return (
        item.lane,
        item.grade_target_fingerprint,
        item.baseline_fingerprint,
        item.report_hash,
        item.strict_equivalent_scoring_contract_fingerprint,
    )


def aggregate_baseline_locked_grader_lane_v1(
    inputs: VerifiedReadinessInputsV1,
    *,
    lane: Literal[1, 2],
    ordinary_fragments: tuple[BaselineLockedGradeFragmentV1, ...],
    contested_grades: tuple[BaselineLockedContestedGradeV1, ...],
) -> BaselineLockedGraderAggregateV1:
    """Validate exact fresh fragment coverage and seal one grader lane."""
    checked = _strict_inputs(inputs)
    if type(lane) is not int or lane not in {1, 2}:
        raise ValueError("grader lane is invalid")
    if type(ordinary_fragments) is not tuple or type(contested_grades) is not tuple:
        raise ValueError("grade fragment inventories are invalid")
    expected_batches = build_baseline_locked_grade_batches_v1(
        checked.gradeable_baseline, lane=cast(Literal[1, 2], lane)
    )
    expected_contests = tuple(
        item.contested_requirement.contested_requirement_id
        for item in checked.gradeable_baseline.contested_requirements
    )
    if len(ordinary_fragments) != len(expected_batches) or len(contested_grades) != len(
        expected_contests
    ):
        raise ValueError("grade fragment coverage is invalid")
    allowlist = set(_requests._report_passage_allowlist(checked.report_text))
    fragments: list[BaselineLockedGradeFragmentV1] = []
    contests: list[BaselineLockedContestedGradeV1] = []
    try:
        for raw, batch in zip(ordinary_fragments, expected_batches, strict=True):
            fragment = _strict_model(
                BaselineLockedGradeFragmentV1,
                raw,
                label="grade fragments",
            )
            if (
                fragment.batch_ref != batch.batch_ref
                or tuple(item.requirement_id for item in fragment.requirement_grades)
                != batch.requirement_ids
                or _item_bindings(fragment)
                != _fragment_bindings(checked, cast(Literal[1, 2], lane))
                or fragment.fragment_fingerprint
                != _fingerprint(fragment.model_dump(mode="json", exclude={"fragment_fingerprint"}))
                or any(
                    passage not in allowlist
                    for grade in fragment.requirement_grades
                    for passage in grade.report_passages
                )
            ):
                raise ValueError
            fragments.append(fragment)
        for raw, expected_id in zip(contested_grades, expected_contests, strict=True):
            contest = _strict_model(
                BaselineLockedContestedGradeV1,
                raw,
                label="grade fragments",
            )
            if (
                contest.contested_requirement_id != expected_id
                or _item_bindings(contest) != _fragment_bindings(checked, cast(Literal[1, 2], lane))
                or contest.grade_fingerprint
                != _fingerprint(contest.model_dump(mode="json", exclude={"grade_fingerprint"}))
                or any(
                    passage not in allowlist
                    for passage in (
                        *contest.reviewer_report_passages,
                        *contest.auditor_report_passages,
                    )
                )
            ):
                raise ValueError
            contests.append(contest)
    except ValueError as error:
        raise ValueError("grade fragments are invalid") from error
    flattened = tuple(grade for fragment in fragments for grade in fragment.requirement_grades)
    expected_ids = tuple(
        item.requirement.requirement_id for item in checked.gradeable_baseline.requirements
    )
    if tuple(item.requirement_id for item in flattened) != expected_ids:
        raise ValueError("grade fragment coverage is invalid")
    return _seal_model(
        BaselineLockedGraderAggregateV1,
        "aggregate_fingerprint",
        lane=lane,
        grade_target_fingerprint=checked.readiness_input.grade_target_fingerprint,
        baseline_fingerprint=checked.gradeable_baseline.binding.baseline_fingerprint,
        report_hash=checked.report_hash,
        strict_equivalent_scoring_contract_fingerprint=(
            checked.readiness_input.strict_equivalent_scoring_contract_fingerprint
        ),
        ordinary_fragments=tuple(fragments),
        contested_grades=tuple(contests),
        requirement_grades=flattened,
    )


def _strict_aggregate_for_projection(
    baseline: GradeableBaselineProjectionV1,
    value: object,
    lane: Literal[1, 2],
) -> BaselineLockedGraderAggregateV1:
    aggregate = _strict_model(BaselineLockedGraderAggregateV1, value, label="grader aggregate")
    expected_ids = tuple(item.requirement.requirement_id for item in baseline.requirements)
    expected_contests = tuple(
        item.contested_requirement.contested_requirement_id
        for item in baseline.contested_requirements
    )
    expected_batches = build_baseline_locked_grade_batches_v1(baseline, lane=lane)
    if (
        aggregate.lane != lane
        or aggregate.grade_target_fingerprint != baseline.binding.grade_target_fingerprint
        or aggregate.baseline_fingerprint != baseline.binding.baseline_fingerprint
        or aggregate.strict_equivalent_scoring_contract_fingerprint
        != baseline.binding.evaluation_rubric_fingerprint
        or tuple(item.requirement_id for item in aggregate.requirement_grades) != expected_ids
        or tuple(item.contested_requirement_id for item in aggregate.contested_grades)
        != expected_contests
        or tuple(
            (
                fragment.batch_ref,
                tuple(grade.requirement_id for grade in fragment.requirement_grades),
            )
            for fragment in aggregate.ordinary_fragments
        )
        != tuple((batch.batch_ref, batch.requirement_ids) for batch in expected_batches)
        or aggregate.aggregate_fingerprint
        != _fingerprint(aggregate.model_dump(mode="json", exclude={"aggregate_fingerprint"}))
    ):
        raise ValueError("grader aggregate is invalid")
    for fragment in aggregate.ordinary_fragments:
        if fragment.fragment_fingerprint != _fingerprint(
            fragment.model_dump(mode="json", exclude={"fragment_fingerprint"})
        ):
            raise ValueError("grader aggregate is invalid")
    for contest in aggregate.contested_grades:
        if contest.grade_fingerprint != _fingerprint(
            contest.model_dump(mode="json", exclude={"grade_fingerprint"})
        ):
            raise ValueError("grader aggregate is invalid")
    return aggregate


def _score(
    observations: Sequence[tuple[BaselineImportanceV1, RequirementDispositionV1]],
    rubric: ReadinessRubricV1,
) -> tuple[
    AbsoluteDispositionV2,
    tuple[str, ...],
    int,
    int,
    int,
    int,
]:
    weighted_denominator = 2 * sum(
        rubric.strict_importance_weights[importance] for importance, _ in observations
    )
    weighted_numerator = sum(
        rubric.strict_importance_weights[importance] * _DISPOSITION_HALF_UNITS[disposition]
        for importance, disposition in observations
    )
    critical = [
        _DISPOSITION_HALF_UNITS[disposition]
        for importance, disposition in observations
        if importance is BaselineImportanceV1.CRITICAL
    ]
    critical_numerator = sum(critical)
    critical_denominator = 2 * len(critical)
    if any(disposition is RequirementDispositionV1.UNCERTAIN for _, disposition in observations):
        return (
            AbsoluteDispositionV2.INCONCLUSIVE,
            ("GRADE_UNCERTAIN",),
            weighted_numerator,
            weighted_denominator,
            critical_numerator,
            critical_denominator,
        )
    reasons: list[str] = []
    if critical_denominator and critical_numerator != critical_denominator:
        reasons.append("CRITICAL_RECALL_BELOW_FLOOR")
    if weighted_denominator and 10 * weighted_numerator < 9 * weighted_denominator:
        reasons.append("WEIGHTED_COVERAGE_BELOW_FLOOR")
    return (
        AbsoluteDispositionV2.FAIL if reasons else AbsoluteDispositionV2.PASS,
        tuple(reasons),
        weighted_numerator,
        weighted_denominator,
        critical_numerator,
        critical_denominator,
    )


def _merge_outcomes(
    first: tuple[AbsoluteDispositionV2, tuple[str, ...]],
    second: tuple[AbsoluteDispositionV2, tuple[str, ...]],
) -> tuple[AbsoluteDispositionV2, tuple[str, ...]]:
    if first[0] is not second[0]:
        return AbsoluteDispositionV2.INCONCLUSIVE, ("GRADER_DISAGREEMENT",)
    return first[0], tuple(dict.fromkeys((*first[1], *second[1])))


def _ordinary_observations(
    baseline: GradeableBaselineProjectionV1,
    lane: BaselineLockedGraderAggregateV1,
) -> list[tuple[BaselineImportanceV1, RequirementDispositionV1]]:
    return [
        (item.requirement.importance, RequirementDispositionV1(grade.disposition))
        for item, grade in zip(baseline.requirements, lane.requirement_grades, strict=True)
    ]


def _contested_lane_outcome(
    baseline: GradeableBaselineProjectionV1,
    lane: BaselineLockedGraderAggregateV1,
    rubric: ReadinessRubricV1,
) -> tuple[AbsoluteDispositionV2, tuple[str, ...], tuple[str, ...]]:
    reviewer_world = _ordinary_observations(baseline, lane)
    auditor_world = list(reviewer_world)
    changing: list[str] = []
    for item, grade in zip(baseline.contested_requirements, lane.contested_grades, strict=True):
        contest = item.contested_requirement
        reviewer = contest.reviewer_alternative
        auditor = contest.auditor_alternative
        reviewer_observation = (
            None
            if reviewer is None
            else (
                reviewer.importance,
                grade.reviewer_alternative_disposition,
            )
        )
        auditor_observation = (
            None
            if auditor is None
            else (
                auditor.importance,
                grade.auditor_alternative_disposition,
            )
        )
        if reviewer_observation is not None:
            reviewer_world.append(reviewer_observation)
        if auditor_observation is not None:
            auditor_world.append(auditor_observation)
        if reviewer_observation != auditor_observation:
            changing.append(contest.contested_requirement_id)
    reviewer_score = _score(reviewer_world, rubric)
    auditor_score = _score(auditor_world, rubric)
    if (
        reviewer_score[0] is AbsoluteDispositionV2.INCONCLUSIVE
        or auditor_score[0] is AbsoluteDispositionV2.INCONCLUSIVE
    ):
        return (
            AbsoluteDispositionV2.INCONCLUSIVE,
            ("BASELINE_EVIDENCE_INSUFFICIENT",),
            (),
        )
    if reviewer_score[0] is not auditor_score[0]:
        return (
            AbsoluteDispositionV2.INCONCLUSIVE,
            ("OUTCOME_SENSITIVE_BASELINE_DISPUTE",),
            tuple(changing),
        )
    disposition, reasons = _merge_outcomes(reviewer_score[:2], auditor_score[:2])
    return disposition, reasons, ()


def derive_baseline_locked_strict_equivalent_v1(
    baseline: GradeableBaselineProjectionV1,
    lane_1: BaselineLockedGraderAggregateV1,
    lane_2: BaselineLockedGraderAggregateV1,
    rubric: ReadinessRubricV1,
) -> BaselineLockedStrictEquivalentV1:
    """Apply retained Protocol 2.2 scoring and contested sensitivity exactly."""
    checked_baseline = _strict_projection(baseline)
    checked_rubric = _strict_rubric(rubric)
    first = _strict_aggregate_for_projection(checked_baseline, lane_1, 1)
    second = _strict_aggregate_for_projection(checked_baseline, lane_2, 2)
    if first.report_hash != second.report_hash:
        raise ValueError("grader aggregates do not bind one report")
    first_score = _score(_ordinary_observations(checked_baseline, first), checked_rubric)
    second_score = _score(_ordinary_observations(checked_baseline, second), checked_rubric)
    disposition, reasons = _merge_outcomes(first_score[:2], second_score[:2])
    changing: tuple[str, ...] = ()
    if disposition is not AbsoluteDispositionV2.INCONCLUSIVE:
        first_world = _contested_lane_outcome(checked_baseline, first, checked_rubric)
        second_world = _contested_lane_outcome(checked_baseline, second, checked_rubric)
        disposition, reasons = _merge_outcomes(first_world[:2], second_world[:2])
        changing = tuple(dict.fromkeys((*first_world[2], *second_world[2])))

    def ratio(numerator: int, denominator: int) -> float:
        return 1.0 if denominator == 0 else numerator / denominator

    return _seal_model(
        BaselineLockedStrictEquivalentV1,
        "strict_equivalent_fingerprint",
        semantics="attorney-eval-v2.2-strict-equivalent",
        absolute_disposition=disposition,
        grader_lanes=(first, second),
        lane_critical_recall=(
            ratio(first_score[4], first_score[5]),
            ratio(second_score[4], second_score[5]),
        ),
        lane_weighted_coverage=(
            ratio(first_score[2], first_score[3]),
            ratio(second_score[2], second_score[3]),
        ),
        reason_codes=reasons,
        outcome_determinative_contested_ids=changing,
    )


def _strict_candidate(
    inputs: VerifiedReadinessInputsV1,
    value: object,
    index: int,
) -> SafetyGapCandidateV1:
    candidate = _strict_model(SafetyGapCandidateV1, value, label="gap candidate")
    descriptor = {
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
    if (
        candidate.candidate_id != f"GC-{index:04d}"
        or candidate.canonical_order != index - 1
        or candidate.baseline_fingerprint != inputs.gradeable_baseline.binding.baseline_fingerprint
        or candidate.report_hash != inputs.report_hash
        or candidate.candidate_fingerprint != _fingerprint(descriptor)
    ):
        raise ValueError("gap candidate is invalid")
    return candidate


def _record_identity(
    record: SafetyGapAssessmentV1 | SafetyFindingProposalV1,
) -> str:
    if type(record) is SafetyGapAssessmentV1:
        return f"candidate:{record.candidate_id}"
    finding = cast(SafetyFindingProposalV1, record)
    return f"finding:{finding.finding_kind.value}:{finding.subject_id}"


def _finding_map(
    findings: Sequence[SafetyFindingProposalV1],
) -> dict[str, SafetyFindingProposalV1]:
    result: dict[str, SafetyFindingProposalV1] = {}
    for finding in findings:
        identity = _record_identity(finding)
        if identity in result:
            raise ValueError("safety finding identities must be unique")
        result[identity] = finding
    return result


def _unresolved_dispute_blockers(
    dispute: SafetyDisputeV1,
    lane_1: SafetyGapAssessmentV1 | SafetyFindingProposalV1 | None,
    lane_2: SafetyGapAssessmentV1 | SafetyFindingProposalV1 | None,
) -> tuple[str, ...]:
    if dispute.dispute_kind == "finding_existence":
        record = lane_1 if lane_1 is not None else lane_2
        if isinstance(record, SafetyFindingProposalV1):
            return (_FINDING_BLOCKER[record.finding_kind],)
        return ("HIDDEN_MATERIAL_GAP",)
    if dispute.dispute_kind in {"rationale", "evidence_binding"}:
        return ("GAP_RATIONALE_INVALID",)
    if dispute.dispute_kind == "visibility":
        return ("HIDDEN_MATERIAL_GAP",)
    if dispute.dispute_kind in {"follow_up", "resolution_test"}:
        return ("MISSING_REQUIRED_FOLLOW_UP",)
    if dispute.dispute_kind == "owner":
        return ("CRITICAL_DISCLOSURE_INVALID",)
    blockers = tuple(
        dict.fromkeys(
            code
            for record in (lane_1, lane_2)
            if record is not None
            for code in (record.blocking_code,)
            if code is not None
        )
    )
    return blockers or ("HIDDEN_MATERIAL_GAP",)


def reconcile_safety_lanes_v1(
    inputs: VerifiedReadinessInputsV1,
    candidates: tuple[SafetyGapCandidateV1, ...],
    lane_1: SafetyLaneResponseV1,
    lane_2: SafetyLaneResponseV1,
    referee_decisions: tuple[SafetyRefereeDecisionV1, ...],
) -> ReconciledSafetyReviewV1:
    """Reconcile every exact safety disagreement without controller preference."""
    checked = _strict_inputs(inputs)
    if type(candidates) is not tuple or type(referee_decisions) is not tuple:
        raise ValueError("safety inventories are invalid")
    exact_candidates = tuple(
        _strict_candidate(checked, value, index) for index, value in enumerate(candidates, 1)
    )
    first = _strict_model(SafetyLaneResponseV1, lane_1, label="safety lane")
    second = _strict_model(SafetyLaneResponseV1, lane_2, label="safety lane")
    disputes = build_safety_disputes_v1(checked, first, second)
    expected_ids = tuple(item.candidate_id for item in exact_candidates)
    if (
        tuple(item.candidate_id for item in first.candidate_assessments) != expected_ids
        or tuple(item.candidate_id for item in second.candidate_assessments) != expected_ids
    ):
        raise ValueError("safety candidate coverage is invalid")
    decisions = tuple(
        _strict_model(SafetyRefereeDecisionV1, value, label="safety referee decision")
        for value in referee_decisions
    )
    if tuple(item.dispute_id for item in decisions) != tuple(item.dispute_id for item in disputes):
        raise ValueError("safety referee coverage is invalid")
    for dispute, decision in zip(disputes, decisions, strict=True):
        if not decision.evidence_refs or not set(decision.evidence_refs).issubset(
            dispute.evidence_refs
        ):
            raise ValueError("safety referee evidence is invalid")

    first_assessments = {_record_identity(item): item for item in first.candidate_assessments}
    second_assessments = {_record_identity(item): item for item in second.candidate_assessments}
    first_findings = _finding_map(first.finding_proposals)
    second_findings = _finding_map(second.finding_proposals)
    reconciled: dict[str, SafetyGapAssessmentV1 | SafetyFindingProposalV1] = {
        **first_assessments,
        **first_findings,
    }
    unresolved_blockers: list[str] = []
    decision_by_id = {item.dispute_id: item for item in decisions}
    for dispute in disputes:
        decision = decision_by_id[dispute.dispute_id]
        identity = dispute.subject_identity
        first_record = first_assessments.get(identity) or first_findings.get(identity)
        second_record = second_assessments.get(identity) or second_findings.get(identity)
        if decision.disposition in {"blocking", "unresolved"}:
            dispute_blockers = _unresolved_dispute_blockers(
                dispute,
                first_record,
                second_record,
            )
            unresolved_blockers.extend(dispute_blockers)
            if identity not in reconciled and second_record is not None:
                reconciled[identity] = second_record
            current = reconciled.get(identity)
            if current is not None and current.blocking_code is None:
                raw = current.model_dump(mode="json")
                raw["blocking_code"] = dispute_blockers[0]
                reconciled[identity] = type(current).model_validate(raw)
            continue
        chosen = first_record if decision.disposition == "lane_1" else second_record
        if dispute.dispute_kind == "finding_existence":
            if chosen is None:
                reconciled.pop(identity, None)
            else:
                reconciled[identity] = chosen
            continue
        if chosen is None:
            raise ValueError("safety referee choice is invalid")
        current = reconciled.get(identity)
        if current is None:
            current = chosen
        choice = (
            dispute.lane_1_choice if decision.disposition == "lane_1" else dispute.lane_2_choice
        )
        if choice is None:
            raise ValueError("safety referee choice is invalid")
        raw = current.model_dump(mode="json")
        raw.update(dict(choice))
        reconciled[identity] = type(current).model_validate(raw)

    assessment_rows = tuple(
        cast(SafetyGapAssessmentV1, reconciled[f"candidate:{candidate.candidate_id}"])
        for candidate in exact_candidates
    )
    finding_rows = tuple(
        cast(SafetyFindingProposalV1, reconciled[identity])
        for identity in sorted(key for key in reconciled if key.startswith("finding:"))
    )
    blockers = list(unresolved_blockers)
    blockers.extend(
        item.blocking_code for item in assessment_rows if item.blocking_code is not None
    )
    blockers.extend(item.blocking_code for item in finding_rows if item.blocking_code is not None)
    blockers.extend(_FINDING_BLOCKER[item.finding_kind] for item in finding_rows)
    ordered_blockers = tuple(
        code for code in checked.readiness_rubric.blocking_codes if code in set(blockers)
    )
    return _seal_model(
        ReconciledSafetyReviewV1,
        "safety_review_fingerprint",
        candidate_assessments=assessment_rows,
        finding_proposals=finding_rows,
        referee_decisions=decisions,
        blocking_codes=ordered_blockers,
    )


def _conservative(
    values: Sequence[RequirementDispositionV1],
) -> RequirementDispositionV1:
    return min(values, key=_DISPOSITION_RANK.__getitem__)


def _strict_lanes_for_inputs(
    inputs: VerifiedReadinessInputsV1,
    lanes: object,
) -> tuple[BaselineLockedGraderAggregateV1, BaselineLockedGraderAggregateV1]:
    return _requests._validate_grade_lanes(inputs, lanes)


def compile_requirement_matrix_v1(
    inputs: VerifiedReadinessInputsV1,
    grader_lanes: tuple[
        BaselineLockedGraderAggregateV1,
        BaselineLockedGraderAggregateV1,
    ],
) -> RequirementMatrixV1:
    """Compile every stable ordinary requirement in canonical order."""
    checked = _strict_inputs(inputs)
    first, second = _strict_lanes_for_inputs(checked, grader_lanes)
    rows: list[RequirementMatrixRowV1] = []
    for item, grade_1, grade_2 in zip(
        checked.gradeable_baseline.requirements,
        first.requirement_grades,
        second.requirement_grades,
        strict=True,
    ):
        requirement = item.requirement
        first_disposition = RequirementDispositionV1(grade_1.disposition)
        second_disposition = RequirementDispositionV1(grade_2.disposition)
        rows.append(
            _seal_model(
                RequirementMatrixRowV1,
                "row_fingerprint",
                requirement_id=requirement.requirement_id,
                canonical_order=requirement.canonical_order,
                statement=requirement.statement,
                kind=requirement.kind.value,
                importance=requirement.importance,
                importance_basis=requirement.importance_basis,
                importance_rationale=requirement.importance_rationale,
                lane_1_disposition=first_disposition,
                lane_2_disposition=second_disposition,
                conservative_disposition=_conservative((first_disposition, second_disposition)),
                lane_1_report_passages=tuple(grade_1.report_passages),
                lane_2_report_passages=tuple(grade_2.report_passages),
            )
        )
    return _seal_model(
        RequirementMatrixV1,
        "matrix_fingerprint",
        grade_target_fingerprint=checked.readiness_input.grade_target_fingerprint,
        report_hash=checked.report_hash,
        rows=tuple(rows),
    )


def _strict_equivalent_for_inputs(
    inputs: VerifiedReadinessInputsV1,
    value: object,
) -> BaselineLockedStrictEquivalentV1:
    checked = _strict_model(
        BaselineLockedStrictEquivalentV1,
        value,
        label="strict-equivalent result",
    )
    if checked.strict_equivalent_fingerprint != _fingerprint(
        checked.model_dump(mode="json", exclude={"strict_equivalent_fingerprint"})
    ):
        raise ValueError("strict-equivalent result is invalid")
    expected = derive_baseline_locked_strict_equivalent_v1(
        inputs.gradeable_baseline,
        checked.grader_lanes[0],
        checked.grader_lanes[1],
        inputs.readiness_rubric,
    )
    if canonical_json_bytes(checked) != canonical_json_bytes(expected):
        raise ValueError("strict-equivalent result is invalid")
    return checked


def _strict_safety(value: object) -> ReconciledSafetyReviewV1:
    checked = _strict_model(ReconciledSafetyReviewV1, value, label="reconciled safety review")
    if (
        checked.safety_review_fingerprint
        != _fingerprint(checked.model_dump(mode="json", exclude={"safety_review_fingerprint"}))
        or any(code not in _BLOCKING_CODES for code in checked.blocking_codes)
        or (
            any(
                decision.disposition in {"blocking", "unresolved"}
                for decision in checked.referee_decisions
            )
            and not checked.blocking_codes
        )
    ):
        raise ValueError("reconciled safety review is invalid")
    return checked


def _importance_contract(
    inputs: VerifiedReadinessInputsV1,
    subject_id: str,
    fallback: BaselineImportanceV1,
) -> tuple[BaselineImportanceV1, tuple[ImportanceBasisV1, ...], str]:
    for item in inputs.gradeable_baseline.requirements:
        if item.requirement.requirement_id == subject_id:
            value = item.requirement
            return value.importance, value.importance_basis, value.importance_rationale
    for contested_item in inputs.gradeable_baseline.contested_requirements:
        contest_value = contested_item.contested_requirement
        if contest_value.contested_requirement_id == subject_id:
            return (
                contest_value.importance,
                contest_value.importance_basis,
                contest_value.importance_rationale,
            )
    if fallback is BaselineImportanceV1.CRITICAL:
        return (
            fallback,
            (ImportanceBasisV1.LEGAL_BOTTOM_LINE,),
            "The unresolved prerequisite could change the scoped legal bottom line.",
        )
    if fallback is BaselineImportanceV1.MATERIAL:
        return (
            fallback,
            (ImportanceBasisV1.ATTORNEY_BRIEFING,),
            "The unresolved point is necessary for a competent attorney briefing.",
        )
    return (
        fallback,
        (ImportanceBasisV1.IMPLEMENTATION_DETAIL,),
        "The unresolved point supplies useful implementation detail.",
    )


def _candidate_kind(inputs: VerifiedReadinessInputsV1, candidate: SafetyGapCandidateV1) -> str:
    if candidate.origin in {GapOriginV1.REQUIREMENT, GapOriginV1.BASELINE_GAP}:
        return next(
            item.requirement.kind.value
            for item in inputs.gradeable_baseline.requirements
            if item.requirement.requirement_id == candidate.subject_id
        )
    if candidate.origin is GapOriginV1.CONTESTED_REQUIREMENT:
        return "contested_requirement"
    return "prerequisite"


def _baseline_order(inputs: VerifiedReadinessInputsV1, subject_id: str) -> int:
    for item in inputs.gradeable_baseline.requirements:
        if item.requirement.requirement_id == subject_id:
            return item.requirement.canonical_order
    for contested_item in inputs.gradeable_baseline.contested_requirements:
        contest = contested_item.contested_requirement
        if contest.contested_requirement_id == subject_id:
            alternatives = (
                contest.reviewer_alternative,
                contest.auditor_alternative,
            )
            return min(
                alternative.canonical_order
                for alternative in alternatives
                if alternative is not None
            )
    return 1_000_000


def compile_gap_follow_up_matrix_v1(
    inputs: VerifiedReadinessInputsV1,
    strict_equivalent: BaselineLockedStrictEquivalentV1,
    candidates: tuple[SafetyGapCandidateV1, ...],
    safety: ReconciledSafetyReviewV1,
) -> GapFollowUpMatrixV1:
    """Compile one immutable open row for every current gap and finding."""
    checked = _strict_inputs(inputs)
    if type(candidates) is not tuple:
        raise ValueError("gap candidate inventory is invalid")
    exact_candidates = tuple(
        _strict_candidate(checked, item, index) for index, item in enumerate(candidates, 1)
    )
    exact_strict = _strict_equivalent_for_inputs(checked, strict_equivalent)
    expected_candidates = _requests.build_gap_candidate_inventory_v1(
        checked,
        cast(
            tuple[
                BaselineLockedGraderAggregateV1,
                BaselineLockedGraderAggregateV1,
            ],
            tuple(exact_strict.grader_lanes),
        ),
    )
    if canonical_json_bytes(exact_candidates) != canonical_json_bytes(expected_candidates):
        raise ValueError("gap candidate inventory is invalid")
    exact_safety = _strict_safety(safety)
    assessments = {item.candidate_id: item for item in exact_safety.candidate_assessments}
    if tuple(assessments) != tuple(item.candidate_id for item in exact_candidates):
        raise ValueError("reconciled safety candidate coverage is invalid")
    pending: list[
        tuple[
            tuple[object, ...],
            GapOriginV1,
            str,
            str,
            BaselineImportanceV1,
            tuple[ImportanceBasisV1, ...],
            str,
            RequirementDispositionV1 | None,
            RequirementDispositionV1 | None,
            SafetyGapAssessmentV1 | SafetyFindingProposalV1,
        ]
    ] = []
    for candidate in exact_candidates:
        assessment = assessments[candidate.candidate_id]
        importance, basis, importance_rationale = _importance_contract(
            checked, candidate.subject_id, candidate.importance
        )
        pending.append(
            (
                (
                    _ORIGIN_PRIORITY[candidate.origin],
                    _baseline_order(checked, candidate.subject_id),
                    candidate.subject_id,
                    _candidate_kind(checked, candidate),
                    candidate.candidate_fingerprint,
                ),
                candidate.origin,
                candidate.subject_id,
                _candidate_kind(checked, candidate),
                importance,
                basis,
                importance_rationale,
                candidate.lane_1_disposition,
                candidate.lane_2_disposition,
                assessment,
            )
        )
    for finding in exact_safety.finding_proposals:
        importance, basis, importance_rationale = _importance_contract(
            checked, finding.subject_id, BaselineImportanceV1.MATERIAL
        )
        fingerprint = _fingerprint(finding.model_dump(mode="json"))
        pending.append(
            (
                (
                    _ORIGIN_PRIORITY[GapOriginV1.SAFETY_FINDING],
                    _baseline_order(checked, finding.subject_id),
                    finding.subject_id,
                    finding.finding_kind.value,
                    fingerprint,
                ),
                GapOriginV1.SAFETY_FINDING,
                finding.subject_id,
                finding.finding_kind.value,
                importance,
                basis,
                importance_rationale,
                None,
                None,
                finding,
            )
        )
    pending.sort(key=lambda item: item[0])
    rows: list[GapFollowUpRowV1] = []
    for index, (
        _,
        origin,
        subject_id,
        kind,
        importance,
        basis,
        importance_rationale,
        lane_1_disposition,
        lane_2_disposition,
        content,
    ) in enumerate(pending, 1):
        dispositions = tuple(
            item for item in (lane_1_disposition, lane_2_disposition) if item is not None
        )
        rows.append(
            _seal_model(
                GapFollowUpRowV1,
                "row_fingerprint",
                gap_id=f"GAP-{index:04d}",
                canonical_order=index - 1,
                origin=origin,
                subject_id=subject_id,
                kind=kind,
                importance=importance,
                importance_basis=basis,
                importance_rationale=importance_rationale,
                lane_1_disposition=lane_1_disposition,
                lane_2_disposition=lane_2_disposition,
                conservative_disposition=(
                    None if not dispositions else _conservative(dispositions)
                ),
                report_passages=content.report_passages,
                shortfall_description=content.shortfall_description,
                rationale_kind=content.rationale_kind,
                why_unresolved=content.why_unresolved,
                why_it_matters=content.why_it_matters,
                evidence_refs=content.evidence_refs,
                disclosure_location=content.disclosure_location,
                visibility=content.visibility,
                blocking_code=content.blocking_code,
                follow_up_code=content.follow_up_code,
                resolution_test=content.resolution_test,
                owner_role=content.owner_role,
                status="open",
                referee_dispute_id=None,
            )
        )
    return _seal_model(
        GapFollowUpMatrixV1,
        "matrix_fingerprint",
        grade_target_fingerprint=checked.readiness_input.grade_target_fingerprint,
        report_hash=checked.report_hash,
        rows=tuple(rows),
    )


def _verify_requirement_matrix(
    inputs: VerifiedReadinessInputsV1,
    strict: BaselineLockedStrictEquivalentV1,
    value: object,
) -> RequirementMatrixV1:
    checked = _strict_model(RequirementMatrixV1, value, label="requirement matrix")
    if checked.matrix_fingerprint != _fingerprint(
        checked.model_dump(mode="json", exclude={"matrix_fingerprint"})
    ):
        raise ValueError("requirement matrix is invalid")
    expected = compile_requirement_matrix_v1(
        inputs,
        cast(
            tuple[
                BaselineLockedGraderAggregateV1,
                BaselineLockedGraderAggregateV1,
            ],
            tuple(strict.grader_lanes),
        ),
    )
    if canonical_json_bytes(checked) != canonical_json_bytes(expected):
        raise ValueError("requirement matrix is invalid")
    return checked


def _verify_gap_matrix(inputs: VerifiedReadinessInputsV1, value: object) -> GapFollowUpMatrixV1:
    checked = _strict_model(GapFollowUpMatrixV1, value, label="gap matrix")
    if (
        checked.grade_target_fingerprint != inputs.readiness_input.grade_target_fingerprint
        or checked.report_hash != inputs.report_hash
        or checked.matrix_fingerprint
        != _fingerprint(checked.model_dump(mode="json", exclude={"matrix_fingerprint"}))
    ):
        raise ValueError("gap matrix is invalid")
    for row in checked.rows:
        if row.row_fingerprint != _fingerprint(
            row.model_dump(mode="json", exclude={"row_fingerprint"})
        ):
            raise ValueError("gap matrix is invalid")
    return checked


def _generic(value: str) -> bool:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    normalized = " ".join(
        "".join(
            character if character.isalnum() or character in {"_", "."} else " "
            for character in normalized
        ).split()
    )
    return bool(_GENERIC_ONLY.fullmatch(normalized))


def _contradictory_completeness_claim(value: str) -> bool:
    if _COMPLETENESS_CLAIM.search(value):
        return True
    normalized = unicodedata.normalize("NFKC", value).casefold()
    tokens = "".join(character if character.isalnum() else " " for character in normalized).split()
    quantifiers = {
        "all",
        "each",
        "every",
        "exhaustive",
        "exhaustively",
        "fully",
        "nothing",
    }
    completion = {
        "address",
        "addressed",
        "addresses",
        "comprehensive",
        "comprehensively",
        "cover",
        "covered",
        "covers",
        "resolve",
        "resolved",
        "resolves",
    }
    shortfalls = {
        "caveat",
        "caveats",
        "gap",
        "gaps",
        "issue",
        "issues",
        "limitation",
        "limitations",
        "omission",
        "omissions",
        "shortfall",
        "shortfalls",
        "uncertainties",
        "uncertainty",
    }
    quantifier_positions = [index for index, token in enumerate(tokens) if token in quantifiers]
    completion_positions = [index for index, token in enumerate(tokens) if token in completion]
    shortfall_positions = [index for index, token in enumerate(tokens) if token in shortfalls]
    return any(
        abs(quantifier - shortfall) <= 8 and abs(done - shortfall) <= 8
        for shortfall in shortfall_positions
        for quantifier in quantifier_positions
        for done in completion_positions
    )


def _gap_blockers(
    inputs: VerifiedReadinessInputsV1,
    requirement_matrix: RequirementMatrixV1,
    gap_matrix: GapFollowUpMatrixV1,
    strict: BaselineLockedStrictEquivalentV1,
    safety: ReconciledSafetyReviewV1,
) -> tuple[str, ...]:
    blockers: list[str] = []
    allowed_refs = {
        cast(str, handle["evidence_ref"]) for handle in _requests._evidence_handles(inputs)
    }
    expected_candidates = _requests.build_gap_candidate_inventory_v1(
        inputs,
        cast(
            tuple[
                BaselineLockedGraderAggregateV1,
                BaselineLockedGraderAggregateV1,
            ],
            tuple(strict.grader_lanes),
        ),
    )
    assessments = {item.candidate_id: item for item in safety.candidate_assessments}
    expected_content: dict[
        tuple[GapOriginV1, str, str],
        SafetyGapAssessmentV1 | SafetyFindingProposalV1,
    ] = {
        (candidate.origin, candidate.subject_id, ""): assessments[candidate.candidate_id]
        for candidate in expected_candidates
    }
    expected_content.update(
        {
            (GapOriginV1.SAFETY_FINDING, finding.subject_id, finding.finding_kind.value): finding
            for finding in safety.finding_proposals
        }
    )
    expected_metadata: dict[tuple[GapOriginV1, str, str], tuple[object, ...]] = {}
    for candidate in expected_candidates:
        importance, basis, importance_rationale = _importance_contract(
            inputs,
            candidate.subject_id,
            candidate.importance,
        )
        dispositions = tuple(
            disposition
            for disposition in (
                candidate.lane_1_disposition,
                candidate.lane_2_disposition,
            )
            if disposition is not None
        )
        content = assessments[candidate.candidate_id]
        expected_metadata[(candidate.origin, candidate.subject_id, "")] = (
            _candidate_kind(inputs, candidate),
            importance,
            basis,
            importance_rationale,
            candidate.lane_1_disposition,
            candidate.lane_2_disposition,
            None if not dispositions else _conservative(dispositions),
            content.blocking_code,
            None,
        )
    for finding in safety.finding_proposals:
        importance, basis, importance_rationale = _importance_contract(
            inputs,
            finding.subject_id,
            BaselineImportanceV1.MATERIAL,
        )
        expected_metadata[
            (
                GapOriginV1.SAFETY_FINDING,
                finding.subject_id,
                finding.finding_kind.value,
            )
        ] = (
            finding.finding_kind.value,
            importance,
            basis,
            importance_rationale,
            None,
            None,
            None,
            finding.blocking_code,
            None,
        )
    actual_content = {
        (
            row.origin,
            row.subject_id,
            row.kind if row.origin is GapOriginV1.SAFETY_FINDING else "",
        ): row
        for row in gap_matrix.rows
    }
    if len(actual_content) != len(gap_matrix.rows) or set(actual_content) != set(expected_content):
        blockers.append("MISSING_REQUIRED_FOLLOW_UP")

    for row in gap_matrix.rows:
        identity = (
            row.origin,
            row.subject_id,
            row.kind if row.origin is GapOriginV1.SAFETY_FINDING else "",
        )
        expected = expected_content.get(identity)
        metadata = expected_metadata.get(identity)
        if row.status != "open":
            blockers.append("FALSE_RESOLUTION")
        if row.blocking_code is not None:
            blockers.append(row.blocking_code)
        prose = (
            row.shortfall_description,
            row.why_unresolved,
            row.why_it_matters,
            row.resolution_test,
        )
        if (
            any(not item.strip() or _generic(item) for item in prose)
            or not row.evidence_refs
            or len(row.evidence_refs) != len(set(row.evidence_refs))
            or not set(row.evidence_refs).issubset(allowed_refs)
        ):
            blockers.append("GAP_RATIONALE_INVALID")
        if (
            row.visibility is GapVisibilityV1.HIDDEN
            or row.disclosure_location is None
            or not row.disclosure_location.strip()
            or not row.report_passages
            or any(inputs.report_text.count(passage) != 1 for passage in row.report_passages)
        ):
            blockers.append("HIDDEN_MATERIAL_GAP")
        if row.importance is BaselineImportanceV1.CRITICAL and (
            row.visibility is not GapVisibilityV1.PROMINENT
            or row.owner_role not in {OwnerRoleV1.REVIEWING_ATTORNEY, OwnerRoleV1.OUTSIDE_COUNSEL}
        ):
            blockers.append("CRITICAL_DISCLOSURE_INVALID")
        if expected is None:
            continue
        if (
            metadata is None
            or (
                row.kind,
                row.importance,
                row.importance_basis,
                row.importance_rationale,
                row.lane_1_disposition,
                row.lane_2_disposition,
                row.conservative_disposition,
                row.blocking_code,
                row.referee_dispute_id,
            )
            != metadata
        ):
            blockers.append("INTEGRITY_OR_PROVENANCE_INVALID")
        if (
            row.shortfall_description != expected.shortfall_description
            or row.rationale_kind is not expected.rationale_kind
            or row.why_unresolved != expected.why_unresolved
            or row.why_it_matters != expected.why_it_matters
            or row.evidence_refs != expected.evidence_refs
        ):
            blockers.append("GAP_RATIONALE_INVALID")
        if (
            row.report_passages != expected.report_passages
            or row.disclosure_location != expected.disclosure_location
            or row.visibility is not expected.visibility
        ):
            blockers.append("HIDDEN_MATERIAL_GAP")
        if (
            row.follow_up_code is not expected.follow_up_code
            or row.resolution_test != expected.resolution_test
            or row.owner_role is not expected.owner_role
        ):
            blockers.append("MISSING_REQUIRED_FOLLOW_UP")
    row_subjects = {
        row.subject_id
        for row in gap_matrix.rows
        if row.origin
        in {
            GapOriginV1.REQUIREMENT,
            GapOriginV1.BASELINE_GAP,
        }
    }
    for requirement_row in requirement_matrix.rows:
        if (
            requirement_row.conservative_disposition is not RequirementDispositionV1.MET
            and requirement_row.requirement_id not in row_subjects
        ):
            blockers.append("MISSING_REQUIRED_FOLLOW_UP")
    if strict.outcome_determinative_contested_ids:
        blockers.append("OUTCOME_DETERMINATIVE_CONTEST")
    if gap_matrix.rows and _contradictory_completeness_claim(inputs.report_text):
        blockers.append("HIDDEN_MATERIAL_GAP")
    return tuple(blockers)


def _lane_fraction(
    inputs: VerifiedReadinessInputsV1,
    lane: BaselineLockedGraderAggregateV1,
) -> tuple[int, int, int, int]:
    observations = _ordinary_observations(inputs.gradeable_baseline, lane)
    for item, grade in zip(
        inputs.gradeable_baseline.contested_requirements,
        lane.contested_grades,
        strict=True,
    ):
        contest = item.contested_requirement
        alternatives: list[RequirementDispositionV1] = []
        if contest.reviewer_alternative is not None:
            alternatives.append(grade.reviewer_alternative_disposition)
        if contest.auditor_alternative is not None:
            alternatives.append(grade.auditor_alternative_disposition)
        if not alternatives:
            raise ValueError("contested requirement has no gradeable alternative")
        observations.append((contest.importance, _conservative(alternatives)))
    score = _score(observations, inputs.readiness_rubric)
    return score[2], score[3], score[4], score[5]


def _historical_status(
    inputs: VerifiedReadinessInputsV1,
    strict_disposition: AbsoluteDispositionV2,
) -> tuple[AbsoluteDispositionV2 | None, HistoricalV22CrossCheckStatusV1]:
    historical = inputs.historical_v22
    if historical is None:
        return None, HistoricalV22CrossCheckStatusV1.NOT_PROVIDED
    if not historical.baseline_comparable:
        status = HistoricalV22CrossCheckStatusV1.BASELINE_NOT_COMPARABLE
    elif not historical.report_comparable:
        status = HistoricalV22CrossCheckStatusV1.REPORT_NOT_COMPARABLE
    elif historical.strict_disposition is strict_disposition:
        status = HistoricalV22CrossCheckStatusV1.MATCH
    else:
        status = HistoricalV22CrossCheckStatusV1.DISPOSITION_DIFFERS
    return historical.strict_disposition, status


def derive_delivery_readiness_v1(
    inputs: VerifiedReadinessInputsV1,
    strict_equivalent: BaselineLockedStrictEquivalentV1,
    requirement_matrix: RequirementMatrixV1,
    gap_matrix: GapFollowUpMatrixV1,
    safety: ReconciledSafetyReviewV1,
) -> DeliveryReadinessResultV1:
    """Derive the fail-closed tier, then attach optional historical context."""
    checked = _strict_inputs(inputs)
    strict = _strict_equivalent_for_inputs(checked, strict_equivalent)
    requirements = _verify_requirement_matrix(checked, strict, requirement_matrix)
    gaps = _verify_gap_matrix(checked, gap_matrix)
    exact_safety = _strict_safety(safety)
    fractions = tuple(_lane_fraction(checked, lane) for lane in strict.grader_lanes)
    weighted = tuple(
        1.0 if denominator == 0 else numerator / denominator
        for numerator, denominator, _, _ in fractions
    )
    critical = tuple(
        1.0 if denominator == 0 else numerator / denominator
        for _, _, numerator, denominator in fractions
    )
    coverage_floor_met = all(
        denominator == 0 or 10 * numerator >= 7 * denominator
        for numerator, denominator, _, _ in fractions
    )
    high_weight_met = all(
        denominator == 0 or 10 * numerator >= 9 * denominator
        for numerator, denominator, _, _ in fractions
    )
    high_critical_met = all(
        denominator == 0 or numerator == denominator for _, _, numerator, denominator in fractions
    )
    blockers = [*exact_safety.blocking_codes]
    expected_candidates = _requests.build_gap_candidate_inventory_v1(
        checked,
        cast(
            tuple[
                BaselineLockedGraderAggregateV1,
                BaselineLockedGraderAggregateV1,
            ],
            tuple(strict.grader_lanes),
        ),
    )
    if tuple(item.candidate_id for item in exact_safety.candidate_assessments) != tuple(
        item.candidate_id for item in expected_candidates
    ):
        raise ValueError("reconciled safety candidate coverage is invalid")
    blockers.extend(_gap_blockers(checked, requirements, gaps, strict, exact_safety))
    if not coverage_floor_met:
        blockers.append("MINIMUM_LANE_COVERAGE_BELOW_FLOOR")
    blocker_set = set(blockers)
    ordered_blockers = tuple(
        code for code in checked.readiness_rubric.blocking_codes if code in blocker_set
    )
    high_disqualifying_gap = any(
        row.origin
        in {
            GapOriginV1.BASELINE_GAP,
            GapOriginV1.CONTESTED_REQUIREMENT,
            GapOriginV1.PREREQUISITE,
            GapOriginV1.SAFETY_FINDING,
        }
        for row in gaps.rows
    )
    if ordered_blockers or not coverage_floor_met:
        tier = DeliveryReadinessTierV1.NOT_DELIVERABLE
    elif (
        strict.absolute_disposition is AbsoluteDispositionV2.PASS
        and high_weight_met
        and high_critical_met
        and not high_disqualifying_gap
        and checked.generation_validation.status == "completed"
        and checked.generation_validation.evidence_precision_valid
        and checked.generation_validation.proposition_coverage_valid
        and checked.generation_validation.provision_recall_valid
    ):
        tier = DeliveryReadinessTierV1.HIGH_ASSURANCE
    else:
        tier = DeliveryReadinessTierV1.REVIEW_READY_WITH_GAPS

    historical_disposition, historical_status = _historical_status(
        checked, strict.absolute_disposition
    )
    return _seal_model(
        DeliveryReadinessResultV1,
        "result_fingerprint",
        protocol_version="delivery-readiness-v1",
        baseline_locked_strict_equivalent_disposition=strict.absolute_disposition,
        historical_v22_strict_disposition=historical_disposition,
        historical_v22_cross_check_status=historical_status,
        delivery_readiness=tier,
        minimum_lane_weighted_coverage=min(weighted),
        lane_critical_recall=critical,
        lane_weighted_coverage=weighted,
        requirement_matrix_fingerprint=requirements.matrix_fingerprint,
        gap_matrix_fingerprint=gaps.matrix_fingerprint,
        blocking_codes=ordered_blockers,
        attorney_review_warning=checked.readiness_rubric.attorney_review_warning,
    )


__all__ = [
    "aggregate_baseline_locked_grader_lane_v1",
    "compile_gap_follow_up_matrix_v1",
    "compile_requirement_matrix_v1",
    "derive_baseline_locked_strict_equivalent_v1",
    "derive_delivery_readiness_v1",
    "reconcile_safety_lanes_v1",
]
