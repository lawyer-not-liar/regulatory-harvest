"""Deterministic private Markdown handoff for delivery-readiness-v1."""

from __future__ import annotations

import math
import re
import unicodedata
from collections.abc import Mapping, Sequence
from enum import Enum
from typing import TypeVar, cast

from pydantic import BaseModel, ValidationError

from regulatory_harvest.evaluation import attorney_readiness_models as _models
from regulatory_harvest.evaluation.attorney_baseline_models import (
    BaselineImportanceV1,
    ImportanceBasisV1,
)
from regulatory_harvest.evaluation.attorney_readiness_models import (
    DeliveryReadinessResultV1,
    DeliveryReadinessTierV1,
    FollowUpCodeV1,
    GapFollowUpMatrixV1,
    GapFollowUpRowV1,
    GapOriginV1,
    GapVisibilityV1,
    HistoricalV22CrossCheckStatusV1,
    OwnerRoleV1,
    RationaleKindV1,
    RequirementDispositionV1,
    RequirementMatrixRowV1,
    RequirementMatrixV1,
    load_readiness_rubric_v1,
)
from regulatory_harvest.evaluation.attorney_v2_models import AbsoluteDispositionV2
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

_MAX_DEPTH = 32
_MAX_NODES = 100_000
_MAX_BYTES = 16 * 1024 * 1024

_TRUSTED_MODEL_TYPES = frozenset(
    {
        RequirementMatrixV1,
        RequirementMatrixRowV1,
        GapFollowUpMatrixV1,
        GapFollowUpRowV1,
        DeliveryReadinessResultV1,
    }
)
_TRUSTED_ENUM_TYPES = frozenset(
    {
        AbsoluteDispositionV2,
        BaselineImportanceV1,
        DeliveryReadinessTierV1,
        FollowUpCodeV1,
        GapOriginV1,
        GapVisibilityV1,
        HistoricalV22CrossCheckStatusV1,
        ImportanceBasisV1,
        OwnerRoleV1,
        RationaleKindV1,
        RequirementDispositionV1,
    }
)
_TRUSTED_MAPPING_TYPES = frozenset({dict, _models._FrozenDict})
_TRUSTED_SEQUENCE_TYPES = frozenset(
    {list, tuple, _models._FrozenJsonList, _models._FrozenWireTuple}
)

_IMPORTANCE_PRIORITY = {
    BaselineImportanceV1.CRITICAL: 0,
    BaselineImportanceV1.MATERIAL: 1,
    BaselineImportanceV1.SUPPORTING: 2,
}
_OWNER_PRIORITY = {
    OwnerRoleV1.OUTSIDE_COUNSEL: 0,
    OwnerRoleV1.REVIEWING_ATTORNEY: 1,
    OwnerRoleV1.RESEARCH_OPERATOR: 2,
}
_DISPOSITION_PRIORITY = {
    RequirementDispositionV1.UNCERTAIN: 0,
    RequirementDispositionV1.NOT_MET: 1,
    RequirementDispositionV1.PARTIALLY_MET: 2,
    RequirementDispositionV1.MET: 3,
}

_REMEDIATION_CLASS = {
    "INTEGRITY_OR_PROVENANCE_INVALID": "provenance_and_integrity_review",
    "MINIMUM_LANE_COVERAGE_BELOW_FLOOR": "minimum_coverage_remediation",
    "MATERIAL_UNSUPPORTED_ASSERTION": "unsupported_assertion_correction",
    "BASELINE_CONTRADICTION": "baseline_contradiction_resolution",
    "HIDDEN_MATERIAL_GAP": "gap_visibility_correction",
    "UNDISCLOSED_DISPOSITIVE_CLIENT_FACT": "client_fact_boundary_resolution",
    "MISLEADING_CURRENTNESS_OR_AUTHORITY": "authority_and_currentness_review",
    "OUTCOME_DETERMINATIVE_CONTEST": "contested_interpretation_resolution",
    "MISSING_REQUIRED_FOLLOW_UP": "follow_up_assignment",
    "GAP_RATIONALE_INVALID": "gap_rationale_correction",
    "CRITICAL_DISCLOSURE_INVALID": "critical_disclosure_correction",
    "FALSE_RESOLUTION": "resolution_status_correction",
}
_GENERIC_ONLY = re.compile(
    r"^(?:more research (?:is )?needed|insufficient information|requirement partially met|"
    r"(?:requirement )?(?:is )?(?:partially met|not met|uncertain|met)|partially_met|"
    r"not_met|[01](?:\.0|\.5)?)$"
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _invalid() -> ValueError:
    return ValueError("attorney readiness handoff input is invalid")


def _charge_amount(amount: int, budget: list[int]) -> None:
    budget[1] += amount
    if budget[1] > _MAX_BYTES:
        raise _invalid()


def _charge_text(value: str, budget: list[int]) -> None:
    if "\r" in value or len(value) > _MAX_BYTES:
        raise _invalid()
    # Match or conservatively exceed ensure_ascii=False JSON string encoding
    # without allocating the escaped representation.
    cost = 2
    remaining = _MAX_BYTES - budget[1]
    for character in value:
        codepoint = ord(character)
        if codepoint < 0x20:
            cost += 6
        elif character in {'"', "\\"}:
            cost += 2
        elif codepoint < 0x80:
            cost += 1
        elif codepoint < 0x800:
            cost += 2
        elif 0xD800 <= codepoint <= 0xDFFF:
            raise _invalid()
        elif codepoint < 0x10000:
            cost += 3
        else:
            cost += 4
        if cost > remaining:
            raise _invalid()
    _charge_amount(cost, budget)


def _preflight(value: object, *, budget: list[int] | None = None) -> None:
    """Bound and type-check native state before Pydantic or JSON can traverse it."""
    current_budget = [0, 0] if budget is None else budget
    active: set[int] = set()

    def visit(item: object, depth: int) -> None:
        current_budget[0] += 1
        if current_budget[0] > _MAX_NODES or depth > _MAX_DEPTH:
            raise _invalid()
        if item is None:
            _charge_amount(4, current_budget)
            return
        if type(item) is bool:
            _charge_amount(5, current_budget)
            return
        if type(item) is int:
            integer = item
            bits = abs(integer).bit_length()
            if bits > 4096:
                raise _invalid()
            decimal_digits = max(1, (bits * 30103) // 100000 + 1)
            _charge_amount(decimal_digits + (1 if integer < 0 else 0), current_budget)
            return
        if type(item) is float:
            if not math.isfinite(item):
                raise _invalid()
            _charge_amount(32, current_budget)
            return
        if type(item) is str:
            _charge_text(item, current_budget)
            return
        if isinstance(item, Enum):
            if type(item) not in _TRUSTED_ENUM_TYPES:
                raise _invalid()
            enum_value = item.value
            if type(enum_value) is not str:
                raise _invalid()
            _charge_text(enum_value, current_budget)
            return
        if isinstance(item, BaseModel):
            if type(item) not in _TRUSTED_MODEL_TYPES:
                raise _invalid()
            identity = id(item)
            if identity in active:
                raise _invalid()
            active.add(identity)
            try:
                state = item.__dict__
                if type(state) is not dict:
                    raise _invalid()
                _charge_amount(2 + 2 * len(state), current_budget)
                for key, nested in state.items():
                    if type(key) is not str:
                        raise _invalid()
                    _charge_text(key, current_budget)
                    visit(nested, depth + 1)
            finally:
                active.remove(identity)
            return
        item_type = type(item)
        if item_type in _TRUSTED_MAPPING_TYPES:
            identity = id(item)
            if identity in active:
                raise _invalid()
            active.add(identity)
            try:
                mapping = cast(Mapping[object, object], item)
                _charge_amount(2 + 2 * len(mapping), current_budget)
                for map_key, nested in mapping.items():
                    if type(map_key) is not str:
                        raise _invalid()
                    _charge_text(map_key, current_budget)
                    visit(nested, depth + 1)
            finally:
                active.remove(identity)
            return
        if item_type in _TRUSTED_SEQUENCE_TYPES:
            identity = id(item)
            if identity in active:
                raise _invalid()
            active.add(identity)
            try:
                sequence = cast(Sequence[object], item)
                _charge_amount(2 + len(sequence), current_budget)
                for nested in sequence:
                    visit(nested, depth + 1)
            finally:
                active.remove(identity)
            return
        raise _invalid()

    visit(value, 0)


def _same_runtime_shape(left: object, right: object) -> bool:
    """Reject model_construct normalization and unsafe caller containers."""
    if type(left) is not type(right):
        return False
    if isinstance(left, BaseModel):
        if type(left) not in _TRUSTED_MODEL_TYPES:
            return False
        left_state = left.__dict__
        right_state = cast(BaseModel, right).__dict__
        return left_state.keys() == right_state.keys() and all(
            _same_runtime_shape(left_state[key], right_state[key]) for key in left_state
        )
    if type(left) in _TRUSTED_MAPPING_TYPES:
        left_map = cast(Mapping[str, object], left)
        right_map = cast(Mapping[str, object], right)
        return left_map.keys() == right_map.keys() and all(
            _same_runtime_shape(left_map[key], right_map[key]) for key in left_map
        )
    if type(left) in _TRUSTED_SEQUENCE_TYPES:
        left_items = cast(Sequence[object], left)
        right_items = cast(Sequence[object], right)
        return len(left_items) == len(right_items) and all(
            _same_runtime_shape(first, second)
            for first, second in zip(left_items, right_items, strict=True)
        )
    return True


def _strict_model(model_type: type[_ModelT], value: object) -> _ModelT:
    if type(value) is not model_type:
        raise _invalid()
    try:
        _preflight(value)
        wire = cast(BaseModel, value).model_dump(mode="json", warnings="error")
        checked = model_type.model_validate(wire)
        _preflight(checked)
        if not _same_runtime_shape(value, checked):
            raise _invalid()
        if canonical_json_bytes(wire) != canonical_json_bytes(
            checked.model_dump(mode="json", warnings="error")
        ):
            raise _invalid()
        return checked
    except (
        AttributeError,
        RecursionError,
        TypeError,
        UnicodeError,
        ValidationError,
        ValueError,
    ):
        raise _invalid() from None


def _fingerprint(model: BaseModel, field: str) -> str:
    return sha256_digest(canonical_json_bytes(model.model_dump(mode="json", exclude={field})))


def _generic(value: str) -> bool:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    normalized = " ".join(
        "".join(
            character if character.isalnum() or character in {"_", "."} else " "
            for character in normalized
        ).split()
    )
    normalized = normalized.rstrip(".")
    return bool(_GENERIC_ONLY.fullmatch(normalized))


def _validate_delivery_semantics(
    report: str,
    requirements: RequirementMatrixV1,
    gaps: GapFollowUpMatrixV1,
    result: DeliveryReadinessResultV1,
) -> None:
    rubric = load_readiness_rubric_v1()
    ordered_blockers = tuple(
        code for code in rubric.blocking_codes if code in set(result.blocking_codes)
    )
    if result.blocking_codes != ordered_blockers:
        raise _invalid()

    historical = result.historical_v22_strict_disposition
    status = result.historical_v22_cross_check_status
    fresh = result.baseline_locked_strict_equivalent_disposition
    if (status is HistoricalV22CrossCheckStatusV1.MATCH and historical is not fresh) or (
        status is HistoricalV22CrossCheckStatusV1.DISPOSITION_DIFFERS and historical is fresh
    ):
        raise _invalid()

    if result.delivery_readiness is DeliveryReadinessTierV1.NOT_DELIVERABLE:
        return
    if result.minimum_lane_weighted_coverage < rubric.review_ready_weighted_coverage_floor:
        raise _invalid()

    def lane_disposition(
        observations: Sequence[tuple[BaselineImportanceV1, RequirementDispositionV1]],
    ) -> AbsoluteDispositionV2:
        if any(
            disposition is RequirementDispositionV1.UNCERTAIN for _, disposition in observations
        ):
            return AbsoluteDispositionV2.INCONCLUSIVE
        denominator = 2 * sum(
            rubric.strict_importance_weights[importance] for importance, _ in observations
        )
        numerator = sum(
            rubric.strict_importance_weights[importance]
            * (2 if disposition is RequirementDispositionV1.MET else 1)
            for importance, disposition in observations
            if disposition in {RequirementDispositionV1.MET, RequirementDispositionV1.PARTIALLY_MET}
        )
        if any(
            disposition is not RequirementDispositionV1.MET
            for importance, disposition in observations
            if importance is BaselineImportanceV1.CRITICAL
        ) or (denominator and 10 * numerator < 9 * denominator):
            return AbsoluteDispositionV2.FAIL
        return AbsoluteDispositionV2.PASS

    requirement_by_id = {row.requirement_id: row for row in requirements.rows}
    contested_rows = tuple(
        row for row in gaps.rows if row.origin is GapOriginV1.CONTESTED_REQUIREMENT
    )
    if len({row.subject_id for row in contested_rows}) != len(contested_rows):
        raise _invalid()

    for gap_row in gaps.rows:
        prose = (
            gap_row.shortfall_description,
            gap_row.why_unresolved,
            gap_row.why_it_matters,
            gap_row.resolution_test,
        )
        if (
            any(_generic(item) for item in prose)
            or not gap_row.evidence_refs
            or gap_row.visibility is GapVisibilityV1.HIDDEN
            or gap_row.disclosure_location is None
            or gap_row.disclosure_location not in report
            or not gap_row.report_passages
            or any(report.count(passage) != 1 for passage in gap_row.report_passages)
            or gap_row.blocking_code is not None
        ):
            raise _invalid()
        if gap_row.origin in {GapOriginV1.REQUIREMENT, GapOriginV1.BASELINE_GAP}:
            requirement_row = requirement_by_id.get(gap_row.subject_id)
            if requirement_row is None or (
                gap_row.kind,
                gap_row.importance,
                gap_row.importance_basis,
                gap_row.importance_rationale,
                gap_row.lane_1_disposition,
                gap_row.lane_2_disposition,
                gap_row.conservative_disposition,
            ) != (
                requirement_row.kind,
                requirement_row.importance,
                requirement_row.importance_basis,
                requirement_row.importance_rationale,
                requirement_row.lane_1_disposition,
                requirement_row.lane_2_disposition,
                requirement_row.conservative_disposition,
            ):
                raise _invalid()
        if gap_row.importance is BaselineImportanceV1.CRITICAL and (
            gap_row.visibility is not GapVisibilityV1.PROMINENT
            or gap_row.owner_role
            not in {OwnerRoleV1.REVIEWING_ATTORNEY, OwnerRoleV1.OUTSIDE_COUNSEL}
        ):
            raise _invalid()

    lane_weighted: list[float] = []
    lane_critical: list[float] = []
    ordinary_lane_dispositions: list[AbsoluteDispositionV2] = []
    combined_lane_dispositions: list[AbsoluteDispositionV2] = []
    for lane in (1, 2):
        observations: list[tuple[BaselineImportanceV1, RequirementDispositionV1]] = [
            (
                row.importance,
                row.lane_1_disposition if lane == 1 else row.lane_2_disposition,
            )
            for row in requirements.rows
        ]
        ordinary_lane_dispositions.append(lane_disposition(observations))
        for row in contested_rows:
            disposition = row.lane_1_disposition if lane == 1 else row.lane_2_disposition
            if disposition is None:
                raise _invalid()
            observations.append((row.importance, disposition))
        combined_lane_dispositions.append(lane_disposition(observations))
        denominator = 2 * sum(
            rubric.strict_importance_weights[importance] for importance, _ in observations
        )
        numerator = sum(
            rubric.strict_importance_weights[importance]
            * (2 if disposition is RequirementDispositionV1.MET else 1)
            for importance, disposition in observations
            if disposition in {RequirementDispositionV1.MET, RequirementDispositionV1.PARTIALLY_MET}
        )
        critical = [
            disposition
            for importance, disposition in observations
            if importance is BaselineImportanceV1.CRITICAL
        ]
        critical_numerator = sum(
            2 if disposition is RequirementDispositionV1.MET else 1
            for disposition in critical
            if disposition in {RequirementDispositionV1.MET, RequirementDispositionV1.PARTIALLY_MET}
        )
        lane_weighted.append(1.0 if denominator == 0 else numerator / denominator)
        lane_critical.append(1.0 if not critical else critical_numerator / (2 * len(critical)))
    if result.lane_weighted_coverage != tuple(
        lane_weighted
    ) or result.lane_critical_recall != tuple(lane_critical):
        raise _invalid()

    ordinary_disposition = (
        ordinary_lane_dispositions[0]
        if ordinary_lane_dispositions[0] is ordinary_lane_dispositions[1]
        else AbsoluteDispositionV2.INCONCLUSIVE
    )
    combined_disposition = (
        combined_lane_dispositions[0]
        if combined_lane_dispositions[0] is combined_lane_dispositions[1]
        else AbsoluteDispositionV2.INCONCLUSIVE
    )
    if ordinary_disposition is AbsoluteDispositionV2.INCONCLUSIVE:
        disposition_valid = fresh is AbsoluteDispositionV2.INCONCLUSIVE
    elif not contested_rows:
        disposition_valid = fresh is ordinary_disposition
    else:
        disposition_valid = fresh in {
            ordinary_disposition,
            combined_disposition,
            AbsoluteDispositionV2.INCONCLUSIVE,
        }
    if not disposition_valid:
        raise _invalid()

    gap_identities = {(row.origin, row.subject_id) for row in gaps.rows}
    for requirement_row in requirements.rows:
        if (
            requirement_row.conservative_disposition is not RequirementDispositionV1.MET
            and (
                GapOriginV1.REQUIREMENT,
                requirement_row.requirement_id,
            )
            not in gap_identities
        ):
            raise _invalid()
        if (
            requirement_row.kind == "gap"
            and (
                GapOriginV1.BASELINE_GAP,
                requirement_row.requirement_id,
            )
            not in gap_identities
        ):
            raise _invalid()

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
    high_eligible = (
        fresh is AbsoluteDispositionV2.PASS
        and all(
            score >= rubric.high_assurance_weighted_coverage_floor
            for score in result.lane_weighted_coverage
        )
        and all(
            score >= rubric.high_assurance_critical_recall_floor
            for score in result.lane_critical_recall
        )
        and not high_disqualifying_gap
    )
    expected = (
        DeliveryReadinessTierV1.HIGH_ASSURANCE
        if high_eligible
        else DeliveryReadinessTierV1.REVIEW_READY_WITH_GAPS
    )
    if result.delivery_readiness is not expected:
        raise _invalid()


def _validate_bindings(
    report_text: object,
    requirement_matrix: object,
    gap_matrix: object,
    result: object,
) -> tuple[str, RequirementMatrixV1, GapFollowUpMatrixV1, DeliveryReadinessResultV1]:
    if type(report_text) is not str:
        raise _invalid()
    combined_budget = [0, 0]
    for item in (report_text, requirement_matrix, gap_matrix, result):
        _preflight(item, budget=combined_budget)
    requirements = _strict_model(RequirementMatrixV1, requirement_matrix)
    gaps = _strict_model(GapFollowUpMatrixV1, gap_matrix)
    checked_result = _strict_model(DeliveryReadinessResultV1, result)
    report = report_text
    report_hash = sha256_digest(report.encode("utf-8"))

    if (
        requirements.matrix_fingerprint != _fingerprint(requirements, "matrix_fingerprint")
        or gaps.matrix_fingerprint != _fingerprint(gaps, "matrix_fingerprint")
        or checked_result.result_fingerprint != _fingerprint(checked_result, "result_fingerprint")
        or any(
            row.row_fingerprint != _fingerprint(row, "row_fingerprint") for row in requirements.rows
        )
        or any(row.row_fingerprint != _fingerprint(row, "row_fingerprint") for row in gaps.rows)
        or requirements.report_hash != report_hash
        or gaps.report_hash != report_hash
        or requirements.grade_target_fingerprint != gaps.grade_target_fingerprint
        or checked_result.requirement_matrix_fingerprint != requirements.matrix_fingerprint
        or checked_result.gap_matrix_fingerprint != gaps.matrix_fingerprint
        or checked_result.attorney_review_warning
        != load_readiness_rubric_v1().attorney_review_warning
        or checked_result.minimum_lane_weighted_coverage
        != min(checked_result.lane_weighted_coverage)
        or any(row.status != "open" for row in gaps.rows)
    ):
        raise _invalid()

    has_blockers = bool(checked_result.blocking_codes)
    if (
        checked_result.delivery_readiness is DeliveryReadinessTierV1.NOT_DELIVERABLE
    ) != has_blockers:
        raise _invalid()
    if any(code not in _REMEDIATION_CLASS for code in checked_result.blocking_codes):
        raise _invalid()

    for requirement_row in requirements.rows:
        expected = min(
            (requirement_row.lane_1_disposition, requirement_row.lane_2_disposition),
            key=_DISPOSITION_PRIORITY.__getitem__,
        )
        if requirement_row.conservative_disposition is not expected:
            raise _invalid()
        if any(
            report.count(passage) != 1
            for passage in (
                *requirement_row.lane_1_report_passages,
                *requirement_row.lane_2_report_passages,
            )
        ):
            raise _invalid()
    for gap_row in gaps.rows:
        dispositions = tuple(
            item
            for item in (gap_row.lane_1_disposition, gap_row.lane_2_disposition)
            if item is not None
        )
        if dispositions:
            expected = min(dispositions, key=_DISPOSITION_PRIORITY.__getitem__)
            if gap_row.conservative_disposition is not expected:
                raise _invalid()
        elif gap_row.conservative_disposition is not None:
            raise _invalid()
        if any(report.count(passage) != 1 for passage in gap_row.report_passages):
            raise _invalid()
    _validate_delivery_semantics(report, requirements, gaps, checked_result)
    return report, requirements, gaps, checked_result


def _cell(value: object) -> str:
    if value is None:
        return "not_applicable"
    text = str(value.value) if isinstance(value, Enum) else str(value)
    text = text.replace("\\", "\\\\")
    for token in ("`", "*", "_", "[", "]", "<", ">", "#", "|"):
        text = text.replace(token, "\\" + token)
    return text.replace("\n", "<br>")


def _items(values: Sequence[object]) -> str:
    return "<br>".join(_cell(value) for value in values) if values else "none"


def _requirement_matrix_markdown(matrix: RequirementMatrixV1) -> str:
    lines = [
        "## Requirement matrix",
        "",
        f"Matrix fingerprint: `{matrix.matrix_fingerprint}`",
        "",
        "| ID | Statement | Kind | Importance | Importance basis | Importance rationale | "
        "Lane 1 | Lane 2 | Conservative | Lane 1 report passages | "
        "Lane 2 report passages | Row fingerprint |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in matrix.rows:
        lines.append(
            "| "
            + " | ".join(
                (
                    _cell(row.requirement_id),
                    _cell(row.statement),
                    _cell(row.kind),
                    _cell(row.importance),
                    _items(row.importance_basis),
                    _cell(row.importance_rationale),
                    _cell(row.lane_1_disposition),
                    _cell(row.lane_2_disposition),
                    _cell(row.conservative_disposition),
                    _items(row.lane_1_report_passages),
                    _items(row.lane_2_report_passages),
                    _cell(row.row_fingerprint),
                )
            )
            + " |"
        )
    return "\n".join(lines)


def _prioritized_actions(rows: Sequence[GapFollowUpRowV1]) -> str:
    groups: dict[tuple[FollowUpCodeV1, OwnerRoleV1], list[GapFollowUpRowV1]] = {}
    for row in rows:
        groups.setdefault((row.follow_up_code, row.owner_role), []).append(row)

    def priority(
        item: tuple[tuple[FollowUpCodeV1, OwnerRoleV1], list[GapFollowUpRowV1]],
    ) -> tuple[int, int, int, str]:
        (follow_up, owner), members = item
        return (
            min(_IMPORTANCE_PRIORITY[row.importance] for row in members),
            _OWNER_PRIORITY[owner],
            min(row.canonical_order for row in members),
            follow_up.value,
        )

    lines = ["## Prioritized follow-up actions", ""]
    for number, ((follow_up, owner), members) in enumerate(sorted(groups.items(), key=priority), 1):
        ordered = sorted(members, key=lambda row: row.canonical_order)
        gap_ids = ", ".join(f"`{row.gap_id}`" for row in ordered)
        highest = min(ordered, key=lambda row: _IMPORTANCE_PRIORITY[row.importance]).importance
        lines.append(
            f"{number}. **{follow_up.value}** — owner: `{owner.value}`; "
            f"gaps: {gap_ids}; highest importance: `{highest.value}`."
        )
    if not groups:
        lines.append("No open follow-up action is recorded.")
    return "\n".join(lines)


def _gap_matrix_markdown(matrix: GapFollowUpMatrixV1) -> str:
    lines = [
        "## Complete gap-and-follow-up matrix",
        "",
        f"Matrix fingerprint: `{matrix.matrix_fingerprint}`",
    ]
    for row in matrix.rows:
        lines.extend(
            (
                "",
                f"### {row.gap_id}",
                "",
                f"- Origin: `{row.origin.value}`",
                f"- Subject: {_cell(row.subject_id)}",
                f"- Kind: {_cell(row.kind)}",
                f"- Importance: `{row.importance.value}`",
                f"- Importance basis: {_items(row.importance_basis)}",
                f"- Importance rationale: {_cell(row.importance_rationale)}",
                f"- Lane 1 disposition: {_cell(row.lane_1_disposition)}",
                f"- Lane 2 disposition: {_cell(row.lane_2_disposition)}",
                f"- Conservative disposition: {_cell(row.conservative_disposition)}",
                f"- Rationale kind: `{row.rationale_kind.value}`",
                f"- Report passages: {_items(row.report_passages)}",
                f"- Evidence references: {_items(row.evidence_refs)}",
                f"- Disclosure location: {_cell(row.disclosure_location)}",
                f"- Visibility: `{row.visibility.value}`",
                f"- Blocking code: {_cell(row.blocking_code)}",
                f"- Follow-up code: `{row.follow_up_code.value}`",
                f"- Status: `{row.status}`",
                f"- Referee dispute: {_cell(row.referee_dispute_id)}",
                f"- Row fingerprint: `{row.row_fingerprint}`",
                "",
                "#### What is missing",
                "",
                _cell(row.shortfall_description),
                "",
                "Why unresolved: " + _cell(row.why_unresolved),
                "",
                "#### Why it matters",
                "",
                _cell(row.why_it_matters),
                "",
                "#### How to resolve it",
                "",
                _cell(row.resolution_test),
                "",
                "#### Owner",
                "",
                f"`{row.owner_role.value}`",
            )
        )
    if not matrix.rows:
        lines.extend(("", "No open gap row is recorded."))
    return "\n".join(lines)


def _evaluation_context(result: DeliveryReadinessResultV1) -> str:
    lines = [
        "## Evaluation context",
        "",
        "Baseline-locked strict-equivalent disposition: "
        + result.baseline_locked_strict_equivalent_disposition.value,
    ]
    if result.historical_v22_strict_disposition is not None:
        lines.extend(
            (
                "Historical Protocol 2.2 strict disposition: "
                + result.historical_v22_strict_disposition.value,
                "Historical cross-check status: " + result.historical_v22_cross_check_status.value,
            )
        )
    lines.extend(
        (
            f"Minimum lane weighted coverage: {result.minimum_lane_weighted_coverage:.6f}",
            "Lane weighted coverage: "
            + ", ".join(f"{score:.6f}" for score in result.lane_weighted_coverage),
            "Lane critical recall: "
            + ", ".join(f"{score:.6f}" for score in result.lane_critical_recall),
        )
    )
    return "\n".join(lines)


def _report_markdown(report: str) -> str:
    longest = 0
    current = 0
    for character in report:
        if character == "`":
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    fence = "`" * max(3, longest + 1)
    delimiter = "" if report.endswith("\n") else "\n"
    return f"## Report\n\n{fence}markdown\n{report}{delimiter}{fence}"


def _nondelivery(result: DeliveryReadinessResultV1) -> bytes:
    lines = [
        "# Attorney Review Handoff",
        "",
        "> **Delivery readiness: NOT_DELIVERABLE**",
        "",
        "This status suppresses attorney work product until the blocking classes are remediated.",
        "",
        "## Blocking reason codes",
        "",
    ]
    lines.extend(f"- `{code}`" for code in result.blocking_codes)
    lines.extend(("", "## Operator-safe remediation", ""))
    lines.extend(f"- `{code}`: `{_REMEDIATION_CLASS[code]}`" for code in result.blocking_codes)
    lines.extend(
        (
            "",
            "## Attorney-review warning",
            "",
            result.attorney_review_warning,
        )
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


def render_attorney_review_handoff_v1(
    *,
    report_text: str,
    requirement_matrix: RequirementMatrixV1,
    gap_matrix: GapFollowUpMatrixV1,
    result: DeliveryReadinessResultV1,
) -> bytes:
    """Render the exact verified result as byte-stable private Markdown."""
    report, requirements, gaps, checked_result = _validate_bindings(
        report_text,
        requirement_matrix,
        gap_matrix,
        result,
    )
    if checked_result.delivery_readiness is DeliveryReadinessTierV1.NOT_DELIVERABLE:
        return _nondelivery(checked_result)

    label = checked_result.delivery_readiness.value
    parts = [
        "# Attorney Review Handoff",
        f"> **Delivery readiness: {label}**\n>\n> Qualified-attorney review required "
        "before any legal advice or client delivery."
        + (
            "\n>\n> Known gaps remain open and are stated below with evidence-bound reasons, "
            "resolution tests, and assigned follow-up owners."
            if checked_result.delivery_readiness is DeliveryReadinessTierV1.REVIEW_READY_WITH_GAPS
            else ""
        ),
        _evaluation_context(checked_result),
        _report_markdown(report),
        _requirement_matrix_markdown(requirements),
    ]
    if checked_result.delivery_readiness is DeliveryReadinessTierV1.REVIEW_READY_WITH_GAPS:
        parts.append(_prioritized_actions(gaps.rows))
    parts.extend(
        (
            _gap_matrix_markdown(gaps),
            "## Attorney-review warning\n\n" + checked_result.attorney_review_warning,
        )
    )
    return ("\n\n".join(parts) + "\n").encode("utf-8")


__all__ = ["render_attorney_review_handoff_v1"]
