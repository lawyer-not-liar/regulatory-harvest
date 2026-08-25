"""Deterministic private attorney handoff rendering."""

from __future__ import annotations

import traceback
from pathlib import Path
from typing import cast
from unittest.mock import patch

import pytest
from test_attorney_readiness_compiler import (
    _clean_qualification,
    _compile,
    _lanes,
    _request_inputs_fixture,
    _with_requirements,
)

from regulatory_harvest.evaluation import attorney_readiness_handoff as handoff_module
from regulatory_harvest.evaluation.attorney_readiness_handoff import (
    render_attorney_review_handoff_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_inputs import (
    VerifiedReadinessInputsV1,
)
from regulatory_harvest.evaluation.attorney_readiness_models import (
    DeliveryReadinessResultV1,
    GapFollowUpMatrixV1,
    GapFollowUpRowV1,
    RequirementMatrixRowV1,
    RequirementMatrixV1,
    load_readiness_rubric_v1,
)
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest


def _seal(model_type, fingerprint_field: str, **values):
    descriptor = dict(values)
    descriptor.pop(fingerprint_field, None)
    return model_type.model_validate(
        {
            **descriptor,
            fingerprint_field: sha256_digest(canonical_json_bytes(descriptor)),
        }
    )


def _reseal_result(
    result: DeliveryReadinessResultV1,
    **changes: object,
) -> DeliveryReadinessResultV1:
    descriptor = result.model_dump(mode="json", exclude={"result_fingerprint"})
    descriptor.update(changes)
    return cast(
        DeliveryReadinessResultV1,
        _seal(DeliveryReadinessResultV1, "result_fingerprint", **descriptor),
    )


def _reseal_requirement_matrix(
    matrix: RequirementMatrixV1,
    *,
    rows: tuple[RequirementMatrixRowV1, ...] | None = None,
    report_hash: str | None = None,
) -> RequirementMatrixV1:
    descriptor = matrix.model_dump(mode="json", exclude={"matrix_fingerprint"})
    if rows is not None:
        descriptor["rows"] = [row.model_dump(mode="json") for row in rows]
    if report_hash is not None:
        descriptor["report_hash"] = report_hash
    return cast(
        RequirementMatrixV1,
        _seal(RequirementMatrixV1, "matrix_fingerprint", **descriptor),
    )


def _reseal_gap_matrix(
    matrix: GapFollowUpMatrixV1,
    *,
    rows: tuple[GapFollowUpRowV1, ...] | None = None,
    report_hash: str | None = None,
) -> GapFollowUpMatrixV1:
    descriptor = matrix.model_dump(mode="json", exclude={"matrix_fingerprint"})
    if rows is not None:
        descriptor["rows"] = [row.model_dump(mode="json") for row in rows]
    if report_hash is not None:
        descriptor["report_hash"] = report_hash
    return cast(
        GapFollowUpMatrixV1,
        _seal(GapFollowUpMatrixV1, "matrix_fingerprint", **descriptor),
    )


def _case(
    tmp_path: Path,
    dispositions: tuple[str, ...],
    *,
    importance: str = "supporting",
) -> dict[str, object]:
    inputs = _request_inputs_fixture.__wrapped__(tmp_path)
    exact = _clean_qualification(_with_requirements(inputs, count=10, importance=importance))
    lanes = _lanes(exact, dispositions)
    _, requirement_matrix, gap_matrix, _, result = _compile(exact, lanes)
    return {
        "report_text": exact.report_text,
        "requirement_matrix": requirement_matrix,
        "gap_matrix": gap_matrix,
        "result": result,
    }


@pytest.fixture
def high_case(tmp_path: Path) -> dict[str, object]:
    case_path = tmp_path / "high"
    case_path.mkdir()
    return _case(case_path, ("met",) * 9 + ("not_met",))


@pytest.fixture
def review_case(tmp_path: Path) -> dict[str, object]:
    case_path = tmp_path / "review"
    case_path.mkdir()
    return _case(case_path, ("met",) * 7 + ("not_met",) * 3)


@pytest.fixture
def blocked_case(tmp_path: Path) -> dict[str, object]:
    case_path = tmp_path / "blocked"
    case_path.mkdir()
    return _case(
        case_path,
        ("met",) * 6 + ("partially_met",) + ("not_met",) * 3,
    )


@pytest.fixture
def critical_review_case(tmp_path: Path) -> dict[str, object]:
    case_path = tmp_path / "critical-review"
    case_path.mkdir()
    return _case(
        case_path,
        ("met",) * 9 + ("partially_met",),
        importance="critical",
    )


def test_high_assurance_contains_exact_report_complete_matrices_and_warning(
    high_case: dict[str, object],
) -> None:
    rendered = render_attorney_review_handoff_v1(**high_case).decode("utf-8")
    report = cast(str, high_case["report_text"])
    requirements = cast(RequirementMatrixV1, high_case["requirement_matrix"])
    gaps = cast(GapFollowUpMatrixV1, high_case["gap_matrix"])
    warning = load_readiness_rubric_v1().attorney_review_warning

    assert rendered.startswith("# Attorney Review Handoff\n\n")
    assert "**Delivery readiness: HIGH_ASSURANCE**" in rendered
    assert "Baseline-locked strict-equivalent disposition: PASS" in rendered
    assert "Historical Protocol 2.2 strict disposition" not in rendered
    assert f"## Report\n\n```markdown\n{report}```" in rendered
    assert "## Requirement matrix" in rendered
    assert "## Complete gap-and-follow-up matrix" in rendered
    assert "## Prioritized follow-up actions" not in rendered
    assert warning in rendered
    assert rendered.endswith(f"{warning}\n")
    assert "\r" not in rendered
    for row in requirements.rows:
        assert row.requirement_id in rendered
        assert row.statement in rendered
        assert row.row_fingerprint in rendered
    for row in gaps.rows:
        assert row.gap_id in rendered
        assert row.shortfall_description in rendered
        assert row.why_unresolved in rendered
        assert row.why_it_matters in rendered
        assert row.resolution_test in rendered
        assert row.row_fingerprint in rendered
    assert rendered.count("#### What is missing") == len(gaps.rows)
    assert rendered.count("#### Why it matters") == len(gaps.rows)
    assert rendered.count("#### How to resolve it") == len(gaps.rows)
    assert rendered.count("#### Owner") == len(gaps.rows)


def test_review_ready_is_prominent_and_prioritizes_complete_grouped_actions(
    review_case: dict[str, object],
) -> None:
    rendered = render_attorney_review_handoff_v1(**review_case).decode("utf-8")
    gaps = cast(GapFollowUpMatrixV1, review_case["gap_matrix"])
    result = cast(DeliveryReadinessResultV1, review_case["result"])

    assert "**Delivery readiness: REVIEW_READY_WITH_GAPS**" in rendered
    assert (
        "Qualified-attorney review required before any legal advice or client delivery." in rendered
    )
    assert "Known gaps remain open" in rendered
    assert (
        f"Baseline-locked strict-equivalent disposition: "
        f"{result.baseline_locked_strict_equivalent_disposition.value}"
    ) in rendered
    assert "## Prioritized follow-up actions" in rendered
    assert "## Complete gap-and-follow-up matrix" in rendered
    for row in gaps.rows:
        assert f"`{row.gap_id}`" in rendered
    grouped_line = next(line for line in rendered.splitlines() if line.startswith("1. "))
    for row in gaps.rows:
        assert row.gap_id in grouped_line
    first_detail = min(rendered.index(f"### {row.gap_id}") for row in gaps.rows)
    assert rendered.index("## Prioritized follow-up actions") < first_detail


def test_follow_up_priority_is_critical_then_owner_then_canonical_order(
    review_case: dict[str, object],
) -> None:
    gap = cast(GapFollowUpMatrixV1, review_case["gap_matrix"])
    requirement = cast(RequirementMatrixV1, review_case["requirement_matrix"])
    result = cast(DeliveryReadinessResultV1, review_case["result"])
    changed: list[GapFollowUpRowV1] = []
    requirement_contracts: dict[str, tuple[str, list[str], str]] = {}
    contracts = (
        (
            "critical",
            ["legal_bottom_line"],
            "Omission could change the legal bottom line.",
            "outside_counsel",
            "OBTAIN_OUTSIDE_COUNSEL_ANALYSIS",
        ),
        (
            "critical",
            ["legal_bottom_line"],
            "Omission could change the legal bottom line.",
            "reviewing_attorney",
            "EXPAND_REQUIREMENT_ANALYSIS",
        ),
        (
            "material",
            ["attorney_briefing"],
            "The point is necessary for a competent attorney briefing.",
            "outside_counsel",
            "VERIFY_PRIMARY_AUTHORITY",
        ),
    )
    for row, (importance, basis, rationale, owner, follow_up) in zip(
        gap.rows, contracts, strict=True
    ):
        descriptor = row.model_dump(mode="json", exclude={"row_fingerprint"})
        descriptor.update(
            importance=importance,
            importance_basis=basis,
            importance_rationale=rationale,
            owner_role=owner,
            follow_up_code=follow_up,
            visibility="prominent" if importance == "critical" else "visible",
            lane_1_disposition="partially_met",
            lane_2_disposition="partially_met",
            conservative_disposition="partially_met",
        )
        requirement_contracts[row.subject_id] = (importance, basis, rationale)
        changed.append(
            cast(
                GapFollowUpRowV1,
                _seal(GapFollowUpRowV1, "row_fingerprint", **descriptor),
            )
        )
    changed_requirements: list[RequirementMatrixRowV1] = []
    for row in requirement.rows:
        contract = requirement_contracts.get(row.requirement_id)
        if contract is None:
            changed_requirements.append(row)
            continue
        importance, basis, rationale = contract
        descriptor = row.model_dump(mode="json", exclude={"row_fingerprint"})
        descriptor.update(
            importance=importance,
            importance_basis=basis,
            importance_rationale=rationale,
            lane_1_disposition="partially_met",
            lane_2_disposition="partially_met",
            conservative_disposition="partially_met",
        )
        changed_requirements.append(
            cast(
                RequirementMatrixRowV1,
                _seal(RequirementMatrixRowV1, "row_fingerprint", **descriptor),
            )
        )
    gap = _reseal_gap_matrix(gap, rows=tuple(changed))
    requirement = _reseal_requirement_matrix(
        requirement,
        rows=tuple(changed_requirements),
    )
    result = _reseal_result(
        result,
        requirement_matrix_fingerprint=requirement.matrix_fingerprint,
        gap_matrix_fingerprint=gap.matrix_fingerprint,
        minimum_lane_weighted_coverage=22 / 30,
        lane_weighted_coverage=[22 / 30, 22 / 30],
        lane_critical_recall=[0.5, 0.5],
    )
    case = {
        **review_case,
        "requirement_matrix": requirement,
        "gap_matrix": gap,
        "result": result,
    }

    rendered = render_attorney_review_handoff_v1(**case).decode("utf-8")
    actions = [line for line in rendered.splitlines() if line[:3] in {"1. ", "2. ", "3. "}]
    assert "outside_counsel" in actions[0]
    assert "GAP-0001" in actions[0]
    assert "reviewing_attorney" in actions[1]
    assert "GAP-0002" in actions[1]
    assert "outside_counsel" in actions[2]
    assert "GAP-0003" in actions[2]


def test_historical_cross_check_is_separate_context_and_does_not_change_priority(
    review_case: dict[str, object],
) -> None:
    result = cast(DeliveryReadinessResultV1, review_case["result"])
    with_history = _reseal_result(
        result,
        historical_v22_strict_disposition="PASS",
        historical_v22_cross_check_status="DISPOSITION_DIFFERS",
    )
    without = render_attorney_review_handoff_v1(**review_case).decode("utf-8")
    with_case = {**review_case, "result": with_history}
    rendered = render_attorney_review_handoff_v1(**with_case).decode("utf-8")

    assert "Historical Protocol 2.2 strict disposition: PASS" in rendered
    assert "Historical cross-check status: DISPOSITION_DIFFERS" in rendered
    assert "**Delivery readiness: REVIEW_READY_WITH_GAPS**" in rendered
    assert [line for line in without.splitlines() if line.startswith(tuple("123456789"))] == [
        line for line in rendered.splitlines() if line.startswith(tuple("123456789"))
    ]


def test_nondeliverable_handoff_suppresses_all_work_product_and_private_mechanics(
    blocked_case: dict[str, object],
) -> None:
    original_report = cast(str, blocked_case["report_text"])
    private_report = (
        original_report
        + "\nprovider_name=PrivateProvider model_name=PrivateModel"
        + "\nPRIVATE SOURCE TEXT"
        + "\n/Users/private/matter eval-readiness-submit-safe anonymous_label role mechanics"
    )
    report_hash = sha256_digest(private_report.encode("utf-8"))
    requirement = _reseal_requirement_matrix(
        cast(RequirementMatrixV1, blocked_case["requirement_matrix"]),
        report_hash=report_hash,
    )
    gap = _reseal_gap_matrix(
        cast(GapFollowUpMatrixV1, blocked_case["gap_matrix"]),
        report_hash=report_hash,
    )
    result = _reseal_result(
        cast(DeliveryReadinessResultV1, blocked_case["result"]),
        requirement_matrix_fingerprint=requirement.matrix_fingerprint,
        gap_matrix_fingerprint=gap.matrix_fingerprint,
    )
    case = {
        "report_text": private_report,
        "requirement_matrix": requirement,
        "gap_matrix": gap,
        "result": result,
    }
    rendered = render_attorney_review_handoff_v1(**case).decode("utf-8")

    assert "**Delivery readiness: NOT_DELIVERABLE**" in rendered
    assert "## Operator-safe remediation" in rendered
    assert "MINIMUM_LANE_COVERAGE_BELOW_FLOOR" in rendered
    assert "## Report" not in rendered
    assert "Requirement matrix" not in rendered
    assert "gap-and-follow-up" not in rendered
    for private in (
        original_report,
        "PrivateProvider",
        "PrivateModel",
        "PRIVATE SOURCE TEXT",
        "/Users/",
        "eval-readiness-submit-safe",
        "anonymous_label",
        "role mechanics",
        cast(GapFollowUpMatrixV1, gap).rows[0].why_unresolved,
        cast(RequirementMatrixV1, requirement).rows[0].statement,
    ):
        assert private not in rendered
    assert rendered.endswith(f"{load_readiness_rubric_v1().attorney_review_warning}\n")


def test_markdown_table_cells_are_escaped_without_environmental_wrapping(
    high_case: dict[str, object],
) -> None:
    matrix = cast(RequirementMatrixV1, high_case["requirement_matrix"])
    first = matrix.rows[0]
    descriptor = first.model_dump(mode="json", exclude={"row_fingerprint"})
    descriptor["statement"] = "Pipe | slash \\ and line\nbreak"
    changed = cast(
        RequirementMatrixRowV1,
        _seal(RequirementMatrixRowV1, "row_fingerprint", **descriptor),
    )
    matrix = _reseal_requirement_matrix(matrix, rows=(changed, *matrix.rows[1:]))
    result = _reseal_result(
        cast(DeliveryReadinessResultV1, high_case["result"]),
        requirement_matrix_fingerprint=matrix.matrix_fingerprint,
    )
    case = {**high_case, "requirement_matrix": matrix, "result": result}

    rendered = render_attorney_review_handoff_v1(**case).decode("utf-8")
    assert "Pipe \\| slash \\\\ and line<br>break" in rendered
    assert max(len(line) for line in rendered.splitlines()) > 80


def test_repeated_render_and_permuted_wire_maps_are_byte_identical(
    review_case: dict[str, object],
) -> None:
    expected = render_attorney_review_handoff_v1(**review_case)
    requirement = cast(RequirementMatrixV1, review_case["requirement_matrix"])
    gap = cast(GapFollowUpMatrixV1, review_case["gap_matrix"])
    result = cast(DeliveryReadinessResultV1, review_case["result"])
    permuted = {
        **review_case,
        "requirement_matrix": RequirementMatrixV1.model_validate(
            dict(reversed(list(requirement.model_dump(mode="json").items())))
        ),
        "gap_matrix": GapFollowUpMatrixV1.model_validate(
            dict(reversed(list(gap.model_dump(mode="json").items())))
        ),
        "result": DeliveryReadinessResultV1.model_validate(
            dict(reversed(list(result.model_dump(mode="json").items())))
        ),
    }
    assert render_attorney_review_handoff_v1(**review_case) == expected
    assert render_attorney_review_handoff_v1(**permuted) == expected


@pytest.mark.parametrize("target", ["requirement_row", "requirement", "gap_row", "gap", "result"])
def test_every_fingerprint_is_recomputed_before_rendering(
    review_case: dict[str, object], target: str
) -> None:
    case = dict(review_case)
    requirement = cast(RequirementMatrixV1, case["requirement_matrix"])
    gap = cast(GapFollowUpMatrixV1, case["gap_matrix"])
    result = cast(DeliveryReadinessResultV1, case["result"])
    if target == "requirement_row":
        forged = requirement.rows[0].model_copy(update={"row_fingerprint": "f" * 64})
        case["requirement_matrix"] = requirement.model_copy(
            update={"rows": (forged, *requirement.rows[1:])}
        )
    elif target == "requirement":
        case["requirement_matrix"] = requirement.model_copy(update={"matrix_fingerprint": "f" * 64})
    elif target == "gap_row":
        forged = gap.rows[0].model_copy(update={"row_fingerprint": "f" * 64})
        case["gap_matrix"] = gap.model_copy(update={"rows": (forged, *gap.rows[1:])})
    elif target == "gap":
        case["gap_matrix"] = gap.model_copy(update={"matrix_fingerprint": "f" * 64})
    else:
        case["result"] = result.model_copy(update={"result_fingerprint": "f" * 64})

    with pytest.raises(ValueError, match="handoff input is invalid"):
        render_attorney_review_handoff_v1(**case)


def test_cross_bindings_warning_order_and_first_version_status_fail_closed(
    review_case: dict[str, object],
) -> None:
    gap = cast(GapFollowUpMatrixV1, review_case["gap_matrix"])
    result = cast(DeliveryReadinessResultV1, review_case["result"])

    wrong_warning = _reseal_result(result, attorney_review_warning="Different warning.")
    with pytest.raises(ValueError, match="handoff input is invalid"):
        render_attorney_review_handoff_v1(**{**review_case, "result": wrong_warning})

    wrong_binding = _reseal_result(result, requirement_matrix_fingerprint="a" * 64)
    with pytest.raises(ValueError, match="handoff input is invalid"):
        render_attorney_review_handoff_v1(**{**review_case, "result": wrong_binding})

    row_descriptor = gap.rows[0].model_dump(mode="json", exclude={"row_fingerprint"})
    row_descriptor["status"] = "resolved"
    resolved = cast(
        GapFollowUpRowV1,
        _seal(GapFollowUpRowV1, "row_fingerprint", **row_descriptor),
    )
    resolved_gap = _reseal_gap_matrix(gap, rows=(resolved, *gap.rows[1:]))
    resolved_result = _reseal_result(result, gap_matrix_fingerprint=resolved_gap.matrix_fingerprint)
    with pytest.raises(ValueError, match="handoff input is invalid"):
        render_attorney_review_handoff_v1(
            **{
                **review_case,
                "gap_matrix": resolved_gap,
                "result": resolved_result,
            }
        )

    reordered = GapFollowUpMatrixV1.model_construct(
        **{**gap.__dict__, "rows": tuple(reversed(gap.rows))}
    )
    with pytest.raises(ValueError, match="handoff input is invalid"):
        render_attorney_review_handoff_v1(**{**review_case, "gap_matrix": reordered})


def test_model_construct_subclass_container_iterator_cycle_depth_node_byte_attacks_fail_closed(
    review_case: dict[str, object],
) -> None:
    requirement = cast(RequirementMatrixV1, review_case["requirement_matrix"])
    result = cast(DeliveryReadinessResultV1, review_case["result"])

    forged = RequirementMatrixV1.model_construct(
        **{**requirement.__dict__, "matrix_fingerprint": "f" * 64}
    )
    with pytest.raises(ValueError, match="handoff input is invalid"):
        render_attorney_review_handoff_v1(**{**review_case, "requirement_matrix": forged})

    class MatrixSubclass(RequirementMatrixV1):
        pass

    subclass = MatrixSubclass.model_validate(requirement.model_dump(mode="json"))
    with pytest.raises(ValueError, match="handoff input is invalid"):
        render_attorney_review_handoff_v1(**{**review_case, "requirement_matrix": subclass})

    class TrapIterator:
        calls = 0

        def __iter__(self):
            self.calls += 1
            return self

        def __next__(self):
            self.calls += 1
            raise StopIteration

    trap = TrapIterator()
    iter_rows = RequirementMatrixV1.model_construct(**{**requirement.__dict__, "rows": trap})
    with pytest.raises(ValueError, match="handoff input is invalid"):
        render_attorney_review_handoff_v1(**{**review_case, "requirement_matrix": iter_rows})
    assert trap.calls == 0

    cycle: list[object] = []
    cycle.append(cycle)
    cyclic = DeliveryReadinessResultV1.model_construct(
        **{**result.__dict__, "blocking_codes": cycle}
    )
    with pytest.raises(ValueError, match="handoff input is invalid"):
        render_attorney_review_handoff_v1(**{**review_case, "result": cyclic})

    deep: object = "leaf"
    for _ in range(80):
        deep = [deep]
    deep_result = DeliveryReadinessResultV1.model_construct(
        **{**result.__dict__, "blocking_codes": deep}
    )
    with pytest.raises(ValueError, match="handoff input is invalid"):
        render_attorney_review_handoff_v1(**{**review_case, "result": deep_result})

    many = tuple("SAFE_CODE" for _ in range(100_001))
    many_result = DeliveryReadinessResultV1.model_construct(
        **{**result.__dict__, "blocking_codes": many}
    )
    with pytest.raises(ValueError, match="handoff input is invalid"):
        render_attorney_review_handoff_v1(**{**review_case, "result": many_result})

    with pytest.raises(ValueError, match="handoff input is invalid"):
        render_attorney_review_handoff_v1(
            **{**review_case, "report_text": "x" * (16 * 1024 * 1024 + 1)}
        )


def test_status_blocker_shape_is_fail_closed(
    blocked_case: dict[str, object],
    high_case: dict[str, object],
) -> None:
    blocked = cast(DeliveryReadinessResultV1, blocked_case["result"])
    high = cast(DeliveryReadinessResultV1, high_case["result"])
    forged_blocked = _reseal_result(blocked, blocking_codes=[])
    forged_high = _reseal_result(
        high,
        blocking_codes=["INTEGRITY_OR_PROVENANCE_INVALID"],
    )
    with pytest.raises(ValueError, match="handoff input is invalid"):
        render_attorney_review_handoff_v1(**{**blocked_case, "result": forged_blocked})
    with pytest.raises(ValueError, match="handoff input is invalid"):
        render_attorney_review_handoff_v1(**{**high_case, "result": forged_high})


def test_report_and_all_exact_passages_remain_cross_bound(
    review_case: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="handoff input is invalid"):
        render_attorney_review_handoff_v1(
            **{**review_case, "report_text": "Different report bytes."}
        )

    requirement = cast(RequirementMatrixV1, review_case["requirement_matrix"])
    first = requirement.rows[0]
    descriptor = first.model_dump(mode="json", exclude={"row_fingerprint"})
    descriptor["lane_1_report_passages"] = ["Passage absent from report."]
    changed = cast(
        RequirementMatrixRowV1,
        _seal(RequirementMatrixRowV1, "row_fingerprint", **descriptor),
    )
    matrix = _reseal_requirement_matrix(requirement, rows=(changed, *requirement.rows[1:]))
    result = _reseal_result(
        cast(DeliveryReadinessResultV1, review_case["result"]),
        requirement_matrix_fingerprint=matrix.matrix_fingerprint,
    )
    with pytest.raises(ValueError, match="handoff input is invalid"):
        render_attorney_review_handoff_v1(
            **{**review_case, "requirement_matrix": matrix, "result": result}
        )


def test_coordinated_reseals_cannot_manufacture_an_unsafe_delivery_tier(
    review_case: dict[str, object],
) -> None:
    requirement = cast(RequirementMatrixV1, review_case["requirement_matrix"])
    gap = cast(GapFollowUpMatrixV1, review_case["gap_matrix"])
    result = cast(DeliveryReadinessResultV1, review_case["result"])

    forged_high = _reseal_result(result, delivery_readiness="HIGH_ASSURANCE")
    with pytest.raises(ValueError, match="handoff input is invalid"):
        render_attorney_review_handoff_v1(**{**review_case, "result": forged_high})

    empty_gap = _reseal_gap_matrix(gap, rows=())
    missing_rows = _reseal_result(
        result,
        gap_matrix_fingerprint=empty_gap.matrix_fingerprint,
    )
    with pytest.raises(ValueError, match="handoff input is invalid"):
        render_attorney_review_handoff_v1(
            **{**review_case, "gap_matrix": empty_gap, "result": missing_rows}
        )

    low_scores = _reseal_result(
        result,
        minimum_lane_weighted_coverage=0.1,
        lane_weighted_coverage=[0.1, 0.2],
    )
    with pytest.raises(ValueError, match="handoff input is invalid"):
        render_attorney_review_handoff_v1(**{**review_case, "result": low_scores})

    history_match = _reseal_result(
        result,
        historical_v22_strict_disposition="PASS",
        historical_v22_cross_check_status="MATCH",
    )
    with pytest.raises(ValueError, match="handoff input is invalid"):
        render_attorney_review_handoff_v1(**{**review_case, "result": history_match})

    nonmet_ids = {
        row.requirement_id for row in requirement.rows if row.conservative_disposition != "met"
    }
    assert nonmet_ids
    assert nonmet_ids.issubset({row.subject_id for row in gap.rows})


@pytest.mark.parametrize(
    ("changes", "importance_changes"),
    [
        ({"visibility": "hidden"}, {}),
        ({"blocking_code": "HIDDEN_MATERIAL_GAP"}, {}),
        ({"why_unresolved": "more research needed"}, {}),
        ({"why_unresolved": "Requirement not met."}, {}),
        ({"disclosure_location": "Footnote 99"}, {}),
        (
            {"visibility": "visible", "owner_role": "research_operator"},
            {
                "importance": "critical",
                "importance_basis": ["legal_bottom_line"],
                "importance_rationale": "Omission could change the legal bottom line.",
            },
        ),
    ],
)
def test_resealed_unsafe_gap_content_cannot_remain_deliverable(
    review_case: dict[str, object],
    changes: dict[str, object],
    importance_changes: dict[str, object],
) -> None:
    gap = cast(GapFollowUpMatrixV1, review_case["gap_matrix"])
    descriptor = gap.rows[0].model_dump(mode="json", exclude={"row_fingerprint"})
    descriptor.update(importance_changes)
    descriptor.update(changes)
    row = cast(
        GapFollowUpRowV1,
        _seal(GapFollowUpRowV1, "row_fingerprint", **descriptor),
    )
    changed_gap = _reseal_gap_matrix(gap, rows=(row, *gap.rows[1:]))
    changed_result = _reseal_result(
        cast(DeliveryReadinessResultV1, review_case["result"]),
        gap_matrix_fingerprint=changed_gap.matrix_fingerprint,
    )
    with pytest.raises(ValueError, match="handoff input is invalid"):
        render_attorney_review_handoff_v1(
            **{
                **review_case,
                "gap_matrix": changed_gap,
                "result": changed_result,
            }
        )


def test_blocker_inventory_must_use_exact_rubric_order(
    blocked_case: dict[str, object],
) -> None:
    result = cast(DeliveryReadinessResultV1, blocked_case["result"])
    reversed_codes = _reseal_result(
        result,
        blocking_codes=[
            "GAP_RATIONALE_INVALID",
            "INTEGRITY_OR_PROVENANCE_INVALID",
        ],
    )
    with pytest.raises(ValueError, match="handoff input is invalid"):
        render_attorney_review_handoff_v1(**{**blocked_case, "result": reversed_codes})


def test_high_assurance_eligible_result_cannot_be_resealed_as_review_ready(
    high_case: dict[str, object],
) -> None:
    result = cast(DeliveryReadinessResultV1, high_case["result"])
    downgraded = _reseal_result(
        result,
        delivery_readiness="REVIEW_READY_WITH_GAPS",
    )
    with pytest.raises(ValueError, match="handoff input is invalid"):
        render_attorney_review_handoff_v1(**{**high_case, "result": downgraded})


def test_resealed_scores_cannot_upgrade_below_floor_matrix(
    blocked_case: dict[str, object],
) -> None:
    result = cast(DeliveryReadinessResultV1, blocked_case["result"])
    forged = _reseal_result(
        result,
        delivery_readiness="REVIEW_READY_WITH_GAPS",
        minimum_lane_weighted_coverage=0.7,
        lane_weighted_coverage=[0.7, 0.7],
        blocking_codes=[],
    )
    with pytest.raises(ValueError, match="handoff input is invalid"):
        render_attorney_review_handoff_v1(**{**blocked_case, "result": forged})


def test_uncertain_lane_cannot_be_resealed_as_pass_and_high_assurance(
    tmp_path: Path,
) -> None:
    case_path = tmp_path / "uncertain"
    case_path.mkdir()
    case = _case(case_path, ("met",) * 9 + ("uncertain",))
    result = cast(DeliveryReadinessResultV1, case["result"])
    assert result.baseline_locked_strict_equivalent_disposition == "INCONCLUSIVE"
    assert result.delivery_readiness == "REVIEW_READY_WITH_GAPS"
    forged = _reseal_result(
        result,
        baseline_locked_strict_equivalent_disposition="PASS",
        delivery_readiness="HIGH_ASSURANCE",
    )
    with pytest.raises(ValueError, match="handoff input is invalid"):
        render_attorney_review_handoff_v1(**{**case, "result": forged})


def test_contested_rows_cannot_mask_ordinary_lane_disagreement(tmp_path: Path) -> None:
    inputs = _request_inputs_fixture.__wrapped__(tmp_path)
    exact = _clean_qualification(
        _with_requirements(inputs, count=7, importance="critical", contested=True)
    )
    lanes = _lanes(
        exact,
        ("met",) * 7,
        ("met",) * 6 + ("not_met",),
        contested_1=(("not_met", "not_met"),),
    )
    _, requirement_matrix, gap_matrix, _, result = _compile(exact, lanes)
    assert result.baseline_locked_strict_equivalent_disposition == "INCONCLUSIVE"
    assert result.delivery_readiness == "REVIEW_READY_WITH_GAPS"
    render_attorney_review_handoff_v1(
        report_text=exact.report_text,
        requirement_matrix=requirement_matrix,
        gap_matrix=gap_matrix,
        result=result,
    )
    forged = _reseal_result(
        result,
        baseline_locked_strict_equivalent_disposition="FAIL",
    )
    with pytest.raises(ValueError, match="handoff input is invalid"):
        render_attorney_review_handoff_v1(
            report_text=exact.report_text,
            requirement_matrix=requirement_matrix,
            gap_matrix=gap_matrix,
            result=forged,
        )


def test_gap_importance_and_dispositions_are_bound_to_requirement_matrix(
    critical_review_case: dict[str, object],
) -> None:
    gap = cast(GapFollowUpMatrixV1, critical_review_case["gap_matrix"])
    descriptor = gap.rows[0].model_dump(mode="json", exclude={"row_fingerprint"})
    descriptor.update(
        importance="supporting",
        importance_basis=["implementation_detail"],
        importance_rationale="The point supplies useful implementation detail.",
        visibility="visible",
        owner_role="research_operator",
    )
    downgraded = cast(
        GapFollowUpRowV1,
        _seal(GapFollowUpRowV1, "row_fingerprint", **descriptor),
    )
    changed_gap = _reseal_gap_matrix(gap, rows=(downgraded, *gap.rows[1:]))
    result = _reseal_result(
        cast(DeliveryReadinessResultV1, critical_review_case["result"]),
        gap_matrix_fingerprint=changed_gap.matrix_fingerprint,
    )
    with pytest.raises(ValueError, match="handoff input is invalid"):
        render_attorney_review_handoff_v1(
            **{
                **critical_review_case,
                "gap_matrix": changed_gap,
                "result": result,
            }
        )


def test_requirement_passage_must_be_exactly_unique(
    review_case: dict[str, object],
) -> None:
    requirement = cast(RequirementMatrixV1, review_case["requirement_matrix"])
    descriptor = requirement.rows[0].model_dump(mode="json", exclude={"row_fingerprint"})
    descriptor["lane_1_report_passages"] = ["e"]
    row = cast(
        RequirementMatrixRowV1,
        _seal(RequirementMatrixRowV1, "row_fingerprint", **descriptor),
    )
    changed = _reseal_requirement_matrix(
        requirement,
        rows=(row, *requirement.rows[1:]),
    )
    result = _reseal_result(
        cast(DeliveryReadinessResultV1, review_case["result"]),
        requirement_matrix_fingerprint=changed.matrix_fingerprint,
    )
    assert cast(str, review_case["report_text"]).count("e") > 1
    with pytest.raises(ValueError, match="handoff input is invalid"):
        render_attorney_review_handoff_v1(
            **{**review_case, "requirement_matrix": changed, "result": result}
        )


def test_report_markdown_cannot_capture_matrices_or_warning(
    review_case: dict[str, object],
) -> None:
    report = cast(str, review_case["report_text"]) + "\n```\n<!--"
    report_hash = sha256_digest(report.encode("utf-8"))
    requirement = _reseal_requirement_matrix(
        cast(RequirementMatrixV1, review_case["requirement_matrix"]),
        report_hash=report_hash,
    )
    gap = _reseal_gap_matrix(
        cast(GapFollowUpMatrixV1, review_case["gap_matrix"]),
        report_hash=report_hash,
    )
    result = _reseal_result(
        cast(DeliveryReadinessResultV1, review_case["result"]),
        requirement_matrix_fingerprint=requirement.matrix_fingerprint,
        gap_matrix_fingerprint=gap.matrix_fingerprint,
    )
    rendered = render_attorney_review_handoff_v1(
        report_text=report,
        requirement_matrix=requirement,
        gap_matrix=gap,
        result=result,
    ).decode("utf-8")

    assert f"````markdown\n{report}\n````" in rendered
    assert rendered.index("````\n\n## Requirement matrix") > rendered.index("<!--")
    assert "## Complete gap-and-follow-up matrix" in rendered
    assert rendered.endswith(f"{load_readiness_rubric_v1().attorney_review_warning}\n")


def test_json_escape_expansion_is_rejected_before_canonical_serialization(
    review_case: dict[str, object],
) -> None:
    result = cast(DeliveryReadinessResultV1, review_case["result"])
    oversized_after_json_escape = DeliveryReadinessResultV1.model_construct(
        **{**result.__dict__, "attorney_review_warning": "\x01" * 3_000_000}
    )
    with (
        patch.object(
            handoff_module,
            "canonical_json_bytes",
            wraps=canonical_json_bytes,
        ) as serializer,
        pytest.raises(ValueError, match="handoff input is invalid"),
    ):
        render_attorney_review_handoff_v1(**{**review_case, "result": oversized_after_json_escape})
    assert serializer.call_count == 0


def test_validation_error_chain_does_not_disclose_suppressed_private_text(
    review_case: dict[str, object],
) -> None:
    private = "PRIVATE-MATTER-TOKEN-DO-NOT-DISCLOSE"
    gap = cast(GapFollowUpMatrixV1, review_case["gap_matrix"])
    malformed_row = GapFollowUpRowV1.model_construct(
        **{**gap.rows[0].__dict__, "importance": private}
    )
    malformed_gap = GapFollowUpMatrixV1.model_construct(
        **{**gap.__dict__, "rows": (malformed_row, *gap.rows[1:])}
    )
    with pytest.raises(ValueError, match="handoff input is invalid") as caught:
        render_attorney_review_handoff_v1(**{**review_case, "gap_matrix": malformed_gap})
    formatted = "".join(traceback.format_exception(caught.value))
    assert private not in formatted
    assert caught.value.__cause__ is None


def test_invalid_report_encoding_is_generic_and_does_not_retain_private_report(
    review_case: dict[str, object],
) -> None:
    private = "PRIVATE REPORT BODY\ud800"
    with pytest.raises(ValueError, match="handoff input is invalid") as caught:
        render_attorney_review_handoff_v1(**{**review_case, "report_text": private})
    formatted = "".join(traceback.format_exception(caught.value))
    assert "PRIVATE REPORT BODY" not in formatted
    assert caught.value.__cause__ is None


def test_helper_inputs_remain_verified_readiness_values(tmp_path: Path) -> None:
    """Keep the cross-test fixture boundary explicit and typed."""
    inputs = _request_inputs_fixture.__wrapped__(tmp_path)
    assert type(inputs) is VerifiedReadinessInputsV1
