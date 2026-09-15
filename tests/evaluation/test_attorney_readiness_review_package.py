"""V3 preserves truthful report observations and emits an actionable review package."""

from dataclasses import replace

import pytest
from test_attorney_readiness_compiler import _clean_qualification, _lanes, _with_requirements
from test_attorney_readiness_compiler import inputs as _inputs_fixture
from test_attorney_readiness_drafts import (
    _assessment_draft,
    _finding_draft,
    _provenance,
    _verified_grader_lanes,
)
from test_attorney_readiness_drafts import safety_inputs as _safety_inputs_fixture
from test_attorney_readiness_requests import _with_report
from test_attorney_readiness_scoped_review import _assessment_with_scope, _result, _scoped

from regulatory_harvest.evaluation.attorney_readiness_compiler import compile_requirement_matrix_v1
from regulatory_harvest.evaluation.attorney_readiness_drafts import (
    CompiledReadinessDraftV1,
    compile_readiness_draft_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_handoff import (
    render_attorney_review_handoff_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_models import (
    SafetyFindingProposalV1,
    SafetyLaneResponseV1,
)
from regulatory_harvest.evaluation.attorney_readiness_requests import (
    build_gap_candidate_inventory_v1,
    build_safety_lane_request_v1,
)
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

V3 = "readiness-safety-response-v3"


@pytest.fixture
def inputs(tmp_path):
    value = _scoped(_inputs_fixture.__wrapped__(tmp_path))
    return replace(
        value,
        readiness_input=value.readiness_input.model_copy(
            update={"safety_response_contract_version": V3}
        ),
    )


def _package(inputs, *, finding=None, disclosure=None):
    lanes = _lanes(inputs, ("met",))
    candidates = build_gap_candidate_inventory_v1(inputs, lanes)
    assessment = _assessment_with_scope(candidates[0], scoped=False).model_dump(mode="json")
    assessment.update(
        {
            "visibility": "hidden",
            "report_passages": (),
            "disclosure_location": disclosure,
        }
    )
    first = SafetyLaneResponseV1.model_validate(
        {
            "lane": 1,
            "candidate_assessments": [assessment],
            "finding_proposals": [] if finding is None else [finding.model_dump(mode="json")],
        }
    )
    matrix, result = _result(inputs, lanes, candidates, first, first.model_copy(update={"lane": 2}))
    return compile_requirement_matrix_v1(inputs, lanes), matrix, result


def test_hidden_open_gap_is_prominently_reviewable_without_changing_report(inputs):
    requirements, gaps, result = _package(inputs)
    assert result.delivery_readiness == "REVIEW_READY_WITH_GAPS"
    assert result.blocking_codes == ()
    assert result.model_dump(mode="json")["review_package_policy"] == "prominent-attorney-issues-v1"
    assert gaps.rows[0].visibility == "hidden"
    rendered = render_attorney_review_handoff_v1(
        report_text=inputs.report_text,
        requirement_matrix=requirements,
        gap_matrix=gaps,
        result=result,
    ).decode()
    before_report = rendered.split("## Report\n", 1)[0]
    for text in (
        gaps.rows[0].shortfall_description,
        gaps.rows[0].why_it_matters,
        gaps.rows[0].resolution_test,
        "reviewing_attorney",
        "PREREQUISITE-CLIENT-FACTS",
    ):
        assert text in before_report.replace("\\", "")
    assert "Observed original-report visibility" in before_report
    assert inputs.report_text in rendered


def test_hidden_critical_and_blocking_finding_compile_with_truthful_visibility(tmp_path_factory):
    inputs = _safety_inputs_fixture.__wrapped__(tmp_path_factory)
    inputs = replace(
        inputs,
        readiness_input=inputs.readiness_input.model_copy(
            update={"safety_response_contract_version": V3}
        ),
    )
    lanes = _verified_grader_lanes(inputs)
    candidates = build_gap_candidate_inventory_v1(inputs, lanes)
    request = build_safety_lane_request_v1(inputs, lanes, candidates, lane=1)
    assessments = [
        _assessment_draft(candidate, passage=inputs.report_text)
        for candidate in request.payload["gap_candidates"]
    ]
    for assessment in assessments:
        assessment.update(
            scope_status="open_gap",
            visibility="hidden",
            disclosure_location=None,
            report_passages=[],
        )
    finding = _finding_draft(request)
    finding.update(visibility="hidden", disclosure_location=None)
    compiled = compile_readiness_draft_v1(
        request,
        {"candidate_assessments": assessments, "finding_proposals": [finding]},
        _provenance(),
    )
    assert isinstance(compiled, CompiledReadinessDraftV1), compiled


@pytest.mark.parametrize(
    "kind",
    [
        "MATERIAL_UNSUPPORTED_ASSERTION",
        "BASELINE_CONTRADICTION",
        "MISLEADING_CURRENTNESS_OR_AUTHORITY",
        "UNDISCLOSED_DISPOSITIVE_CLIENT_FACT",
    ],
)
def test_hard_finding_kind_cannot_lose_blocker_when_code_is_null(inputs, kind):
    lanes = _lanes(inputs, ("met",))
    request = build_safety_lane_request_v1(
        inputs, lanes, build_gap_candidate_inventory_v1(inputs, lanes), lane=1
    )
    raw = _finding_draft(request)
    raw.update(finding_kind=kind, blocking_code=None, visibility="hidden", disclosure_location=None)
    finding = SafetyFindingProposalV1.model_validate(raw)
    requirements, gaps, result = _package(inputs, finding=finding)
    assert kind in result.blocking_codes
    assert result.delivery_readiness == "NOT_DELIVERABLE"
    rendered = render_attorney_review_handoff_v1(
        report_text=inputs.report_text,
        requirement_matrix=requirements,
        gap_matrix=gaps,
        result=result,
    ).decode()
    assert inputs.report_text not in rendered


def test_supplied_false_disclosure_binding_still_blocks(inputs):
    _, _, result = _package(inputs, disclosure="Invented disclosure not in report")
    assert result.delivery_readiness == "NOT_DELIVERABLE"
    assert "HIDDEN_MATERIAL_GAP" in result.blocking_codes


def _reseal(value, field, **updates):
    raw = value.model_dump(mode="json")
    raw.update(updates)
    raw[field] = sha256_digest(canonical_json_bytes({k: v for k, v in raw.items() if k != field}))
    return type(value).model_validate(raw)


def test_standalone_renderer_refuses_resealed_misleading_completeness(inputs):
    current = _with_report(inputs, inputs.report_text + "\nAll gaps are fully resolved.\n")
    requirements, gaps, result = _package(current)
    assert "HIDDEN_MATERIAL_GAP" in result.blocking_codes
    forged = _reseal(
        result, "result_fingerprint", blocking_codes=[], delivery_readiness="REVIEW_READY_WITH_GAPS"
    )
    with pytest.raises(ValueError):
        render_attorney_review_handoff_v1(
            report_text=current.report_text,
            requirement_matrix=requirements,
            gap_matrix=gaps,
            result=forged,
        )


def test_legacy_result_policy_is_omitted_and_grading_stays_identical(inputs):
    from regulatory_harvest.evaluation.attorney_readiness_models import DeliveryReadinessResultV1
    from regulatory_harvest.evaluation.attorney_readiness_requests import (
        build_baseline_locked_grade_batches_v1,
        build_baseline_locked_grade_request_v1,
    )

    _, _, result = _package(inputs)
    legacy = replace(
        inputs,
        readiness_input=inputs.readiness_input.model_copy(
            update={"safety_response_contract_version": "readiness-safety-response-v2"}
        ),
    )
    batch = build_baseline_locked_grade_batches_v1(inputs.gradeable_baseline, lane=1)[0]
    assert canonical_json_bytes(
        build_baseline_locked_grade_request_v1(inputs, batch)
    ) == canonical_json_bytes(build_baseline_locked_grade_request_v1(legacy, batch))
    raw = result.model_dump(mode="json")
    raw.pop("review_package_policy")
    assert "review_package_policy" not in DeliveryReadinessResultV1.model_validate(raw).model_dump(
        mode="json"
    )


def test_standalone_renderer_refuses_removed_hard_finding_code(inputs):
    lanes = _lanes(inputs, ("met",))
    request = build_safety_lane_request_v1(
        inputs, lanes, build_gap_candidate_inventory_v1(inputs, lanes), lane=1
    )
    raw = _finding_draft(request)
    raw.update(blocking_code=None, visibility="hidden", disclosure_location=None)
    requirements, gaps, result = _package(
        inputs, finding=SafetyFindingProposalV1.model_validate(raw)
    )
    forged = _reseal(
        result, "result_fingerprint", blocking_codes=[], delivery_readiness="REVIEW_READY_WITH_GAPS"
    )
    with pytest.raises(ValueError):
        render_attorney_review_handoff_v1(
            report_text=inputs.report_text,
            requirement_matrix=requirements,
            gap_matrix=gaps,
            result=forged,
        )


@pytest.mark.parametrize(
    "dispositions,blocker,owner,expected_code",
    [
        (("partially_met", "met"), None, "reviewing_attorney", None),
        (("not_met", "met"), None, "reviewing_attorney", "MINIMUM_LANE_COVERAGE_BELOW_FLOOR"),
        (
            ("partially_met", "met"),
            "HIDDEN_MATERIAL_GAP",
            "reviewing_attorney",
            "HIDDEN_MATERIAL_GAP",
        ),
        (("partially_met", "met"), None, "research_operator", "CRITICAL_DISCLOSURE_INVALID"),
    ],
)
def test_actual_hidden_requirement_shortfall_keeps_coverage_and_explicit_safety_guards(
    inputs,
    dispositions,
    blocker,
    owner,
    expected_code,
):
    current = _clean_qualification(_with_requirements(inputs, count=2, importance="critical"))
    lanes = _lanes(current, dispositions)
    candidates = build_gap_candidate_inventory_v1(current, lanes)
    assessments = []
    for candidate in candidates:
        raw = _assessment_with_scope(candidate, scoped=False).model_dump(mode="json")
        raw.update(
            visibility="hidden",
            disclosure_location=None,
            report_passages=[],
            owner_role=owner,
            blocking_code=blocker,
        )
        assessments.append(raw)
    first = SafetyLaneResponseV1.model_validate(
        {
            "lane": 1,
            "candidate_assessments": assessments,
            "finding_proposals": [],
        }
    )
    gaps, result = _result(current, lanes, candidates, first, first.model_copy(update={"lane": 2}))
    assert any(row.origin == "requirement" for row in gaps.rows)
    if expected_code:
        assert expected_code in result.blocking_codes
        assert result.delivery_readiness == "NOT_DELIVERABLE"
    else:
        assert result.minimum_lane_weighted_coverage == 0.75
        assert result.delivery_readiness == "REVIEW_READY_WITH_GAPS"
        assert all(row.visibility == "hidden" for row in gaps.rows)
        rendered = render_attorney_review_handoff_v1(
            report_text=current.report_text,
            requirement_matrix=compile_requirement_matrix_v1(current, lanes),
            gap_matrix=gaps,
            result=result,
        ).decode()
        assert "REQ-0001" in rendered.split("## Report\n", 1)[0]


def test_v3_scope_cleared_row_still_binds_supplied_disclosure(inputs):
    lanes = _lanes(inputs, ("met",))
    candidates = build_gap_candidate_inventory_v1(inputs, lanes)
    raw = _assessment_with_scope(candidates[0]).model_dump(mode="json")
    raw["disclosure_location"] = "Invented disclosure not in report"
    first = SafetyLaneResponseV1.model_validate(
        {
            "lane": 1,
            "candidate_assessments": [raw],
            "finding_proposals": [],
        }
    )
    _, result = _result(inputs, lanes, candidates, first, first.model_copy(update={"lane": 2}))
    assert "HIDDEN_MATERIAL_GAP" in result.blocking_codes


@pytest.mark.parametrize("kind", ["HIDDEN_OR_UNDERSTATED_LIMITATION", "UNDISCLOSED_GRADER_GAP"])
def test_ordinary_omission_finding_is_reviewable_when_not_explicitly_blocking(inputs, kind):
    lanes = _lanes(inputs, ("met",))
    request = build_safety_lane_request_v1(
        inputs, lanes, build_gap_candidate_inventory_v1(inputs, lanes), lane=1
    )
    raw = _finding_draft(request)
    raw.update(
        finding_kind=kind,
        blocking_code=None,
        visibility="hidden",
        disclosure_location=None,
        report_passages=[],
    )
    _, gaps, result = _package(inputs, finding=SafetyFindingProposalV1.model_validate(raw))
    assert any(row.kind == kind for row in gaps.rows)
    assert result.blocking_codes == ()
    assert result.delivery_readiness == "REVIEW_READY_WITH_GAPS"


@pytest.mark.parametrize(
    "warning",
    [
        "Not all issues are resolved.",
        "This report does not resolve all issues.",
        "This report is not fully comprehensive.",
        "No assurance is given that all issues are resolved.",
        "Attorney must resolve all outstanding issues before reliance.",
        "Verify all issues are resolved before client delivery.",
        "If all issues are resolved, counsel may proceed.",
        "All issues are not resolved.",
        "Are all issues resolved?",
        "This report doesn't resolve all issues.",
        "This report doesn\u2019t resolve all issues.",
        "Every issue isn't resolved.",
        "All issues aren't resolved.",
        "This report can't resolve all issues.",
        "This report does not resolve all issues and limitations.",
    ],
)
def test_v3_honest_warning_or_review_instruction_does_not_claim_completeness(inputs, warning):
    current = _with_report(inputs, inputs.report_text + "\n" + warning + "\n")
    requirements, gaps, result = _package(current)
    assert result.delivery_readiness == "REVIEW_READY_WITH_GAPS"
    rendered = render_attorney_review_handoff_v1(
        report_text=current.report_text,
        requirement_matrix=requirements,
        gap_matrix=gaps,
        result=result,
    ).decode()
    assert current.report_text in rendered


@pytest.mark.parametrize(
    "claim",
    [
        "All issues are resolved.",
        "No material gaps remain.",
        "Not all issues are resolved. No material gaps remain.",
        "Not all issues were addressed earlier. This report resolves every outstanding issue.",
        "Not all issues are resolved, but no material gaps remain.",
        "Not only are all issues resolved, the report is comprehensive.",
        "All issues are resolved, but attorney review is required.",
        "Not all issues are resolved; however, all issues are resolved.",
        "This report doesn't resolve all issues. No material gaps remain.",
        "All issues aren't resolved, but no material gaps remain.",
        "This report does not fully address all issues and resolves every outstanding question.",
    ],
)
def test_v3_actual_completeness_claim_is_not_waived_by_nearby_warning(inputs, claim):
    current = _with_report(inputs, inputs.report_text + "\n" + claim + "\n")
    requirements, gaps, result = _package(current)
    assert "HIDDEN_MATERIAL_GAP" in result.blocking_codes
    forged = _reseal(
        result, "result_fingerprint", blocking_codes=[], delivery_readiness="REVIEW_READY_WITH_GAPS"
    )
    with pytest.raises(ValueError):
        render_attorney_review_handoff_v1(
            report_text=current.report_text,
            requirement_matrix=requirements,
            gap_matrix=gaps,
            result=forged,
        )


def test_repeated_report_is_admitted_with_only_unique_passages_and_full_report_fallback(tmp_path):
    from test_attorney_readiness_inputs import _make_verified_inputs
    from test_attorney_readiness_workflow import _draft

    from regulatory_harvest.evaluation.attorney_readiness_artifacts import verify_readiness_run_v1
    from regulatory_harvest.evaluation.attorney_readiness_drafts import (
        NeedsReadinessClarificationV1,
        ReadinessEngineDefectV1,
    )
    from regulatory_harvest.evaluation.attorney_readiness_models import ReadinessEvaluatorRequestV1
    from regulatory_harvest.evaluation.attorney_readiness_workflow import (
        guarded_submit_readiness_response_v1,
        initialize_readiness_v1,
        next_readiness_request_v1,
    )

    source = _make_verified_inputs(tmp_path)
    report = "# Repeated report\n\nRepeated summary.\n\nRepeated summary.\n\nUnique detail.\n"
    report_path = tmp_path / "repeated-report.md"
    report_path.write_text(report)
    run = tmp_path / "review"
    initialize_readiness_v1(
        run,
        baseline_run_dir=source.baseline_run_dir,
        qualification_run_dir=source.qualification_run_dir,
        external_report_path=report_path,
    )
    first = next_readiness_request_v1(run)
    assert first is not None
    request = first
    allowlist = request.payload["report_passage_allowlist"]
    assert list(allowlist) == ["# Repeated report", "Unique detail.", report]
    draft = _draft(request)
    for grade in draft["requirement_grades"]:
        grade["report_passages"] = [report]
    assert isinstance(
        compile_readiness_draft_v1(request, draft, _provenance()), CompiledReadinessDraftV1
    )
    draft["requirement_grades"][0]["report_passages"] = ["Repeated summary."]
    assert isinstance(
        compile_readiness_draft_v1(request, draft, _provenance()), NeedsReadinessClarificationV1
    )
    forged_raw = request.model_dump(mode="json")
    forged_raw["payload"]["report_passage_allowlist"].insert(1, "Repeated summary.")
    forged = _reseal(ReadinessEvaluatorRequestV1.model_validate(forged_raw), "request_fingerprint")
    assert isinstance(
        compile_readiness_draft_v1(forged, draft, _provenance()), ReadinessEngineDefectV1
    )
    for _ in range(30):
        call = next_readiness_request_v1(run)
        if call is None:
            break
        request = call
        if "report_passage_allowlist" in request.payload:
            assert all(
                report.count(passage) == 1
                for passage in request.payload["report_passage_allowlist"]
            )
        compiled = compile_readiness_draft_v1(request, _draft(request), _provenance())
        assert isinstance(compiled, CompiledReadinessDraftV1), compiled
        assert guarded_submit_readiness_response_v1(run, compiled.response).accepted
    else:
        pytest.fail("Repeated report workflow did not finish")
    assert verify_readiness_run_v1(run).valid
    assert report_path.read_text() == report


def test_v3_passage_policy_filters_ambiguous_substrings_without_changing_legacy(inputs):
    from regulatory_harvest.evaluation.attorney_readiness_requests import (
        build_baseline_locked_grade_batches_v1,
        build_baseline_locked_grade_request_v1,
    )

    report = "# Report\nShort text.\nPrefix Short text. suffix\n"
    current = _with_report(inputs, report)
    legacy = replace(
        current,
        readiness_input=current.readiness_input.model_copy(
            update={"safety_response_contract_version": "readiness-safety-response-v2"}
        ),
    )
    batch = build_baseline_locked_grade_batches_v1(current.gradeable_baseline, lane=1)[0]
    new = build_baseline_locked_grade_request_v1(current, batch)
    old = build_baseline_locked_grade_request_v1(legacy, batch)
    assert list(old.payload["report_passage_allowlist"]) == [
        "# Report",
        "Short text.",
        "Prefix Short text. suffix",
        report,
    ]
    assert list(new.payload["report_passage_allowlist"]) == [
        "# Report",
        "Prefix Short text. suffix",
        report,
    ]
    assert set(new.payload) == set(old.payload)


@pytest.mark.parametrize("version", ["readiness-safety-response-v2", V3])
def test_exact_full_report_quote_preserves_whitespace_without_relaxing_other_fields(
    inputs, version
):
    from test_attorney_readiness_drafts import _ordinary_draft

    from regulatory_harvest.evaluation.attorney_readiness_drafts import (
        NeedsReadinessClarificationV1,
    )
    from regulatory_harvest.evaluation.attorney_readiness_requests import (
        build_baseline_locked_grade_batches_v1,
        build_baseline_locked_grade_request_v1,
    )

    report = "# Exact report\n\nUnique paragraph with original terminal newline.\n"
    current = _with_report(inputs, report)
    current = replace(
        current,
        readiness_input=current.readiness_input.model_copy(
            update={"safety_response_contract_version": version}
        ),
    )
    batch = build_baseline_locked_grade_batches_v1(current.gradeable_baseline, lane=1)[0]
    request = build_baseline_locked_grade_request_v1(current, batch)
    draft = _ordinary_draft(request)
    draft["requirement_grades"][0]["report_passages"] = [report]
    compiled = compile_readiness_draft_v1(request, draft, _provenance())
    assert isinstance(compiled, CompiledReadinessDraftV1), compiled
    assert list(compiled.response.payload["requirement_grades"][0]["report_passages"]) == [report]
    for altered in (report + " ", " " + report, report.rstrip(), " # Exact report "):
        draft["requirement_grades"][0]["report_passages"] = [altered]
        assert isinstance(
            compile_readiness_draft_v1(request, draft, _provenance()), NeedsReadinessClarificationV1
        )
    draft["requirement_grades"][0]["report_passages"] = [report]
    draft["rationale"] = " " + draft["rationale"]
    assert isinstance(
        compile_readiness_draft_v1(request, draft, _provenance()), NeedsReadinessClarificationV1
    )
