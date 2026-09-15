"""Review-package safety policy behavior and byte-exact portable replay parity."""

from __future__ import annotations

import copy
import json
import shutil
from dataclasses import asdict, replace
from pathlib import Path

import pytest
from test_readiness_scoped_review_portable import _helpers


def test_portable_admission_selects_review_package_policy(tmp_path, monkeypatch):
    portable, make_inputs, _, _ = _helpers(monkeypatch)
    source = make_inputs(tmp_path)
    report = tmp_path / "report.md"
    report.write_text(source.report_text, encoding="utf-8")
    run = tmp_path / "portable"
    portable.initialize_readiness_v1(
        run,
        baseline_run_dir=source.baseline_run_dir,
        qualification_run_dir=source.qualification_run_dir,
        external_report_path=report,
    )
    saved = json.loads((run / "readiness-input.json").read_bytes())
    assert saved["readiness_input"]["safety_response_contract_version"] == (
        "readiness-safety-response-v3"
    )


@pytest.mark.parametrize("visibility", ["hidden", "visible"])
@pytest.mark.parametrize(
    "finding_kind,expected_blocker",
    [
        (None, None),
        ("MATERIAL_UNSUPPORTED_ASSERTION", "MATERIAL_UNSUPPORTED_ASSERTION"),
        ("BASELINE_CONTRADICTION", "BASELINE_CONTRADICTION"),
        ("MISLEADING_CURRENTNESS_OR_AUTHORITY", "MISLEADING_CURRENTNESS_OR_AUTHORITY"),
        ("HIDDEN_OR_UNDERSTATED_LIMITATION", None),
        ("UNDISCLOSED_GRADER_GAP", None),
    ],
)
def test_review_package_graph_preserves_visibility_and_derives_blockers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    visibility: str,
    finding_kind: str | None,
    expected_blocker: str | None,
    *,
    referee: str | None = None,
    report_suffix: str = "",
    grade_mode: str = "met",
    explicit_code: str | None = None,
    disclosure: str | None = None,
    ambiguous_passage: str | None = None,
) -> None:
    portable, make_inputs, draft_for, provenance = _helpers(monkeypatch)
    from regulatory_harvest.evaluation.attorney_readiness_artifacts import (
        initialize_readiness_run_storage_v1,
        verify_readiness_run_v1,
    )
    from regulatory_harvest.evaluation.attorney_readiness_drafts import (
        CompiledReadinessDraftV1,
        NeedsReadinessClarificationV1,
        compile_readiness_draft_v1,
    )
    from regulatory_harvest.evaluation.attorney_readiness_inputs import (
        build_verified_readiness_input_v1,
    )
    from regulatory_harvest.evaluation.attorney_readiness_requests import (
        build_baseline_locked_grade_batches_v1,
        build_baseline_locked_grade_request_v1,
    )
    from regulatory_harvest.evaluation.attorney_readiness_workflow import (
        guarded_submit_readiness_response_v1,
        next_readiness_request_v1,
    )

    source = make_inputs(tmp_path)
    input_args = source.without_history()
    if report_suffix:
        report_path = tmp_path / "external-report.md"
        report_path.write_text(source.report_text + report_suffix, encoding="utf-8")
        input_args.pop("generation_run_dir", None)
        input_args.pop("validation_receipt_path", None)
        input_args["external_report_path"] = report_path
    inputs = build_verified_readiness_input_v1(**input_args)
    inputs = replace(
        inputs,
        readiness_input=inputs.readiness_input.model_copy(
            update={"safety_response_contract_version": "readiness-safety-response-v3"}
        ),
    )
    batch = build_baseline_locked_grade_batches_v1(inputs.gradeable_baseline, lane=1)[0]
    first = build_baseline_locked_grade_request_v1(inputs, batch)
    full, other = tmp_path / "full", tmp_path / "portable"
    initialize_readiness_run_storage_v1(full, inputs, first)
    shutil.copytree(full, other)
    while (request := next_readiness_request_v1(full)) is not None:
        raw_request = request.model_dump(mode="json")
        assert portable.next_readiness_request_v1(other) == raw_request
        draft = draft_for(request, grade_mode=grade_mode, blocking_safety=finding_kind is not None)
        if ambiguous_passage is not None and request.operation.value == "baseline_locked_grade":
            allowlist = request.payload["report_passage_allowlist"]
            assert ambiguous_passage not in allowlist
            assert inputs.report_text in allowlist
            invalid = copy.deepcopy(draft)
            invalid["requirement_grades"][0]["report_passages"] = [ambiguous_passage]
            assert isinstance(
                compile_readiness_draft_v1(request, invalid, provenance()),
                NeedsReadinessClarificationV1,
            )
            with pytest.raises(portable.PortableEvaluationInputError):
                portable.compile_readiness_draft_v1(raw_request, invalid, asdict(provenance()))
            invalid["requirement_grades"][0]["report_passages"] = [inputs.report_text + " "]
            assert isinstance(
                compile_readiness_draft_v1(request, invalid, provenance()),
                NeedsReadinessClarificationV1,
            )
            with pytest.raises(portable.PortableEvaluationInputError):
                portable.compile_readiness_draft_v1(raw_request, invalid, asdict(provenance()))
            for grade in draft["requirement_grades"]:
                grade["report_passages"] = [inputs.report_text]
            from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

            truncated_inventory = copy.deepcopy(raw_request)
            truncated_inventory["payload"]["report_passage_allowlist"] = [inputs.report_text]
            truncated_inventory["request_fingerprint"] = sha256_digest(
                canonical_json_bytes(
                    {
                        key: value
                        for key, value in truncated_inventory.items()
                        if key != "request_fingerprint"
                    }
                )
            )
            with pytest.raises(portable.PortableEvaluationInputError):
                portable.compile_readiness_draft_v1(
                    truncated_inventory, draft, asdict(provenance())
                )
        if request.operation.value == "safety_review":
            for assessment in draft["candidate_assessments"]:
                assessment.update(
                    scope_status="open_gap",
                    visibility=visibility,
                    report_passages=[],
                    disclosure_location=disclosure,
                    blocking_code=explicit_code,
                )
                if referee is not None and request.payload["lane"] == 2:
                    assessment["owner_role"] = "outside_counsel"
            for finding in draft["finding_proposals"]:
                prefix = {
                    "BASELINE_CONTRADICTION": "BASELINE-",
                    "UNDISCLOSED_GRADER_GAP": "BASELINE-",
                    "UNDISCLOSED_DISPOSITIVE_CLIENT_FACT": "PREREQUISITE-CLIENT-FACTS",
                }.get(finding_kind, "SOURCE-")
                ref = next(
                    item["evidence_ref"]
                    for item in request.payload["evidence_handles"]
                    if item["evidence_ref"].startswith(prefix)
                )
                finding.update(
                    finding_kind=finding_kind,
                    evidence_refs=[ref],
                    why_it_matters=f"legal conclusion: {ref} could change the scoped answer.",
                    visibility=visibility,
                    disclosure_location=None,
                    blocking_code=None,
                )
        if request.operation.value == "safety_referee" and referee is not None:
            draft["disposition"] = referee
        compiled = compile_readiness_draft_v1(request, draft, provenance())
        assert isinstance(compiled, CompiledReadinessDraftV1), compiled
        response = portable.compile_readiness_draft_v1(raw_request, draft, asdict(provenance()))
        assert response == compiled.response.model_dump(mode="json")
        assert guarded_submit_readiness_response_v1(full, compiled.response).accepted
        assert portable.guarded_submit_readiness_response_v1(other, response)["accepted"]
    assert verify_readiness_run_v1(full).valid
    assert portable.verify_readiness_run_v1(other)["valid"]
    for path in full.rglob("*"):
        if path.is_file() and path.name != ".readiness.lock":
            assert path.read_bytes() == (other / path.relative_to(full)).read_bytes(), path
    result = json.loads((other / "delivery-readiness.json").read_bytes())
    assert result["review_package_policy"] == "prominent-attorney-issues-v1"
    if expected_blocker != "HIDDEN_MATERIAL_GAP":
        assert "HIDDEN_MATERIAL_GAP" not in result["blocking_codes"]
    assert "CRITICAL_DISCLOSURE_INVALID" not in result["blocking_codes"]
    assert result["blocking_codes"] == ([] if expected_blocker is None else [expected_blocker])
    assert result["delivery_readiness"] == (
        "NOT_DELIVERABLE" if expected_blocker is not None else "REVIEW_READY_WITH_GAPS"
    )
    rows = json.loads((other / "gap-follow-up-matrix.json").read_bytes())["rows"]
    assert rows and {row["visibility"] for row in rows} == {visibility}
    if grade_mode != "met":
        assert any(row["origin"] == "requirement" for row in rows)
    handoff = (other / "attorney-review-handoff.md").read_text()
    if expected_blocker is not None:
        assert source.report_text not in handoff
    else:
        prefix, report = handoff.split("## Report\n", 1)
        prefix = prefix.replace("\\_", "_")
        assert source.report_text + report_suffix in report
        for row in rows:
            assert row["gap_id"] in prefix
            assert row["shortfall_description"] in prefix
            assert row["why_unresolved"] in prefix
            assert row["why_it_matters"] in prefix
            assert row["resolution_test"] in prefix
            assert row["owner_role"] in prefix


@pytest.mark.parametrize(
    "selected,blocker",
    [
        ("lane_1", None),
        ("lane_2", None),
        ("unresolved", "GAP_RATIONALE_INVALID"),
    ],
)
def test_v3_whole_assessment_referee_graph_parity(tmp_path, monkeypatch, selected, blocker):
    test_review_package_graph_preserves_visibility_and_derives_blockers(
        tmp_path,
        monkeypatch,
        "hidden",
        None,
        blocker,
        referee=selected,
    )


def test_v3_false_completeness_cannot_be_cured_by_issue_flags(tmp_path, monkeypatch):
    test_review_package_graph_preserves_visibility_and_derives_blockers(
        tmp_path,
        monkeypatch,
        "hidden",
        None,
        "HIDDEN_MATERIAL_GAP",
        report_suffix="\nAll issues are resolved.\n",
    )


@pytest.mark.parametrize(
    "statement,blocker",
    [
        ("Not all issues are resolved.", None),
        ("This report does not resolve all issues.", None),
        ("Attorney must resolve all outstanding issues before reliance.", None),
        ("Verify all issues are resolved before client delivery.", None),
        ("All issues are not resolved.", None),
        ("Are all issues resolved?", None),
        ("All issues are resolved.", "HIDDEN_MATERIAL_GAP"),
        ("No material gaps remain.", "HIDDEN_MATERIAL_GAP"),
        ("This report resolves every outstanding issue.", "HIDDEN_MATERIAL_GAP"),
        ("Not all issues are resolved. All issues are resolved.", "HIDDEN_MATERIAL_GAP"),
        ("Not all issues are resolved; however, all issues are resolved.", "HIDDEN_MATERIAL_GAP"),
        ("Not only are all issues resolved, the report is comprehensive.", "HIDDEN_MATERIAL_GAP"),
        (
            "This report does not resolve all issues. No material gaps remain.",
            "HIDDEN_MATERIAL_GAP",
        ),
    ],
)
def test_v3_distinguishes_warnings_from_asserted_completeness_in_real_graphs(
    tmp_path,
    monkeypatch,
    statement,
    blocker,
):
    test_review_package_graph_preserves_visibility_and_derives_blockers(
        tmp_path,
        monkeypatch,
        "hidden",
        None,
        blocker,
        report_suffix="\n" + statement + "\n",
    )


@pytest.mark.parametrize(
    "statement,blocker",
    [
        ("This report doesn't resolve all issues.", None),
        ("This report doesn\u2019t resolve all issues.", None),
        ("This report doesn't resolve all issues. All issues are resolved.", "HIDDEN_MATERIAL_GAP"),
    ],
)
def test_v3_contracted_warnings_preserve_review_package_without_waiving_assertions(
    tmp_path,
    monkeypatch,
    statement,
    blocker,
):
    test_review_package_graph_preserves_visibility_and_derives_blockers(
        tmp_path,
        monkeypatch,
        "hidden",
        None,
        blocker,
        report_suffix="\n" + statement + "\n",
    )


@pytest.mark.parametrize(
    "statement,blocker",
    [
        (
            "This report does not fully address all issues "
            "and resolves every outstanding question.",
            "HIDDEN_MATERIAL_GAP",
        ),
        ("This report does not resolve all issues and limitations.", None),
        ("This report does not address all issues and resolve every outstanding question.", None),
    ],
)
def test_v3_conjoined_assertion_does_not_inherit_unrelated_negation(
    tmp_path,
    monkeypatch,
    statement,
    blocker,
):
    test_review_package_graph_preserves_visibility_and_derives_blockers(
        tmp_path,
        monkeypatch,
        "hidden",
        None,
        blocker,
        report_suffix="\n" + statement + "\n",
    )


@pytest.mark.parametrize(
    "case,blocker",
    [
        ("coverage", "MINIMUM_LANE_COVERAGE_BELOW_FLOOR"),
        ("explicit", "FALSE_RESOLUTION"),
        ("disclosure", "HIDDEN_MATERIAL_GAP"),
    ],
)
def test_v3_retains_floor_explicit_codes_and_supplied_disclosure_binding(
    tmp_path,
    monkeypatch,
    case,
    blocker,
):
    test_review_package_graph_preserves_visibility_and_derives_blockers(
        tmp_path,
        monkeypatch,
        "hidden",
        None,
        blocker,
        grade_mode="partial" if case == "coverage" else "met",
        explicit_code="FALSE_RESOLUTION" if case == "explicit" else None,
        disclosure="Invented original disclosure" if case == "disclosure" else None,
    )


def test_v3_original_report_code_fence_does_not_escape_report_container(tmp_path, monkeypatch):
    test_review_package_graph_preserves_visibility_and_derives_blockers(
        tmp_path,
        monkeypatch,
        "hidden",
        None,
        None,
        report_suffix="\n```text\nAn original report code sample.\n```\n",
    )


@pytest.mark.parametrize(
    "passage,suffix",
    [
        ("A repeated paragraph.", "\nA repeated paragraph.\n\nA repeated paragraph.\n"),
        (
            "## Repeated heading",
            "\n## Repeated heading\nOne section.\n## Repeated heading\nAnother section.\n",
        ),
        (
            "A report statement.",
            "\nA report statement.\nA report statement. More contextual words.\n",
        ),
    ],
)
def test_v3_duplicate_text_stays_gradeable_without_ambiguous_quote_binding(
    tmp_path,
    monkeypatch,
    passage,
    suffix,
):
    test_review_package_graph_preserves_visibility_and_derives_blockers(
        tmp_path,
        monkeypatch,
        "hidden",
        None,
        None,
        report_suffix=suffix,
        ambiguous_passage=passage,
        referee="lane_1",
    )
