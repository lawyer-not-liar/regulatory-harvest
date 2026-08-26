"""Mutation-sensitive public-synthetic stress coverage for portable readiness."""

from __future__ import annotations

import importlib.util
import json
import sys
from copy import deepcopy
from dataclasses import asdict, replace
from hashlib import sha256
from pathlib import Path
from types import ModuleType
from typing import cast

import pytest

from regulatory_harvest.evaluation.attorney_baseline_projection import (
    project_gradeable_baseline_v1,
    verify_gradeable_baseline_projection_v1,
)
from regulatory_harvest.evaluation.attorney_models import (
    CaseAdmissionJudgment,
    CaseReadiness,
    model_fingerprint,
)
from regulatory_harvest.evaluation.attorney_readiness_artifacts import (
    initialize_readiness_run_storage_v1,
    load_verified_readiness_context_v1,
    verify_readiness_run_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_drafts import (
    CompiledReadinessDraftV1,
    ReadinessEvaluatorProvenanceV1,
    compile_readiness_draft_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_models import (
    HistoricalV22CrossCheckV1,
    ReadinessOperationV1,
)
from regulatory_harvest.evaluation.attorney_readiness_workflow import (
    _grade_requests,
    guarded_submit_readiness_response_v1,
    next_readiness_request_v1,
    readiness_exit_code_v1,
    resume_readiness_v1,
)
from regulatory_harvest.storage import canonical_json_bytes

ROOT = Path(__file__).parents[2]
PORTABLE = ROOT / "scripts" / "attorney_eval_portable.py"
REQUIREMENT_COUNTS = (0, 1, 5, 6, 52, 128, 129)
FINDING_COUNTS = (0, 1, 5, 6, 21, 129)
COVERAGE_MODES = (
    "all_met", "below_070", "at_070", "above_070", "below_090",
    "at_090", "above_090", "all_not_met", "uncertain",
)
HISTORY_MODES = (
    "none", "one_a_baseline_not_comparable", "one_b_report_not_comparable",
    "two_ab_match", "two_ba_differs", "one_a_inconclusive",
)
DISPUTE_KINDS = (
    "finding_existence", "rationale", "evidence_binding", "visibility",
    "blocker", "follow_up", "owner", "resolution_test",
)


def _portable() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "attorney_readiness_portable_stress", PORTABLE
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _tree(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*")) if path.is_file()
    }


def _digest(label: str) -> str:
    return sha256(label.encode()).hexdigest()


def _vector(seed: int, rubric: dict[str, object]) -> dict[str, object]:
    requirement_count = REQUIREMENT_COUNTS[seed] if seed < 7 else 5
    finding_count = FINDING_COUNTS[seed] if seed < 5 else 1
    if seed == 13:
        finding_count = 129
    coverage_mode = COVERAGE_MODES[seed % len(COVERAGE_MODES)]
    if 7 <= seed <= 12:
        requirement_count = (6, 5, 6, 6, 5, 6)[seed - 7]
        coverage_mode = COVERAGE_MODES[seed - 6]
    if 24 <= seed < 32:
        finding_count, coverage_mode = 1, "all_not_met"
    if seed >= 32:
        coverage_mode = "all_not_met"
    if seed == 14:
        requirement_count, finding_count, coverage_mode = 5, 0, "all_met"
    if seed == 15:
        requirement_count, finding_count, coverage_mode = 5, 0, "at_070"
    if seed == 16:
        requirement_count, finding_count, coverage_mode = 5, 0, "uncertain"
    if seed in {17, 19}:
        requirement_count, finding_count, coverage_mode = 5, 0, "all_met"
    history_mode = HISTORY_MODES[seed % len(HISTORY_MODES)]
    if seed == 17:
        history_mode = "two_ab_match"
    if seed == 19:
        history_mode = "two_ba_differs"
    if seed in {20, 21, 22, 23}:
        finding_count = max(1, finding_count)
    rationale = cast(list[str], rubric["rationale_kinds"])
    follow_up = cast(list[str], rubric["follow_up_codes"])
    owners = cast(list[str], rubric["owner_roles"])
    blockers = cast(list[str], rubric["blocking_codes"])
    return {
        "seed": seed,
        "requirement_count": requirement_count,
        "finding_count": finding_count,
        "coverage_mode": coverage_mode,
        "history_mode": history_mode,
        "dispute_kind": DISPUTE_KINDS[seed % len(DISPUTE_KINDS)],
        "lane_dispute": 24 <= seed < 32,
        "normalization": seed == 20,
        "one_repair_success": seed == 21,
        "second_refusal_pause": seed == 22,
        "interrupt_resume": seed == 23,
        "rationale_kind": rationale[seed % len(rationale)],
        "follow_up_code": follow_up[seed % len(follow_up)],
        "alternate_follow_up_code": next(
            item for item in follow_up if item != "EXPAND_REQUIREMENT_ANALYSIS"
        ),
        "owner_role": owners[seed % len(owners)],
        "alternate_owner_role": next(
            item for item in owners if item != "reviewing_attorney"
        ),
        "visibility": ("hidden", "visible", "prominent")[seed % 3],
        "blocking_code": blockers[(seed - 40) % len(blockers)] if seed >= 40 else None,
        "alternate_blocking_code": blockers[0],
    }


def _history(mode: str, report_hash: str) -> HistoricalV22CrossCheckV1 | None:
    if mode == "none":
        return None
    count = 2 if mode.startswith("two_") else 1
    orientation = "ba" if "ba_" in mode else "ab"
    labels = [f"history-{orientation}-{index}" for index in range(count * 2)]
    if orientation == "ba":
        labels.reverse()
    return HistoricalV22CrossCheckV1(
        report_hash=report_hash if "report_not_comparable" not in mode else _digest(mode),
        strict_disposition=(
            "INCONCLUSIVE"
            if mode.endswith("inconclusive")
            else "FAIL"
            if mode.endswith("differs")
            else "PASS"
        ),
        result_fingerprint=_digest(f"{mode}-result"),
        manifest_fingerprint=_digest(f"{mode}-manifest"),
        baseline_fingerprint=_digest(f"{mode}-baseline"),
        grader_aggregate_fingerprints=tuple(_digest(label) for label in labels),
        reason_codes=(f"SYNTHETIC_{count}_REPORT_{orientation.upper()}",),
        baseline_comparable="baseline_not_comparable" not in mode,
        report_comparable="report_not_comparable" not in mode,
    )


def _inputs(
    tmp_path: Path,
    vector: dict[str, object],
    requests: ModuleType,
    projections: ModuleType,
    input_helpers: ModuleType,
    full_workflow: ModuleType,
):
    tmp_path.mkdir()
    limitations = (
        "Machine translated."
        if vector["rationale_kind"] == "LANGUAGE_LIMITATION"
        else None
    )
    source_artifacts = input_helpers._make_verified_inputs(
        tmp_path, limitations=limitations
    )
    source = full_workflow.build_verified_readiness_input_v1(
        baseline_run_dir=source_artifacts.baseline_run_dir,
        qualification_run_dir=source_artifacts.qualification_run_dir,
        generation_run_dir=source_artifacts.generation_run_dir,
        validation_receipt_path=source_artifacts.validation_receipt_path,
    )
    prerequisite_code = {
        "CURRENTNESS_NOT_ESTABLISHED": "CURRENTNESS_EVIDENCE",
        "LANGUAGE_LIMITATION": "LANGUAGE_RESOLUTION",
    }.get(cast(str, vector["rationale_kind"]))
    receipt_fingerprint: str | None = None
    if prerequisite_code is not None:
        changed_checks = tuple(
            replace(
                item,
                satisfied=False,
                material=False,
                rationale=(
                    f"The public synthetic fixture leaves {item.code} unresolved."
                ),
            )
            if item.code == prerequisite_code
            else item
            for item in source.qualification_limits.admission_checks
        )
        judgment = CaseAdmissionJudgment.model_validate(
            {
                "request_fingerprint": source.qualification_limits.request_fingerprint,
                "checks": [asdict(item) for item in changed_checks],
                "issues": [],
            }
        )
        judgment_fingerprint = model_fingerprint(judgment)
        readiness = CaseReadiness(
            status="ADMITTED",
            case_fingerprint=source.qualification_limits.case_fingerprint,
            judgment_fingerprint=judgment_fingerprint,
            issue_codes=[],
            rationale=source.qualification_limits.receipt_readiness.rationale,
        )
        receipt_descriptor = {
            "schema_version": "1.0",
            "case_fingerprint": source.qualification_limits.case_fingerprint,
            "source_record_fingerprint": (
                source.qualification_limits.source_record_fingerprint
            ),
            "request_fingerprint": source.qualification_limits.request_fingerprint,
            "judgment_fingerprint": judgment_fingerprint,
            "readiness": readiness.model_dump(mode="json"),
        }
        receipt_fingerprint = sha256(canonical_json_bytes(receipt_descriptor)).hexdigest()
        source = replace(
            source,
            qualification_limits=replace(
                source.qualification_limits,
                qualification_receipt_fingerprint=receipt_fingerprint,
                judgment_fingerprint=judgment_fingerprint,
                admission_checks=changed_checks,
            ),
            qualification_binding=replace(
                source.qualification_binding,
                qualification_receipt_fingerprint=receipt_fingerprint,
            ),
        )
    input_mutation: dict[str, object] = {}
    if receipt_fingerprint is not None:
        input_mutation["qualification_receipt_fingerprint"] = receipt_fingerprint
    if vector["rationale_kind"] == "APPLICABILITY_FACT_MISSING":
        input_mutation.update(
            client_facts=None,
            client_facts_binding="explicit-null",
        )
        source = replace(
            source,
            generation_binding=replace(
                source.generation_binding,
                client_facts_hash=None,
            ),
        )
    count = cast(int, vector["requirement_count"])
    requirements = tuple(
        requests._requirement(index, importance="material")
        for index in range(1, count + 1)
    )
    base_contest = requests._contest()
    reviewer = requests._requirement(count + 1, importance="critical")
    auditor = reviewer.model_copy(
        update={
            "statement": "The fictional duty may require a narrower filing.",
            "confidence": "ambiguous",
            "substantive_rationale": "The source permits the narrower reading.",
        }
    )
    contest = base_contest.model_copy(
        update={
            "reviewer_alternative": reviewer,
            "auditor_alternative": auditor,
        }
    )
    context = projections._resealed_context(
        source.baseline_context,
        input_mutation=input_mutation,
        baseline_mutation={
            "requirements": requirements,
            "relationships": (),
            "contested_requirements": (contest,) if count == 0 else (),
        },
    )
    projection = verify_gradeable_baseline_projection_v1(
        context, project_gradeable_baseline_v1(context)
    )
    historical = _history(cast(str, vector["history_mode"]), source.report_hash)
    readiness_input = source.readiness_input.model_copy(
        update={
            "gradeable_baseline": projection,
            "grade_target_fingerprint": projection.binding.grade_target_fingerprint,
            "historical_v22_cross_check": historical,
        }
    )
    return replace(
        source,
        readiness_input=readiness_input,
        baseline_context=context,
        gradeable_baseline=projection,
        historical_v22=historical,
    )


def _portable_initialize(portable: ModuleType, full: Path, output: Path) -> None:
    persisted_bytes = (full / "readiness-input.json").read_bytes()
    rubric_bytes = (full / "readiness-rubric.json").read_bytes()
    persisted, rubric = json.loads(persisted_bytes), json.loads(rubric_bytes)
    readiness_input = persisted["readiness_input"]
    request = portable._readiness_grade_requests(readiness_input, rubric)[0]
    call_id = request["payload"]["controller_lane_id"]
    files = {
        "readiness-input.json": persisted_bytes,
        "readiness-rubric.json": rubric_bytes,
        f"requests/{call_id}.json": portable.canonical_json_bytes(request),
    }
    manifest = portable._readiness_manifest(readiness_input, files, request)
    with portable._open_run_storage(output, initialize=True) as storage:
        for path in sorted(files):
            storage.atomic_write(path, files[path], mutable=False)
        storage.atomic_write(
            "readiness-manifest.json", portable.canonical_json_bytes(manifest), mutable=False
        )


def _coverage_units(mode: str, total: int) -> int:
    return {
        "all_met": 2 * total,
        "below_070": max(0, (14 * total - 1) // 10),
        "at_070": 7 if total == 5 else int(1.4 * total),
        "above_070": min(2 * total, (14 * total) // 10 + 1),
        "below_090": max(0, (18 * total - 1) // 10),
        "at_090": 9 if total == 5 else int(1.8 * total),
        "above_090": min(2 * total, (18 * total) // 10 + 1),
        "all_not_met": 0,
        "uncertain": 2 * total,
    }[mode]


def _grade_draft(
    request: object, workflow: ModuleType, mode: str, total: int
) -> dict[str, object]:
    draft = workflow._draft(request, grade_mode="review")
    if request.operation is ReadinessOperationV1.BASELINE_LOCKED_CONTESTED_GRADE:
        draft.update(
            reviewer_alternative_disposition="met",
            auditor_alternative_disposition="met",
            reviewer_rationale="The exact passage addresses this alternative.",
            auditor_rationale="The exact passage addresses this alternative.",
        )
        return draft
    grades = cast(list[dict[str, object]], draft["requirement_grades"])
    units = _coverage_units(mode, total)
    for grade in grades:
        index = int(cast(str, grade["requirement_id"]).split("-")[1]) - 1
        if mode == "uncertain" and index == 0:
            disposition = "uncertain"
        elif index < units // 2:
            disposition = "met"
        elif index == units // 2 and units % 2:
            disposition = "partially_met"
        else:
            disposition = "not_met"
        if disposition == "met":
            grade.update(
                disposition="met", omission=None,
                rationale="The exact report passage addresses this requirement.",
            )
        elif disposition == "partially_met":
            grade.update(
                disposition="partially_met",
                omission="The remaining implementation detail is not addressed.",
            )
        else:
            grade.update(
                disposition=disposition, report_passages=[],
                omission="The report does not establish this requirement.",
                rationale="The exact report does not establish this requirement.",
            )
    return draft


def _safety_draft(
    request: object,
    workflow: ModuleType,
    drafts: ModuleType,
    vector: dict[str, object],
) -> dict[str, object]:
    result = workflow._draft(request, grade_mode="met", blocking_safety=False)
    base = drafts._finding_draft(request)
    findings: list[dict[str, object]] = []
    for index in range(cast(int, vector["finding_count"])):
        item = deepcopy(base)
        item.update(
            subject_id=f"public-synthetic-assertion-{index + 1:04d}",
            blocking_code=vector["blocking_code"],
        )
        if vector["blocking_code"] is not None:
            item.update(visibility="prominent", owner_role="reviewing_attorney")
        rationale_kind = cast(str, vector["rationale_kind"])
        prefix_and_kind = {
            "CURRENTNESS_NOT_ESTABLISHED": (
                "PREREQUISITE-CURRENTNESS-",
                "MISLEADING_CURRENTNESS_OR_AUTHORITY",
            ),
            "LANGUAGE_LIMITATION": (
                "PREREQUISITE-LANGUAGE-",
                "HIDDEN_OR_UNDERSTATED_LIMITATION",
            ),
            "APPLICABILITY_FACT_MISSING": (
                "PREREQUISITE-CLIENT-FACTS",
                "UNDISCLOSED_DISPOSITIVE_CLIENT_FACT",
            ),
        }.get(rationale_kind, ("SOURCE-", "MATERIAL_UNSUPPORTED_ASSERTION"))
        evidence_ref = next(
            cast(str, handle["evidence_ref"])
            for handle in request.payload["evidence_handles"]
            if cast(str, handle["evidence_ref"]).startswith(prefix_and_kind[0])
        )
        item.update(
            finding_kind=prefix_and_kind[1],
            rationale_kind=rationale_kind,
            evidence_refs=[evidence_ref],
            why_unresolved=(
                f"{evidence_ref} does not establish the exact missing legal treatment."
            ),
            why_it_matters=(
                f"legal_conclusion: {evidence_ref} leaves the scoped answer incomplete."
            ),
        )
        findings.append(item)
    if cast(int, vector["seed"]) >= 32:
        candidates = {
            item["candidate_id"]: item for item in request.payload["gap_candidates"]
        }
        target = next(
            item
            for item in result["candidate_assessments"]
            if candidates[item["candidate_id"]]["importance"] != "critical"
        )
        target.update(
            visibility=vector["visibility"],
            owner_role=vector["owner_role"],
            follow_up_code=vector["follow_up_code"],
            blocking_code=vector["blocking_code"],
        )
    if cast(bool, vector["lane_dispute"]) and request.payload["lane"] == 2:
        kind = cast(str, vector["dispute_kind"])
        if kind == "finding_existence":
            findings = []
        else:
            candidates = {
                item["candidate_id"]: item for item in request.payload["gap_candidates"]
            }
            target = next(
                item for item in result["candidate_assessments"]
                if candidates[item["candidate_id"]]["importance"] != "critical"
            )
        if kind != "finding_existence":
            if kind == "rationale":
                target["shortfall_description"] = "The second lane identifies a narrower gap."
            elif kind == "evidence_binding":
                refs = list(cast(list[str], target["evidence_refs"]))
                alternate = next(
                    item["evidence_ref"] for item in request.payload["evidence_handles"]
                    if item["evidence_ref"] not in refs
                )
                target["evidence_refs"] = [*refs, alternate]
            elif kind == "visibility":
                target["visibility"] = (
                    "hidden" if target["visibility"] != "hidden" else "prominent"
                )
            elif kind == "blocker":
                target["blocking_code"] = vector["alternate_blocking_code"]
            elif kind == "follow_up":
                target["follow_up_code"] = vector["alternate_follow_up_code"]
            elif kind == "owner":
                target["owner_role"] = vector["alternate_owner_role"]
            else:
                target["resolution_test"] = (
                    "Obtain exact official evidence and verify the complete legal treatment."
                )
    result["finding_proposals"] = findings
    return result


@pytest.mark.parametrize("seed", range(96))
def test_readiness_seeded_scoring_boundary_matrix(
    seed: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each seed independently exercises and compares an actual full/portable graph."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    requests = __import__("test_attorney_readiness_requests")
    projections = __import__("test_attorney_baseline_projection")
    input_helpers = __import__("test_attorney_readiness_inputs")
    full_workflow = __import__(
        "regulatory_harvest.evaluation.attorney_readiness_workflow",
        fromlist=["*"],
    )
    workflow = __import__("test_attorney_readiness_workflow")
    drafts = __import__("test_attorney_readiness_drafts")
    portable = _portable()
    rubric_bytes, rubric, _ = portable._readiness_rubric_v1()
    vector = _vector(seed, rubric)
    inputs = _inputs(
        tmp_path / "inputs",
        vector,
        requests,
        projections,
        input_helpers,
        full_workflow,
    )
    full_run, portable_run = tmp_path / "full", tmp_path / "portable"
    grade_requests = _grade_requests(inputs)
    initialize_readiness_run_storage_v1(full_run, inputs, grade_requests[0])
    _portable_initialize(portable, full_run, portable_run)
    assert rubric_bytes == (full_run / "readiness-rubric.json").read_bytes()
    assert _tree(full_run) == _tree(portable_run)
    provenance = ReadinessEvaluatorProvenanceV1(
        provider_name="public-stress-provider", model_name="public-stress-model",
        judge_isolation="scripted_fixture",
    )
    portable_provenance = {
        "provider_name": provenance.provider_name,
        "model_name": provenance.model_name,
        "judge_isolation": provenance.judge_isolation,
    }
    transcript: list[tuple[bytes, bytes]] = []
    finding_counts: list[int] = []
    disputes: list[str] = []
    normalization_seen = probe_done = False
    while (request := next_readiness_request_v1(full_run)) is not None:
        portable_request = portable.next_readiness_request_v1(portable_run)
        request_bytes = canonical_json_bytes(request.model_dump(mode="json"))
        assert portable.canonical_json_bytes(portable_request) == request_bytes
        before = _tree(full_run), _tree(portable_run)
        if cast(bool, vector["interrupt_resume"]) and not probe_done:
            assert next_readiness_request_v1(full_run) == request
            assert portable.next_readiness_request_v1(portable_run) == portable_request
            assert (_tree(full_run), _tree(portable_run)) == before
            probe_done = True
        repair = cast(bool, vector["one_repair_success"])
        refusal = cast(bool, vector["second_refusal_pause"])
        if (repair or refusal) and not probe_done:
            for _ in range(2 if refusal else 1):
                clarification = compile_readiness_draft_v1(request, {}, provenance)
                assert tuple(item.value for item in clarification.reason_codes) == (
                    "DRAFT_INVALID",
                )
                with pytest.raises(portable.PortableEvaluationInputError):
                    portable.compile_readiness_draft_v1(portable_request, {}, portable_provenance)
                assert (_tree(full_run), _tree(portable_run)) == before
            if refusal:
                # Pause belongs to the live host; isolated status remains write-free.
                assert portable.readiness_status_payload_v1(portable_run)["engine_paused"] is False
            probe_done = True
        if request.operation in {
            ReadinessOperationV1.BASELINE_LOCKED_GRADE,
            ReadinessOperationV1.BASELINE_LOCKED_CONTESTED_GRADE,
        }:
            draft = _grade_draft(
                request,
                workflow,
                cast(str, vector["coverage_mode"]),
                cast(int, vector["requirement_count"]),
            )
        elif request.operation is ReadinessOperationV1.SAFETY_REVIEW:
            draft = _safety_draft(request, workflow, drafts, vector)
            finding_counts.append(len(cast(list[object], draft["finding_proposals"])))
            if cast(bool, vector["normalization"]) and not normalization_seen:
                findings = cast(list[dict[str, object]], draft["finding_proposals"])
                findings.append(deepcopy(findings[0]))
        else:
            disputes.append(cast(str, request.payload["dispute_kind"]))
            draft = workflow._draft(request, grade_mode="met")
        compiled = compile_readiness_draft_v1(request, deepcopy(draft), provenance)
        assert isinstance(compiled, CompiledReadinessDraftV1), (
            request.operation,
            draft,
            compiled,
        )
        if (
            cast(bool, vector["normalization"])
            and not normalization_seen
            and request.operation is ReadinessOperationV1.SAFETY_REVIEW
        ):
            assert compiled.normalization_codes == ("DRAFT_NORMALIZED_DUPLICATES",)
            normalization_seen = True
        portable_response = portable.compile_readiness_draft_v1(
            portable_request, deepcopy(draft), portable_provenance
        )
        response_bytes = canonical_json_bytes(compiled.response.model_dump(mode="json"))
        assert portable.canonical_json_bytes(portable_response) == response_bytes
        transcript.append((request_bytes, response_bytes))
        assert guarded_submit_readiness_response_v1(full_run, compiled.response).accepted
        assert portable.guarded_submit_readiness_response_v1(
            portable_run, portable_response
        )["accepted"]
        assert _tree(full_run) == _tree(portable_run)
    assert transcript and finding_counts[0] == cast(int, vector["finding_count"])
    if cast(bool, vector["lane_dispute"]):
        assert disputes == [vector["dispute_kind"]]
    if cast(bool, vector["normalization"]):
        assert normalization_seen
    tree = _tree(portable_run)
    safety_lane = json.loads(tree["responses/safety-lane-1.json"])["payload"]
    if cast(int, vector["seed"]) >= 32:
        assert safety_lane["finding_proposals"][0]["rationale_kind"] == vector[
            "rationale_kind"
        ]
        material = safety_lane["candidate_assessments"][0]
        assert material["visibility"] == vector["visibility"]
        assert material["follow_up_code"] == vector["follow_up_code"]
        assert material["owner_role"] == vector["owner_role"]
        assert material["blocking_code"] == vector["blocking_code"]
    result = json.loads(tree["delivery-readiness.json"])
    strict = json.loads(tree["baseline-locked-strict-equivalent.json"])
    requirements = json.loads(tree["requirement-matrix.json"])
    gaps = json.loads(tree["gap-follow-up-matrix.json"])
    count = cast(int, vector["requirement_count"])
    if vector["blocking_code"] is not None:
        assert vector["blocking_code"] in result["blocking_codes"]
    if count and vector["coverage_mode"] != "uncertain":
        expected_coverage = _coverage_units(
            cast(str, vector["coverage_mode"]), count
        ) / (2 * count)
        assert result["lane_weighted_coverage"] == [
            expected_coverage,
            expected_coverage,
        ]
    if seed == 14:
        assert result["delivery_readiness"] == "HIGH_ASSURANCE"
        assert strict["absolute_disposition"] == "PASS"
    elif seed == 15:
        assert result["delivery_readiness"] == "REVIEW_READY_WITH_GAPS"
        assert strict["absolute_disposition"] == "FAIL"
    elif seed == 16:
        assert strict["absolute_disposition"] == "INCONCLUSIVE"
    assert len(requirements["rows"]) == count
    assert [item["canonical_order"] for item in requirements["rows"]] == list(range(count))
    assert [item["canonical_order"] for item in gaps["rows"]] == list(range(len(gaps["rows"])))
    assert requirements["matrix_fingerprint"] == result["requirement_matrix_fingerprint"]
    assert gaps["matrix_fingerprint"] == result["gap_matrix_fingerprint"]
    manifest = json.loads(tree["readiness-manifest.json"])
    assert strict["strict_equivalent_fingerprint"] == manifest[
        "baseline_locked_strict_equivalent_fingerprint"
    ]
    assert tree["attorney-review-handoff.md"]
    full_verification = verify_readiness_run_v1(full_run).model_dump(mode="json")
    portable_verification = portable.verify_readiness_run_v1(portable_run)
    assert portable_verification == full_verification
    assert portable_verification["valid"] is True
    state = resume_readiness_v1(full_run)
    assert state.terminal_status == "COMPLETED"
    status = portable.readiness_status_payload_v1(portable_run)
    assert status["delivery_readiness"] == result["delivery_readiness"]
    assert status["baseline_locked_strict_equivalent_disposition"] == result[
        "baseline_locked_strict_equivalent_disposition"
    ]
    assert (4 if result["delivery_readiness"] == "NOT_DELIVERABLE" else 0) == (
        readiness_exit_code_v1(
            load_verified_readiness_context_v1(full_run).result,
            paused=False,
        )
    )
    historical = inputs.historical_v22
    if historical is None:
        assert result["historical_v22_cross_check_status"] == "NOT_PROVIDED"
        assert "historical-v22-cross-check.json" not in tree
    else:
        assert tree["historical-v22-cross-check.json"] == canonical_json_bytes(
            historical.model_dump(mode="json")
        )
        expected = (
            "BASELINE_NOT_COMPARABLE" if not historical.baseline_comparable
            else "REPORT_NOT_COMPARABLE" if not historical.report_comparable
            else "MATCH" if historical.strict_disposition.value == strict["absolute_disposition"]
            else "DISPOSITION_DIFFERS"
        )
        assert result["historical_v22_cross_check_status"] == expected


def test_readiness_stress_matrix_covers_every_executed_dimension() -> None:
    portable = _portable()
    _, rubric, _ = portable._readiness_rubric_v1()
    vectors = [_vector(seed, rubric) for seed in range(96)]
    assert {item["requirement_count"] for item in vectors} == set(REQUIREMENT_COUNTS)
    assert {item["finding_count"] for item in vectors} == set(FINDING_COUNTS)
    assert {item["coverage_mode"] for item in vectors} == set(COVERAGE_MODES)
    assert {item["history_mode"] for item in vectors} == set(HISTORY_MODES)
    assert {item["dispute_kind"] for item in vectors if item["lane_dispute"]} == set(DISPUTE_KINDS)
    for key, inventory in (
        ("rationale_kind", rubric["rationale_kinds"]),
        ("follow_up_code", rubric["follow_up_codes"]),
        ("owner_role", rubric["owner_roles"]),
    ):
        assert {item[key] for item in vectors} == set(inventory)
    assert {item["visibility"] for item in vectors} == {"hidden", "visible", "prominent"}
    assert {
        item["blocking_code"] for item in vectors if item["blocking_code"] is not None
    } == set(rubric["blocking_codes"])
    for field in (
        "lane_dispute", "normalization", "one_repair_success",
        "second_refusal_pause", "interrupt_resume",
    ):
        assert {item[field] for item in vectors} == {False, True}
