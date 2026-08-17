from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path

import pytest

import regulatory_harvest.evaluation.attorney_cli as attorney_cli
import regulatory_harvest.evaluation.attorney_workflow as attorney_workflow
from regulatory_harvest.cli import main
from regulatory_harvest.evaluation.attorney_artifacts import (
    EvaluationIntegrityError,
    load_verified_evaluation_run,
    verify_evaluation_run,
)
from regulatory_harvest.evaluation.attorney_cli import _case_from_fixture
from regulatory_harvest.evaluation.attorney_models import (
    AttorneyEvaluationCase,
    CandidateGrade,
    CoverageDisposition,
    EntryGrade,
    JudgeIsolation,
    JudgeOperation,
    JudgeRequest,
    JudgeResponse,
    LedgerAudit,
    LegalLedger,
    NarrativeScore,
)
from regulatory_harvest.evaluation.attorney_workflow import (
    guarded_submit_judge_response,
    initialize_evaluation,
    next_judge_request,
    run_evaluation,
)
from regulatory_harvest.storage import canonical_json_bytes

FIXTURE = Path(__file__).parents[1] / "fixtures" / "attorney-eval"
_DIMENSIONS = (
    "executive_summary",
    "regulatory_walk",
    "key_requirements",
    "penalties_enforcement",
    "qualification_placement",
    "requirements_workplan_boundary",
    "limitations",
    "scanability",
)


class MechanicalFixtureJudge:
    """Independent local grader derived from the copied source and report bytes."""

    def __init__(self, fixture: Path) -> None:
        scripted = json.loads(
            (fixture / "responses" / "scripted-responses.json").read_text(encoding="utf-8")
        )
        self._ledger = LegalLedger.model_validate(scripted["responses"][1]["payload"])
        self._response_number = 0
        self.scripted_responses: list[dict[str, object]] = []

    async def evaluate(self, request: JudgeRequest) -> JudgeResponse:
        self._response_number += 1
        payload = self._payload(request)
        self.scripted_responses.append(
            {
                "expect": {
                    "request_fingerprint": request.request_fingerprint,
                    **request.safe_metadata,
                },
                "operation": request.operation.value,
                "payload": payload,
            }
        )
        return JudgeResponse(
            operation=request.operation,
            request_fingerprint=request.request_fingerprint,
            provider_name="mechanical-cc0-fixture",
            model_name="no-provider",
            judge_isolation=JudgeIsolation.SCRIPTED_FIXTURE,
            response_id=f"mechanical-response-{self._response_number}",
            payload=payload,
        )

    def _payload(self, request: JudgeRequest) -> dict[str, object]:
        if request.operation is JudgeOperation.ADMIT_CASE:
            return {
                "request_fingerprint": request.request_fingerprint,
                "checks": [
                    {
                        "code": code,
                        "satisfied": True,
                        "material": True,
                        "rationale": "The copied CC0 source record supplies this check.",
                        "source_ids": ["synthetic-rule-1-source"],
                    }
                    for code in (
                        "AUTHORITY_ALIGNMENT",
                        "OPERATIVE_TEXT",
                        "CURRENTNESS_EVIDENCE",
                        "LANGUAGE_RESOLUTION",
                        "SOURCE_PARITY",
                    )
                ],
                "issues": [],
            }
        if request.operation is JudgeOperation.BUILD_LEDGER:
            return self._ledger.model_copy(
                update={"case_fingerprint": request.safe_metadata["source_record_fingerprint"]}
            ).model_dump(mode="json")
        if request.operation is JudgeOperation.AUDIT_LEDGER:
            return LedgerAudit(
                request_fingerprint=request.request_fingerprint,
                disputes=[],
                complete=True,
            ).model_dump(mode="json")
        if request.operation is JudgeOperation.GRADE_REPORT:
            report = request.payload["anonymous_report"]
            assert isinstance(report, dict)
            report_text = report["report_text"]
            assert isinstance(report_text, str)
            return self._grade_payload(request, report_text, self._response_number)
        raise AssertionError(f"unexpected operation: {request.operation}")

    def _grade_payload(
        self,
        request: JudgeRequest,
        report_text: str,
        grader_number: int,
    ) -> dict[str, object]:
        grades = [
            EntryGrade(
                ledger_id=entry.ledger_id,
                disposition=CoverageDisposition.COMPLETE,
                rationale=(
                    f"Independent copied-fixture grader {grader_number} found this fact covered."
                ),
                report_location="paragraph 1",
                report_passage=report_text,
            ).model_dump(mode="json")
            for entry in self._ledger.entries
        ]
        by_id = {grade["ledger_id"]: grade for grade in grades}
        claims: list[dict[str, object]] = []
        source_record = request.payload["source_record"]
        assert isinstance(source_record, dict)
        source_record_fingerprint = source_record["source_record_fingerprint"]
        narratives = [
            NarrativeScore(
                dimension=dimension,
                score=4,
                rationale=(
                    "Independent copied-fixture grader "
                    f"{grader_number} found this dimension covered."
                ),
                report_passage=report_text,
            ).model_dump(mode="json")
            for dimension in _DIMENSIONS
        ]

        if "file a registry notice" not in report_text:
            by_id["file-notice"].update(
                disposition="MISSING",
                report_location=None,
                report_passage=None,
                finding_codes=["CRITICAL_LEDGER_ENTRY_MISSING"],
            )
        if "do not apply during an emergency" not in report_text:
            by_id["emergency-exception"].update(
                disposition="MISSING",
                report_location=None,
                report_passage=None,
                finding_codes=["MATERIAL_EXCEPTION_MISSING"],
            )
        if "within 30 days" in report_text:
            by_id["notice-deadline"]["disposition"] = "OVERSTATED"
        if "$5,000" in report_text:
            claims.append(
                {
                    "claim_id": "invented-penalty",
                    "claim_text": "a violation may result in a civil penalty of $5,000",
                    "report_location": "paragraph 1",
                    "disposition": "UNSUPPORTED",
                    "category": "penalty",
                    "materiality": "material",
                    "related_ledger_ids": ["civil-penalty"],
                    "source_record_fingerprint": source_record_fingerprint,
                    "evidence_basis": "closed_universe_absence",
                    "evidence_spans": [],
                    "rationale": "The changed amount is absent from the copied source record.",
                }
            )
        if "civil penalty of $500 applies" in report_text:
            by_id["civil-penalty"].update(
                disposition="PARTIAL",
                finding_codes=["CONSEQUENCE_TRIGGER_DETACHED"],
            )
        if "repealed yesterday" in report_text:
            claims.append(
                {
                    "claim_id": "stale-status",
                    "claim_text": "The rule was repealed yesterday.",
                    "report_location": "paragraph 1",
                    "disposition": "UNSUPPORTED",
                    "category": "status",
                    "materiality": "material",
                    "related_ledger_ids": [],
                    "source_record_fingerprint": source_record_fingerprint,
                    "evidence_basis": "closed_universe_absence",
                    "evidence_spans": [],
                    "rationale": "The copied source record has no repeal statement.",
                }
            )
        if "retain proof of filing" not in report_text:
            next(score for score in narratives if score["dimension"] == "key_requirements").update(
                score=2,
                finding_codes=["KEY_REQUIREMENTS_ACTION_PLAN"],
            )
        if "will always waive every filing duty" in report_text:
            claims.append(
                {
                    "claim_id": "unsupported-fluent-prose",
                    "claim_text": "The Bureau will always waive every filing duty.",
                    "report_location": "paragraph 1",
                    "disposition": "UNSUPPORTED",
                    "category": "requirement",
                    "materiality": "material",
                    "related_ledger_ids": ["file-notice"],
                    "source_record_fingerprint": source_record_fingerprint,
                    "evidence_basis": "closed_universe_absence",
                    "evidence_spans": [],
                    "rationale": "The fluent assertion is absent from the copied source record.",
                }
            )

        return CandidateGrade(
            request_fingerprint=request.request_fingerprint,
            anonymous_label=request.safe_metadata["anonymous_label"],  # type: ignore[arg-type]
            ledger_fingerprint=request.safe_metadata["legal_ledger_fingerprint"],
            entry_grades=[EntryGrade.model_validate(grade) for grade in grades],
            out_of_ledger_claims=claims,
            narrative_scores=[NarrativeScore.model_validate(score) for score in narratives],
        ).model_dump(mode="json")


def _fixture_copy(tmp_path: Path) -> Path:
    fixture = tmp_path / "attorney-eval"
    shutil.copytree(FIXTURE, fixture)
    return fixture


def _write_canonical(path: Path, value: dict[str, object]) -> None:
    path.write_bytes(canonical_json_bytes(value) + b"\n")


def _generate_scripted_fixture(fixture: Path, output: Path) -> None:
    case = _case_from_fixture(fixture / "case.json", root=fixture)
    judge = MechanicalFixtureJudge(fixture)
    asyncio.run(run_evaluation(case, judge, output, seed_hex="0" * 64))
    _write_canonical(
        fixture / "responses" / "scripted-responses.json",
        {"fixture_type": "local-scripted", "responses": judge.scripted_responses},
    )


def _run_public_cli(fixture: Path, output: Path) -> int:
    return main(
        [
            "eval",
            "attorney",
            "run",
            "--case",
            str(fixture / "case.json"),
            "--scripted-responses",
            str(fixture / "responses" / "scripted-responses.json"),
            "--output",
            str(output),
            "--json",
        ]
    )


def _artifact_tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_guarded_submit_transition_integrity_error_is_exit_five_and_write_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A guarded transition fault preserves the run and reaches the public integrity exit."""
    fixture = _fixture_copy(tmp_path)
    _generate_scripted_fixture(fixture, tmp_path / "script-generation")
    output = tmp_path / "guarded-transition-fault"
    before: dict[str, bytes] = {}

    def fail_transition(*args: object, **kwargs: object) -> None:
        raise EvaluationIntegrityError("injected guarded transition fault")

    async def guarded_transition_fault(
        case: AttorneyEvaluationCase,
        judge: object,
        run_dir: Path,
        *,
        seed_hex: str,
        generation_capsule_paths: object,
    ) -> object:
        initialize_evaluation(
            case,
            run_dir,
            seed_hex=seed_hex,
            generation_capsule_paths=generation_capsule_paths,
        )
        request = next_judge_request(run_dir)
        assert request is not None
        response = await judge.evaluate(request)  # type: ignore[attr-defined]
        before.update(_artifact_tree_bytes(run_dir))
        guarded_submit_judge_response(run_dir, response)
        raise AssertionError("guarded submission should propagate the integrity fault")

    monkeypatch.setattr(attorney_workflow, "_accepted_transition", fail_transition)
    monkeypatch.setattr(attorney_cli, "run_evaluation", guarded_transition_fault)

    status = main(
        [
            "eval",
            "attorney",
            "run",
            "--case",
            str(fixture / "case.json"),
            "--scripted-responses",
            str(fixture / "responses" / "scripted-responses.json"),
            "--output",
            str(output),
            "--json",
        ]
    )

    assert status == 5
    assert _artifact_tree_bytes(output) == before
    assert json.loads(capsys.readouterr().out) == {
        "error": "evaluation_integrity_invalid",
        "ok": False,
    }


def _input_snapshot(fixture: Path) -> dict[str, bytes]:
    paths = (
        "case.json",
        "sources/synthetic-rule.txt",
        "reports/correct.md",
    )
    return {path: (fixture / path).read_bytes() for path in paths}


def _normalized_fact(value: str) -> str:
    return " ".join(value.split()).casefold()


@pytest.mark.parametrize(
    ("mutation", "old", "new", "expected_codes", "absolute", "exit_code"),
    [
        (
            "missing-critical-duty",
            (
                "A covered operator must file a registry notice within 10 days and retain proof "
                "of filing."
            ),
            (
                "A registry notice is due within 10 days, and the covered operator must retain "
                "proof of filing."
            ),
            {
                "CRITICAL_LEDGER_ENTRY_MISSING",
                "CRITICAL_RECALL_BELOW_FLOOR",
                "WEIGHTED_RECALL_BELOW_FLOOR",
            },
            "FAIL",
            4,
        ),
        (
            "missing-exception",
            "The duties do not apply during an emergency. ",
            "",
            {"MATERIAL_EXCEPTION_MISSING", "WEIGHTED_RECALL_BELOW_FLOOR"},
            "FAIL",
            4,
        ),
        (
            "wrong-deadline",
            "within 10 days",
            "within 30 days",
            {"OVERSTATED_MATERIAL_DEADLINE", "WEIGHTED_RECALL_BELOW_FLOOR"},
            "FAIL",
            4,
        ),
        (
            "invented-penalty",
            "$500",
            "$5,000",
            {"CLAIM_PRECISION_BELOW_FLOOR", "UNSUPPORTED_MATERIAL_PENALTY"},
            "FAIL",
            4,
        ),
        (
            "detached-consequence",
            "a violation may result in a civil penalty of $500",
            "a civil penalty of $500 applies",
            {"CONSEQUENCE_TRIGGER_DETACHED"},
            "PASS",
            0,
        ),
        (
            "stale-status",
            "a violation may result in a civil penalty of $500.\n",
            "a violation may result in a civil penalty of $500. The rule was repealed yesterday.\n",
            {"CLAIM_PRECISION_BELOW_FLOOR", "UNSUPPORTED_MATERIAL_STATUS"},
            "FAIL",
            4,
        ),
        (
            "action-plan-key-requirements",
            "and retain proof of filing.",
            ".",
            {"KEY_REQUIREMENTS_ACTION_PLAN"},
            "PASS",
            0,
        ),
        (
            "unsupported-fluent-prose",
            "a violation may result in a civil penalty of $500.\n",
            (
                "a violation may result in a civil penalty of $500. "
                "The Bureau will always waive every filing duty.\n"
            ),
            {"CLAIM_PRECISION_BELOW_FLOOR", "UNSUPPORTED_MATERIAL_OBLIGATION"},
            "FAIL",
            4,
        ),
    ],
)
def test_mechanical_report_mutation_is_end_to_end_and_exact(
    tmp_path: Path,
    mutation: str,
    old: str,
    new: str,
    expected_codes: set[str],
    absolute: str,
    exit_code: int,
) -> None:
    fixture = _fixture_copy(tmp_path)
    report_path = fixture / "reports" / "correct.md"
    before_inputs = _input_snapshot(fixture)
    before = report_path.read_text(encoding="utf-8")
    assert before.count(old) == 1
    report_path.write_text(before.replace(old, new), encoding="utf-8")
    after = report_path.read_text(encoding="utf-8")
    assert after != before
    assert old not in after
    assert new in after
    before_fact = _normalized_fact(before)
    after_fact = _normalized_fact(after)
    old_fact = _normalized_fact(old)
    assert before_fact.count(old_fact) == 1
    assert after_fact != before_fact
    assert after_fact == _normalized_fact(before.replace(old, new))
    if mutation == "missing-critical-duty":
        assert "file a registry notice" not in after
        assert "A registry notice is due within 10 days" in after
        assert "must retain proof of filing" in after
    after_inputs = _input_snapshot(fixture)
    assert {
        path for path in before_inputs if before_inputs[path] != after_inputs[path]
    } == {"reports/correct.md"}

    _generate_scripted_fixture(fixture, tmp_path / f"{mutation}-script-generation")
    output = tmp_path / mutation
    assert _run_public_cli(fixture, output) == exit_code
    verification = verify_evaluation_run(output)
    assert verification.valid is True
    manifest, result = load_verified_evaluation_run(output)
    artifact = json.loads((output / "evaluation-result.json").read_text(encoding="utf-8"))
    report = result.reports[0]

    assert manifest.terminal_status is not None
    assert manifest.terminal_status.value == "completed"
    assert artifact["reports"][0]["absolute_disposition"] == absolute
    assert result.readiness.status.value == "ADMITTED"
    assert report.absolute_disposition.value == absolute
    assert set(report.issue_codes) | set(report.blocking_codes) == expected_codes
    assert artifact["reports"][0]["issue_codes"] == report.issue_codes
    assert artifact["reports"][0]["blocking_codes"] == report.blocking_codes


@pytest.mark.parametrize(
    ("mutation", "field", "value", "expected_code"),
    [
        ("wrong-instrument", "authority_type", "statute", "AUTHORITY_MISMATCH"),
        ("snippet-only", "completeness", "snippet", "OPERATIVE_TEXT_MISSING"),
    ],
)
def test_mechanical_admission_mutation_is_end_to_end_and_exact(
    tmp_path: Path,
    mutation: str,
    field: str,
    value: str,
    expected_code: str,
) -> None:
    fixture = _fixture_copy(tmp_path)
    case_path = fixture / "case.json"
    before_inputs = _input_snapshot(fixture)
    before = json.loads(case_path.read_text(encoding="utf-8"))
    after = json.loads(case_path.read_text(encoding="utf-8"))
    target = (
        after["requested_authorities"][0]
        if mutation == "wrong-instrument"
        else after["sources"][0]
    )
    before_target = dict(target)
    assert target[field] != value
    target[field] = value
    _write_canonical(case_path, after)
    assert json.loads(case_path.read_text(encoding="utf-8")) != before
    assert {key for key in target if target[key] != before_target[key]} == {field}
    assert _normalized_fact(str(before_target[field])) != _normalized_fact(value)
    after_inputs = _input_snapshot(fixture)
    assert {
        path for path in before_inputs if before_inputs[path] != after_inputs[path]
    } == {"case.json"}

    _generate_scripted_fixture(fixture, tmp_path / f"{mutation}-script-generation")
    output = tmp_path / mutation
    assert _run_public_cli(fixture, output) == 3
    verification = verify_evaluation_run(output)
    assert verification.valid is True
    manifest, result = load_verified_evaluation_run(output)
    artifact = json.loads((output / "evaluation-result.json").read_text(encoding="utf-8"))

    assert manifest.terminal_status is not None
    assert manifest.terminal_status.value == "case-invalid"
    assert result.readiness.status.value == "CASE_INVALID"
    assert result.readiness.issue_codes == [expected_code]
    assert result.reports == []
    assert artifact["readiness"]["issue_codes"] == [expected_code]
