import argparse
import asyncio
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from regulatory_harvest.analysis import (
    AnalysisDraft,
    build_source_unit_inventory,
    evaluate_atomic_coverage,
)
from regulatory_harvest.evaluation import attorney_generation, attorney_workflow
from regulatory_harvest.evaluation.attorney_baseline_artifacts import (
    load_verified_baseline_run,
)
from regulatory_harvest.evaluation.attorney_baseline_models import (
    BaselineCorrectionRecordV1,
)
from regulatory_harvest.evaluation.attorney_cli import _case_and_capsules_from_fixture
from regulatory_harvest.evaluation.attorney_v2_workflow import initialize_evaluation_v2
from regulatory_harvest.evaluation.attorney_v21_workflow import initialize_evaluation_v21
from regulatory_harvest.evaluation.attorney_v22_drafts import (
    CompiledDraftV22,
    EvaluatorProvenanceV22,
    compile_evaluator_draft_v22,
)
from regulatory_harvest.evaluation.attorney_v22_models import (
    validate_evaluator_request_v22,
)
from regulatory_harvest.evaluation.attorney_v22_workflow import (
    next_evaluator_request_v22,
    submit_evaluator_response_v22,
)
from regulatory_harvest.models import SourceRecord
from regulatory_harvest.storage import canonical_json_bytes

ROOT = Path(__file__).parents[2]
SKILL_RUNNER = ROOT / "scripts" / "harvest_skill.py"
PORTABLE_RUNNER = ROOT / "scripts" / "harvest_portable.py"
EVALUATION_FIXTURE = ROOT / "tests" / "fixtures" / "attorney-eval"
EVALUATION_FIXTURE_V2 = ROOT / "tests" / "fixtures" / "attorney-eval-v2"
SKILL_SPEC = importlib.util.spec_from_file_location("regulatory_harvest_skill_runner", SKILL_RUNNER)
assert SKILL_SPEC is not None and SKILL_SPEC.loader is not None
skill_runner = importlib.util.module_from_spec(SKILL_SPEC)
SKILL_SPEC.loader.exec_module(skill_runner)
PORTABLE_SPEC = importlib.util.spec_from_file_location(
    "regulatory_harvest_portable_runner_for_skill_tests", PORTABLE_RUNNER
)
assert PORTABLE_SPEC is not None and PORTABLE_SPEC.loader is not None
portable_runner = importlib.util.module_from_spec(PORTABLE_SPEC)
PORTABLE_SPEC.loader.exec_module(portable_runner)


def _normalized_markdown_slice(
    relative_path: str,
    start_heading: str,
    end_heading: str | None,
) -> str:
    text = (ROOT / relative_path).read_text(encoding="utf-8")
    assert text.count(start_heading) == 1
    section = text.split(start_heading, 1)[1]
    if end_heading is not None:
        assert section.count(end_heading) == 1
        section = section.split(end_heading, 1)[0]
    return " ".join(section.casefold().split())


# Task 8's differential contract deliberately names every semantic and safety
# boundary.  The individual payload variations are exercised by the portable
# substrate tests; this runner-level table locks the public, no-site surface to
# the full evaluator's bytes and refusal behavior.
V2_PARITY_VECTORS = (
    "empty_audit_single_report_pass",
    "audited_correction_pair_fail_and_pass",
    "unresolved_source_dispute",
    "grader_disagreement",
    "material_unsupported_assertion",
    "ambiguous_source_quote",
    "ambiguous_report_quote",
    "first_mechanical_repair",
    "second_mechanical_failure",
    "tampered_baseline",
    "unknown_protocol",
    "retained_protocol_1_3_replay",
)

PROTOCOL_21_PORTABLE_PARITY_VECTORS = (
    "no_dispute",
    "mixed_referee_reviewer_auditor_unresolved",
    "stable_pass",
    "stable_fail",
    "outcome_changing_inconclusive",
    "referee_repair",
    "grade_repair",
    "mechanical_terminal",
    "partial_referee_resume",
    "partial_grade_resume",
    "retained_2_0",
    "retained_1_3",
    "unknown",
    "swapped_fragment",
    "tampered_aggregate",
    "tampered_lane_aggregate",
    "tampered_reconciliation",
    "tampered_sensitivity",
    "tampered_result",
    "cross_label_metadata",
    "cross_lane_metadata",
    "cross_batch_metadata",
    "symlink_path_refusal",
)

PROTOCOL_22_PORTABLE_PARITY_VECTORS = (
    "review_fragmentation",
    "audit_fragmentation",
    "normalized_prose_enum_and_quote",
    "clarification_then_accept",
    "nested_clarification_then_accept",
    "nested_missing_passage_then_accept",
    "nested_missing_dependency_then_accept",
    "nested_missing_audit_dependency_then_accept",
    "nested_blank_rationale_then_accept",
    "nested_blank_audit_explanation_then_accept",
    "engine_pause",
    "nested_engine_pause",
    "nested_missing_passage_pause",
    "nested_missing_dependency_pause",
    "nested_missing_audit_dependency_pause",
    "nested_blank_rationale_pause",
    "nested_blank_audit_explanation_pause",
    "later_resume",
    "stable_pass",
    "stable_fail",
    "outcome_sensitive_inconclusive",
    "insufficient_inconclusive",
    "empty_source_inconclusive",
    "low_quality_acceptance",
    "partial_source_review_resume",
    "partial_source_audit_resume",
    "partial_referee_resume",
    "partial_ordinary_grade_resume",
    "partial_contested_grade_resume",
    "candidate_label_a",
    "candidate_label_b",
    "scripted_exhaustion",
    "scripted_surplus",
    "scripted_malformed",
    "scripted_probe_error",
    "scripted_symlink",
    "scripted_oversize",
    "retained_1_3",
    "retained_2_0",
    "retained_2_1",
    "corrupt_retained_1_3",
    "corrupt_retained_2_0",
    "corrupt_retained_2_1",
    "unknown_protocol",
    "unknown_schema",
    "missing_root",
    "empty_root",
    "absent_protocol_marker",
    "review_cross_fragment_duplicate",
    "review_cross_fragment_conflict",
    "review_nonfinal_fragment_duplicate",
    "review_nonfinal_fragment_conflict",
    "audit_cross_fragment_duplicate",
    "audit_cross_fragment_conflict",
    "audit_nonfinal_fragment_duplicate",
    "audit_nonfinal_fragment_conflict",
    "cross_case_swap",
    "cross_lane_swap",
    "cross_dispute_swap",
    "cross_batch_swap",
    "cross_fragment_swap",
    "compiler_contract_tamper",
    "aggregate_reseal",
    "result_reseal",
    "symlink_path_refusal",
)

_TEMPLATE_DUTY_QUOTE = (
    "A covered operator must maintain a public incident register."
)
_TEMPLATE_EXCEPTION_QUOTE = (
    "The operator need not include an incident affecting only test data in the register."
)
_TEMPLATE_SUBMISSION_QUOTE = (
    "A covered operator must submit the incident register after the reporting trigger."
)
_TEMPLATE_NAVIGATION_TEXT = "Navigation index."
_TEMPLATE_SOURCE_TEXT = " ".join(
    (_TEMPLATE_DUTY_QUOTE, _TEMPLATE_EXCEPTION_QUOTE, _TEMPLATE_SUBMISSION_QUOTE)
) + f"\n\n{_TEMPLATE_NAVIGATION_TEXT}"


def _charter(source_name: str) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "matter_id": "synthetic-matter",
        "matter_title": "Synthetic Documentation Rule",
        "question": "What documentation is required before deployment?",
        "jurisdictions": ["US"],
        "as_of": "2026-08-06",
        "source_mode": "provided-only",
        "context": "Synthetic test material only.",
        "excluded_topics": [],
        "output_instructions": "Produce a concise attorney briefing.",
        "sources": [
            {
                "location": source_name,
                "title": "Synthetic Documentation Rule",
                "jurisdiction": "US",
                "authority_type": "synthetic example",
                "citation": "Synthetic Rule 1",
                "source_quality": "unknown",
                "license_assertion": "CC0-1.0",
            }
        ],
    }


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SKILL_RUNNER), *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


_V2_RUNNER_RECORDS: list[tuple[str, str, tuple[int, str, str]]] | None = None


def _run_runner(runner: Path, *args: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [sys.executable, str(runner), *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if _V2_RUNNER_RECORDS is not None:
        runner_name = "full" if runner == SKILL_RUNNER else "portable"
        _V2_RUNNER_RECORDS.append(
            (runner_name, args[0], (result.returncode, result.stdout, result.stderr))
        )
    return result


@contextmanager
def _assert_v2_runner_command_parity() -> Iterator[None]:
    """Capture each public command and require full/portable result-byte parity."""
    global _V2_RUNNER_RECORDS
    previous = _V2_RUNNER_RECORDS
    records: list[tuple[str, str, tuple[int, str, str]]] = []
    _V2_RUNNER_RECORDS = records
    try:
        yield
    finally:
        _V2_RUNNER_RECORDS = previous
    full = [(command, result) for runner, command, result in records if runner == "full"]
    portable = [(command, result) for runner, command, result in records if runner == "portable"]
    assert full
    assert len(full) == len(portable)
    for full_record, portable_record in zip(full, portable, strict=True):
        assert full_record == portable_record


@contextmanager
def _suspend_v2_runner_capture() -> Iterator[None]:
    """Exclude the full-only reviewer baseline witness from public vector parity."""
    global _V2_RUNNER_RECORDS
    previous = _V2_RUNNER_RECORDS
    _V2_RUNNER_RECORDS = None
    try:
        yield
    finally:
        _V2_RUNNER_RECORDS = previous


def _run_qualification_surface(
    runner: Path,
    *args: str,
) -> subprocess.CompletedProcess[str]:
    python_args = [sys.executable]
    if runner == PORTABLE_RUNNER:
        python_args.extend(("-I", "-S"))
    return subprocess.run(
        [*python_args, str(runner), *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _run_baseline_surface(
    runner: Path,
    *args: str,
) -> subprocess.CompletedProcess[str]:
    """Run the full or genuinely no-site portable baseline CLI."""
    python_args = [sys.executable]
    if runner == PORTABLE_RUNNER:
        python_args.extend(("-I", "-S"))
    return subprocess.run(
        [*python_args, str(runner), *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_build_prompt_requires_two_level_atomic_evidence_coverage() -> None:
    prompt = (
        ROOT / "src" / "regulatory_harvest" / "analysis" / "prompts" / "build-v1.md"
    ).read_text(encoding="utf-8")

    assert (
        "For every stated atom element, bind at least one exact `source_supported` "
        "claim whose resolved quotation span overlaps at least one assigned unit or "
        "lead. Across the atom\N{RIGHT SINGLE QUOTATION MARK}s stated elements, "
        "require the combined exact evidence "
        "to cover every assigned unit and lead. Bind each relationship to exact "
        "evidence from both endpoint source contexts."
    ) in prompt
    assert (
        "resolved quotation spans overlap every assigned unit and lead" not in prompt
    )


def test_v2_template_models_complete_atomic_rule_authoring_contract() -> None:
    """A stale example would teach agents to submit V1 rows to new V2 matters."""
    payload = json.loads(
        (ROOT / "assets" / "analysis-draft.template.json").read_text(
            encoding="utf-8"
        )
    )

    typed = AnalysisDraft.model_validate(payload)
    portable = portable_runner._draft(payload)

    assert typed.coverage_contract_version == "proposition-coverage-v2"
    assert portable["coverage_contract_version"] == "proposition-coverage-v2"
    assert typed.lead_reviews == []
    assert typed.proposition_coverage == []
    dimension_names = {
        "authority_status_timing",
        "actors_scope_activities",
        "definitions_categories",
        "duties_rights_prohibitions",
        "triggers_thresholds",
        "conditions_exceptions_defenses",
        "deadlines_transitions",
        "enforcement_remedies_consequences",
        "cross_references_dependencies",
    }
    assert typed.unit_reviews
    assert all(
        set(type(review.dimensions).model_fields) == dimension_names
        for review in typed.unit_reviews
    )
    assert any(
        review.disposition.value == "mapped" and "atom-duty-__REPLACE__" in review.atom_ids
        for review in typed.lead_dispositions_v2
    )
    assert any(
        review.disposition.value == "not_material" and review.rationale
        for review in typed.lead_dispositions_v2
    )
    atoms = {atom.atom_id: atom for atom in typed.rule_atoms}
    assert atoms["atom-duty-__REPLACE__"].proposition_type.value == "duty"
    assert atoms["atom-exception-__REPLACE__"].proposition_type.value == "exception"
    assert atoms["atom-submission-duty-__REPLACE__"].proposition_type.value == "duty"
    relationships = {
        relationship.relationship_id: relationship
        for relationship in typed.rule_relationships
    }
    exception_edge = relationships["relationship-exception-__REPLACE__"]
    assert exception_edge.relation_type.value == "exception_to"
    assert exception_edge.source_atom_id == "atom-exception-__REPLACE__"
    assert exception_edge.target_atom_id == "atom-duty-__REPLACE__"
    deadline_edge = relationships["relationship-deadline-__REPLACE__"]
    assert deadline_edge.relation_type.value == "deadline_for"
    assert deadline_edge.source_atom_id == "atom-deadline-__REPLACE__"
    assert deadline_edge.target_atom_id == "atom-submission-duty-__REPLACE__"
    assert deadline_edge.claim_ids == ["claim-deadline-__REPLACE__"]
    timing = atoms["atom-deadline-__REPLACE__"].elements.timing
    assert timing.status.value == "stated"
    assert timing.text == "after the reporting trigger"
    assert timing.claim_ids == ["claim-deadline-__REPLACE__"]
    gap = next(
        gap
        for gap in typed.gaps
        if gap.code == "REGISTER_SUBMISSION_INTERVAL_NOT_ESTABLISHED___REPLACE__"
    )
    assert gap.source_ids == ["src___REPLACE__"]

    requirements = next(
        section for section in typed.brief.sections if section.role.value == "key_requirements"
    )
    visible_items = [
        item
        for block in requirements.blocks
        for item in block.items
    ]
    bound = next(
        item
        for item in visible_items
        if set(item.atom_ids)
        >= {
            "atom-duty-__REPLACE__",
            "atom-exception-__REPLACE__",
            "atom-submission-duty-__REPLACE__",
        }
    )
    assert "relationship-exception-__REPLACE__" in bound.relationship_ids
    assert "atom-" not in bound.text
    assert "relationship-" not in bound.text


def _materialized_v2_template(source_id: str) -> dict[str, Any]:
    raw = (ROOT / "assets" / "analysis-draft.template.json").read_text(
        encoding="utf-8"
    )
    payload = json.loads(
        raw.replace("__REPLACE__", "template").replace("src_template", source_id)
    )
    for issue in payload["issues"]:
        issue["jurisdictions"] = ["US"]
    for finding in payload["findings"]:
        finding["authority"] = "Fictional Incident Register Rule"
        finding["jurisdiction"] = "US"
    for gap in payload["gaps"]:
        gap["jurisdiction"] = "US"
    return payload


def _template_v2_inventories(source_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    rule_end = _TEMPLATE_SOURCE_TEXT.index("\n\n")
    navigation_start = rule_end + 2
    units = {
        "inventory_version": "source-units-v1",
        "eligible_source_count": 1,
        "unit_count": 2,
        "required_unit_count": 2,
        "units": [
            {
                "unit_id": "unit-rule-template",
                "source_id": source_id,
                "start_char": 0,
                "end_char": rule_end,
                "heading": None,
                "locator": f"chars:0-{rule_end}",
                "excerpt": _TEMPLATE_SOURCE_TEXT[:rule_end],
                "coverage_required": True,
            },
            {
                "unit_id": "unit-navigation-template",
                "source_id": source_id,
                "start_char": navigation_start,
                "end_char": len(_TEMPLATE_SOURCE_TEXT),
                "heading": None,
                "locator": f"chars:{navigation_start}-{len(_TEMPLATE_SOURCE_TEXT)}",
                "excerpt": _TEMPLATE_NAVIGATION_TEXT,
                "coverage_required": True,
            },
        ],
    }
    lead_specs = (
        ("lead-duty-template", "duties", "requirements", _TEMPLATE_DUTY_QUOTE, True),
        (
            "lead-exception-template",
            "exceptions",
            "requirements",
            _TEMPLATE_EXCEPTION_QUOTE,
            True,
        ),
        (
            "lead-deadline-template",
            "deadlines",
            "deadlines",
            _TEMPLATE_SUBMISSION_QUOTE,
            True,
        ),
        (
            "lead-navigation-template",
            "navigation",
            "other",
            _TEMPLATE_NAVIGATION_TEXT,
            False,
        ),
    )
    leads = []
    for lead_id, topic, issue_category, excerpt, review_required in lead_specs:
        start = _TEMPLATE_SOURCE_TEXT.index(excerpt)
        leads.append(
            {
                "lead_id": lead_id,
                "source_id": source_id,
                "topic": topic,
                "issue_category": issue_category,
                "start_char": start,
                "end_char": start + len(excerpt),
                "heading": None,
                "excerpt": excerpt,
                "signals": [] if not review_required else [topic],
                "review_required": review_required,
            }
        )
    evidence = {
        "inventory_version": "provision-leads-v2",
        "notice": "Heuristic research leads, not legal conclusions.",
        "source_count": 1,
        "lead_count": 4,
        "priority_lead_count": 3,
        "priority_topic_counts": {"deadlines": 1, "duties": 1, "exceptions": 1},
        "priority_cap_per_topic": 3,
        "topic_counts": {
            "deadlines": 1,
            "duties": 1,
            "exceptions": 1,
            "navigation": 1,
        },
        "leads": leads,
    }
    return units, evidence


def test_v2_template_reaches_identical_completed_full_and_portable_gates(
    tmp_path: Path,
) -> None:
    """A parseable example with a finite atom defect strands every copied draft."""
    source = tmp_path / "fictional-rule.txt"
    source.write_text(_TEMPLATE_SOURCE_TEXT + "\n", encoding="utf-8")
    charter = tmp_path / "research-charter.json"
    charter.write_text(json.dumps(_charter(source.name)), encoding="utf-8")
    matters = (tmp_path / "full-matter", tmp_path / "portable-matter")
    runners = (SKILL_RUNNER, PORTABLE_RUNNER)
    reviews: list[bytes] = []

    for runner, matter in zip(runners, matters, strict=True):
        prepared = _run_runner(
            runner,
            "prepare",
            "--charter",
            str(charter),
            "--matter",
            str(matter),
        )
        assert prepared.returncode == 0, prepared.stderr
        dossier_path = matter / "agent-dossier.json"
        dossier = json.loads(dossier_path.read_text(encoding="utf-8"))
        source_id = dossier["sources"][0]["source_id"]
        assert dossier["sources"][0]["normalized_text"] == _TEMPLATE_SOURCE_TEXT
        units, evidence = _template_v2_inventories(source_id)
        dossier["source_unit_inventory"] = units
        dossier["evidence_inventory"] = evidence
        dossier_path.write_text(json.dumps(dossier), encoding="utf-8")
        payload = _materialized_v2_template(source_id)
        draft_path = matter / "materialized-template.json"
        draft_path.write_text(json.dumps(payload), encoding="utf-8")

        typed = AnalysisDraft.model_validate(payload)
        parsed = portable_runner._draft(payload)
        typed_sources = [SourceRecord.model_validate(row) for row in dossier["sources"]]
        full_review = evaluate_atomic_coverage(units, evidence, typed, typed_sources)
        portable_review = portable_runner._evaluate_portable_atomic_coverage(
            units,
            evidence,
            parsed,
            dossier["sources"],
        )
        assert full_review["valid"] is True, full_review["issues"]
        assert canonical_json_bytes(full_review) == portable_runner._canonical_bytes(
            portable_review
        )

        finalized = _run_runner(
            runner,
            "finalize",
            "--matter",
            str(matter),
            "--draft",
            str(draft_path),
        )
        assert finalized.returncode == 0, finalized.stderr or finalized.stdout
        receipt = json.loads(finalized.stdout)
        assert {
            "evidence_precision_valid": receipt["evidence_precision_valid"],
            "proposition_coverage_valid": receipt["proposition_coverage_valid"],
            "provision_recall_valid": receipt["provision_recall_valid"],
            "status": receipt["status"],
        } == {
            "evidence_precision_valid": True,
            "proposition_coverage_valid": True,
            "provision_recall_valid": True,
            "status": "completed",
        }
        reviews.append(Path(receipt["coverage_review"]).read_bytes())

    assert reviews[0] == reviews[1]
    payload = _materialized_v2_template("src-template")
    atoms = {atom["atom_id"]: atom for atom in payload["rule_atoms"]}
    relationships = {
        relationship["relationship_id"]: relationship
        for relationship in payload["rule_relationships"]
    }
    rule_dimensions = payload["unit_reviews"][0]["dimensions"]
    assert rule_dimensions["actors_scope_activities"] == {
        "disposition": "gap",
        "gap_codes": ["COVERED_OPERATOR_SCOPE_NOT_ESTABLISHED_template"],
    }
    assert rule_dimensions["deadlines_transitions"] == {
        "disposition": "gap",
        "gap_codes": ["REGISTER_SUBMISSION_INTERVAL_NOT_ESTABLISHED_template"],
    }
    assert atoms["atom-submission-duty-template"]["proposition_type"] == "duty"
    assert atoms["atom-submission-duty-template"]["elements"]["operative_action"][
        "text"
    ] == "submit"
    assert atoms["atom-deadline-template"]["elements"]["timing"] == {
        "status": "stated",
        "text": "after the reporting trigger",
        "claim_ids": ["claim-deadline-template"],
    }
    assert relationships["relationship-deadline-template"] == {
        "relationship_id": "relationship-deadline-template",
        "relation_type": "deadline_for",
        "source_atom_id": "atom-deadline-template",
        "target_atom_id": "atom-submission-duty-template",
        "claim_ids": ["claim-deadline-template"],
    }
    requirements_item = payload["brief"]["sections"][0]["blocks"][0]["items"][0]
    assert "atom-submission-duty-template" in requirements_item["atom_ids"]
    assert "relationship-deadline-template" in requirements_item["relationship_ids"]


def test_atomic_authoring_instructions_require_unit_atom_relationship_and_delivery_gates() -> None:
    """Broad mapping guidance alone would not constrain atom-level legal coverage."""
    surfaces = "\n".join(
        (ROOT / relative).read_text(encoding="utf-8")
        for relative in (
            "SKILL.md",
            "references/draft-schema.md",
            "references/research-protocol.md",
        )
    ).casefold()

    for required in (
        "all nine dimensions",
        "broad unit mapping is insufficient",
        "independent actions",
        "distinct atoms",
        "genuine gaps remain gaps",
        "related atoms may share natural prose",
        "typed relationships",
        "attorney never edits the atom graph",
        "not rendered as a database view",
        "proposition_coverage_valid",
        "provision_recall_valid",
        "evidence_precision_valid",
    ):
        assert required in surfaces


def _canonical_response(request: dict[str, object], payload: object) -> str:
    """Build the one canonical, request-bound judge envelope accepted by the CLI."""
    return json.dumps(
        {
            "schema_version": "1.0",
            "operation": request["operation"],
            "request_fingerprint": request["request_fingerprint"],
            "provider_name": "local-scripted-fixture",
            "model_name": "no-provider",
            "judge_isolation": "scripted_fixture",
            "payload": payload,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _reseal_protocol_21_run(run: Path) -> None:
    """Recompute only outer artifact/manifest hashes after an adversarial rewrite."""
    manifest_path = run / "run-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    assert isinstance(manifest, dict)
    artifacts = manifest["artifacts"]
    assert isinstance(artifacts, list)
    for record in artifacts:
        assert isinstance(record, dict)
        path = record["artifact_path"]
        assert isinstance(path, str)
        record["artifact_hash"] = hashlib.sha256((run / path).read_bytes()).hexdigest()
    body = dict(manifest)
    body.pop("manifest_fingerprint")
    manifest["manifest_fingerprint"] = hashlib.sha256(_canonical_bytes(body)).hexdigest()
    manifest_path.write_bytes(_canonical_bytes(manifest))


def _forge_protocol_21_report_derivation(run: Path, kind: str) -> None:
    """Re-seal one model-valid but semantically forged terminal report chain."""
    manifest_path = run / "run-manifest.json"
    result_path = run / "result.json"
    manifest = json.loads(manifest_path.read_bytes())
    result = json.loads(result_path.read_bytes())
    report = result["reports"][0]
    label = report["anonymous_label"]
    sensitivity_path = run / "sensitivities" / f"{label}.json"
    sensitivity = json.loads(sensitivity_path.read_bytes())
    if kind == "reconciliation":
        reconciliation = report["reconciliation"]
        reconciliation["absolute_disposition"] = "FAIL"
        reconciliation["reason_codes"] = ["CRITICAL_RECALL_BELOW_FLOOR"]
        body = dict(reconciliation)
        body.pop("reconciliation_fingerprint")
        reconciliation["reconciliation_fingerprint"] = hashlib.sha256(
            _canonical_bytes(body)
        ).hexdigest()
        sensitivity["reconciliation_fingerprint"] = reconciliation[
            "reconciliation_fingerprint"
        ]
    else:
        assert kind == "sensitivity"
    sensitivity["absolute_disposition"] = "FAIL"
    sensitivity["reason_codes"] = ["CRITICAL_RECALL_BELOW_FLOOR"]
    body = dict(sensitivity)
    body.pop("sensitivity_fingerprint")
    sensitivity["sensitivity_fingerprint"] = hashlib.sha256(
        _canonical_bytes(body)
    ).hexdigest()
    sensitivity_path.write_bytes(_canonical_bytes(sensitivity))
    report["sensitivity"] = sensitivity
    body = dict(report)
    body.pop("result_fingerprint")
    report["result_fingerprint"] = hashlib.sha256(_canonical_bytes(body)).hexdigest()
    dispositions = [item["sensitivity"]["absolute_disposition"] for item in result["reports"]]
    if dispositions == ["FAIL", "PASS"]:
        result["comparison"] = {
            "disposition": "comparator_win",
            "winner_label": "B",
            "rationale": "Only the comparator report passed the rubric.",
        }
    elif dispositions == ["PASS", "FAIL"]:
        result["comparison"] = {
            "disposition": "candidate_win",
            "winner_label": "A",
            "rationale": "Only the candidate report passed the rubric.",
        }
    elif dispositions == ["FAIL", "FAIL"]:
        result["comparison"] = {
            "disposition": "neither",
            "winner_label": None,
            "rationale": "Neither report passed the rubric.",
        }
    body = dict(result)
    body.pop("result_fingerprint")
    result["result_fingerprint"] = hashlib.sha256(_canonical_bytes(body)).hexdigest()
    result_path.write_bytes(_canonical_bytes(result))
    sensitivity_index = next(
        index
        for index, item in enumerate(result["reports"])
        if item["anonymous_label"] == label
    )
    manifest["sensitivity_fingerprints"][sensitivity_index] = sensitivity[
        "sensitivity_fingerprint"
    ]
    manifest["result_hash"] = result["result_fingerprint"]
    manifest_path.write_bytes(_canonical_bytes(manifest))
    _reseal_protocol_21_run(run)


def _bound_scripted_payload(
    request: dict[str, object], payload: dict[str, object]
) -> dict[str, object]:
    """Bind a copied synthetic judgment to the request issued by this exact run."""
    bound = json.loads(json.dumps(payload))
    if "request_fingerprint" in bound:
        bound["request_fingerprint"] = request["request_fingerprint"]
    return bound


def _observed_controller_response_bytes(
    request: dict[str, object],
    payload: dict[str, object],
    *,
    observed_context_id: str,
    prior_context_ids: set[str],
    mechanical_repair: bool,
) -> bytes | None:
    """Build a response only after deriving isolation from an observed context."""
    reused_context = observed_context_id in prior_context_ids
    if mechanical_repair and reused_context:
        return None
    isolation = "sequential_same_context" if reused_context else "fresh_context"
    response = json.loads(
        (ROOT / "assets" / "attorney-evaluation-response.template.json").read_bytes()
    )
    assert response["judge_isolation"] == "fresh_context"
    response.update(
        {
            "judge_isolation": isolation,
            "model_name": f"synthetic-role-{observed_context_id}",
            "operation": request["operation"],
            "payload": payload,
            "provider_name": "local-role-context-fixture",
            "request_fingerprint": request["request_fingerprint"],
        }
    )
    return _canonical_bytes(response)


def _fresh_role_response_bytes(
    request: dict[str, object],
    payload: dict[str, object],
    *,
    prior_context_ids: set[str],
    python_executable: Path | str = sys.executable,
) -> tuple[bytes, str] | None:
    """Have a separate role process author a response and report its observed identity."""
    executor = r"""
import json
import os
import sys

packet = json.loads(sys.stdin.buffer.read())
context_id = str(os.getpid())
if context_id in packet["prior_context_ids"]:
    raise SystemExit(3)
response = packet["template"]
if response["judge_isolation"] != "fresh_context":
    raise SystemExit(4)
response.update(
    {
        "judge_isolation": "fresh_context",
        "model_name": f"synthetic-role-{context_id}",
        "operation": packet["request"]["operation"],
        "payload": packet["payload"],
        "provider_name": "local-role-context-fixture",
        "request_fingerprint": packet["request"]["request_fingerprint"],
    }
)
observation = {"context_id": context_id, "response": response}
sys.stdout.write(
    json.dumps(
        observation,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
)
"""
    packet = {
        "payload": payload,
        "prior_context_ids": sorted(prior_context_ids),
        "request": request,
        "template": json.loads(
            (ROOT / "assets" / "attorney-evaluation-response.template.json").read_bytes()
        ),
    }
    try:
        completed = subprocess.run(
            [str(python_executable), "-I", "-S", "-c", executor],
            cwd=ROOT,
            input=_canonical_bytes(packet),
            check=False,
            capture_output=True,
        )
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    try:
        observation = json.loads(completed.stdout)
        context_id = str(observation["context_id"])
        response = observation["response"]
    except (KeyError, TypeError, ValueError):
        return None
    if (
        not isinstance(response, dict)
        or context_id == str(os.getpid())
        or context_id in prior_context_ids
        or response.get("judge_isolation") != "fresh_context"
        or response.get("model_name") != f"synthetic-role-{context_id}"
    ):
        return None
    return _canonical_bytes(response), context_id


def _write_exact_evaluation_fixture(
    root: Path,
    *,
    source_bytes: bytes = b"Synthetic Rule. A covered operator must file notice.",
    report_a_bytes: bytes = b"Report A states the filing duty.",
    report_b_bytes: bytes = b"Report B states the filing duty.",
    client_facts_bytes: bytes | None = b"The operator is covered.",
) -> Path:
    """Write a strict filesystem case whose commitments come from literal input bytes."""
    (root / "sources").mkdir(parents=True)
    (root / "sources" / "rule.txt").write_bytes(source_bytes)
    if client_facts_bytes is not None:
        (root / "client-facts.txt").write_bytes(client_facts_bytes)

    candidates: list[dict[str, object]] = []
    for index, (label, role, report_bytes) in enumerate(
        (
            ("a", "candidate", report_a_bytes),
            ("b", "comparator", report_b_bytes),
        ),
        start=1,
    ):
        capture = root / "generation-inputs" / label
        (capture / "sources").mkdir(parents=True)
        (capture / "generator").mkdir()
        (capture / "sources" / "rule.txt").write_bytes(source_bytes)
        (capture / "generator" / "descriptor.bin").write_bytes(b"test-generator")
        if client_facts_bytes is not None:
            (capture / "client-facts.txt").write_bytes(client_facts_bytes)
        generation_input = {
            "candidate_id": f"report-{label}",
            "client_facts_path": (
                "client-facts.txt" if client_facts_bytes is not None else None
            ),
            "generation_instructions": "Produce the attorney report from the supplied record.",
            "generator_artifacts": [
                {"artifact_id": "generator", "path": "generator/descriptor.bin"}
            ],
            "question": "What does the synthetic rule require?",
            "schema_version": "1.0",
            "sources": [{"path": "sources/rule.txt", "source_id": "source-1"}],
        }
        generation_input_path = capture / "generation-input.json"
        generation_input_path.write_bytes(_canonical_bytes(generation_input))
        capsule = root / "capsules" / f"report-{label}"
        attorney_generation.initialize_generation(
            generation_input_path,
            capsule,
            nonce_hex=str(index) * 64,
        )
        request = attorney_generation.next_generation_request(capsule)
        assert request is not None
        response = {
            "generation_isolation": "scripted_fixture",
            "model_name": "no-provider",
            "operation": "generate_report",
            "payload": {"report_text": report_bytes.decode("utf-8")},
            "provider_name": "local-scripted-fixture",
            "request_fingerprint": request["request_fingerprint"],
            "response_id": None,
            "schema_version": "1.0",
            "usage": {},
        }
        response_path = capture / "response.json"
        response_path.write_bytes(_canonical_bytes(response))
        attorney_generation.submit_generation_response(capsule, response_path)
        candidates.append(
            {
                "candidate_id": f"report-{label}",
                "external_report_path": None,
                "generation_capsule_path": f"capsules/report-{label}",
                "role": role,
            }
        )

    case = {
        "as_of": "2026-08-12",
        "candidates": candidates,
        "case_id": "exact-input-case",
        "client_facts_path": (
            "client-facts.txt" if client_facts_bytes is not None else None
        ),
        "jurisdiction": "Example State",
        "mode": "closed-universe",
        "question": "What does the synthetic rule require?",
        "requested_authorities": [
            {
                "authority_id": "synthetic-rule",
                "authority_type": "regulation",
                "jurisdiction": "Example State",
                "source_ids": ["source-1"],
                "title": "Synthetic Rule",
            }
        ],
        "schema_version": "1.1",
        "sources": [
            {
                "authority_type": "regulation",
                "completeness": "complete",
                "jurisdiction": "Example State",
                "language": "en",
                "path": "sources/rule.txt",
                "source_id": "source-1",
                "source_quality": "primary",
                "source_role": "official_primary",
                "title": "Synthetic Rule",
            }
        ],
    }
    case_path = root / "case.json"
    case_path.write_bytes(_canonical_bytes(case))
    return case_path


def _replace_nested_case_value(
    case: dict[str, object],
    path: tuple[str | int, ...],
    replacement: object,
) -> None:
    """Replace one fixture value without weakening the production JSON grammar."""
    target: object = case
    for segment in path[:-1]:
        if isinstance(segment, int):
            assert isinstance(target, list)
            target = target[segment]
        else:
            assert isinstance(target, dict)
            target = target[segment]
    final = path[-1]
    if isinstance(final, int):
        assert isinstance(target, list)
        target[final] = replacement
    else:
        assert isinstance(target, dict)
        target[final] = replacement


def _nested_case_value(
    case: dict[str, object],
    path: tuple[str | int, ...],
) -> object:
    target: object = case
    for segment in path:
        if isinstance(segment, int):
            assert isinstance(target, list)
            target = target[segment]
        else:
            assert isinstance(target, dict)
            target = target[segment]
    return target


def _admission_payload(request: dict[str, object]) -> dict[str, object]:
    source_ids = [source["source_id"] for source in request["payload"]["sources"]]
    return {
        "request_fingerprint": request["request_fingerprint"],
        "checks": [
            {
                "code": code,
                "satisfied": True,
                "material": True,
                "rationale": "The synthetic source record supplies this check.",
                "source_ids": source_ids,
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


def _omit_valid_evaluation_defaults(payload: dict[str, object]) -> None:
    if "checks" in payload:
        payload.pop("issues")
    elif "entries" in payload:
        payload.pop("gaps")
    elif "complete" in payload:
        payload.pop("disputes")
    elif "narrative_scores" in payload:
        payload.pop("out_of_ledger_claims")
        for entry_grade in payload["entry_grades"]:
            entry_grade.pop("finding_codes")
        for narrative_score in payload["narrative_scores"]:
            narrative_score.pop("finding_codes")


def _next_packet(runner: Path, run: Path) -> dict[str, object]:
    result = _run_runner(runner, "eval-next", "--run", str(run))
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _v2_source_review_response(request: dict[str, object]) -> dict[str, object]:
    """Build the smallest semantically complete local response for a v2 source review."""
    source_record = request["payload"]["source_record"]
    assert isinstance(source_record, dict)
    sources = source_record["sources"]
    assert isinstance(sources, list) and len(sources) == 1
    source = sources[0]
    assert isinstance(source, dict)
    version = str(request["schema_version"])
    return {
        "schema_version": version,
        "operation": "source_review",
        "request_fingerprint": request["request_fingerprint"],
        "provider_name": "local-scripted-fixture",
        "model_name": "no-provider",
        "judge_isolation": "scripted_fixture",
        "payload": {
            "schema_version": version,
            "proposals": [
                {
                    "statement": "A covered operator must file the registry notice.",
                    "kind": "obligation",
                    "importance": "critical",
                    "passages": [
                        {
                            "source_id": source["source_id"],
                            "quote": source["normalized_text"],
                        }
                    ],
                    "dependency": None,
                    "confidence": "clear",
                    "rationale": "The synthetic operative text states the filing duty.",
                }
            ],
        },
    }


def _v21_source_review_response(request: dict[str, object]) -> dict[str, object]:
    """Build the same source-only judgment under the v2.1 fragment envelope."""
    source_record = request["payload"]["source_record"]
    assert isinstance(source_record, dict)
    sources = source_record["sources"]
    assert isinstance(sources, list) and len(sources) == 1
    source = sources[0]
    assert isinstance(source, dict)
    return {
        "schema_version": "2.1",
        "operation": "source_review",
        "request_fingerprint": request["request_fingerprint"],
        "provider_name": "local-scripted-fixture",
        "model_name": "no-provider",
        "judge_isolation": "scripted_fixture",
        "payload": {
            "schema_version": "2.1",
            "proposals": [
                {
                    "statement": "A covered operator must file the registry notice.",
                    "kind": "obligation",
                    "importance": "critical",
                    "passages": [
                        {
                            "source_id": source["source_id"],
                            "quote": source["normalized_text"],
                        }
                    ],
                    "dependency": None,
                    "confidence": "clear",
                    "rationale": "The synthetic operative text states the filing duty.",
                }
            ],
        },
    }


def _v21_response(
    request: dict[str, object],
    *,
    proposal_count: int = 1,
    disputed: bool = False,
    mixed_referee: bool = False,
    stable_fail: bool = False,
    outcome_changing: bool = False,
) -> dict[str, object]:
    """Author one literal Protocol 2.1 judgment for the issued fragment."""
    operation = request["operation"]
    request_payload = request["payload"]
    assert isinstance(request_payload, dict)
    payload: dict[str, object]
    if operation == "source_review":
        source_record = request_payload["source_record"]
        assert isinstance(source_record, dict)
        sources = source_record["sources"]
        assert isinstance(sources, list) and len(sources) == 1
        source = sources[0]
        assert isinstance(source, dict)
        payload = {
            "schema_version": "2.1",
            "proposals": [
                {
                    "statement": f"Duty {index}: a covered operator must file notice.",
                    "kind": "obligation",
                    "importance": "critical",
                    "passages": [
                        {
                            "source_id": source["source_id"],
                            "quote": source["normalized_text"],
                        }
                    ],
                    "dependency": None,
                    "confidence": "clear",
                    "rationale": "The synthetic source states the filing duty.",
                }
                for index in range(1, proposal_count + 1)
            ],
        }
    elif operation == "source_audit":
        indexed = request_payload["indexed_proposals"]
        assert isinstance(indexed, list)
        concerns: list[dict[str, object]] = []
        if disputed or mixed_referee:
            selected = indexed if mixed_referee or len(indexed) > 1 else indexed[:1]
            for index, item in enumerate(selected, start=1):
                assert isinstance(item, dict)
                proposal = item["proposal"]
                assert isinstance(proposal, dict)
                correction = None
                if mixed_referee and index in {2, 3}:
                    correction = {
                        **proposal,
                        "statement": f"Auditor alternative duty {index}.",
                        "rationale": "The alternative is supported by the source.",
                    }
                concerns.append(
                    {
                        "target_proposal_ref": item["proposal_ref"],
                        "concern_type": "ambiguity",
                        "passages": proposal["passages"],
                        "explanation": "The reviewed interpretation is materially disputed.",
                        "correction": correction,
                    }
                )
        payload = {"schema_version": "2.1", "concerns": concerns}
    elif operation == "source_referee_fragment":
        disputes = request_payload["material_disputes"]
        assert isinstance(disputes, list) and len(disputes) == 1
        dispute = disputes[0]
        assert isinstance(dispute, dict)
        evidence = dispute["evidence"]
        assert isinstance(evidence, list) and evidence
        decision = "accept_reviewer"
        unresolved_reason = None
        if mixed_referee:
            decision = {
                "D0001": "accept_reviewer",
                "D0002": "accept_auditor",
                "D0003": "unresolved",
            }[str(dispute["dispute_id"])]
            if decision == "unresolved":
                unresolved_reason = "SOURCE_AMBIGUITY"
        elif disputed:
            decision = "unresolved"
            unresolved_reason = "SOURCE_AMBIGUITY"
        payload = {
            "schema_version": "2.1",
            "decision": decision,
            "unresolved_reason": unresolved_reason,
            "evidence_refs": [evidence[0]["evidence_ref"]],
            "rationale": "The closed source record supports this substantive judgment.",
        }
    elif operation == "ordinary_grade_fragment":
        requirements = request_payload["requirements"]
        report_text = request_payload["report_text"]
        assert isinstance(report_text, str) and isinstance(requirements, list)
        payload = {
            "schema_version": "2.1",
            "anonymous_label": request_payload["anonymous_label"],
            "grader_lane": request_payload["grader_lane"],
            "batch_ref": request_payload["batch_ref"],
            "baseline_fingerprint": request_payload["baseline_fingerprint"],
            "report_fingerprint": request_payload["report_fingerprint"],
            "requirement_grades": [
                {
                    "requirement_id": requirement["requirement_id"],
                    "disposition": "not_met" if stable_fail else "met",
                    "report_passages": [report_text],
                    "rationale": "The report is assessed against the supplied requirement.",
                    "omission": None,
                }
                for requirement in requirements
            ],
            "rationale": "The bounded ordinary batch is complete.",
        }
    else:
        assert operation == "contested_grade_fragment"
        report_text = request_payload["report_text"]
        contested = request_payload["contested_requirement"]
        assert isinstance(report_text, str) and isinstance(contested, dict)
        reviewer_disposition = "not_met" if stable_fail else "met"
        auditor_disposition = (
            "not_met" if stable_fail or outcome_changing else "met"
        )
        payload = {
            "schema_version": "2.1",
            "anonymous_label": request_payload["anonymous_label"],
            "grader_lane": request_payload["grader_lane"],
            "contested_requirement_id": contested["contested_requirement_id"],
            "baseline_fingerprint": request_payload["baseline_fingerprint"],
            "report_fingerprint": request_payload["report_fingerprint"],
            "reviewer_alternative_grade": {
                "disposition": reviewer_disposition,
                "report_passages": [report_text],
                "rationale": "The reviewer alternative was assessed.",
            },
            "auditor_alternative_grade": {
                "disposition": auditor_disposition,
                "report_passages": [report_text],
                "rationale": "The auditor alternative was assessed.",
            },
            "ambiguity_disposition": (
                "overstated"
                if outcome_changing and request_payload["grader_lane"] == 2
                else "acknowledged"
            ),
            "rationale": "Both supported alternatives were assessed.",
        }
    return {
        "schema_version": "2.1",
        "operation": operation,
        "request_fingerprint": request["request_fingerprint"],
        "provider_name": "local-scripted-fixture",
        "model_name": "no-provider",
        "judge_isolation": "scripted_fixture",
        "payload": payload,
    }


def _v2_empty_audit_response(request: dict[str, object]) -> dict[str, object]:
    version = str(request["schema_version"])
    return {
        "schema_version": version, "operation": "source_audit",
        "request_fingerprint": request["request_fingerprint"],
        "provider_name": "local-scripted-fixture", "model_name": "no-provider",
        "judge_isolation": "scripted_fixture",
        "payload": {"schema_version": version, "concerns": []},
    }


def _v2_disputed_audit_response(request: dict[str, object]) -> dict[str, object]:
    payload = request["payload"]
    assert isinstance(payload, dict)
    indexed = payload["indexed_proposals"]
    assert isinstance(indexed, list) and len(indexed) == 1
    proposal = indexed[0]["proposal"]
    assert isinstance(proposal, dict)
    version = str(request["schema_version"])
    return {
        "schema_version": version, "operation": "source_audit",
        "request_fingerprint": request["request_fingerprint"],
        "provider_name": "local-scripted-fixture", "model_name": "no-provider",
        "judge_isolation": "scripted_fixture",
        "payload": {"schema_version": version, "concerns": [{
            "target_proposal_ref": "P0001", "concern_type": "incorrect_statement",
            "passages": proposal["passages"],
            "explanation": "The source review needs a checked correction for this legal duty.",
            "correction": proposal,
        }]},
    }


def _v2_corrected_disputed_audit_response(request: dict[str, object]) -> dict[str, object]:
    """Return a valid audit correction that changes the reviewed requirement."""
    response = _v2_disputed_audit_response(request)
    payload = response["payload"]
    assert isinstance(payload, dict)
    concerns = payload["concerns"]
    assert isinstance(concerns, list) and len(concerns) == 1
    concern = concerns[0]
    assert isinstance(concern, dict)
    correction = concern["correction"]
    assert isinstance(correction, dict)
    corrected = dict(correction)
    corrected["statement"] = "A covered operator must file notice."
    corrected["passages"] = [
        {"source_id": "source-1", "quote": "A covered operator must file notice."}
    ]
    concern["correction"] = corrected
    return response


def _v2_referee_accept_reviewer_response(request: dict[str, object]) -> dict[str, object]:
    payload = request["payload"]
    assert isinstance(payload, dict)
    disputes = payload["material_disputes"]
    assert isinstance(disputes, list) and len(disputes) == 1
    dispute = disputes[0]
    assert isinstance(dispute, dict)
    if request["schema_version"] == "2.1":
        evidence = dispute["evidence"]
        assert isinstance(evidence, list) and evidence
        return {
            "schema_version": "2.1", "operation": "source_referee_fragment",
            "request_fingerprint": request["request_fingerprint"],
            "provider_name": "local-scripted-fixture", "model_name": "no-provider",
            "judge_isolation": "scripted_fixture",
            "payload": {
                "schema_version": "2.1", "decision": "accept_reviewer",
                "unresolved_reason": None,
                "evidence_refs": [evidence[0]["evidence_ref"]],
                "rationale": "The frozen source record supports the original reviewed legal duty.",
            },
        }
    concern = dispute["audit_concern"]
    assert isinstance(concern, dict)
    return {
        "schema_version": "2.0", "operation": "source_referee",
        "request_fingerprint": request["request_fingerprint"],
        "provider_name": "local-scripted-fixture", "model_name": "no-provider",
        "judge_isolation": "scripted_fixture",
        "payload": {"schema_version": "2.0", "decisions": [{
            "dispute_id": dispute["dispute_id"], "decision": "accept_reviewer",
            "passages": concern["passages"],
            "rationale": "The frozen source record supports the original reviewed legal duty.",
        }]},
    }


def _v2_referee_accept_auditor_response(request: dict[str, object]) -> dict[str, object]:
    """Accept the audit's materially corrected proposal and its exact passage."""
    response = _v2_referee_accept_reviewer_response(request)
    payload = response["payload"]
    assert isinstance(payload, dict)
    if request["schema_version"] == "2.1":
        payload["decision"] = "accept_auditor"
        payload["rationale"] = "The corrected duty is exactly supported by the frozen source."
        return response
    decisions = payload["decisions"]
    assert isinstance(decisions, list) and len(decisions) == 1
    decision = decisions[0]
    assert isinstance(decision, dict)
    dispute = request["payload"]["material_disputes"][0]  # type: ignore[index]
    assert isinstance(dispute, dict)
    concern = dispute["audit_concern"]
    assert isinstance(concern, dict)
    correction = concern["correction"]
    assert isinstance(correction, dict)
    decision["decision"] = "accept_auditor"
    decision["passages"] = correction["passages"]
    decision["rationale"] = "The corrected duty is exactly supported by the frozen source."
    return response


def _v2_grade_response(request: dict[str, object]) -> dict[str, object]:
    if request["schema_version"] == "2.1":
        return _v21_response(request)
    payload = request["payload"]
    assert isinstance(payload, dict)
    report = payload["anonymous_report"]
    requirements = payload["requirements"]
    assert isinstance(report, dict)
    assert isinstance(requirements, list)
    return {
        "schema_version": "2.0",
        "operation": "grade_report",
        "request_fingerprint": request["request_fingerprint"],
        "provider_name": "local-scripted-fixture",
        "model_name": "no-provider",
        "judge_isolation": "scripted_fixture",
        "payload": {
            "schema_version": "2.0",
            "anonymous_label": report["anonymous_label"],
            "baseline_fingerprint": payload["baseline_fingerprint"],
            "requirement_grades": [
                {
                    "requirement_id": requirement["requirement_id"],
                    "disposition": "met",
                    "report_passages": [],
                    "rationale": "The report addresses the supplied requirement.",
                    "omission": None,
                }
                for requirement in requirements
            ],
            "unsupported_assertions": [],
            "baseline_defect": None,
        },
    }


def _initialize_eval_run(
    runner: Path, run: Path, *, case_path: Path = EVALUATION_FIXTURE / "case.json"
) -> None:
    """Materialize a frozen protocol-1.3 fixture without exposing legacy initialization."""
    del runner
    case, capsule_paths = _case_and_capsules_from_fixture(
        case_path, root=case_path.parent
    )
    attorney_workflow.initialize_evaluation(
        case,
        run,
        seed_hex="7" * 64,
        generation_capsule_paths=capsule_paths,
    )


def _initialize_v2_eval_run(run: Path) -> None:
    """Materialize a retained 2.0 run without exercising the 2.1 init default."""
    case, capsule_paths = _case_and_capsules_from_fixture(
        EVALUATION_FIXTURE / "case.json", root=EVALUATION_FIXTURE
    )
    initialize_evaluation_v2(
        case,
        run,
        seed_hex="6" * 64,
        generation_capsule_paths=capsule_paths,
    )


def _initialize_v21_eval_run(run: Path) -> None:
    """Materialize a retained 2.1 run for the Protocol 2.2 CLI boundary."""
    case, capsule_paths = _case_and_capsules_from_fixture(
        EVALUATION_FIXTURE / "case.json", root=EVALUATION_FIXTURE
    )
    initialize_evaluation_v21(
        case,
        run,
        seed_hex="5" * 64,
        generation_capsule_paths=capsule_paths,
    )


def _stopped_shape_audit_payload(request: dict[str, object]) -> dict[str, object]:
    """Return a fictional audit with the add/edit/split shape that previously stopped."""
    return {
        "request_fingerprint": request["request_fingerprint"],
        "complete": True,
        "disputes": [
            {
                "dispute_id": "add-covered-operator-scope",
                "action": "add",
                "target_ledger_ids": [],
                "proposed_entries": [],
                "materiality": "supporting",
                "rationale": (
                    "synthetic-rule-1-source has a missing covered operator scope ledger "
                    "entry from Rule 1."
                ),
            },
            {
                "dispute_id": "edit-retained-proof",
                "action": "edit",
                "target_ledger_ids": ["retain-proof"],
                "proposed_entries": [],
                "materiality": "supporting",
                "rationale": (
                    "The retained proof requirement needs an edit to link the filing "
                    "duty in the ledger."
                ),
            },
            {
                "dispute_id": "split-filing-and-deadline",
                "action": "split",
                "target_ledger_ids": ["file-notice"],
                "proposed_entries": [],
                "materiality": "supporting",
                "rationale": (
                    "The file notice requirement combines a filing duty and deadline "
                    "and requires a split."
                ),
            },
            {
                "dispute_id": "edit-enforcement-relationship",
                "action": "edit",
                "target_ledger_ids": ["bureau-order"],
                "proposed_entries": [],
                "materiality": "supporting",
                "rationale": (
                    "The Bureau enforcement trigger relationship needs an edit after "
                    "splitting the filing duty."
                ),
            },
            {
                "dispute_id": "delete-duplicate-deadline",
                "action": "delete",
                "target_ledger_ids": ["notice-deadline"],
                "proposed_entries": [],
                "materiality": "supporting",
                "rationale": (
                    "The existing deadline ledger entry needs deletion because the split "
                    "creates its exact replacement."
                ),
            },
        ],
    }


def _stopped_shape_repair_payload(
    request: dict[str, object], *, corruption: str | None = None
) -> dict[str, object]:
    """Return one closed fictional repair, optionally with one isolated corruption."""
    request_payload = request["payload"]
    proposed = request_payload["proposed_ledger"]
    proposed_by_id = {entry["ledger_id"]: entry for entry in proposed["entries"]}
    citation = json.loads(json.dumps(proposed_by_id["file-notice"]["citations"][0]))

    added_scope = json.loads(json.dumps(proposed_by_id["file-notice"]))
    added_scope.update(
        {
            "ledger_id": "covered-operator-scope-added",
            "walk_order": 0,
            "category": "scope",
            "materiality": "supporting",
            "modality": "applies",
            "operative_action": "cover",
            "proposition": "Rule 1 applies to a covered operator.",
            "materiality_rationale": (
                "Identifying the covered operator prevents a concrete scope error."
            ),
            "actor": None,
            "object": None,
            "timing": None,
            "relationship_ids": [],
            "citations": [citation],
        }
    )

    filing_duty = json.loads(json.dumps(proposed_by_id["file-notice"]))
    filing_duty.update(
        {
            "ledger_id": "notice-filing-duty-split",
            "walk_order": 1,
            "timing": None,
            "proposition": "A covered operator must file a registry notice.",
            "materiality_rationale": (
                "Omitting the filing duty creates a concrete registry compliance violation."
            ),
            "relationship_ids": [],
            "citations": [citation],
        }
    )

    filing_deadline = json.loads(json.dumps(proposed_by_id["notice-deadline"]))
    filing_deadline.update(
        {
            "ledger_id": "notice-filing-deadline-split",
            "walk_order": 2,
            "proposition": "The registry notice filing deadline is within 10 days.",
            "materiality_rationale": (
                "Missing the ten day deadline creates a concrete late filing risk."
            ),
            "relationship_ids": ["notice-filing-duty-split"],
            "citations": [citation],
        }
    )

    retained_proof = json.loads(json.dumps(proposed_by_id["retain-proof"]))
    retained_proof.update(
        {
            "walk_order": 3,
            "materiality_rationale": (
                "Missing retained proof prevents concrete demonstration of compliant filing."
            ),
            "relationship_ids": ["notice-filing-duty-split"],
            "citations": [citation],
        }
    )

    emergency = json.loads(json.dumps(proposed_by_id["emergency-exception"]))
    emergency.update(
        {
            "walk_order": 4,
            "relationship_ids": ["notice-filing-duty-split"],
            "citations": [citation],
        }
    )
    enforcement = json.loads(json.dumps(proposed_by_id["bureau-order"]))
    enforcement.update(
        {
            "walk_order": 5,
            "relationship_ids": ["notice-filing-duty-split"],
            "citations": [citation],
        }
    )
    penalty = json.loads(json.dumps(proposed_by_id["civil-penalty"]))
    penalty.update(
        {
            "walk_order": 6,
            "relationship_ids": ["notice-filing-duty-split"],
            "citations": [citation],
        }
    )
    entries = [
        added_scope,
        filing_duty,
        filing_deadline,
        retained_proof,
        emergency,
        enforcement,
        penalty,
    ]
    payload = {
        "repaired_ledger": {
            "schema_version": "1.0",
            "case_fingerprint": request["safe_metadata"]["source_record_fingerprint"],
            "entries": entries,
            "gaps": [],
        },
        "remaining_audit": {
            "request_fingerprint": request["request_fingerprint"],
            "complete": True,
            "disputes": [],
        },
    }

    if corruption == "duplicate_or_noncontiguous_walk_order":
        entries[2]["walk_order"] = 1
    elif corruption == "unknown_relationship_target":
        enforcement["relationship_ids"] = ["unknown-ledger-entry"]
    elif corruption == "stale_split_relationship_target":
        enforcement["relationship_ids"] = ["file-notice"]
    elif corruption == "citation_offset_or_quote_mismatch":
        added_scope["citations"][0]["end_char"] -= 1
    elif corruption == "missing_category_required_field":
        filing_duty["actor"] = None
    elif corruption == "generic_materiality_rationale":
        filing_duty["materiality_rationale"] = "material"
    elif corruption == "wrong_remaining_audit_fingerprint":
        payload["remaining_audit"]["request_fingerprint"] = "f" * 64
    elif corruption is not None:
        raise AssertionError(f"unknown stopped-shape corruption: {corruption}")
    return payload


def _submit_eval_payload(
    runner: Path,
    run: Path,
    request: dict[str, object],
    payload: dict[str, object],
    *,
    response_path: Path,
) -> subprocess.CompletedProcess[str]:
    response_path.write_text(_canonical_response(request, payload), encoding="utf-8")
    return _run_runner(
        runner,
        "eval-submit-safe",
        "--run",
        str(run.resolve()),
        "--response",
        str(response_path),
    )


def _advance_to_stopped_shape_repair(
    runner: Path, run: Path
) -> dict[str, object]:
    """Advance one fresh run through a valid fictional add/edit/split audit."""
    _initialize_eval_run(runner, run)
    scripted = json.loads(
        (EVALUATION_FIXTURE / "responses" / "scripted-responses.json").read_text(
            encoding="utf-8"
        )
    )["responses"]
    for index in range(2):
        request = _next_packet(runner, run)
        payload = _bound_scripted_payload(request, scripted[index]["payload"])
        submitted = _submit_eval_payload(
            runner,
            run,
            request,
            payload,
            response_path=run.parent / f"{run.name}-setup-{index}.json",
        )
        assert submitted.returncode == 0, submitted.stdout or submitted.stderr
        assert json.loads(submitted.stdout)["accepted"] is True

    audit_request = _next_packet(runner, run)
    assert audit_request["operation"] == "audit_ledger"
    submitted = _submit_eval_payload(
        runner,
        run,
        audit_request,
        _stopped_shape_audit_payload(audit_request),
        response_path=run.parent / f"{run.name}-setup-audit.json",
    )
    assert submitted.returncode == 0, submitted.stdout or submitted.stderr
    assert json.loads(submitted.stdout)["accepted"] is True
    repair_request = _next_packet(runner, run)
    assert repair_request["operation"] == "repair_ledger"
    return repair_request


def _write_qualification_fixture(root: Path, *, schema_version: str = "1.0") -> Path:
    """Write one fictional source-only fixture whose source bytes are CLI inputs."""
    (root / "sources").mkdir(parents=True)
    source_bytes = (
        "Regla sintética. El operador presentará aviso.\r\n"
        "Estado: vigente al 2026-08-15.\r\n"
    ).encode() if schema_version == "1.1" else (
        b"Synthetic Rule. A covered operator must file notice."
    )
    (root / "sources" / "rule.txt").write_bytes(source_bytes)
    case = {
        "schema_version": schema_version,
        "case_id": "synthetic-source-qualification",
        "mode": "current-law",
        "question": "What notice must a covered operator file?",
        "jurisdiction": "Example State",
        "as_of": "2026-08-15",
        "requested_authorities": [
            {
                "authority_id": "synthetic-rule-1",
                "title": "Synthetic Rule 1",
                "jurisdiction": "Example State",
                "authority_type": "regulation",
                "source_ids": ["source-1"],
            }
        ],
        "sources": [
            {
                "source_id": "source-1",
                "title": "Synthetic Rule",
                "path": "sources/rule.txt",
                "qualification_role": "operative_text",
                "jurisdiction": "Example State",
                "authority_type": "regulation",
                "source_role": "official_primary",
                "source_quality": "primary",
                "completeness": "complete",
                "language": "es" if schema_version == "1.1" else "en",
            }
        ],
    }
    if schema_version == "1.1":
        case["sources"][0].update(
            {
                "version": "edición 2026",
                "effective_date": "2026-08-15",
            }
        )
        case.update(
            {
                "build_binding": {
                    "commit": "a" * 40,
                    "archive_sha256": "b" * 64,
                },
                "language_treatments": [
                    {
                        "source_ids": ["source-1"],
                        "method": "Revisión bilingüe del texto oficial.",
                        "rationale": "La traducción conserva la obligación jurídica.",
                        "limitations": "La terminología técnica sigue en español.",
                    }
                ],
            }
        )
    case_path = root / "qualification.json"
    case_path.write_bytes(_canonical_bytes(case))
    return case_path


def _qualification_response_envelope(
    request: dict[str, object],
) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "operation": "admit_case",
        "request_fingerprint": request["request_fingerprint"],
        "provider_name": "fictional-provider",
        "model_name": "fictional-model",
        "judge_isolation": "fresh_context",
        "response_id": "fictional-response-1",
        "usage": {"input_tokens": 101, "output_tokens": 202},
        "payload": _admission_payload(request),
    }


def _write_connected_controller_fixture(root: Path) -> dict[str, Path]:
    """Write one byte-identical source graph for qualification, generation, and evaluation."""
    source_bytes = (EVALUATION_FIXTURE / "sources" / "synthetic-rule.txt").read_bytes()
    report_bytes = (EVALUATION_FIXTURE / "reports" / "correct.md").read_bytes()
    source_id = "synthetic-rule-1-source"
    question = "What must a covered operator do under Synthetic Rule 1?"
    common = {
        "as_of": "2026-08-12",
        "case_id": "connected-controller-case",
        "jurisdiction": "Example State",
        "mode": "closed-universe",
        "question": question,
        "requested_authorities": [
            {
                "authority_id": "synthetic-rule-1",
                "authority_type": "regulation",
                "jurisdiction": "Example State",
                "source_ids": [source_id],
                "title": "Synthetic Rule 1",
            }
        ],
    }
    source = {
        "authority_type": "regulation",
        "completeness": "complete",
        "jurisdiction": "Example State",
        "language": "en",
        "path": "sources/synthetic-rule.txt",
        "source_id": source_id,
        "source_quality": "primary",
        "source_role": "official_primary",
        "title": "Synthetic Rule 1",
    }

    qualification_root = root / "qualification-input"
    (qualification_root / "sources").mkdir(parents=True)
    (qualification_root / "sources" / "synthetic-rule.txt").write_bytes(source_bytes)
    qualification_case = qualification_root / "qualification.json"
    qualification_case.write_bytes(
        _canonical_bytes({**common, "schema_version": "1.0", "sources": [source]})
    )

    generation_root = root / "generation-input"
    (generation_root / "sources").mkdir(parents=True)
    (generation_root / "generator").mkdir()
    (generation_root / "sources" / "synthetic-rule.txt").write_bytes(source_bytes)
    report_text = report_bytes.decode("utf-8")
    generator_source = (
        "import json, sys\n"
        "request = json.load(sys.stdin)\n"
        "source = request['sources'][0]['text']\n"
        "required = 'A covered operator must file a registry notice within 10 days.'\n"
        "if required not in source:\n"
        "    raise SystemExit(2)\n"
        f"sys.stdout.write({report_text!r})\n"
    ).encode()
    generator_artifact = generation_root / "generator" / "build.bin"
    generator_artifact.write_bytes(generator_source)
    generation_input = generation_root / "generation-input.json"
    generation_input.write_bytes(
        _canonical_bytes(
            {
                "candidate_id": "synthetic-harvest",
                "client_facts_path": None,
                "generation_instructions": (
                    "Produce the attorney report from only the supplied synthetic rule."
                ),
                "generator_artifacts": [
                    {"artifact_id": "generator", "path": "generator/build.bin"}
                ],
                "question": question,
                "schema_version": "1.0",
                "sources": [
                    {"path": "sources/synthetic-rule.txt", "source_id": source_id}
                ],
            }
        )
    )

    evaluation_root = root / "evaluation-fixture"
    (evaluation_root / "sources").mkdir(parents=True)
    (evaluation_root / "sources" / "synthetic-rule.txt").write_bytes(source_bytes)
    generation_capsule = evaluation_root / "capsules" / "synthetic-harvest"
    evaluation_case = evaluation_root / "case.json"
    evaluation_case.write_bytes(
        _canonical_bytes(
            {
                **common,
                "candidates": [
                    {
                        "candidate_id": "synthetic-harvest",
                        "external_report_path": None,
                        "generation_capsule_path": "capsules/synthetic-harvest",
                        "role": "candidate",
                    }
                ],
                "client_facts_path": None,
                "schema_version": "1.1",
                "sources": [source],
            }
        )
    )
    return {
        "evaluation_case": evaluation_case,
        "generation_artifact": generator_artifact,
        "generation_capsule": generation_capsule,
        "generation_input": generation_input,
        "qualification_case": qualification_case,
        "report_fixture": EVALUATION_FIXTURE / "reports" / "correct.md",
        "source_fixture": EVALUATION_FIXTURE / "sources" / "synthetic-rule.txt",
    }


@pytest.mark.parametrize(
    "relative_path",
    ["SKILL.md", "references/attorney-evaluation.md"],
)
def test_installed_skill_qualification_and_bounded_repair_contract(
    relative_path: str,
) -> None:
    """Removing a controller guard from either installed instruction surface is unsafe."""
    instructions = (ROOT / relative_path).read_text(encoding="utf-8").casefold()

    for required_contract in (
        "qualify every locked case before generating a candidate",
        "use eval-submit-safe for every evaluator response",
        "never retry an unfavorable substantive judgment",
        "accept an unfavorable substantive result without retry",
        "verify terminal evaluation artifacts",
        "start every mechanical repair in a genuinely fresh role context",
        "stop rather than repair in the same role context",
    ):
        assert required_contract in instructions

    if relative_path == "SKILL.md":
        current_contract = _normalized_markdown_slice(
            relative_path, "## Choose the journey", "## Non-negotiable result"
        )
    else:
        current_contract = _normalized_markdown_slice(
            relative_path,
            "## Protocol 2.1 new-run contract",
            "## Retained Protocol 1.3 operator reference",
        )
    assert "one initial response" in current_contract
    assert "at most one fresh mechanical repair" in current_contract
    assert "per fragment" in current_contract
    assert "second mechanical refusal" in current_contract
    assert "inconclusive_mechanical" in current_contract
    assert "one initial response and at most two mechanical repairs" not in current_contract
    assert "qualification readiness is not a report-quality pass" in instructions
    assert "changing any source byte creates a new versioned case" in instructions


def test_installed_retained_protocol_13_preserves_historical_repair_contract() -> None:
    retained_contract = _normalized_markdown_slice(
        "references/attorney-evaluation.md",
        "## Retained Protocol 1.3 operator reference",
        None,
    )

    assert "one initial response and at most two mechanical repairs" in retained_contract
    assert "same diagnostic code occurs twice" in retained_contract
    assert "stop after the second repair even if the diagnostic codes differ" in retained_contract
    assert (
        "one initial response and at most one fresh mechanical repair per fragment"
        not in retained_contract
    )


def test_bounded_repair_controller_trace_stops_after_a_repeated_safe_diagnostic(
    tmp_path: Path,
) -> None:
    """One byte-bound case must qualify, generate, evaluate, and stop safely."""
    events: list[str] = []
    fixture = _write_connected_controller_fixture(tmp_path / "connected")

    qualification_run = tmp_path / "qualification-run"
    initialized = _run_runner(
        SKILL_RUNNER,
        "eval-qualify-init",
        "--case",
        str(fixture["qualification_case"]),
        "--run",
        str(qualification_run.resolve()),
        "--nonce-hex",
        "1" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    qualification_request = json.loads(
        _run_runner(
            SKILL_RUNNER,
            "eval-qualify-next",
            "--run",
            str(qualification_run.resolve()),
        ).stdout
    )
    qualification_response = tmp_path / "qualification-response.json"
    qualification_response.write_bytes(
        _canonical_bytes(_admission_payload(qualification_request))
    )
    qualified = _run_runner(
        SKILL_RUNNER,
        "eval-qualify-submit",
        "--run",
        str(qualification_run.resolve()),
        "--response",
        str(qualification_response),
    )
    assert qualified.returncode == 0, qualified.stderr
    assert json.loads(qualified.stdout)["accepted"] is True
    qualification_verified = _run_runner(
        SKILL_RUNNER,
        "eval-qualify-verify",
        "--run",
        str(qualification_run.resolve()),
    )
    assert qualification_verified.returncode == 0, qualification_verified.stderr
    assert json.loads(qualification_verified.stdout)["valid"] is True
    qualification_receipt = json.loads(
        (qualification_run / "qualification-receipt.json").read_bytes()
    )
    assert qualification_receipt["readiness"]["status"] == "ADMITTED"
    qualification_state = json.loads(
        _run_runner(
            SKILL_RUNNER,
            "eval-qualify-status",
            "--run",
            str(qualification_run.resolve()),
        ).stdout
    )
    assert qualification_state["status"] == "qualified"
    assert qualification_state["root_hash"] == json.loads(
        qualification_verified.stdout
    )["root_hash"]
    events.append("qualification-verified")

    generation_run = fixture["generation_capsule"]
    generation_initialized = _run_runner(
        SKILL_RUNNER,
        "eval-gen-init",
        "--input",
        str(fixture["generation_input"]),
        "--run",
        str(generation_run.resolve()),
        "--nonce-hex",
        "2" * 64,
    )
    assert generation_initialized.returncode == 0, generation_initialized.stderr
    generation_request = json.loads(
        _run_runner(
            SKILL_RUNNER,
            "eval-gen-next",
            "--run",
            str(generation_run.resolve()),
        ).stdout
    )
    captured_generator = generation_run / "captured" / "generator" / "generator.bin"
    generator_hash = hashlib.sha256(captured_generator.read_bytes()).hexdigest()
    assert generator_hash == generation_request["generator_artifacts"][0]["content_hash"]
    assert generator_hash == hashlib.sha256(
        fixture["generation_artifact"].read_bytes()
    ).hexdigest()
    generated_report = subprocess.run(
        [sys.executable, "-I", "-S", str(captured_generator)],
        cwd=tmp_path,
        env={**os.environ, "PYTHONNOUSERSITE": "1"},
        input=_canonical_bytes(generation_request),
        check=False,
        capture_output=True,
    )
    assert generated_report.returncode == 0, generated_report.stderr
    assert generated_report.stdout == fixture["report_fixture"].read_bytes()
    generation_response = tmp_path / "generation-response.json"
    generation_response.write_bytes(
        _canonical_bytes(
            {
                "generation_isolation": "fresh_context",
                "model_name": "captured-synthetic-build",
                "operation": "generate_report",
                "payload": {"report_text": generated_report.stdout.decode("utf-8")},
                "provider_name": "local-runnable-fixture",
                "request_fingerprint": generation_request["request_fingerprint"],
                "response_id": None,
                "schema_version": "1.0",
                "usage": {},
            }
        )
    )
    generated = _run_runner(
        SKILL_RUNNER,
        "eval-gen-submit",
        "--run",
        str(generation_run.resolve()),
        "--response",
        str(generation_response),
    )
    assert generated.returncode == 0, generated.stderr
    assert json.loads(generated.stdout)["state"] == "completed"
    generation_verified = _run_runner(
        SKILL_RUNNER,
        "eval-gen-verify",
        "--run",
        str(generation_run.resolve()),
    )
    assert generation_verified.returncode == 0, generation_verified.stderr
    generation_verification = json.loads(generation_verified.stdout)
    assert generation_verification["ok"] is True
    assert generation_verification["state"]["state"] == "completed"
    qualification_input = json.loads(fixture["qualification_case"].read_bytes())
    evaluation_input = json.loads(fixture["evaluation_case"].read_bytes())
    assert qualification_input["question"] == generation_request["question"]
    assert generation_request["question"] == evaluation_input["question"]
    expected_source_hash = hashlib.sha256(fixture["source_fixture"].read_bytes()).hexdigest()
    assert qualification_request["payload"]["sources"][0]["content_hash"] == (
        expected_source_hash
    )
    assert generation_request["sources"][0]["content_hash"] == expected_source_hash
    generation_record = json.loads(
        (generation_run / "generation-record.json").read_bytes()
    )
    assert generation_record["source_hashes"] == {
        "synthetic-rule-1-source": expected_source_hash
    }
    assert generation_record["report_hash"] == hashlib.sha256(
        generated_report.stdout
    ).hexdigest()
    events.append("generation-verified")
    assert events == ["qualification-verified", "generation-verified"]

    evaluation_run = tmp_path / "evaluation-run"
    _initialize_eval_run(
        PORTABLE_RUNNER, evaluation_run, case_path=fixture["evaluation_case"]
    )
    evaluation_envelope = json.loads(
        (evaluation_run / "case-envelope.json").read_bytes()
    )
    evaluation_source = evaluation_envelope["case"]["sources"][0]
    evaluation_candidate = evaluation_envelope["case"]["candidates"][0]
    assert evaluation_source["content_hash"] == expected_source_hash
    assert evaluation_candidate["report_hash"] == generation_record["report_hash"]
    assert evaluation_candidate["validation_receipt"]["capsule_root"] == (
        generation_verification["manifest_root"]
    )
    assert evaluation_candidate["validation_receipt"]["generation_record"] == (
        generation_record
    )
    # This deliberately frozen 1.3 run remains replayable but is no longer a
    # public lifecycle surface.  The v2 workflow owns source review/audit/grade
    # behavior; the full CLI must refuse every retained mutation without
    # changing the sealed historical record.
    before = _run_snapshot(evaluation_run)
    status = _run_runner(SKILL_RUNNER, "eval-status", "--run", str(evaluation_run))
    verified = _run_runner(SKILL_RUNNER, "eval-verify", "--run", str(evaluation_run))
    mutation = _run_runner(
        SKILL_RUNNER,
        "eval-submit-safe",
        "--run",
        str(evaluation_run),
        "--response",
        str(tmp_path / "ignored.json"),
    )
    assert status.returncode == verified.returncode == 0
    assert mutation.returncode == 2
    assert json.loads(mutation.stderr)["code"] == "EVALUATION_LEGACY_READ_ONLY"
    assert _run_snapshot(evaluation_run) == before


def test_controller_defaults_to_protocol_21_and_preserves_truthful_template_metadata(
    tmp_path: Path,
) -> None:
    """A new public run exposes the v2.1 source-review request and truthful labels."""
    run = tmp_path / "v21-source-review"
    initialized = _run_runner(
        SKILL_RUNNER,
        "eval-init",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(run),
        "--seed-hex",
        "a" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    request = _next_packet(SKILL_RUNNER, run)
    assert request["schema_version"] == "2.1"
    assert request["operation"] == "source_review"
    assert json.loads(
        (ROOT / "assets" / "attorney-evaluation-response.template.json").read_bytes()
    )["judge_isolation"] == "fresh_context"


def _baseline_cli_control(tmp_path: Path) -> Path:
    fixture_root = tmp_path / "baseline-fixture"
    case_path = _write_qualification_fixture(fixture_root, schema_version="1.1")
    qualification = tmp_path / "qualification"
    initialized = _run_runner(
        SKILL_RUNNER,
        "eval-qualify-init",
        "--case",
        str(case_path),
        "--run",
        str(qualification),
        "--nonce-hex",
        "1" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    request_result = _run_runner(
        SKILL_RUNNER, "eval-qualify-next", "--run", str(qualification)
    )
    assert request_result.returncode == 0, request_result.stderr
    request = json.loads(request_result.stdout)
    response_path = tmp_path / "qualification-response.json"
    response_path.write_bytes(_canonical_bytes(_qualification_response_envelope(request)))
    submitted = _run_runner(
        SKILL_RUNNER,
        "eval-qualify-submit",
        "--run",
        str(qualification),
        "--response",
        str(response_path),
    )
    assert submitted.returncode == 0, submitted.stderr
    control = tmp_path / "baseline-control.json"
    control.write_bytes(
        _canonical_bytes(
            {
                "client_facts_path": None,
                "qualification_capsule_path": "qualification",
                "schema_version": "1.0",
            }
        )
    )
    return control


def _assert_baseline_surface_parity(
    full_args: tuple[str, ...],
    portable_args: tuple[str, ...],
) -> tuple[subprocess.CompletedProcess[str], subprocess.CompletedProcess[str]]:
    full = _run_baseline_surface(SKILL_RUNNER, *full_args)
    portable = _run_baseline_surface(PORTABLE_RUNNER, *portable_args)
    assert (portable.returncode, portable.stdout, portable.stderr) == (
        full.returncode,
        full.stdout,
        full.stderr,
    )
    return full, portable


def _complete_baseline_parity_pair(
    tmp_path: Path, *, suffix: str
) -> tuple[Path, Path, Path]:
    """Create one minimal terminal pair for bounded adversarial rows."""
    control = _baseline_cli_control(tmp_path)
    full_run = tmp_path / f"baseline-full-{suffix}"
    portable_run = tmp_path / f"baseline-portable-{suffix}"
    common = ("--input", str(control), "--nonce-hex", "8" * 64)
    _assert_baseline_surface_parity(
        ("eval-baseline-init", *common, "--run", str(full_run)),
        ("eval-baseline-init", *common, "--run", str(portable_run)),
    )
    payloads = (
        {
            "proposals": [
                {
                    "statement": "A covered operator must file notice.",
                    "kind": "obligation",
                    "importance": "critical",
                    "importance_basis": ["legal_bottom_line"],
                    "importance_rationale": "Omission could change the legal bottom line.",
                    "passages": [{"source_id": "source-1", "quote": "presentará aviso"}],
                    "dependency": None,
                    "confidence": "clear",
                    "substantive_rationale": "The fictional rule uses mandatory language.",
                }
            ],
            "review_complete": True,
        },
        {
            "concerns": [],
            "importance_findings": [
                {
                    "proposal_ref": "PR-0001",
                    "reviewed_importance": "critical",
                    "reviewed_importance_basis": ["legal_bottom_line"],
                    "importance_rationale": "Omission could change the legal bottom line.",
                    "disposition": "agree",
                }
            ],
            "audit_complete": True,
        },
    )
    for ordinal, payload in enumerate(payloads, 1):
        request, _ = _assert_baseline_surface_parity(
            ("eval-baseline-next", "--run", str(full_run)),
            ("eval-baseline-next", "--run", str(portable_run)),
        )
        assert json.loads(request.stdout)["operation"] in {
            "baseline_source_review", "baseline_source_audit"
        }
        response = tmp_path / f"baseline-{suffix}-response-{ordinal}.json"
        response.write_bytes(_canonical_bytes(payload))
        flags = (
            "--response", str(response), "--provider-name", "fictional-provider",
            "--model-name", "fictional-model", "--judge-isolation", "scripted_fixture",
        )
        _assert_baseline_surface_parity(
            ("eval-baseline-submit-safe", "--run", str(full_run), *flags),
            ("eval-baseline-submit-safe", "--run", str(portable_run), *flags),
        )
    assert _run_snapshot(portable_run) == _run_snapshot(full_run)
    return control, full_run, portable_run


def _reseal_baseline_parity_run(
    run: Path,
    changes: dict[str, bytes],
    *,
    manifest_updates: dict[str, object] | None = None,
) -> None:
    """Rehash changed artifacts and both outer manifest fingerprints only."""
    manifest_path = run / "baseline-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    records = {item["artifact_path"]: item for item in manifest["artifacts"]}
    for path, data in changes.items():
        target = run / path
        target.chmod(0o600)
        target.write_bytes(data)
        records[path]["artifact_hash"] = hashlib.sha256(data).hexdigest()
    manifest["artifacts"] = [records[path] for path in sorted(records)]
    if manifest_updates is not None:
        manifest.update(manifest_updates)
    manifest["root_hash"] = "0" * 64
    manifest["manifest_fingerprint"] = "0" * 64
    manifest["manifest_fingerprint"] = hashlib.sha256(
        _canonical_bytes(
            {
                key: value
                for key, value in manifest.items()
                if key not in {"manifest_fingerprint", "root_hash"}
            }
        )
    ).hexdigest()
    manifest["root_hash"] = hashlib.sha256(
        _canonical_bytes({key: value for key, value in manifest.items() if key != "root_hash"})
    ).hexdigest()
    manifest_path.chmod(0o600)
    manifest_path.write_bytes(_canonical_bytes(manifest))


def _write_baseline_parity_correction(
    tmp_path: Path, prior_run: Path, *, suffix: str, correction_id: str
) -> Path:
    manifest = json.loads((prior_run / "baseline-manifest.json").read_bytes())
    baseline = json.loads((prior_run / "canonical-baseline.json").read_bytes())
    replacement = dict(baseline["requirements"][0])
    replacement["statement"] = f"The covered operator must file a notice {suffix}."
    payload = {
        "schema_version": "baseline-correction-v1",
        "prior_baseline_root": manifest["root_hash"],
        "prior_baseline_fingerprint": baseline["baseline_fingerprint"],
        "correction_id": correction_id,
        "actions": [
            {
                "action": "replace_requirement",
                "requirement_id": replacement["requirement_id"],
                "relationship_id": None,
                "requirement": replacement,
                "relationship": None,
            }
        ],
        "reason": "The attorney approved a source-bound wording correction.",
        "attorney_approval": {
            "approved_by": "Fictional Reviewing Attorney",
            "approved_at": "2026-08-24T20:00:00-07:00",
            "approval_statement": "I approve this source-bound baseline correction.",
        },
        "correction_fingerprint": "0" * 64,
    }
    payload["correction_fingerprint"] = hashlib.sha256(
        _canonical_bytes(
            {key: value for key, value in payload.items() if key != "correction_fingerprint"}
        )
    ).hexdigest()
    path = tmp_path / f"correction-{suffix}.json"
    path.write_bytes(_canonical_bytes(payload))
    return path


def _correct_baseline_parity_pair(
    tmp_path: Path,
    control: Path,
    full_prior: Path,
    portable_prior: Path,
    *,
    full_ancestry: tuple[Path, ...] = (),
    portable_ancestry: tuple[Path, ...] = (),
    suffix: str,
    correction_id: str,
) -> tuple[Path, Path]:
    correction = _write_baseline_parity_correction(
        tmp_path, full_prior, suffix=suffix, correction_id=correction_id
    )
    full_run = tmp_path / f"full-corrected-{suffix}"
    portable_run = tmp_path / f"portable-corrected-{suffix}"
    shared = (
        "eval-baseline-init", "--input", str(control), "--nonce-hex", "7" * 64,
        "--correction", str(correction),
    )
    full_priors = tuple(
        item for prior in (*full_ancestry, full_prior) for item in ("--prior-baseline", str(prior))
    )
    portable_priors = tuple(
        item
        for prior in (*portable_ancestry, portable_prior)
        for item in ("--prior-baseline", str(prior))
    )
    _assert_baseline_surface_parity(
        (*shared, *full_priors, "--run", str(full_run)),
        (*shared, *portable_priors, "--run", str(portable_run)),
    )
    assert _run_snapshot(portable_run) == _run_snapshot(full_run)
    return full_run, portable_run


def _rewrite_baseline_proof_attack(run: Path, attack: str) -> None:
    proof = json.loads((run / "correction-proof.json").read_bytes())
    nodes = proof["nodes"]
    assert len(nodes) == 2
    if attack == "tampered-resealed":
        node = nodes[0]
        artifact = next(
            item for item in node["artifacts"]
            if item["artifact_path"] == "canonical-baseline.json"
        )
        baseline = json.loads(artifact["artifact_json"])
        baseline["requirements"][0]["substantive_rationale"] = "Forged ancestor rationale."
        baseline["baseline_fingerprint"] = "0" * 64
        unsigned_baseline = dict(baseline)
        unsigned_baseline.pop("baseline_fingerprint")
        baseline["baseline_fingerprint"] = hashlib.sha256(
            _canonical_bytes(unsigned_baseline)
        ).hexdigest()
        artifact["artifact_json"] = _canonical_bytes(baseline).decode()
        artifact["artifact_hash"] = hashlib.sha256(
            artifact["artifact_json"].encode()
        ).hexdigest()
        ancestor_manifest = json.loads(node["manifest_json"])
        for record in ancestor_manifest["artifacts"]:
            if record["artifact_path"] == "canonical-baseline.json":
                record["artifact_hash"] = artifact["artifact_hash"]
        ancestor_manifest["baseline_fingerprint"] = baseline["baseline_fingerprint"]
        ancestor_manifest["root_hash"] = "0" * 64
        ancestor_manifest["manifest_fingerprint"] = "0" * 64
        ancestor_manifest["manifest_fingerprint"] = hashlib.sha256(
            _canonical_bytes(
                {
                    key: value for key, value in ancestor_manifest.items()
                    if key not in {"manifest_fingerprint", "root_hash"}
                }
            )
        ).hexdigest()
        ancestor_manifest["root_hash"] = hashlib.sha256(
            _canonical_bytes(
                {key: value for key, value in ancestor_manifest.items() if key != "root_hash"}
            )
        ).hexdigest()
        node["manifest_json"] = _canonical_bytes(ancestor_manifest).decode()
    elif attack == "omitted-prefix":
        proof["nodes"] = nodes[1:]
    elif attack == "reordered":
        proof["nodes"] = list(reversed(nodes))
    elif attack == "disconnected-prefix":
        node = nodes[0]
        manifest = json.loads(node["manifest_json"])
        manifest["root_hash"] = "f" * 64
        node["manifest_json"] = _canonical_bytes(manifest).decode()
    else:
        assert attack == "truncated-prefix"
        proof["nodes"] = nodes[:1]
    unsigned = {"schema_version": proof["schema_version"], "nodes": proof["nodes"]}
    proof["proof_fingerprint"] = hashlib.sha256(_canonical_bytes(unsigned)).hexdigest()
    proof_bytes = _canonical_bytes(proof)
    _reseal_baseline_parity_run(
        run,
        {"correction-proof.json": proof_bytes},
        manifest_updates={"correction_proof_fingerprint": proof["proof_fingerprint"]},
    )


def test_baseline_parity_stable_zero_dispute_lifecycle_and_complete_tree(
    tmp_path: Path,
) -> None:
    """Deleting any portable lifecycle branch breaks exact command/tree parity."""
    control = _baseline_cli_control(tmp_path)
    full_run = tmp_path / "baseline-full"
    portable_run = tmp_path / "baseline-portable"
    common = (
        "--input",
        str(control),
        "--nonce-hex",
        "2" * 64,
    )
    _assert_baseline_surface_parity(
        ("eval-baseline-init", *common, "--run", str(full_run)),
        ("eval-baseline-init", *common, "--run", str(portable_run)),
    )
    first_full, _ = _assert_baseline_surface_parity(
        ("eval-baseline-next", "--run", str(full_run)),
        ("eval-baseline-next", "--run", str(portable_run)),
    )
    assert json.loads(first_full.stdout)["operation"] == "baseline_source_review"

    malformed = tmp_path / "baseline-malformed.json"
    malformed.write_bytes(_canonical_bytes({"private_path": str(tmp_path), "source": "secret"}))
    before_full = _run_snapshot(full_run)
    before_portable = _run_snapshot(portable_run)
    submit_flags = (
        "--response",
        str(malformed),
        "--provider-name",
        "fictional-provider",
        "--model-name",
        "fictional-model",
        "--judge-isolation",
        "scripted_fixture",
    )
    refused, _ = _assert_baseline_surface_parity(
        ("eval-baseline-submit-safe", "--run", str(full_run), *submit_flags),
        ("eval-baseline-submit-safe", "--run", str(portable_run), *submit_flags),
    )
    assert refused.returncode == 2
    assert _run_snapshot(full_run) == before_full
    assert _run_snapshot(portable_run) == before_portable

    review = tmp_path / "baseline-review.json"
    review.write_bytes(
        _canonical_bytes(
            {
                "proposals": [
                    {
                        "statement": "A covered operator must file notice.",
                        "kind": "obligation",
                        "importance": "critical",
                        "importance_basis": ["legal_bottom_line"],
                        "importance_rationale": "Omission could change the legal bottom line.",
                        "passages": [{"source_id": "source-1", "quote": "presentará aviso"}],
                        "dependency": None,
                        "confidence": "clear",
                        "substantive_rationale": "The fictional rule uses mandatory language.",
                    }
                ],
                "review_complete": True,
            }
        )
    )
    review_flags = (
        "--response",
        str(review),
        "--provider-name",
        "fictional-provider",
        "--model-name",
        "fictional-model",
        "--judge-isolation",
        "scripted_fixture",
    )
    _assert_baseline_surface_parity(
        ("eval-baseline-submit-safe", "--run", str(full_run), *review_flags),
        ("eval-baseline-submit-safe", "--run", str(portable_run), *review_flags),
    )
    audit_request, _ = _assert_baseline_surface_parity(
        ("eval-baseline-next", "--run", str(full_run)),
        ("eval-baseline-next", "--run", str(portable_run)),
    )
    assert json.loads(audit_request.stdout)["operation"] == "baseline_source_audit"

    audit = tmp_path / "baseline-audit.json"
    audit.write_bytes(
        _canonical_bytes(
            {
                "concerns": [],
                "importance_findings": [
                    {
                        "proposal_ref": "PR-0001",
                        "reviewed_importance": "critical",
                        "reviewed_importance_basis": ["legal_bottom_line"],
                        "importance_rationale": "Omission could change the legal bottom line.",
                        "disposition": "agree",
                    }
                ],
                "audit_complete": True,
            }
        )
    )
    audit_flags = (
        "--response",
        str(audit),
        "--provider-name",
        "fictional-provider",
        "--model-name",
        "fictional-model",
        "--judge-isolation",
        "scripted_fixture",
    )
    _assert_baseline_surface_parity(
        ("eval-baseline-submit-safe", "--run", str(full_run), *audit_flags),
        ("eval-baseline-submit-safe", "--run", str(portable_run), *audit_flags),
    )
    for command in ("eval-baseline-next", "eval-baseline-status", "eval-baseline-verify"):
        _assert_baseline_surface_parity(
            (command, "--run", str(full_run)),
            (command, "--run", str(portable_run)),
        )

    assert _run_snapshot(portable_run) == _run_snapshot(full_run)

    from regulatory_harvest.evaluation.attorney_baseline_projection import (
        project_gradeable_baseline_v1,
    )

    full_projection = project_gradeable_baseline_v1(
        load_verified_baseline_run(full_run)
    )
    projection_spec = importlib.util.spec_from_file_location(
        "attorney_eval_portable_baseline_projection_test",
        ROOT / "scripts" / "attorney_eval_portable.py",
    )
    assert projection_spec is not None and projection_spec.loader is not None
    portable_substrate = importlib.util.module_from_spec(projection_spec)
    sys.modules[projection_spec.name] = portable_substrate
    projection_spec.loader.exec_module(portable_substrate)
    portable_projection = portable_substrate._baseline_gradeable_projection_bytes_for_test(
        _run_snapshot(portable_run)
    )
    assert portable_projection == _canonical_bytes(
        full_projection.model_dump(mode="json")
    )

    prior_manifest = json.loads((full_run / "baseline-manifest.json").read_bytes())
    prior_baseline = json.loads((full_run / "canonical-baseline.json").read_bytes())
    replacement = dict(prior_baseline["requirements"][0])
    replacement["statement"] = "The covered operator must file a notice."
    action = {
        "action": "replace_requirement",
        "requirement_id": replacement["requirement_id"],
        "relationship_id": None,
        "requirement": replacement,
        "relationship": None,
    }
    correction_payload = {
        "schema_version": "baseline-correction-v1",
        "prior_baseline_root": prior_manifest["root_hash"],
        "prior_baseline_fingerprint": prior_baseline["baseline_fingerprint"],
        "correction_id": "CORR-0001",
        "actions": [action],
        "reason": "The attorney approved a source-bound wording correction.",
        "attorney_approval": {
            "approved_by": "Fictional Reviewing Attorney",
            "approved_at": "2026-08-24T20:00:00-07:00",
            "approval_statement": "I approve this source-bound baseline correction.",
        },
        "correction_fingerprint": "0" * 64,
    }
    correction_payload["correction_fingerprint"] = hashlib.sha256(
        _canonical_bytes(
            {
                key: value
                for key, value in correction_payload.items()
                if key != "correction_fingerprint"
            }
        )
    ).hexdigest()
    correction = tmp_path / "baseline-parity-correction.json"
    correction.write_bytes(_canonical_bytes(correction_payload))
    full_corrected = tmp_path / "baseline-full-corrected"
    portable_corrected = tmp_path / "baseline-portable-corrected"
    correction_common = (
        "--input", str(control), "--nonce-hex", "4" * 64,
        "--correction", str(correction),
    )
    _assert_baseline_surface_parity(
        (
            "eval-baseline-init", *correction_common, "--prior-baseline", str(full_run),
            "--run", str(full_corrected),
        ),
        (
            "eval-baseline-init", *correction_common, "--prior-baseline", str(portable_run),
            "--run", str(portable_corrected),
        ),
    )
    for command in ("eval-baseline-next", "eval-baseline-status", "eval-baseline-verify"):
        _assert_baseline_surface_parity(
            (command, "--run", str(full_corrected)),
            (command, "--run", str(portable_corrected)),
        )
    assert _run_snapshot(portable_corrected) == _run_snapshot(full_corrected)
    assert "correction-proof.json" in _run_snapshot(portable_corrected)


@pytest.mark.parametrize(
    "command",
    (
        "eval-baseline-init",
        "eval-baseline-next",
        "eval-baseline-submit-safe",
        "eval-baseline-status",
        "eval-baseline-verify",
    ),
)
def test_baseline_parity_isolated_help(command: str) -> None:
    """Removing a portable command or importing site packages breaks isolated help."""
    full = _run_baseline_surface(SKILL_RUNNER, command, "--help")
    portable = _run_baseline_surface(PORTABLE_RUNNER, command, "--help")
    assert (portable.returncode, portable.stdout, portable.stderr) == (
        full.returncode,
        full.stdout,
        full.stderr,
    )


@pytest.mark.parametrize(
    ("dispute_kind", "decision"),
    (
        ("semantic", "accept_reviewer"),
        ("importance", "accept_auditor"),
        ("semantic", "unresolved"),
    ),
)
def test_baseline_parity_disputes_pause_resume_and_complete_tree(
    tmp_path: Path, dispute_kind: str, decision: str
) -> None:
    """Semantic, importance-only, and unresolved referee paths stay byte-identical."""
    control = _baseline_cli_control(tmp_path)
    full_run = tmp_path / f"baseline-full-{dispute_kind}-{decision}"
    portable_run = tmp_path / f"baseline-portable-{dispute_kind}-{decision}"
    common = ("--input", str(control), "--nonce-hex", "3" * 64)
    _assert_baseline_surface_parity(
        ("eval-baseline-init", *common, "--run", str(full_run)),
        ("eval-baseline-init", *common, "--run", str(portable_run)),
    )
    review = tmp_path / f"review-{dispute_kind}-{decision}.json"
    review.write_bytes(
        _canonical_bytes(
            {
                "proposals": [
                    {
                        "statement": "A covered operator must file notice.",
                        "kind": "obligation",
                        "importance": "critical",
                        "importance_basis": ["legal_bottom_line"],
                        "importance_rationale": "Omission could change the legal bottom line.",
                        "passages": [{"source_id": "source-1", "quote": "presentará aviso"}],
                        "dependency": None,
                        "confidence": "clear",
                        "substantive_rationale": "The fictional rule uses mandatory language.",
                    }
                ],
                "review_complete": True,
            }
        )
    )
    common_submit = (
        "--provider-name", "fictional-provider", "--model-name", "fictional-model",
        "--judge-isolation", "scripted_fixture",
    )
    _assert_baseline_surface_parity(
        (
            "eval-baseline-submit-safe", "--run", str(full_run),
            "--response", str(review), *common_submit,
        ),
        (
            "eval-baseline-submit-safe", "--run", str(portable_run),
            "--response", str(review), *common_submit,
        ),
    )
    for command in ("eval-baseline-status", "eval-baseline-next"):
        before_full = _run_snapshot(full_run)
        before_portable = _run_snapshot(portable_run)
        _assert_baseline_surface_parity(
            (command, "--run", str(full_run)),
            (command, "--run", str(portable_run)),
        )
        assert _run_snapshot(full_run) == before_full
        assert _run_snapshot(portable_run) == before_portable

    audit = tmp_path / f"audit-{dispute_kind}-{decision}.json"
    importance = "material" if dispute_kind == "importance" else "critical"
    basis = ["attorney_briefing"] if dispute_kind == "importance" else ["legal_bottom_line"]
    rationale = (
        "The notice duty is necessary for a competent attorney briefing."
        if dispute_kind == "importance"
        else "Omission could change the legal bottom line."
    )
    audit.write_bytes(
        _canonical_bytes(
            {
                "concerns": (
                    [
                        {
                            "target_proposal_ref": "PR-0001",
                            "concern_type": "ambiguity",
                            "passages": [
                                {"source_id": "source-1", "quote": "presentará aviso"}
                            ],
                            "explanation": "The retained text could support a narrower duty.",
                            "correction": None,
                        }
                    ]
                    if dispute_kind == "semantic"
                    else []
                ),
                "importance_findings": [
                    {
                        "proposal_ref": "PR-0001",
                        "reviewed_importance": importance,
                        "reviewed_importance_basis": basis,
                        "importance_rationale": rationale,
                        "disposition": "correct" if dispute_kind == "importance" else "agree",
                    }
                ],
                "audit_complete": True,
            }
        )
    )
    _assert_baseline_surface_parity(
        (
            "eval-baseline-submit-safe", "--run", str(full_run),
            "--response", str(audit), *common_submit,
        ),
        (
            "eval-baseline-submit-safe", "--run", str(portable_run),
            "--response", str(audit), *common_submit,
        ),
    )
    referee_full, _ = _assert_baseline_surface_parity(
        ("eval-baseline-next", "--run", str(full_run)),
        ("eval-baseline-next", "--run", str(portable_run)),
    )
    for command in ("eval-baseline-status", "eval-baseline-next"):
        before_full = _run_snapshot(full_run)
        before_portable = _run_snapshot(portable_run)
        _assert_baseline_surface_parity(
            (command, "--run", str(full_run)),
            (command, "--run", str(portable_run)),
        )
        assert _run_snapshot(full_run) == before_full
        assert _run_snapshot(portable_run) == before_portable
    dispute_id = json.loads(referee_full.stdout)["payload"]["dispute"]["dispute_id"]
    referee = tmp_path / f"referee-{dispute_kind}-{decision}.json"
    referee.write_bytes(
        _canonical_bytes(
            {
                "dispute_id": dispute_id,
                "decision": decision,
                "passages": [{"source_id": "source-1", "quote": "presentará aviso"}],
                "importance": importance,
                "importance_basis": basis,
                "importance_rationale": rationale,
                "substantive_rationale": "The source-bound alternatives require this decision.",
            }
        )
    )
    _assert_baseline_surface_parity(
        (
            "eval-baseline-submit-safe", "--run", str(full_run),
            "--response", str(referee), *common_submit,
        ),
        (
            "eval-baseline-submit-safe", "--run", str(portable_run),
            "--response", str(referee), *common_submit,
        ),
    )
    _assert_baseline_surface_parity(
        ("eval-baseline-verify", "--run", str(full_run)),
        ("eval-baseline-verify", "--run", str(portable_run)),
    )
    assert _run_snapshot(portable_run) == _run_snapshot(full_run)


@pytest.mark.parametrize(
    "attack",
    (
        "artifact-tamper",
        "semantic-reseal",
        "request-response-swap",
        "source-result-swap",
        "symlink",
        "fifo",
        "hardlink",
    ),
)
def test_baseline_parity_tamper_reseal_swap_and_physical_storage(
    tmp_path: Path, attack: str
) -> None:
    """Tamper and physical-storage attacks return the same bounded verification bytes."""
    if attack in {"symlink", "fifo", "hardlink"} and os.name != "posix":
        pytest.skip("POSIX special-file proof")
    _, full_run, portable_run = _complete_baseline_parity_pair(tmp_path, suffix=attack)
    for label, run in (("full", full_run), ("portable", portable_run)):
        if attack == "artifact-tamper":
            target = run / "canonical-baseline.json"
            target.chmod(0o600)
            target.write_bytes(target.read_bytes() + b"\n")
        elif attack == "semantic-reseal":
            raw = json.loads((run / "canonical-baseline.json").read_bytes())
            raw["requirements"][0]["substantive_rationale"] = "A forged rationale."
            raw["baseline_fingerprint"] = "0" * 64
            unsigned = dict(raw)
            unsigned.pop("baseline_fingerprint")
            raw["baseline_fingerprint"] = hashlib.sha256(
                _canonical_bytes(unsigned)
            ).hexdigest()
            _reseal_baseline_parity_run(
                run, {"canonical-baseline.json": _canonical_bytes(raw)}
            )
        elif attack == "request-response-swap":
            left = "requests/source-review-0001.json"
            right = "responses/source-review-0001.json"
            _reseal_baseline_parity_run(
                run, {left: (run / right).read_bytes(), right: (run / left).read_bytes()}
            )
        elif attack == "source-result-swap":
            left = "baseline-input.json"
            right = "canonical-baseline.json"
            _reseal_baseline_parity_run(
                run, {left: (run / right).read_bytes(), right: (run / left).read_bytes()}
            )
        elif attack == "symlink":
            target = run / "baseline-input.json"
            outside = tmp_path / f"outside-{label}.json"
            outside.write_bytes(target.read_bytes())
            target.unlink()
            target.symlink_to(outside)
        elif attack == "fifo":
            target = run / "baseline-input.json"
            target.unlink()
            os.mkfifo(target)
        else:
            os.link(run / "baseline-input.json", tmp_path / f"alias-{label}.json")
    full = _run_baseline_surface(SKILL_RUNNER, "eval-baseline-verify", "--run", str(full_run))
    portable = _run_baseline_surface(
        PORTABLE_RUNNER, "eval-baseline-verify", "--run", str(portable_run)
    )
    assert (portable.returncode, portable.stdout, portable.stderr) == (
        full.returncode, full.stdout, full.stderr
    )
    assert full.returncode == 5


def test_baseline_parity_concurrent_status_and_verify_are_read_only(tmp_path: Path) -> None:
    """Concurrent readers observe only one exact immutable terminal root."""
    _, full_run, portable_run = _complete_baseline_parity_pair(tmp_path, suffix="concurrent")
    before_full = _run_snapshot(full_run)
    before_portable = _run_snapshot(portable_run)
    commands = ("eval-baseline-status", "eval-baseline-verify") * 4
    with ThreadPoolExecutor(max_workers=8) as executor:
        full_futures = [
            executor.submit(_run_baseline_surface, SKILL_RUNNER, command, "--run", str(full_run))
            for command in commands
        ]
        portable_futures = [
            executor.submit(
                _run_baseline_surface, PORTABLE_RUNNER, command, "--run", str(portable_run)
            )
            for command in commands
        ]
    for full_future, portable_future in zip(full_futures, portable_futures, strict=True):
        full = full_future.result()
        portable = portable_future.result()
        assert (portable.returncode, portable.stdout, portable.stderr) == (
            full.returncode, full.stdout, full.stderr
        )
    assert _run_snapshot(full_run) == before_full
    assert _run_snapshot(portable_run) == before_portable


@pytest.mark.parametrize("failure", ("rollback", "root-replacement"))
def test_baseline_parity_transition_failure_preserves_owned_trees(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    """Injected failures roll back owned bytes and never advance a replacement root."""
    if failure == "root-replacement" and os.name != "posix":
        pytest.skip("POSIX root identity proof")
    control = _baseline_cli_control(tmp_path)
    full_run = tmp_path / f"full-{failure}"
    portable_run = tmp_path / f"portable-{failure}"
    common = ("--input", str(control), "--nonce-hex", "9" * 64)
    _assert_baseline_surface_parity(
        ("eval-baseline-init", *common, "--run", str(full_run)),
        ("eval-baseline-init", *common, "--run", str(portable_run)),
    )
    payload = {
        "proposals": [
            {
                "statement": "A covered operator must file notice.",
                "kind": "obligation",
                "importance": "critical",
                "importance_basis": ["legal_bottom_line"],
                "importance_rationale": "Omission could change the legal bottom line.",
                "passages": [{"source_id": "source-1", "quote": "presentará aviso"}],
                "dependency": None,
                "confidence": "clear",
                "substantive_rationale": "The fictional rule uses mandatory language.",
            }
        ],
        "review_complete": True,
    }
    from regulatory_harvest.evaluation import attorney_artifacts as full_storage
    from regulatory_harvest.evaluation.attorney_baseline_workflow import (
        guarded_submit_baseline_response_v1,
    )

    portable_spec = importlib.util.spec_from_file_location(
        f"attorney_eval_portable_{failure}", ROOT / "scripts" / "attorney_eval_portable.py"
    )
    assert portable_spec is not None and portable_spec.loader is not None
    portable = importlib.util.module_from_spec(portable_spec)
    sys.modules[portable_spec.name] = portable
    portable_spec.loader.exec_module(portable)
    integrity_errors = (
        full_storage.EvaluationIntegrityError,
        portable.EvaluationIntegrityError,
    )

    def submit_full() -> object:
        return guarded_submit_baseline_response_v1(
            full_run, payload, provider_name="fictional-provider",
            model_name="fictional-model", judge_isolation="scripted_fixture",
        )

    def submit_portable() -> object:
        return portable.guarded_submit_baseline_response_v1(
            portable_run, payload, provider_name="fictional-provider",
            model_name="fictional-model", judge_isolation="scripted_fixture",
        )

    if failure == "rollback":
        for storage_type, run, submit in (
            (full_storage._PosixRunStorage, full_run, submit_full),
            (portable._PosixRunStorage, portable_run, submit_portable),
        ):
            before = _run_snapshot(run)
            original = storage_type.atomic_write
            failed = False

            def fail_after_owned_writes(
                storage: object, path: str, data: bytes, *, mutable: bool,
                _original: object = original,
            ) -> bool:
                nonlocal failed
                created = _original(storage, path, data, mutable=mutable)  # type: ignore[operator]
                if path == "baseline-manifest.json" and mutable and not failed:
                    failed = True
                    raise OSError("injected baseline write failure")
                return created

            monkeypatch.setattr(storage_type, "atomic_write", fail_after_owned_writes)
            with pytest.raises(integrity_errors):
                submit()
            monkeypatch.setattr(storage_type, "atomic_write", original)
            assert failed
            assert _run_snapshot(run) == before
        return

    parked_snapshots: dict[str, dict[str, bytes]] = {}
    for label, run, submit in (
        ("full", full_run, submit_full),
        ("portable", portable_run, submit_portable),
    ):
        before = _run_snapshot(run)
        parked = tmp_path / f"parked-{label}"
        replacement = tmp_path / f"replacement-{label}"
        replacement.mkdir()
        (replacement / "outside.txt").write_bytes(b"outside\n")
        original_link = os.link
        swapped = False

        def replace_root(
            source: object, destination: object, *, src_dir_fd: int | None = None,
            dst_dir_fd: int | None = None, follow_symlinks: bool = True,
            _run: Path = run, _parked: Path = parked,
            _replacement: Path = replacement, _original_link: object = original_link,
        ) -> None:
            nonlocal swapped
            if not swapped and destination == "source-audit-0001.json":
                _run.rename(_parked)
                _replacement.rename(_run)
                swapped = True
            _original_link(
                source, destination, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd,
                follow_symlinks=follow_symlinks,
            )  # type: ignore[operator]

        monkeypatch.setattr(os, "link", replace_root)
        with pytest.raises(integrity_errors):
            submit()
        monkeypatch.setattr(os, "link", original_link)
        assert swapped
        assert (run / "outside.txt").read_bytes() == b"outside\n"
        assert _run_snapshot(run) == {"outside.txt": b"outside\n"}
        parked_snapshots[label] = _run_snapshot(parked)
        assert set(before).issubset(parked_snapshots[label])
    assert parked_snapshots["portable"] == parked_snapshots["full"]


@pytest.mark.parametrize(
    "attack",
    (
        "tampered-resealed",
        "omitted-prefix",
        "reordered",
        "disconnected-prefix",
        "truncated-prefix",
    ),
)
def test_baseline_review_fix_multihop_proof_attacks_match_full(
    tmp_path: Path, attack: str
) -> None:
    """Deleting oldest-to-newest replay makes a two-hop proof attack pass portably."""
    control, full_zero, portable_zero = _complete_baseline_parity_pair(
        tmp_path, suffix=f"proof-zero-{attack}"
    )
    full_one, portable_one = _correct_baseline_parity_pair(
        tmp_path,
        control,
        full_zero,
        portable_zero,
        suffix=f"proof-one-{attack}",
        correction_id="CORR-0001",
    )
    full_two, portable_two = _correct_baseline_parity_pair(
        tmp_path,
        control,
        full_one,
        portable_one,
        full_ancestry=(full_zero,),
        portable_ancestry=(portable_zero,),
        suffix=f"proof-two-{attack}",
        correction_id="CORR-0002",
    )
    full_attack = tmp_path / f"full-proof-attack-{attack}"
    portable_attack = tmp_path / f"portable-proof-attack-{attack}"
    shutil.copytree(full_two, full_attack)
    shutil.copytree(portable_two, portable_attack)
    _rewrite_baseline_proof_attack(full_attack, attack)
    _rewrite_baseline_proof_attack(portable_attack, attack)
    full = _run_baseline_surface(
        SKILL_RUNNER, "eval-baseline-verify", "--run", str(full_attack)
    )
    portable = _run_baseline_surface(
        PORTABLE_RUNNER, "eval-baseline-verify", "--run", str(portable_attack)
    )
    assert (portable.returncode, portable.stdout, portable.stderr) == (
        full.returncode, full.stdout, full.stderr
    )
    assert full.returncode == 5


@pytest.mark.parametrize(
    "mutation",
    ("source-extra", "authority-extra", "source-type", "client-facts-type"),
)
def test_baseline_review_fix_nested_input_is_as_strict_as_full(
    tmp_path: Path, mutation: str
) -> None:
    """Removing nested input checks makes malformed legal identity portable-only valid."""
    control = _baseline_cli_control(tmp_path)
    portable_run = tmp_path / f"portable-input-{mutation}"
    initialized = _run_baseline_surface(
        PORTABLE_RUNNER,
        "eval-baseline-init", "--input", str(control), "--run", str(portable_run),
        "--nonce-hex", "6" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    raw = json.loads((portable_run / "baseline-input.json").read_bytes())
    if mutation == "source-extra":
        raw["sources"][0]["unknown_nested_key"] = True
    elif mutation == "authority-extra":
        raw["requested_authorities"][0]["unknown_nested_key"] = True
    elif mutation == "source-type":
        raw["sources"][0]["normalized_text"] = 7
    else:
        raw["client_facts"] = 7
    portable_spec = importlib.util.spec_from_file_location(
        f"attorney_eval_portable_input_{mutation}",
        ROOT / "scripts" / "attorney_eval_portable.py",
    )
    assert portable_spec is not None and portable_spec.loader is not None
    portable = importlib.util.module_from_spec(portable_spec)
    sys.modules[portable_spec.name] = portable
    portable_spec.loader.exec_module(portable)
    raw["legal_input_fingerprint"] = hashlib.sha256(
        _canonical_bytes(portable._baseline_legal_projection(raw))
    ).hexdigest()

    from regulatory_harvest.evaluation.attorney_baseline_models import BaselineInputV1

    full_raw = json.loads(_canonical_bytes(raw))
    full_raw["evaluation_rubric_bytes"] = full_raw["evaluation_rubric_bytes"].encode()
    full_raw["importance_policy_bytes"] = full_raw["importance_policy_bytes"].encode()
    with pytest.raises(ValueError):
        BaselineInputV1.model_validate(full_raw)
    with pytest.raises((portable.EvaluationIntegrityError, portable.PortableEvaluationInputError)):
        portable._baseline_validate_input(raw)


@pytest.mark.parametrize("mutation", ("requirement-extra", "relationship-extra"))
def test_baseline_review_fix_nested_correction_is_as_strict_as_full(
    tmp_path: Path, mutation: str
) -> None:
    """Nested correction values must reject extras before any canonical baseline write."""
    requirement = {
        "requirement_id": "REQ-0002",
        "canonical_order": 1,
        "statement": "The notice must identify the operator.",
        "kind": "obligation",
        "importance": "material",
        "importance_basis": ["attorney_briefing"],
        "importance_rationale": "Necessary for a competent attorney briefing.",
        "passages": [
            {
                "source_id": "source-1", "quote": "presentará aviso",
                "start_char": 32, "end_char": 48,
            }
        ],
        "dependency": None,
        "confidence": "clear",
        "substantive_rationale": "The source supports the corrected requirement.",
    }
    relationship = {
        "relationship_id": "REL-0001",
        "relationship": "depends_on",
        "source_requirement_id": "REQ-0001",
        "target_requirement_id": "REQ-0002",
    }
    if mutation == "requirement-extra":
        requirement["unknown_nested_key"] = True
        action = {
            "action": "add_requirement", "requirement_id": None,
            "relationship_id": None, "requirement": requirement, "relationship": None,
        }
    else:
        relationship["unknown_nested_key"] = True
        action = {
            "action": "add_relationship", "requirement_id": None,
            "relationship_id": None, "requirement": None, "relationship": relationship,
        }
    payload = {
        "schema_version": "baseline-correction-v1",
        "prior_baseline_root": "a" * 64,
        "prior_baseline_fingerprint": "b" * 64,
        "correction_id": "CORR-0001",
        "actions": [action],
        "reason": "The attorney approved the exact source-bound correction.",
        "attorney_approval": {
            "approved_by": "Fictional Reviewing Attorney",
            "approved_at": "2026-08-24T20:00:00-07:00",
            "approval_statement": "I approve this exact source-bound correction.",
        },
        "correction_fingerprint": "0" * 64,
    }
    payload["correction_fingerprint"] = hashlib.sha256(
        _canonical_bytes(
            {key: value for key, value in payload.items() if key != "correction_fingerprint"}
        )
    ).hexdigest()
    path = tmp_path / f"nested-{mutation}.json"
    path.write_bytes(_canonical_bytes(payload))
    from regulatory_harvest.evaluation.attorney_baseline_models import (
        BaselineCorrectionRecordV1,
    )

    with pytest.raises(ValueError):
        BaselineCorrectionRecordV1.model_validate_json(path.read_bytes())
    portable_spec = importlib.util.spec_from_file_location(
        f"attorney_eval_portable_correction_{mutation}",
        ROOT / "scripts" / "attorney_eval_portable.py",
    )
    assert portable_spec is not None and portable_spec.loader is not None
    portable = importlib.util.module_from_spec(portable_spec)
    sys.modules[portable_spec.name] = portable
    portable_spec.loader.exec_module(portable)
    with pytest.raises(portable.BaselineInputError):
        portable._baseline_load_correction(path)


def test_baseline_review_fix_sealed_crash_boundary_matches_full(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crash after sealing resumes verification without repeating accepted work."""
    control = _baseline_cli_control(tmp_path)
    full_run = tmp_path / "sealed-full"
    portable_run = tmp_path / "sealed-portable"
    common = ("--input", str(control), "--nonce-hex", "7" * 64)
    _assert_baseline_surface_parity(
        ("eval-baseline-init", *common, "--run", str(full_run)),
        ("eval-baseline-init", *common, "--run", str(portable_run)),
    )
    review_payload = {
        "proposals": [
            {
                "statement": "A covered operator must file notice.",
                "kind": "obligation",
                "importance": "critical",
                "importance_basis": ["legal_bottom_line"],
                "importance_rationale": "Omission could change the legal bottom line.",
                "passages": [{"source_id": "source-1", "quote": "presentará aviso"}],
                "dependency": None,
                "confidence": "clear",
                "substantive_rationale": "The fictional rule uses mandatory language.",
            }
        ],
        "review_complete": True,
    }
    review_response = tmp_path / "sealed-review.json"
    review_response.write_bytes(_canonical_bytes(review_payload))
    flags = (
        "--response", str(review_response), "--provider-name", "fictional-provider",
        "--model-name", "fictional-model", "--judge-isolation", "scripted_fixture",
    )
    _assert_baseline_surface_parity(
        ("eval-baseline-submit-safe", "--run", str(full_run), *flags),
        ("eval-baseline-submit-safe", "--run", str(portable_run), *flags),
    )
    audit_payload = {
        "concerns": [],
        "importance_findings": [
            {
                "proposal_ref": "PR-0001",
                "reviewed_importance": "critical",
                "reviewed_importance_basis": ["legal_bottom_line"],
                "importance_rationale": "Omission could change the legal bottom line.",
                "disposition": "agree",
            }
        ],
        "audit_complete": True,
    }
    from regulatory_harvest.evaluation import attorney_baseline_artifacts as full_artifacts
    from regulatory_harvest.evaluation.attorney_baseline_workflow import (
        guarded_submit_baseline_response_v1 as full_submit,
    )

    portable_spec = importlib.util.spec_from_file_location(
        "attorney_eval_portable_sealed_crash",
        ROOT / "scripts" / "attorney_eval_portable.py",
    )
    assert portable_spec is not None and portable_spec.loader is not None
    portable = importlib.util.module_from_spec(portable_spec)
    sys.modules[portable_spec.name] = portable
    portable_spec.loader.exec_module(portable)

    original_full_commit = full_artifacts.commit_baseline_transition_v1

    def crash_after_full_seal(*args: object, **kwargs: object) -> object:
        successor = args[3]
        result = original_full_commit(*args, **kwargs)
        if successor.phase.value == "baseline_sealed":
            raise full_artifacts.EvaluationIntegrityError("injected crash after seal")
        return result

    monkeypatch.setattr(full_artifacts, "commit_baseline_transition_v1", crash_after_full_seal)
    with pytest.raises(full_artifacts.EvaluationIntegrityError):
        full_submit(
            full_run, audit_payload, provider_name="fictional-provider",
            model_name="fictional-model", judge_isolation="scripted_fixture",
        )
    monkeypatch.setattr(
        full_artifacts, "commit_baseline_transition_v1", original_full_commit
    )

    original_portable_commit = portable._baseline_commit

    def crash_after_portable_seal(*args: object, **kwargs: object) -> object:
        successor = original_portable_commit(*args, **kwargs)
        if successor["phase"] == "baseline_sealed":
            raise portable.EvaluationIntegrityError("injected crash after seal")
        return successor

    monkeypatch.setattr(portable, "_baseline_commit", crash_after_portable_seal)
    with pytest.raises(portable.EvaluationIntegrityError):
        portable.guarded_submit_baseline_response_v1(
            portable_run, audit_payload, provider_name="fictional-provider",
            model_name="fictional-model", judge_isolation="scripted_fixture",
        )
    monkeypatch.setattr(portable, "_baseline_commit", original_portable_commit)

    assert json.loads((full_run / "baseline-manifest.json").read_bytes())["phase"] == (
        "baseline_sealed"
    )
    assert _run_snapshot(portable_run) == _run_snapshot(full_run)
    _assert_baseline_surface_parity(
        ("eval-baseline-status", "--run", str(full_run)),
        ("eval-baseline-status", "--run", str(portable_run)),
    )
    _assert_baseline_surface_parity(
        ("eval-baseline-verify", "--run", str(full_run)),
        ("eval-baseline-verify", "--run", str(portable_run)),
    )
    _assert_baseline_surface_parity(
        ("eval-baseline-next", "--run", str(full_run)),
        ("eval-baseline-next", "--run", str(portable_run)),
    )
    manifest = json.loads((portable_run / "baseline-manifest.json").read_bytes())
    assert manifest["phase"] == "completed"
    assert len(manifest["accepted_calls"]) == 2
    assert _run_snapshot(portable_run) == _run_snapshot(full_run)


@pytest.mark.parametrize("failure_type", (RuntimeError, OSError, ValueError))
def test_baseline_review_fix_provider_exception_taxonomy_matches_full(
    tmp_path: Path, failure_type: type[Exception]
) -> None:
    """Ordinary provider exceptions pause without mutating the pending request."""
    control = _baseline_cli_control(tmp_path)
    full_run = tmp_path / f"provider-full-{failure_type.__name__}"
    portable_run = tmp_path / f"provider-portable-{failure_type.__name__}"
    common = ("--input", str(control), "--nonce-hex", "5" * 64)
    _assert_baseline_surface_parity(
        ("eval-baseline-init", *common, "--run", str(full_run)),
        ("eval-baseline-init", *common, "--run", str(portable_run)),
    )
    before_full = _run_snapshot(full_run)
    before_portable = _run_snapshot(portable_run)

    class FailingEvaluator:
        provider_name = "fictional-provider"
        model_name = "fictional-model"
        judge_isolation = "scripted_fixture"

        async def evaluate_draft(self, prompt: object) -> object:
            del prompt
            raise failure_type("private provider detail")

    from regulatory_harvest.evaluation.attorney_baseline_workflow import (
        continue_baseline_v1 as full_continue,
    )

    portable_spec = importlib.util.spec_from_file_location(
        f"attorney_eval_portable_provider_{failure_type.__name__}",
        ROOT / "scripts" / "attorney_eval_portable.py",
    )
    assert portable_spec is not None and portable_spec.loader is not None
    portable = importlib.util.module_from_spec(portable_spec)
    sys.modules[portable_spec.name] = portable
    portable_spec.loader.exec_module(portable)
    full = asyncio.run(full_continue(full_run, FailingEvaluator(), max_roles=1))
    observed = asyncio.run(
        portable.continue_baseline_v1(portable_run, FailingEvaluator(), max_roles=1)
    )
    assert (
        observed.exit_code,
        observed.engine_paused,
        observed.pause_reason_codes,
        observed.state,
        observed.pending_request,
    ) == (
        full.exit_code,
        full.engine_paused,
        full.pause_reason_codes,
        full.state.model_dump(mode="json"),
        None if full.pending_request is None else full.pending_request.model_dump(mode="json"),
    )
    assert _run_snapshot(full_run) == before_full
    assert _run_snapshot(portable_run) == before_portable


def test_baseline_review_fix_concurrent_submit_matches_full(tmp_path: Path) -> None:
    """Concurrent duplicate drafts accept once and safely refuse every stale duplicate."""
    control = _baseline_cli_control(tmp_path)
    full_run = tmp_path / "submit-full"
    portable_run = tmp_path / "submit-portable"
    common = ("--input", str(control), "--nonce-hex", "4" * 64)
    _assert_baseline_surface_parity(
        ("eval-baseline-init", *common, "--run", str(full_run)),
        ("eval-baseline-init", *common, "--run", str(portable_run)),
    )
    payload = {
        "proposals": [
            {
                "statement": "A covered operator must file notice.",
                "kind": "obligation",
                "importance": "critical",
                "importance_basis": ["legal_bottom_line"],
                "importance_rationale": "Omission could change the legal bottom line.",
                "passages": [{"source_id": "source-1", "quote": "presentará aviso"}],
                "dependency": None,
                "confidence": "clear",
                "substantive_rationale": "The fictional rule uses mandatory language.",
            }
        ],
        "review_complete": True,
    }
    from regulatory_harvest.evaluation.attorney_baseline_workflow import (
        guarded_submit_baseline_response_v1 as full_submit,
    )

    portable_spec = importlib.util.spec_from_file_location(
        "attorney_eval_portable_concurrent_submit",
        ROOT / "scripts" / "attorney_eval_portable.py",
    )
    assert portable_spec is not None and portable_spec.loader is not None
    portable = importlib.util.module_from_spec(portable_spec)
    sys.modules[portable_spec.name] = portable
    portable_spec.loader.exec_module(portable)

    def batch(submit: object, run: Path) -> list[tuple[bool, tuple[str, ...]]]:
        barrier = threading.Barrier(8)

        def one() -> tuple[bool, tuple[str, ...]]:
            barrier.wait()
            result = submit(  # type: ignore[operator]
                run, payload, provider_name="fictional-provider",
                model_name="fictional-model", judge_isolation="scripted_fixture",
            )
            if isinstance(result, dict):
                return bool(result["accepted"]), tuple(result["diagnostics"])
            return result.accepted, tuple(result.issue_codes)

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(one) for _ in range(8)]
            return sorted(future.result() for future in futures)

    assert batch(portable.guarded_submit_baseline_response_v1, portable_run) == batch(
        full_submit, full_run
    )
    assert _run_snapshot(portable_run) == _run_snapshot(full_run)


@pytest.mark.parametrize(
    "mutation",
    (
        "requirement-identity",
        "relationship-inventory",
        "contested-inventory",
        "provenance-binding",
        "baseline-fingerprint",
    ),
)
def test_baseline_review_fix_projection_semantic_mutations_match_full(
    tmp_path: Path, mutation: str
) -> None:
    """Every gradeable semantic identity remains downstream of verified run replay."""
    _, full_run, portable_run = _complete_baseline_parity_pair(
        tmp_path, suffix=f"projection-{mutation}"
    )
    for run in (full_run, portable_run):
        baseline = json.loads((run / "canonical-baseline.json").read_bytes())
        if mutation == "requirement-identity":
            baseline["requirements"][0]["statement"] += " Tampered."
        elif mutation == "relationship-inventory":
            baseline["relationships"] = [
                {
                    "relationship_id": "REL-0001",
                    "relationship": "depends_on",
                    "source_requirement_id": "REQ-0001",
                    "target_requirement_id": "REQ-0001",
                }
            ]
        elif mutation == "contested-inventory":
            baseline["contested_requirements"] = [
                {
                    "contested_requirement_id": "CONT-0001",
                    "reviewer_alternative": None,
                    "auditor_alternative": None,
                    "unresolved_reason": "SOURCE_GAP",
                    "importance": "critical",
                    "importance_basis": ["legal_bottom_line"],
                    "importance_rationale": "Omission could change the legal bottom line.",
                    "substantive_rationale": "The source remains unresolved.",
                    "referee_fragment_fingerprint": "a" * 64,
                }
            ]
        elif mutation == "provenance-binding":
            baseline["provenance"]["legal_input_fingerprint"] = "b" * 64
        else:
            baseline["baseline_fingerprint"] = "c" * 64
        if mutation != "baseline-fingerprint":
            baseline["baseline_fingerprint"] = hashlib.sha256(
                _canonical_bytes(
                    {key: value for key, value in baseline.items() if key != "baseline_fingerprint"}
                )
            ).hexdigest()
        _reseal_baseline_parity_run(
            run,
            {"canonical-baseline.json": _canonical_bytes(baseline)},
            manifest_updates={"baseline_fingerprint": baseline["baseline_fingerprint"]},
        )
    _assert_baseline_surface_parity(
        ("eval-baseline-verify", "--run", str(full_run)),
        ("eval-baseline-verify", "--run", str(portable_run)),
    )
    full = _run_baseline_surface(
        SKILL_RUNNER, "eval-baseline-verify", "--run", str(full_run)
    )
    assert full.returncode == 5


def test_baseline_review_fix_report_only_revision_reuses_grade_target(tmp_path: Path) -> None:
    """Distinct report bytes have no field in the verified grade-target projection."""
    _, full_run, portable_run = _complete_baseline_parity_pair(
        tmp_path, suffix="report-only-grade-target"
    )
    report_a = b"First report revision."
    report_b = b"Materially different second report revision."
    assert report_a != report_b
    portable_spec = importlib.util.spec_from_file_location(
        "attorney_eval_portable_report_only_projection",
        ROOT / "scripts" / "attorney_eval_portable.py",
    )
    assert portable_spec is not None and portable_spec.loader is not None
    portable = importlib.util.module_from_spec(portable_spec)
    sys.modules[portable_spec.name] = portable
    portable_spec.loader.exec_module(portable)
    projection_a = portable._baseline_gradeable_projection_bytes_for_test(
        _run_snapshot(portable_run)
    )
    projection_b = portable._baseline_gradeable_projection_bytes_for_test(
        _run_snapshot(portable_run)
    )
    assert projection_a == projection_b
    assert report_a not in projection_a and report_b not in projection_b

    from regulatory_harvest.evaluation.attorney_baseline_projection import (
        project_gradeable_baseline_v1,
    )

    full_projection = project_gradeable_baseline_v1(load_verified_baseline_run(full_run))
    portable_projection = json.loads(projection_a)
    assert portable_projection["binding"] == full_projection.binding.model_dump(mode="json")


@pytest.mark.parametrize("mutation", ("one-byte", "unknown-extra-key"))
def test_baseline_parity_public_policy_mutation_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    """Public verification refuses a fully rehashed non-packaged policy identically."""
    control = _baseline_cli_control(tmp_path)
    full_run = tmp_path / f"policy-full-{mutation}"
    portable_run = tmp_path / f"policy-portable-{mutation}"
    common = ("--input", str(control), "--nonce-hex", "3" * 64)
    _assert_baseline_surface_parity(
        ("eval-baseline-init", *common, "--run", str(full_run)),
        ("eval-baseline-init", *common, "--run", str(portable_run)),
    )
    full_attack = tmp_path / f"policy-full-attack-{mutation}"
    portable_attack = tmp_path / f"policy-portable-attack-{mutation}"
    shutil.copytree(full_run, full_attack)
    shutil.copytree(portable_run, portable_attack)

    portable_spec = importlib.util.spec_from_file_location(
        f"attorney_eval_portable_policy_verify_{mutation}",
        ROOT / "scripts" / "attorney_eval_portable.py",
    )
    assert portable_spec is not None and portable_spec.loader is not None
    portable = importlib.util.module_from_spec(portable_spec)
    sys.modules[portable_spec.name] = portable
    portable_spec.loader.exec_module(portable)
    packaged = (ROOT / "assets" / "evaluation-baseline-policy-v1.json").read_bytes()
    policy = json.loads(packaged)
    if mutation == "one-byte":
        policy["definitions"]["critical"] = policy["definitions"]["critical"].replace(
            "omission", "Omission", 1
        )
    else:
        policy["unknown_policy_key"] = True
    mutated_policy = _canonical_bytes(policy)
    if mutation == "one-byte":
        assert len(mutated_policy) == len(packaged)
        assert sum(left != right for left, right in zip(packaged, mutated_policy, strict=True)) == 1
    policy_fingerprint = hashlib.sha256(mutated_policy).hexdigest()
    portable_input: dict[str, object] | None = None
    for run in (full_attack, portable_attack):
        baseline_input = json.loads((run / "baseline-input.json").read_bytes())
        baseline_input["importance_policy_bytes"] = mutated_policy.decode()
        baseline_input["importance_policy_fingerprint"] = policy_fingerprint
        baseline_input["compiler_contract"] = portable._baseline_contract(policy_fingerprint)
        baseline_input["compiler_contract_fingerprint"] = hashlib.sha256(
            _canonical_bytes(baseline_input["compiler_contract"])
        ).hexdigest()
        baseline_input["legal_input_fingerprint"] = hashlib.sha256(
            _canonical_bytes(portable._baseline_legal_projection(baseline_input))
        ).hexdigest()
        _reseal_baseline_parity_run(
            run,
            {"baseline-input.json": _canonical_bytes(baseline_input)},
            manifest_updates={
                "legal_input_fingerprint": baseline_input["legal_input_fingerprint"]
            },
        )
        if run == portable_attack:
            portable_input = baseline_input

    full, observed = _assert_baseline_surface_parity(
        ("eval-baseline-verify", "--run", str(full_attack)),
        ("eval-baseline-verify", "--run", str(portable_attack)),
    )
    assert full.returncode == observed.returncode == 5
    assert portable_input is not None
    with pytest.raises(portable.EvaluationIntegrityError):
        portable._baseline_validate_input(portable_input)
    with monkeypatch.context() as scoped:
        scoped.setattr(
            portable,
            "_baseline_policy",
            lambda: (mutated_policy, policy, policy_fingerprint),
        )
        assert portable._baseline_validate_input(portable_input) == portable_input


@pytest.mark.parametrize(
    "field",
    (
        "evaluation_rubric_bytes",
        "evaluation_rubric_version",
        "evaluation_rubric_fingerprint",
        "importance_policy_bytes",
        "importance_policy_version",
        "importance_policy_fingerprint",
        "compiler_contract",
        "compiler_contract_fingerprint",
    ),
)
def test_baseline_parity_public_binding_type_mutation_verification(
    tmp_path: Path, field: str
) -> None:
    """Malformed binding types remain artifact-invalid before semantic comparison."""
    control = _baseline_cli_control(tmp_path)
    full_run = tmp_path / f"binding-type-full-{field}"
    portable_run = tmp_path / f"binding-type-portable-{field}"
    common = ("--input", str(control), "--nonce-hex", "2" * 64)
    _assert_baseline_surface_parity(
        ("eval-baseline-init", *common, "--run", str(full_run)),
        ("eval-baseline-init", *common, "--run", str(portable_run)),
    )
    for run in (full_run, portable_run):
        baseline_input = json.loads((run / "baseline-input.json").read_bytes())
        baseline_input[field] = 7
        _reseal_baseline_parity_run(
            run,
            {"baseline-input.json": _canonical_bytes(baseline_input)},
        )
    full, observed = _assert_baseline_surface_parity(
        ("eval-baseline-verify", "--run", str(full_run)),
        ("eval-baseline-verify", "--run", str(portable_run)),
    )
    assert full.returncode == observed.returncode == 5


def test_baseline_full_runner_exposes_exact_commands_safe_status_and_exit_mapping(
    tmp_path: Path,
) -> None:
    """The additive baseline family stays separate from retained legal dispositions."""
    parser = skill_runner._full_evaluation_runner()._parser()
    subparser_action = next(
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )
    assert set(subparser_action.choices) >= {
        "eval-baseline-init",
        "eval-baseline-next",
        "eval-baseline-submit-safe",
        "eval-baseline-status",
        "eval-baseline-verify",
    }
    retained = parser.parse_args(
        ["eval-init", "--case", "case.json", "--run", "run", "--seed-hex", "0" * 64]
    )
    assert retained.protocol == "2.1"

    run = tmp_path / "baseline"
    initialized = _run_runner(
        SKILL_RUNNER,
        "eval-baseline-init",
        "--input",
        str(_baseline_cli_control(tmp_path)),
        "--run",
        str(run),
        "--nonce-hex",
        "2" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    first = _run_runner(SKILL_RUNNER, "eval-baseline-next", "--run", str(run))
    second = _run_runner(SKILL_RUNNER, "eval-baseline-next", "--run", str(run))
    assert first.returncode == second.returncode == 0
    assert first.stdout == second.stdout
    request = json.loads(first.stdout)
    assert request["operation"] == "baseline_source_review"

    malformed = tmp_path / "malformed-baseline-response.json"
    malformed.write_bytes(_canonical_bytes({"private_path": str(tmp_path), "source": "secret"}))
    before = _run_snapshot(run)
    refused = _run_runner(
        SKILL_RUNNER,
        "eval-baseline-submit-safe",
        "--run",
        str(run),
        "--response",
        str(malformed),
        "--provider-name",
        "fictional-provider",
        "--model-name",
        "fictional-model",
        "--judge-isolation",
        "scripted_fixture",
    )
    assert refused.returncode == 2
    assert json.loads(refused.stderr)["code"] == "BASELINE_EXTERNAL_RESPONSE_INVALID"
    assert str(tmp_path) not in refused.stderr
    assert "secret" not in refused.stderr
    assert _run_snapshot(run) == before

    review = tmp_path / "review.json"
    review.write_bytes(
        _canonical_bytes(
            {
                "proposals": [
                    {
                        "statement": "A covered operator must file notice.",
                        "kind": "obligation",
                        "importance": "critical",
                        "importance_basis": ["legal_bottom_line"],
                        "importance_rationale": (
                            "Omission could change the legal bottom line."
                        ),
                        "passages": [
                            {"source_id": "source-1", "quote": "presentará aviso"}
                        ],
                        "dependency": None,
                        "confidence": "clear",
                        "substantive_rationale": "The fictional rule uses mandatory language.",
                    }
                ],
                "review_complete": True,
            }
        )
    )
    accepted = _run_runner(
        SKILL_RUNNER,
        "eval-baseline-submit-safe",
        "--run",
        str(run),
        "--response",
        str(review),
        "--provider-name",
        "fictional-provider",
        "--model-name",
        "fictional-model",
        "--judge-isolation",
        "scripted_fixture",
    )
    assert accepted.returncode == 0, accepted.stderr
    audit_request = json.loads(
        _run_runner(SKILL_RUNNER, "eval-baseline-next", "--run", str(run)).stdout
    )
    assert audit_request["operation"] == "baseline_source_audit"
    audit = tmp_path / "audit.json"
    audit.write_bytes(
        _canonical_bytes(
            {
                "concerns": [],
                "importance_findings": [
                    {
                        "proposal_ref": "PR-0001",
                        "reviewed_importance": "critical",
                        "reviewed_importance_basis": ["legal_bottom_line"],
                        "importance_rationale": (
                            "Omission could change the legal bottom line."
                        ),
                        "disposition": "agree",
                    }
                ],
                "audit_complete": True,
            }
        )
    )
    completed = _run_runner(
        SKILL_RUNNER,
        "eval-baseline-submit-safe",
        "--run",
        str(run),
        "--response",
        str(audit),
        "--provider-name",
        "fictional-provider",
        "--model-name",
        "fictional-model",
        "--judge-isolation",
        "scripted_fixture",
    )
    assert completed.returncode == 0, completed.stderr

    status = _run_runner(SKILL_RUNNER, "eval-baseline-status", "--run", str(run))
    verified = _run_runner(SKILL_RUNNER, "eval-baseline-verify", "--run", str(run))
    assert status.returncode == verified.returncode == 0
    status_payload = json.loads(status.stdout)
    assert set(status_payload) == {
        "baseline_fingerprint",
        "engine_paused",
        "legal_input_fingerprint",
        "manifest_fingerprint",
        "pending_operation",
        "phase",
        "protocol_version",
        "request_fingerprint",
        "root_hash",
    }
    assert status_payload["phase"] == "completed"
    assert status_payload["pending_operation"] is None
    assert status_payload["request_fingerprint"] is None
    assert status_payload["engine_paused"] is False
    assert "PASS" not in status.stdout
    assert str(tmp_path) not in status.stdout + verified.stdout
    assert "presentará aviso" not in status.stdout + verified.stdout
    assert json.loads(verified.stdout) == {
        "issues": [],
        "ok": True,
        "protocol_version": "evaluation-baseline-v1",
    }

    prior = load_verified_baseline_run(run)
    existing_requirement = prior.baseline.requirements[0]
    replacement = existing_requirement.model_copy(
        update={"statement": "The covered operator must file a notice."}
    )
    correction_payload: dict[str, object] = {
        "schema_version": "baseline-correction-v1",
        "prior_baseline_root": prior.manifest.root_hash,
        "prior_baseline_fingerprint": prior.baseline.baseline_fingerprint,
        "correction_id": "CORR-0001",
        "actions": [
            {
                "action": "replace_requirement",
                "requirement_id": existing_requirement.requirement_id,
                "requirement": replacement.model_dump(mode="json"),
            }
        ],
        "reason": "The attorney approved a source-bound wording correction.",
        "attorney_approval": {
            "approved_by": "Fictional Reviewing Attorney",
            "approved_at": "2026-08-24T20:00:00-07:00",
            "approval_statement": "I approve this source-bound baseline correction.",
        },
        "correction_fingerprint": "0" * 64,
    }
    provisional = BaselineCorrectionRecordV1.model_validate(correction_payload)
    correction_payload["correction_fingerprint"] = hashlib.sha256(
        _canonical_bytes(
            provisional.model_dump(
                mode="json", exclude={"correction_fingerprint"}
            )
        )
    ).hexdigest()
    correction = tmp_path / "baseline-correction.json"
    correction.write_bytes(_canonical_bytes(correction_payload))
    corrected_run = tmp_path / "baseline-corrected"
    corrected_init = _run_runner(
        SKILL_RUNNER,
        "eval-baseline-init",
        "--input",
        str(tmp_path / "baseline-control.json"),
        "--run",
        str(corrected_run),
        "--nonce-hex",
        "3" * 64,
        "--prior-baseline",
        str(run),
        "--correction",
        str(correction),
    )
    assert corrected_init.returncode == 0, corrected_init.stderr

    corrected_next = _run_runner(
        SKILL_RUNNER, "eval-baseline-next", "--run", str(corrected_run)
    )
    corrected_status = _run_runner(
        SKILL_RUNNER, "eval-baseline-status", "--run", str(corrected_run)
    )
    corrected_verify = _run_runner(
        SKILL_RUNNER, "eval-baseline-verify", "--run", str(corrected_run)
    )
    assert (
        corrected_next.returncode
        == corrected_status.returncode
        == corrected_verify.returncode
        == 0
    )
    assert json.loads(corrected_next.stdout) is None
    corrected_status_payload = json.loads(corrected_status.stdout)
    assert set(corrected_status_payload) == set(status_payload)
    assert corrected_status_payload["phase"] == "completed"
    assert corrected_status_payload["pending_operation"] is None
    assert json.loads(corrected_verify.stdout) == {
        "issues": [],
        "ok": True,
        "protocol_version": "evaluation-baseline-v1",
    }
    safe_output = (
        corrected_init.stdout
        + corrected_next.stdout
        + corrected_status.stdout
        + corrected_verify.stdout
    )
    assert str(tmp_path) not in safe_output
    assert "presentará aviso" not in safe_output


def test_controller_stops_on_integrity_failure_without_consuming_response(
    tmp_path: Path,
) -> None:
    """An integrity failure is never a mechanical-repair opportunity."""
    run = tmp_path / "integrity-stop"
    initialized = _run_runner(
        SKILL_RUNNER,
        "eval-init",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(run),
        "--seed-hex",
        "b" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    envelope = run / "inputs" / "case.json"
    envelope.write_bytes(envelope.read_bytes() + b"\n")
    after_tamper = _run_snapshot(run)

    stopped = _run_runner(SKILL_RUNNER, "eval-status", "--run", str(run.resolve()))
    assert stopped.returncode == 5
    assert _run_snapshot(run) == after_tamper


def test_controller_stops_when_fresh_repair_executor_is_unavailable(
    tmp_path: Path,
) -> None:
    """A retained run has no full-CLI repair or submission escape hatch."""
    run = tmp_path / "fresh-repair-unavailable"
    _initialize_eval_run(SKILL_RUNNER, run)
    response = tmp_path / "refused-initial-response.json"
    response.write_bytes(b"{}")
    before = _run_snapshot(run)

    for command in ("eval-next", "eval-preflight", "eval-submit", "eval-submit-safe"):
        args = [command, "--run", str(run.resolve())]
        if command != "eval-next":
            args.extend(("--response", str(response)))
        refused = _run_runner(SKILL_RUNNER, *args)
        assert refused.returncode == 2
        assert json.loads(refused.stderr)["code"] == "EVALUATION_LEGACY_READ_ONLY"

    assert _run_snapshot(run) == before


def test_protocol_21_stop_is_terminal_and_verifiable(
    tmp_path: Path,
) -> None:
    """A pending v2.1 request may stop only through the bounded generic reason."""
    run = tmp_path / "stopped-v21-evaluation"
    initialized = _run_runner(
        SKILL_RUNNER,
        "eval-init",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(run),
        "--seed-hex",
        "c" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    stopped = _run_runner(
        SKILL_RUNNER,
        "eval-stop-inconclusive",
        "--run",
        str(run),
        "--reason",
        "MECHANICAL_RESPONSE_INVALID",
    )
    assert stopped.returncode == 3
    assert json.loads(stopped.stdout)["terminal_status"] == "INCONCLUSIVE_MECHANICAL"
    verified = _run_runner(SKILL_RUNNER, "eval-verify", "--run", str(run))
    assert verified.returncode == 3
    assert json.loads(verified.stdout)["ok"] is True


@pytest.mark.parametrize(
    "exact_bytes",
    [
        b"  Exact retained content  ",
        b"Exact retained content\n",
        b"Exact retained content\r\n",
        b"\xef\xbb\xbfExact retained content",
    ],
)
def test_eval_init_preserves_exact_utf8_bytes_with_full_portable_parity(
    exact_bytes: bytes,
    tmp_path: Path,
) -> None:
    """Text-mode reads or trimming would collapse byte-distinct evaluation evidence."""
    fixture = tmp_path / "fixture"
    case_path = _write_exact_evaluation_fixture(
        fixture,
        source_bytes=exact_bytes,
        report_a_bytes=exact_bytes,
        report_b_bytes=exact_bytes,
        client_facts_bytes=exact_bytes,
    )
    runs = [tmp_path / "full", tmp_path / "portable"]

    for runner, run in zip((SKILL_RUNNER, PORTABLE_RUNNER), runs, strict=True):
        _initialize_eval_run(runner, run, case_path=case_path)

    assert (runs[0] / "case-envelope.json").read_bytes() == (
        runs[1] / "case-envelope.json"
    ).read_bytes()
    envelope = json.loads((runs[0] / "case-envelope.json").read_bytes())
    exact_text = exact_bytes.decode("utf-8")
    expected_hash = hashlib.sha256(exact_bytes).hexdigest()
    assert envelope["case"]["sources"][0]["normalized_text"] == exact_text
    assert envelope["case"]["sources"][0]["content_hash"] == expected_hash
    assert {item["report_text"] for item in envelope["case"]["candidates"]} == {
        exact_text
    }
    assert {item["report_hash"] for item in envelope["case"]["candidates"]} == {
        expected_hash
    }
    assert envelope["case"]["client_facts"] == exact_text


@pytest.mark.parametrize("client_facts_bytes", [b"The operator is covered.", None])
def test_eval_init_accepts_one_strict_case_with_full_portable_parity(
    client_facts_bytes: bytes | None,
    tmp_path: Path,
) -> None:
    """Strict typing must preserve valid string and nullable-path cases exactly."""
    case_path = _write_exact_evaluation_fixture(
        tmp_path / "fixture", client_facts_bytes=client_facts_bytes
    )
    runs = [tmp_path / "full", tmp_path / "portable"]

    for runner, run in zip((SKILL_RUNNER, PORTABLE_RUNNER), runs, strict=True):
        _initialize_eval_run(runner, run, case_path=case_path)

    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        pytest.param(("case_id",), True, id="top-case-id-bool"),
        pytest.param(("mode",), None, id="top-mode-null"),
        pytest.param(("question",), None, id="top-question-null"),
        pytest.param(("jurisdiction",), False, id="top-jurisdiction-bool"),
        pytest.param(("as_of",), 20260812, id="top-date-int"),
        pytest.param(("client_facts_path",), False, id="top-path-bool"),
        pytest.param(("requested_authorities",), None, id="authorities-container-null"),
        pytest.param(
            ("requested_authorities", 0, "authority_id"),
            True,
            id="authority-id-bool",
        ),
        pytest.param(
            ("requested_authorities", 0, "title"),
            None,
            id="authority-title-null",
        ),
        pytest.param(
            ("requested_authorities", 0, "jurisdiction"),
            False,
            id="authority-jurisdiction-bool",
        ),
        pytest.param(
            ("requested_authorities", 0, "authority_type"),
            1,
            id="authority-type-int",
        ),
        pytest.param(
            ("requested_authorities", 0, "source_ids"),
            False,
            id="authority-source-ids-bool",
        ),
        pytest.param(
            ("requested_authorities", 0, "source_ids", 0),
            None,
            id="authority-source-id-null",
        ),
        pytest.param(("sources",), False, id="sources-container-bool"),
        pytest.param(("sources", 0, "source_id"), True, id="source-id-bool"),
        pytest.param(("sources", 0, "title"), None, id="source-title-null"),
        pytest.param(("sources", 0, "path"), False, id="source-path-bool"),
        pytest.param(
            ("sources", 0, "jurisdiction"), 1, id="source-jurisdiction-int"
        ),
        pytest.param(
            ("sources", 0, "authority_type"), True, id="source-authority-type-bool"
        ),
        pytest.param(("sources", 0, "source_role"), None, id="source-role-null"),
        pytest.param(
            ("sources", 0, "source_quality"), False, id="source-quality-bool"
        ),
        pytest.param(
            ("sources", 0, "completeness"), 1, id="source-completeness-int"
        ),
        pytest.param(("sources", 0, "language"), True, id="source-language-bool"),
        pytest.param(("candidates",), {}, id="candidates-container-object"),
        pytest.param(
            ("candidates", 0, "generation_capsule_path"),
            False,
            id="candidate-capsule-path-bool",
        ),
        pytest.param(
            ("candidates", 0, "candidate_id"), True, id="candidate-id-bool"
        ),
        pytest.param(("candidates", 0, "role"), None, id="candidate-role-null"),
        pytest.param(
            ("candidates", 0, "external_report_path"),
            1,
            id="candidate-external-path-int",
        ),
    ],
)
def test_eval_init_rejects_non_string_case_values_with_full_portable_parity(
    path: tuple[str | int, ...],
    replacement: object,
    tmp_path: Path,
) -> None:
    """JSON scalars must not become legal metadata through full-runner coercion."""
    fixture = tmp_path / "fixture"
    case_path = _write_exact_evaluation_fixture(fixture)
    case = json.loads(case_path.read_bytes())
    _replace_nested_case_value(case, path, replacement)
    case_path.write_bytes(_canonical_bytes(case))

    return_codes = []
    for runner_name, runner in (("full", SKILL_RUNNER), ("portable", PORTABLE_RUNNER)):
        result = _run_runner(
            runner,
            "eval-init",
            "--case",
            str(case_path),
            "--run",
            str(tmp_path / f"{runner_name}-run"),
            "--seed-hex",
            "5" * 64,
        )
        return_codes.append(result.returncode)

    assert return_codes == [2, 2]


def test_eval_case_fingerprint_distinguishes_lf_crlf_and_final_newline(
    tmp_path: Path,
) -> None:
    """Changing only line-ending bytes must change both runners' case identity."""
    fingerprints: set[str] = set()
    for index, exact_bytes in enumerate((b"Rule", b"Rule\n", b"Rule\r\n")):
        fixture = tmp_path / f"fixture-{index}"
        case_path = _write_exact_evaluation_fixture(
            fixture,
            source_bytes=exact_bytes,
        )
        per_runner: list[str] = []
        for runner_name, runner in (("full", SKILL_RUNNER), ("portable", PORTABLE_RUNNER)):
            run = tmp_path / f"run-{index}-{runner_name}"
            _initialize_eval_run(runner, run, case_path=case_path)
            per_runner.append(
                json.loads((run / "case-envelope.json").read_bytes())["case_fingerprint"]
            )
        assert per_runner[0] == per_runner[1]
        fingerprints.add(per_runner[0])

    assert len(fingerprints) == 3


@pytest.mark.parametrize("changed_input", ["source", "report", "client-facts"])
def test_eval_case_fingerprint_binds_each_exact_content_input(
    changed_input: str,
    tmp_path: Path,
) -> None:
    """Changing only one content-bearing input must change the frozen case identity."""
    fingerprints: list[str] = []
    for variant in (b"Exact bytes", b"Exact bytes\n"):
        fixture = tmp_path / f"{changed_input}-{len(fingerprints)}"
        inputs = {
            "source_bytes": b"Source bytes",
            "report_a_bytes": b"Report A bytes",
            "report_b_bytes": b"Report B bytes",
            "client_facts_bytes": b"Client facts bytes",
        }
        if changed_input == "source":
            inputs["source_bytes"] = variant
        elif changed_input == "report":
            inputs["report_a_bytes"] = variant
        else:
            inputs["client_facts_bytes"] = variant
        case_path = _write_exact_evaluation_fixture(fixture, **inputs)
        run = tmp_path / f"{changed_input}-run-{len(fingerprints)}"
        _initialize_eval_run(SKILL_RUNNER, run, case_path=case_path)
        fingerprints.append(
            json.loads((run / "case-envelope.json").read_bytes())["case_fingerprint"]
        )

    assert fingerprints[0] != fingerprints[1]


def _submit_synthetic_admission(
    runner: Path,
    run: Path,
    response_path: Path,
) -> subprocess.CompletedProcess[str]:
    request = _next_packet(runner, run)
    response_path.write_text(
        _canonical_response(request, _admission_payload(request)),
        encoding="utf-8",
    )
    return _run_runner(
        runner,
        "eval-submit",
        "--run",
        str(run),
        "--response",
        str(response_path),
    )


def test_eval_init_uses_two_verified_generation_capsules(
    tmp_path: Path,
) -> None:
    """The protocol-2 loader admits two reports only after capsule verification."""
    case_path = _write_exact_evaluation_fixture(tmp_path / "fixture")
    run = tmp_path / "full-v2-run"
    initialized = _run_runner(
        SKILL_RUNNER,
        "eval-init",
        "--case",
        str(case_path),
        "--run",
        str(run),
        "--seed-hex",
        "a" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    state = json.loads(initialized.stdout)
    assert state["schema_version"] == "2.1"
    assert state["phase"] == "source_review"
    request = _next_packet(SKILL_RUNNER, run)
    assert request["operation"] == "source_review"


@pytest.mark.parametrize(
    "mutation",
    ["intermediate-source-symlink", "capsule-dir-symlink", "client-facts-leaf-symlink"],
)
def test_eval_init_rejects_symlinks_across_every_exact_input_boundary(
    mutation: str,
    tmp_path: Path,
) -> None:
    """Following a symlink would let an input change outside the retained fixture root."""
    fixture = tmp_path / "fixture"
    case_path = _write_exact_evaluation_fixture(fixture)
    try:
        if mutation == "intermediate-source-symlink":
            retained = fixture / "retained-sources"
            (fixture / "sources").replace(retained)
            (fixture / "sources").symlink_to(retained, target_is_directory=True)
        elif mutation == "capsule-dir-symlink":
            target = fixture / "capsules" / "retained-a"
            leaf = fixture / "capsules" / "report-a"
            leaf.replace(target)
            leaf.symlink_to(target, target_is_directory=True)
        else:
            target = fixture / "retained-client-facts.txt"
            leaf = fixture / "client-facts.txt"
            leaf.replace(target)
            leaf.symlink_to(target)
    except OSError as error:
        pytest.skip(f"fixture symlinks are unavailable: {error}")

    results = []
    for runner_name, runner in (("full", SKILL_RUNNER), ("portable", PORTABLE_RUNNER)):
        run = tmp_path / f"{runner_name}-run"
        result = _run_runner(
            runner,
            "eval-init",
            "--case",
            str(case_path),
            "--run",
            str(run),
            "--seed-hex",
            "e" * 64,
        )
        results.append(result)
        assert result.returncode == 2
        assert not run.exists()
    assert (results[0].returncode, results[0].stdout, results[0].stderr) == (
        results[1].returncode,
        results[1].stdout,
        results[1].stderr,
    )


def test_eval_init_detects_case_leaf_replacement_during_retained_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A same-name replacement during read must fail in both full and portable loaders."""
    from regulatory_harvest.evaluation import attorney_artifacts

    for runner_name in ("full", "portable"):
        fixture = tmp_path / f"{runner_name}-fixture"
        case_path = _write_exact_evaluation_fixture(fixture)
        replaced = False
        if runner_name == "full":
            original_read_all = attorney_artifacts._read_all

            def replace_then_read(
                descriptor: int,
                *,
                retained_case_path: Path = case_path,
                retained_fixture: Path = fixture,
                retained_reader=original_read_all,
            ) -> bytes:
                nonlocal replaced
                if not replaced:
                    replaced = True
                    retained_case_path.replace(retained_fixture / "case.replaced.json")
                    retained_case_path.write_bytes(b"{}")
                return retained_reader(descriptor)

            with monkeypatch.context() as context:
                context.setattr(attorney_artifacts, "_read_all", replace_then_read)
                status = skill_runner.main(
                    [
                        "eval-init",
                        "--case",
                        str(case_path),
                        "--run",
                        str(tmp_path / "full-run"),
                        "--seed-hex",
                        "f" * 64,
                    ]
                )
        else:
            substrate = portable_runner._evaluation_substrate()
            original_read_all = substrate._read_all

            def replace_then_read(
                descriptor: int,
                *,
                retained_case_path: Path = case_path,
                retained_fixture: Path = fixture,
                retained_reader=original_read_all,
            ) -> bytes:
                nonlocal replaced
                if not replaced:
                    replaced = True
                    retained_case_path.replace(retained_fixture / "case.replaced.json")
                    retained_case_path.write_bytes(b"{}")
                return retained_reader(descriptor)

            with monkeypatch.context() as context:
                context.setattr(substrate, "_read_all", replace_then_read)
                context.setattr(
                    portable_runner,
                    "_evaluation_substrate",
                    lambda retained_substrate=substrate: retained_substrate,
                )
                status = portable_runner.main(
                    [
                        "eval-init",
                        "--case",
                        str(case_path),
                        "--run",
                        str(tmp_path / "portable-run"),
                        "--seed-hex",
                        "f" * 64,
                    ]
                )
        assert status == 2
        assert replaced is True
        capsys.readouterr()


def _run_snapshot(run: Path) -> dict[str, bytes]:
    return {
        path.relative_to(run).as_posix(): path.read_bytes()
        for path in sorted(run.rglob("*"))
        if path.is_file()
    }


def test_stopped_shape_repair_contract_advances_full_and_portable(
    tmp_path: Path,
) -> None:
    """New public evaluation runs expose semantic v2 work, never a repair phase."""
    run = tmp_path / "full-v2-no-repair"
    initialized = _run_runner(
        SKILL_RUNNER,
        "eval-init",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(run),
        "--seed-hex",
        "d" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    request = _next_packet(SKILL_RUNNER, run)
    assert request["operation"] == "source_review"
    assert "repair" not in request["operation"]


@pytest.mark.parametrize(
    "corruption",
    [
        "duplicate_or_noncontiguous_walk_order",
        "unknown_relationship_target",
        "stale_split_relationship_target",
        "citation_offset_or_quote_mismatch",
        "missing_category_required_field",
        "generic_materiality_rationale",
        "wrong_remaining_audit_fingerprint",
    ],
)
def test_stopped_shape_repair_contract_refusal_is_write_free_and_matches_portable(
    corruption: str,
    tmp_path: Path,
) -> None:
    """A frozen 1.3 repair-era run refuses mutation and preserves its bytes."""
    run = tmp_path / f"legacy-stopped-shape-{corruption}"
    _initialize_eval_run(SKILL_RUNNER, run)
    response_path = tmp_path / f"stopped-shape-{corruption}.json"
    response_path.write_bytes(b"{}")
    before = _run_snapshot(run)
    refused = _run_runner(
        SKILL_RUNNER,
        "eval-submit-safe",
        "--run",
        str(run),
        "--response",
        str(response_path),
    )
    assert refused.returncode == 2
    assert json.loads(refused.stderr)["code"] == "EVALUATION_LEGACY_READ_ONLY"
    assert _run_snapshot(run) == before


def test_shipped_qualification_template_completes_full_and_portable_replay(
    tmp_path: Path,
) -> None:
    """The public template must reach ADMITTED on both installed runtime paths."""
    fixture_root = tmp_path / "template-fixture"
    sources_root = fixture_root / "sources"
    sources_root.mkdir(parents=True)
    template = json.loads(
        (ROOT / "assets" / "attorney-evaluation-qualification.template.json").read_bytes()
    )
    materialized = json.loads(json.dumps(template).replace("__REPLACE__", "test"))
    source_bytes = {
        "fictional-public-workshop-rule-operative-test.txt": (
            b"Fictional rule text for testing only. A public workshop keeps a record."
        ),
        "fictional-public-workshop-rule-status-test.txt": (
            b"Fictional status record for testing only. Version 2026-08-15 is "
            b"effective and unsuperseded as of 2026-08-15."
        ),
    }
    for name, content in source_bytes.items():
        (sources_root / name).write_bytes(content)
    case_path = fixture_root / "qualification.json"
    case_path.write_bytes(_canonical_bytes(materialized))
    response_path = tmp_path / "qualification-response.json"
    runs = (tmp_path / "full-template-run", tmp_path / "portable-template-run")
    environment = {
        **os.environ,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INDEX": "1",
        "PYTHONNOUSERSITE": "1",
    }

    def run(portable: bool, *args: str) -> subprocess.CompletedProcess[str]:
        python_args = [sys.executable]
        if portable:
            python_args.extend(("-I", "-S"))
        return subprocess.run(
            [*python_args, str(SKILL_RUNNER), *args],
            cwd=tmp_path,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )

    initialized = [
        run(
            portable,
            "eval-qualify-init",
            "--case",
            str(case_path),
            "--run",
            str(run_dir),
            "--nonce-hex",
            "6" * 64,
        )
        for portable, run_dir in zip((False, True), runs, strict=True)
    ]
    assert initialized[0].returncode == initialized[1].returncode == 0
    assert initialized[0].stdout == initialized[1].stdout
    assert initialized[0].stderr == initialized[1].stderr == ""
    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])

    next_results = [
        run(portable, "eval-qualify-next", "--run", str(run_dir))
        for portable, run_dir in zip((False, True), runs, strict=True)
    ]
    assert next_results[0].returncode == next_results[1].returncode == 0
    assert next_results[0].stdout == next_results[1].stdout
    assert next_results[0].stderr == next_results[1].stderr == ""
    request = json.loads(next_results[0].stdout)
    response_path.write_bytes(_canonical_bytes(_qualification_response_envelope(request)))
    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])

    submitted = [
        run(
            portable,
            "eval-qualify-submit",
            "--run",
            str(run_dir),
            "--response",
            str(response_path),
        )
        for portable, run_dir in zip((False, True), runs, strict=True)
    ]
    assert submitted[0].returncode == submitted[1].returncode == 0
    assert submitted[0].stdout == submitted[1].stdout
    assert submitted[0].stderr == submitted[1].stderr == ""
    submission = json.loads(submitted[0].stdout)
    assert submission["accepted"] is True
    assert submission["receipt"]["readiness"]["status"] == "ADMITTED"
    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])

    status_results = [
        run(portable, "eval-qualify-status", "--run", str(run_dir))
        for portable, run_dir in zip((False, True), runs, strict=True)
    ]
    assert status_results[0].returncode == status_results[1].returncode == 0
    assert status_results[0].stdout == status_results[1].stdout
    assert status_results[0].stderr == status_results[1].stderr == ""
    status = json.loads(status_results[0].stdout)
    assert status["status"] == "qualified"
    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])

    verified = [
        run(portable, "eval-qualify-verify", "--run", str(run_dir))
        for portable, run_dir in zip((False, True), runs, strict=True)
    ]
    assert verified[0].returncode == verified[1].returncode == 0
    assert verified[0].stdout == verified[1].stdout
    assert verified[0].stderr == verified[1].stderr == ""
    verification = json.loads(verified[0].stdout)
    assert verification["valid"] is True
    assert verification["root_hash"] == status["root_hash"]
    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])


@pytest.mark.parametrize(
    "mutation",
    [
        "schema",
        "request",
        "semantic",
    ],
)
def test_eval_submit_safe_is_read_only_on_refusal_and_matches_explicit_submit(
    mutation: str,
    tmp_path: Path,
) -> None:
    """The v2 guarded route rejects invalid responses without changing its run."""
    full_run = tmp_path / "full-safe"
    explicit_run = tmp_path / "explicit"
    for run in (full_run, explicit_run):
        initialized = _run_runner(
            SKILL_RUNNER,
            "eval-init",
            "--case",
            str(EVALUATION_FIXTURE / "case.json"),
            "--run",
            str(run),
            "--seed-hex",
            "e" * 64,
        )
        assert initialized.returncode == 0, initialized.stderr
    request = _next_packet(SKILL_RUNNER, full_run)
    assert request == _next_packet(SKILL_RUNNER, explicit_run)
    invalid: dict[str, object] = {
        "schema_version": "2.0",
        "operation": "source_review",
        "request_fingerprint": request["request_fingerprint"],
        "provider_name": "scripted-fixture",
        "model_name": "no-provider",
        "judge_isolation": "scripted_fixture",
        "payload": {},
    }
    if mutation == "schema":
        invalid.pop("provider_name")
    elif mutation == "request":
        invalid["request_fingerprint"] = "0" * 64
    # An empty source-review proposal set is syntactically valid but semantically invalid.
    invalid_path = tmp_path / "invalid-safe.json"
    invalid_path.write_bytes(_canonical_bytes(invalid))
    before = _run_snapshot(full_run)
    refused = _run_runner(
        SKILL_RUNNER,
        "eval-submit-safe",
        "--run",
        str(full_run.resolve()),
        "--response",
        str(invalid_path),
    )

    assert refused.returncode == 2
    assert refused.stderr == ""
    refused_payload = json.loads(refused.stdout)
    assert refused_payload["accepted"] is False
    assert refused_payload["preflight"]["valid"] is False
    assert _run_snapshot(full_run) == before

    explicit = _run_runner(
        SKILL_RUNNER,
        "eval-submit",
        "--run",
        str(explicit_run.resolve()),
        "--response", str(invalid_path),
    )
    assert explicit.returncode == 2
    assert _run_snapshot(explicit_run) == _run_snapshot(full_run)


def test_eval_qualify_cli_has_exact_full_portable_stdout_and_artifact_parity(
    tmp_path: Path,
) -> None:
    """Every source-qualification CLI transition must preserve canonical byte parity."""
    case_path = _write_qualification_fixture(tmp_path / "fixture")
    runs = (tmp_path / "full-qualification", tmp_path / "portable-qualification")
    runners = (SKILL_RUNNER, PORTABLE_RUNNER)

    initialized = [
        _run_runner(
            runner,
            "eval-qualify-init",
            "--case",
            str(case_path),
            "--run",
            str(run.resolve()),
            "--nonce-hex",
            "8" * 64,
        )
        for runner, run in zip(runners, runs, strict=True)
    ]
    assert initialized[0].returncode == initialized[1].returncode == 0
    assert initialized[0].stdout == initialized[1].stdout
    assert initialized[0].stderr == initialized[1].stderr == ""
    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])

    next_results = [
        _run_runner(runner, "eval-qualify-next", "--run", str(run.resolve()))
        for runner, run in zip(runners, runs, strict=True)
    ]
    assert next_results[0].returncode == next_results[1].returncode == 0
    assert next_results[0].stdout == next_results[1].stdout
    request = json.loads(next_results[0].stdout)
    assert "candidates" not in request["payload"]
    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])

    response = tmp_path / "qualification-response.json"
    response.write_bytes(_canonical_bytes(_admission_payload(request)))
    submitted = [
        _run_runner(
            runner,
            "eval-qualify-submit",
            "--run",
            str(run.resolve()),
            "--response",
            str(response),
        )
        for runner, run in zip(runners, runs, strict=True)
    ]
    assert submitted[0].returncode == submitted[1].returncode == 0
    assert submitted[0].stdout == submitted[1].stdout
    assert submitted[0].stderr == submitted[1].stderr == ""
    assert json.loads(submitted[0].stdout)["accepted"] is True
    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])

    for command in (
        "eval-qualify-next",
        "eval-qualify-status",
        "eval-qualify-verify",
    ):
        results = [
            _run_runner(runner, command, "--run", str(run.resolve()))
            for runner, run in zip(runners, runs, strict=True)
        ]
        assert results[0].returncode == results[1].returncode == 0
        assert results[0].stdout == results[1].stdout
        assert results[0].stderr == results[1].stderr == ""
        assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])

    sealed = [_run_snapshot(run) for run in runs]
    terminal_refusals = [
        _run_runner(
            runner,
            "eval-qualify-submit",
            "--run",
            str(run.resolve()),
            "--response",
            str(response),
        )
        for runner, run in zip(runners, runs, strict=True)
    ]
    assert terminal_refusals[0].returncode == terminal_refusals[1].returncode == 2
    assert terminal_refusals[0].stdout == terminal_refusals[1].stdout
    assert terminal_refusals[0].stderr == terminal_refusals[1].stderr == ""
    assert json.loads(terminal_refusals[0].stdout)["preflight"]["issues"][0]["code"] == (
        "EVALUATION_NO_PENDING_REQUEST"
    )
    assert [_run_snapshot(run) for run in runs] == sealed

    for run in runs:
        (run / "qualification-case.json").write_bytes(b"{}")
    invalid_verifications = [
        _run_runner(runner, "eval-qualify-verify", "--run", str(run.resolve()))
        for runner, run in zip(runners, runs, strict=True)
    ]
    assert invalid_verifications[0].returncode == invalid_verifications[1].returncode == 5
    assert invalid_verifications[0].stdout == invalid_verifications[1].stdout
    assert invalid_verifications[0].stderr == invalid_verifications[1].stderr == ""
    assert json.loads(invalid_verifications[0].stdout) == {
        "issues": ["QUALIFICATION_INTEGRITY_INVALID"],
        "root_hash": None,
        "valid": False,
    }


@pytest.mark.parametrize(
    "judge_isolation",
    ["fresh_context", "sequential_same_context", "scripted_fixture"],
)
def test_eval_qualification_schema_1_1_response_envelope_lifecycle_parity(
    judge_isolation: str,
    tmp_path: Path,
) -> None:
    case_path = _write_qualification_fixture(
        tmp_path / "fixture",
        schema_version="1.1",
    )
    runs = (tmp_path / "full-schema-1-1", tmp_path / "portable-schema-1-1")
    runners = (SKILL_RUNNER, PORTABLE_RUNNER)
    initialized = [
        _run_qualification_surface(
            runner,
            "eval-qualify-init",
            "--case",
            str(case_path),
            "--run",
            str(run.resolve()),
            "--nonce-hex",
            "f" * 64,
        )
        for runner, run in zip(runners, runs, strict=True)
    ]
    assert initialized[0].returncode == initialized[1].returncode == 0
    assert initialized[0].stdout == initialized[1].stdout
    assert initialized[0].stderr == initialized[1].stderr == ""
    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])
    next_results = [
        _run_qualification_surface(
            runner,
            "eval-qualify-next",
            "--run",
            str(run.resolve()),
        )
        for runner, run in zip(runners, runs, strict=True)
    ]
    assert next_results[0].returncode == next_results[1].returncode == 0
    assert next_results[0].stdout == next_results[1].stdout
    assert next_results[0].stderr == next_results[1].stderr == ""
    request = json.loads(next_results[0].stdout)
    assert {
        "provider_name",
        "model_name",
        "judge_isolation",
        "payload",
    }.issubset(request["json_schema"]["properties"])
    assert set(request["json_schema"]["properties"]["payload"]["properties"]) == {
        "request_fingerprint",
        "checks",
        "issues",
    }
    response_value = _qualification_response_envelope(request)
    response_value["judge_isolation"] = judge_isolation
    response_bytes = _canonical_bytes(response_value)
    response_path = tmp_path / "qualification-response-envelope.json"
    response_path.write_bytes(response_bytes)

    submitted = [
        _run_qualification_surface(
            runner,
            "eval-qualify-submit",
            "--run",
            str(run.resolve()),
            "--response",
            str(response_path),
        )
        for runner, run in zip(runners, runs, strict=True)
    ]
    assert submitted[0].returncode == submitted[1].returncode == 0
    assert submitted[0].stdout == submitted[1].stdout
    assert submitted[0].stderr == submitted[1].stderr == ""
    assert json.loads(submitted[0].stdout)["accepted"] is True
    for run in runs:
        assert (run / "admission-response.json").read_bytes() == response_bytes
    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])
    for command in ("eval-qualify-status", "eval-qualify-verify"):
        results = [
            _run_qualification_surface(runner, command, "--run", str(run.resolve()))
            for runner, run in zip(runners, runs, strict=True)
        ]
        assert results[0].returncode == results[1].returncode == 0
        assert results[0].stdout == results[1].stdout
        assert results[0].stderr == results[1].stderr == ""
        assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])
    assert json.loads(results[0].stdout)["valid"] is True


def test_eval_qualification_schema_1_1_response_envelope_optional_fields_preserve_bytes(
    tmp_path: Path,
) -> None:
    case_path = _write_qualification_fixture(
        tmp_path / "fixture",
        schema_version="1.1",
    )
    runs = (tmp_path / "full-schema-1-1", tmp_path / "portable-schema-1-1")
    runners = (SKILL_RUNNER, PORTABLE_RUNNER)
    initialized = [
        _run_qualification_surface(
            runner,
            "eval-qualify-init",
            "--case",
            str(case_path),
            "--run",
            str(run.resolve()),
            "--nonce-hex",
            "f" * 64,
        )
        for runner, run in zip(runners, runs, strict=True)
    ]
    assert initialized[0].returncode == initialized[1].returncode == 0
    assert initialized[0].stdout == initialized[1].stdout
    assert initialized[0].stderr == initialized[1].stderr == ""
    next_results = [
        _run_qualification_surface(
            runner,
            "eval-qualify-next",
            "--run",
            str(run.resolve()),
        )
        for runner, run in zip(runners, runs, strict=True)
    ]
    assert next_results[0].returncode == next_results[1].returncode == 0
    assert next_results[0].stdout == next_results[1].stdout
    request = json.loads(next_results[0].stdout)
    response_value = _qualification_response_envelope(request)
    response_value.pop("response_id")
    response_value.pop("usage")
    response_bytes = _canonical_bytes(response_value)
    response_path = tmp_path / "qualification-response-required-only.json"
    response_path.write_bytes(response_bytes)

    submitted = [
        _run_qualification_surface(
            runner,
            "eval-qualify-submit",
            "--run",
            str(run.resolve()),
            "--response",
            str(response_path),
        )
        for runner, run in zip(runners, runs, strict=True)
    ]
    assert submitted[0].returncode == submitted[1].returncode == 0
    assert submitted[0].stdout == submitted[1].stdout
    assert submitted[0].stderr == submitted[1].stderr == ""
    assert json.loads(submitted[0].stdout)["accepted"] is True
    for run in runs:
        assert (run / "admission-response.json").read_bytes() == response_bytes
    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])
    verified = [
        _run_qualification_surface(
            runner,
            "eval-qualify-verify",
            "--run",
            str(run.resolve()),
        )
        for runner, run in zip(runners, runs, strict=True)
    ]
    assert verified[0].returncode == verified[1].returncode == 0
    assert verified[0].stdout == verified[1].stdout
    assert verified[0].stderr == verified[1].stderr == ""
    assert json.loads(verified[0].stdout)["valid"] is True


def test_eval_qualification_schema_1_1_treatment_source_ids_normalize_with_cli_parity(
    tmp_path: Path,
) -> None:
    case_path = _write_qualification_fixture(
        tmp_path / "fixture",
        schema_version="1.1",
    )
    case = json.loads(case_path.read_bytes())
    case["language_treatments"][0]["source_ids"] = ["  source-1\t"]
    case_path.write_bytes(_canonical_bytes(case))
    fixture_bytes = case_path.read_bytes()
    runs = (tmp_path / "full-normalized", tmp_path / "portable-normalized")

    full = _run_qualification_surface(
        SKILL_RUNNER,
        "eval-qualify-init",
        "--case",
        str(case_path),
        "--run",
        str(runs[0].resolve()),
        "--nonce-hex",
        "c" * 64,
    )
    portable = _run_qualification_surface(
        PORTABLE_RUNNER,
        "eval-qualify-init",
        "--case",
        str(case_path),
        "--run",
        str(runs[1].resolve()),
        "--nonce-hex",
        "c" * 64,
    )

    assert full.returncode == 0, full.stderr
    full_case = json.loads((runs[0] / "qualification-case.json").read_bytes())
    assert full_case["language_treatments"][0]["source_ids"] == ["source-1"]
    assert portable.returncode == 0, portable.stderr
    assert portable.stdout == full.stdout
    assert portable.stderr == full.stderr == ""
    assert _run_snapshot(runs[1]) == _run_snapshot(runs[0])
    assert case_path.read_bytes() == fixture_bytes


@pytest.mark.parametrize(
    ("field_name", "fixture_path", "stored_path", "supplied", "expected"),
    [
        (
            "case-id",
            ("case_id",),
            ("case_id",),
            "  synthetic-source-qualification\t",
            "synthetic-source-qualification",
        ),
        (
            "question",
            ("question",),
            ("question",),
            "\n What notice must a covered operator file?  ",
            "What notice must a covered operator file?",
        ),
        (
            "case-jurisdiction",
            ("jurisdiction",),
            ("jurisdiction",),
            "  Example State\t",
            "Example State",
        ),
        (
            "authority-id",
            ("requested_authorities", 0, "authority_id"),
            ("requested_authorities", 0, "authority_id"),
            "\tsynthetic-rule-1 ",
            "synthetic-rule-1",
        ),
        (
            "authority-title",
            ("requested_authorities", 0, "title"),
            ("requested_authorities", 0, "title"),
            " Synthetic Rule 1\n",
            "Synthetic Rule 1",
        ),
        (
            "authority-jurisdiction",
            ("requested_authorities", 0, "jurisdiction"),
            ("requested_authorities", 0, "jurisdiction"),
            " Example State ",
            "Example State",
        ),
        (
            "authority-type",
            ("requested_authorities", 0, "authority_type"),
            ("requested_authorities", 0, "authority_type"),
            " regulation\t",
            "regulation",
        ),
        (
            "authority-source-id",
            ("requested_authorities", 0, "source_ids", 0),
            ("requested_authorities", 0, "source_ids", 0),
            "\nsource-1 ",
            "source-1",
        ),
        (
            "source-id",
            ("sources", 0, "source_id"),
            ("sources", 0, "source_id"),
            "  source-1\t",
            "source-1",
        ),
        (
            "source-title",
            ("sources", 0, "title"),
            ("sources", 0, "title"),
            " Synthetic Rule\n",
            "Synthetic Rule",
        ),
        (
            "source-jurisdiction",
            ("sources", 0, "jurisdiction"),
            ("sources", 0, "jurisdiction"),
            " Example State ",
            "Example State",
        ),
        (
            "source-authority-type",
            ("sources", 0, "authority_type"),
            ("sources", 0, "authority_type"),
            "\tregulation ",
            "regulation",
        ),
        (
            "source-language",
            ("sources", 0, "language"),
            ("sources", 0, "language"),
            " es\n",
            "es",
        ),
        (
            "source-canonical-url",
            ("sources", 0, "canonical_url"),
            ("sources", 0, "canonical_url"),
            " https://public.example/synthetic-rule ",
            "https://public.example/synthetic-rule",
        ),
        (
            "source-publisher",
            ("sources", 0, "publisher"),
            ("sources", 0, "publisher"),
            " Example Rules Office\t",
            "Example Rules Office",
        ),
        (
            "source-version",
            ("sources", 0, "version"),
            ("sources", 0, "version"),
            " edición 2026 ",
            "edición 2026",
        ),
        (
            "source-effective-date",
            ("sources", 0, "effective_date"),
            ("sources", 0, "effective_date"),
            " 2026-08-15\n",
            "2026-08-15",
        ),
        (
            "source-supersession",
            ("sources", 0, "supersession"),
            ("sources", 0, "supersession"),
            " Not superseded\t",
            "Not superseded",
        ),
        (
            "source-relationship-id",
            ("sources", 0, "relationship_ids", 0),
            ("sources", 0, "relationship_ids", 0),
            "\nsource-1 ",
            "source-1",
        ),
        (
            "treatment-source-id",
            ("language_treatments", 0, "source_ids", 0),
            ("language_treatments", 0, "source_ids", 0),
            "  source-1\t",
            "source-1",
        ),
        (
            "treatment-method",
            ("language_treatments", 0, "method"),
            ("language_treatments", 0, "method"),
            " Revisión bilingüe del texto oficial.\n",
            "Revisión bilingüe del texto oficial.",
        ),
        (
            "treatment-rationale",
            ("language_treatments", 0, "rationale"),
            ("language_treatments", 0, "rationale"),
            "\tLa traducción conserva la obligación jurídica. ",
            "La traducción conserva la obligación jurídica.",
        ),
        (
            "treatment-limitations",
            ("language_treatments", 0, "limitations"),
            ("language_treatments", 0, "limitations"),
            " La terminología técnica sigue en español.\t",
            "La terminología técnica sigue en español.",
        ),
        (
            "source-content",
            ("__source_content__",),
            ("sources", 0, "normalized_text"),
            "\r\n Regla sintética conservada exactamente. \r\n",
            "\r\n Regla sintética conservada exactamente. \r\n",
        ),
    ],
)
def test_eval_qualification_schema_1_1_nonblank_normalization_matrix_has_lifecycle_parity(
    field_name: str,
    fixture_path: tuple[str | int, ...],
    stored_path: tuple[str | int, ...],
    supplied: str,
    expected: str,
    tmp_path: Path,
) -> None:
    """Every full-model trim must produce the same immutable portable capsule."""
    fixture_root = tmp_path / "fixture"
    case_path = _write_qualification_fixture(fixture_root, schema_version="1.1")
    case = json.loads(case_path.read_bytes())
    case["sources"][0].update(
        {
            "canonical_url": "https://public.example/synthetic-rule",
            "publisher": "Example Rules Office",
            "supersession": "Not superseded",
            "relationship_ids": ["source-1"],
        }
    )
    source_path = fixture_root / "sources" / "rule.txt"
    if fixture_path == ("__source_content__",):
        source_path.write_bytes(supplied.encode("utf-8"))
    else:
        _replace_nested_case_value(case, fixture_path, supplied)
    case_path.write_bytes(_canonical_bytes(case))
    case_before = case_path.read_bytes()
    source_before = source_path.read_bytes()
    runs = (tmp_path / "full-normalized", tmp_path / "portable-normalized")
    runners = (SKILL_RUNNER, PORTABLE_RUNNER)

    initialized = [
        _run_qualification_surface(
            runner,
            "eval-qualify-init",
            "--case",
            str(case_path),
            "--run",
            str(run.resolve()),
            "--nonce-hex",
            "9" * 64,
        )
        for runner, run in zip(runners, runs, strict=True)
    ]

    assert initialized[0].returncode == initialized[1].returncode == 0, (
        field_name,
        initialized[0].stderr,
        initialized[1].stderr,
    )
    assert initialized[0].stdout == initialized[1].stdout
    assert initialized[0].stderr == initialized[1].stderr == ""
    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])
    stored_case = json.loads((runs[0] / "qualification-case.json").read_bytes())
    assert _nested_case_value(stored_case, stored_path) == expected
    next_results = [
        _run_qualification_surface(
            runner,
            "eval-qualify-next",
            "--run",
            str(run.resolve()),
        )
        for runner, run in zip(runners, runs, strict=True)
    ]
    assert next_results[0].returncode == next_results[1].returncode == 0
    assert next_results[0].stdout == next_results[1].stdout
    assert next_results[0].stderr == next_results[1].stderr == ""
    request = json.loads(next_results[0].stdout)
    response_path = tmp_path / "qualification-response.json"
    response_path.write_bytes(
        _canonical_bytes(_qualification_response_envelope(request))
    )
    submitted = [
        _run_qualification_surface(
            runner,
            "eval-qualify-submit",
            "--run",
            str(run.resolve()),
            "--response",
            str(response_path),
        )
        for runner, run in zip(runners, runs, strict=True)
    ]
    assert submitted[0].returncode == submitted[1].returncode == 0
    assert submitted[0].stdout == submitted[1].stdout
    assert submitted[0].stderr == submitted[1].stderr == ""
    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])
    for command in ("eval-qualify-status", "eval-qualify-verify"):
        results = [
            _run_qualification_surface(
                runner,
                command,
                "--run",
                str(run.resolve()),
            )
            for runner, run in zip(runners, runs, strict=True)
        ]
        assert results[0].returncode == results[1].returncode == 0
        assert results[0].stdout == results[1].stdout
        assert results[0].stderr == results[1].stderr == ""
        assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])
    assert case_path.read_bytes() == case_before
    assert source_path.read_bytes() == source_before


@pytest.mark.parametrize(
    ("control", "path", "supplied"),
    [
        ("schema-version", ("schema_version",), " 1.1 "),
        ("mode", ("mode",), " current-law "),
        ("as-of", ("as_of",), " 2026-08-15 "),
        ("source-role", ("sources", 0, "source_role"), " official_primary "),
        ("source-quality", ("sources", 0, "source_quality"), " primary "),
        ("completeness", ("sources", 0, "completeness"), " complete "),
        (
            "qualification-role",
            ("sources", 0, "qualification_role"),
            " operative_text ",
        ),
        ("commit", ("build_binding", "commit"), " " + "a" * 40),
        (
            "archive-sha256",
            ("build_binding", "archive_sha256"),
            "b" * 64 + " ",
        ),
        ("unsafe-case-id", ("case_id",), " bad/id "),
        ("blank-authority-id", ("requested_authorities", 0, "authority_id"), " \t "),
        ("blank-source-id", ("sources", 0, "source_id"), "\n "),
        (
            "unsafe-treatment-source-id",
            ("language_treatments", 0, "source_ids", 0),
            " bad/id ",
        ),
        ("blank-source-content", ("__source_content__",), " \r\n\t"),
    ],
)
def test_eval_qualification_schema_1_1_non_normalizing_controls_refuse_without_writes(
    control: str,
    path: tuple[str | int, ...],
    supplied: str,
    tmp_path: Path,
) -> None:
    fixture_root = tmp_path / "fixture"
    case_path = _write_qualification_fixture(fixture_root, schema_version="1.1")
    case = json.loads(case_path.read_bytes())
    if path == ("__source_content__",):
        (fixture_root / "sources" / "rule.txt").write_bytes(supplied.encode("utf-8"))
    else:
        _replace_nested_case_value(case, path, supplied)
        case_path.write_bytes(_canonical_bytes(case))
    runs = (tmp_path / "full-invalid", tmp_path / "portable-invalid")
    results = [
        _run_qualification_surface(
            runner,
            "eval-qualify-init",
            "--case",
            str(case_path),
            "--run",
            str(run.resolve()),
            "--nonce-hex",
            "8" * 64,
        )
        for runner, run in zip((SKILL_RUNNER, PORTABLE_RUNNER), runs, strict=True)
    ]

    assert results[0].returncode == results[1].returncode == 2, control
    assert results[0].stdout == results[1].stdout == ""
    assert results[0].stderr == results[1].stderr
    assert json.loads(results[0].stderr) == {
        "code": "EVALUATION_INPUT_INVALID",
        "message": "The qualification case fixture is invalid.",
    }
    assert all(not run.exists() for run in runs)


def test_eval_qualify_init_deep_case_has_input_invalid_parity_and_no_write(
    tmp_path: Path,
) -> None:
    """Canonical recursion failure belongs to the stable fixture-input contract."""
    invalid_root = tmp_path / "invalid-fixtures"
    invalid_root.mkdir()
    fixtures = {
        "deep-canonical": (
            b'{"case_id":' + b"[" * 1500 + b"0" + b"]" * 1500 + b"}"
        ),
        "malformed": b"{",
        "ordinary-canonical": b"{}",
    }
    for name, fixture_bytes in fixtures.items():
        case_path = invalid_root / f"{name}.json"
        case_path.write_bytes(fixture_bytes)
        runs = (
            tmp_path / f"full-{name}",
            tmp_path / f"portable-{name}",
        )
        results = [
            _run_qualification_surface(
                runner,
                "eval-qualify-init",
                "--case",
                str(case_path),
                "--run",
                str(run.resolve()),
                "--nonce-hex",
                "7" * 64,
            )
            for runner, run in zip((SKILL_RUNNER, PORTABLE_RUNNER), runs, strict=True)
        ]

        assert results[0].returncode == results[1].returncode == 2, name
        assert results[0].stdout == results[1].stdout == ""
        assert results[0].stderr == results[1].stderr
        assert json.loads(results[0].stderr) == {
            "code": "EVALUATION_INPUT_INVALID",
            "message": "The qualification case fixture is invalid.",
        }
        assert all(not run.exists() for run in runs)

    valid_case = _write_qualification_fixture(
        tmp_path / "valid-fixture",
        schema_version="1.1",
    )
    valid_runs = (tmp_path / "full-valid", tmp_path / "portable-valid")
    valid_results = [
        _run_qualification_surface(
            runner,
            "eval-qualify-init",
            "--case",
            str(valid_case),
            "--run",
            str(run.resolve()),
            "--nonce-hex",
            "7" * 64,
        )
        for runner, run in zip((SKILL_RUNNER, PORTABLE_RUNNER), valid_runs, strict=True)
    ]
    assert valid_results[0].returncode == valid_results[1].returncode == 0
    assert valid_results[0].stdout == valid_results[1].stdout
    assert valid_results[0].stderr == valid_results[1].stderr == ""
    assert _run_snapshot(valid_runs[0]) == _run_snapshot(valid_runs[1])


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("raw-inner", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("operation", "EVALUATION_RESPONSE_REQUEST_MISMATCH"),
        ("outer-fingerprint", "EVALUATION_RESPONSE_REQUEST_MISMATCH"),
        ("inner-fingerprint", "EVALUATION_RESPONSE_REQUEST_MISMATCH"),
        ("blank-provider", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("blank-model", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("invalid-isolation", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("extra-key", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("noncanonical", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("missing", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("oversize", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("too-deep", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("usage-numeric-string", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("usage-boolean", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
    ],
)
def test_eval_qualification_schema_1_1_response_envelope_refusal_is_write_free(
    mutation: str,
    expected_code: str,
    tmp_path: Path,
) -> None:
    case_path = _write_qualification_fixture(
        tmp_path / "fixture",
        schema_version="1.1",
    )
    runs = (tmp_path / "full-schema-1-1", tmp_path / "portable-schema-1-1")
    runners = (SKILL_RUNNER, PORTABLE_RUNNER)
    initialized = [
        _run_qualification_surface(
            runner,
            "eval-qualify-init",
            "--case",
            str(case_path),
            "--run",
            str(run.resolve()),
            "--nonce-hex",
            "e" * 64,
        )
        for runner, run in zip(runners, runs, strict=True)
    ]
    assert initialized[0].returncode == initialized[1].returncode == 0
    assert initialized[0].stdout == initialized[1].stdout
    assert initialized[0].stderr == initialized[1].stderr == ""
    request_results = [
        _run_qualification_surface(
            runner,
            "eval-qualify-next",
            "--run",
            str(run.resolve()),
        )
        for runner, run in zip(runners, runs, strict=True)
    ]
    assert request_results[0].returncode == request_results[1].returncode == 0
    assert request_results[0].stdout == request_results[1].stdout
    request = json.loads(request_results[0].stdout)
    response_value = _qualification_response_envelope(request)
    response_path = tmp_path / f"qualification-invalid-{mutation}.json"
    if mutation == "raw-inner":
        response_path.write_bytes(_canonical_bytes(response_value["payload"]))
    elif mutation == "noncanonical":
        response_path.write_bytes(b"{ " + _canonical_bytes(response_value)[1:])
    elif mutation == "missing":
        assert not response_path.exists()
    elif mutation == "oversize":
        response_path.write_bytes(b"{" + b" " * (1024 * 1024) + b"}")
    elif mutation == "too-deep":
        nested: object = []
        for _ in range(65):
            nested = [nested]
        response_path.write_bytes(_canonical_bytes({"nested": nested}))
    else:
        if mutation == "operation":
            response_value["operation"] = "grade_report"
        elif mutation == "outer-fingerprint":
            response_value["request_fingerprint"] = "0" * 64
        elif mutation == "inner-fingerprint":
            response_value["payload"]["request_fingerprint"] = "0" * 64
        elif mutation == "blank-provider":
            response_value["provider_name"] = "   "
        elif mutation == "blank-model":
            response_value["model_name"] = "\t"
        elif mutation == "invalid-isolation":
            response_value["judge_isolation"] = "not-isolated"
        elif mutation == "usage-numeric-string":
            response_value["usage"] = {"input_tokens": "101"}
        elif mutation == "usage-boolean":
            response_value["usage"] = {"input_tokens": True}
        else:
            response_value["unexpected"] = "forbidden"
        response_path.write_bytes(_canonical_bytes(response_value))
    before = [_run_snapshot(run) for run in runs]

    results = [
        _run_qualification_surface(
            runner,
            "eval-qualify-submit",
            "--run",
            str(run.resolve()),
            "--response",
            str(response_path),
        )
        for runner, run in zip(runners, runs, strict=True)
    ]

    assert results[0].returncode == results[1].returncode == 2
    assert results[0].stdout == results[1].stdout
    assert results[0].stderr == results[1].stderr == ""
    payload = json.loads(results[0].stdout)
    assert payload["accepted"] is False
    assert payload["receipt"] is None
    assert payload["preflight"]["issues"][0]["code"] == expected_code
    assert [_run_snapshot(run) for run in runs] == before


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-build-binding",
        "missing-language-treatments",
        "duplicate-treatment",
        "malformed-commit",
        "malformed-archive",
        "blank-method",
    ],
)
def test_eval_qualification_schema_1_1_case_refusal_has_exact_cli_parity(
    mutation: str,
    tmp_path: Path,
) -> None:
    case_path = _write_qualification_fixture(
        tmp_path / "fixture",
        schema_version="1.1",
    )
    case = json.loads(case_path.read_bytes())
    if mutation == "missing-build-binding":
        case.pop("build_binding")
    elif mutation == "missing-language-treatments":
        case.pop("language_treatments")
    elif mutation == "duplicate-treatment":
        case["language_treatments"].append(
            json.loads(json.dumps(case["language_treatments"][0]))
        )
    elif mutation == "malformed-commit":
        case["build_binding"]["commit"] = "A" * 40
    elif mutation == "malformed-archive":
        case["build_binding"]["archive_sha256"] = "b" * 63
    else:
        case["language_treatments"][0]["method"] = "   "
    case_path.write_bytes(_canonical_bytes(case))
    runs = (tmp_path / "full-invalid", tmp_path / "portable-invalid")

    results = [
        _run_qualification_surface(
            runner,
            "eval-qualify-init",
            "--case",
            str(case_path),
            "--run",
            str(run.resolve()),
            "--nonce-hex",
            "d" * 64,
        )
        for runner, run in zip((SKILL_RUNNER, PORTABLE_RUNNER), runs, strict=True)
    ]

    assert results[0].returncode == results[1].returncode == 2
    assert results[0].stdout == results[1].stdout == ""
    assert results[0].stderr == results[1].stderr
    assert json.loads(results[0].stderr) == {
        "code": "EVALUATION_INPUT_INVALID",
        "message": "The qualification case fixture is invalid.",
    }
    assert all(not run.exists() for run in runs)


@pytest.mark.parametrize(
    ("response_bytes", "expected_code"),
    [
        (b'{"checks": []}\n', "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        (
            _canonical_bytes(
                {"request_fingerprint": "0" * 64, "checks": [[[[[[[[[]]]]]]]]]}
            ),
            "EVALUATION_RESPONSE_SCHEMA_INVALID",
        ),
    ],
)
def test_eval_qualify_submit_refuses_invalid_transport_or_schema_without_writes(
    response_bytes: bytes,
    expected_code: str,
    tmp_path: Path,
) -> None:
    """Canonical transport and schema guards must fail identically without mutation."""
    case_path = _write_qualification_fixture(tmp_path / "fixture")
    runs = (tmp_path / "full-qualification", tmp_path / "portable-qualification")
    runners = (SKILL_RUNNER, PORTABLE_RUNNER)
    for runner, run in zip(runners, runs, strict=True):
        initialized = _run_runner(
            runner,
            "eval-qualify-init",
            "--case",
            str(case_path),
            "--run",
            str(run.resolve()),
            "--nonce-hex",
            "9" * 64,
        )
        assert initialized.returncode == 0, initialized.stderr
    before = [_run_snapshot(run) for run in runs]
    response = tmp_path / "qualification-invalid.json"
    response.write_bytes(response_bytes)

    results = [
        _run_runner(
            runner,
            "eval-qualify-submit",
            "--run",
            str(run.resolve()),
            "--response",
            str(response),
        )
        for runner, run in zip(runners, runs, strict=True)
    ]

    assert results[0].returncode == results[1].returncode == 2
    assert results[0].stdout == results[1].stdout
    assert results[0].stderr == results[1].stderr == ""
    payload = json.loads(results[0].stdout)
    assert set(payload) == {"accepted", "preflight", "receipt", "schema_version"}
    assert payload["schema_version"] == "1.0"
    assert payload["accepted"] is False
    assert payload["receipt"] is None
    assert payload["preflight"]["issues"][0]["code"] == expected_code
    assert [_run_snapshot(run) for run in runs] == before


@pytest.mark.parametrize("transport", ["oversize", "too-deep"])
def test_eval_qualify_submit_enforces_size_and_depth_guards_with_exact_parity(
    transport: str,
    tmp_path: Path,
) -> None:
    """Removing either bounded-input guard must fail before any capsule mutation."""
    case_path = _write_qualification_fixture(tmp_path / "fixture")
    runs = (tmp_path / "full-qualification", tmp_path / "portable-qualification")
    runners = (SKILL_RUNNER, PORTABLE_RUNNER)
    for runner, run in zip(runners, runs, strict=True):
        initialized = _run_runner(
            runner,
            "eval-qualify-init",
            "--case",
            str(case_path),
            "--run",
            str(run.resolve()),
            "--nonce-hex",
            "a" * 64,
        )
        assert initialized.returncode == 0, initialized.stderr
    response = tmp_path / f"qualification-{transport}.json"
    if transport == "oversize":
        response.write_bytes(b"{" + b" " * (1024 * 1024) + b"}")
    else:
        nested: object = []
        for _ in range(65):
            nested = [nested]
        response.write_bytes(_canonical_bytes({"nested": nested}))
    before = [_run_snapshot(run) for run in runs]

    results = [
        _run_runner(
            runner,
            "eval-qualify-submit",
            "--run",
            str(run.resolve()),
            "--response",
            str(response),
        )
        for runner, run in zip(runners, runs, strict=True)
    ]

    assert results[0].returncode == results[1].returncode == 2
    assert results[0].stdout == results[1].stdout
    assert results[0].stderr == results[1].stderr == ""
    payload = json.loads(results[0].stdout)
    assert set(payload) == {"accepted", "preflight", "receipt", "schema_version"}
    assert payload["schema_version"] == "1.0"
    assert payload["accepted"] is False
    assert payload["receipt"] is None
    assert payload["preflight"]["issues"][0] == {
        "code": "EVALUATION_RESPONSE_SCHEMA_INVALID",
        "message": "The response does not satisfy the canonical response schema.",
        "related_ids": [],
    }
    assert [_run_snapshot(run) for run in runs] == before


def test_eval_qualify_init_rejects_an_absolute_source_path_with_exact_parity(
    tmp_path: Path,
) -> None:
    """Qualification fixtures must not escape the retained local fixture root."""
    case_path = _write_qualification_fixture(tmp_path / "fixture")
    case = json.loads(case_path.read_bytes())
    case["sources"][0]["path"] = str((tmp_path / "outside.txt").resolve())
    case_path.write_bytes(_canonical_bytes(case))
    results = [
        _run_runner(
            runner,
            "eval-qualify-init",
            "--case",
            str(case_path),
            "--run",
            str((tmp_path / runner.stem).resolve()),
            "--nonce-hex",
            "b" * 64,
        )
        for runner in (SKILL_RUNNER, PORTABLE_RUNNER)
    ]

    assert results[0].returncode == results[1].returncode == 2
    assert results[0].stdout == results[1].stdout == ""
    assert results[0].stderr == results[1].stderr
    assert json.loads(results[0].stderr) == {
        "code": "EVALUATION_INPUT_INVALID",
        "message": "The qualification case fixture is invalid.",
    }


def test_eval_qualify_init_normalizes_relative_run_to_the_process_physical_root(
    tmp_path: Path,
) -> None:
    """A relative controller path must bind the same physical run on both surfaces."""
    case_path = _write_qualification_fixture(tmp_path / "fixture")
    outputs: list[subprocess.CompletedProcess[str]] = []
    for runner_name, runner in (("full", SKILL_RUNNER), ("portable", PORTABLE_RUNNER)):
        outputs.append(
            subprocess.run(
                [
                    sys.executable,
                    str(runner),
                    "eval-qualify-init",
                    "--case",
                    str(case_path),
                    "--run",
                    f"{runner_name}-relative-run",
                    "--nonce-hex",
                    "c" * 64,
                ],
                cwd=tmp_path,
                check=False,
                capture_output=True,
                text=True,
            )
        )

    assert outputs[0].returncode == outputs[1].returncode == 0
    assert outputs[0].stdout == outputs[1].stdout
    assert outputs[0].stderr == outputs[1].stderr == ""
    assert _run_snapshot(tmp_path / "full-relative-run") == _run_snapshot(
        tmp_path / "portable-relative-run"
    )


@pytest.mark.parametrize(
    "transport",
    [
        "dev-null",
        "invalid-json",
        "missing",
        "large-integer",
        "nonfinite",
        "noncanonical",
        "oversize",
        "too-deep",
    ],
)
def test_safe_submit_transport_failures_are_canonical_read_only_and_portable(
    transport: str,
    tmp_path: Path,
) -> None:
    """Qualification transport failures remain byte-identical on both surfaces."""
    command = "eval-qualify-submit"
    runners = (SKILL_RUNNER, PORTABLE_RUNNER)
    runs = (tmp_path / f"full-{command}", tmp_path / f"portable-{command}")
    case_path = _write_qualification_fixture(tmp_path / "fixture")
    for runner, run in zip(runners, runs, strict=True):
        initialized = _run_runner(
            runner,
            "eval-qualify-init",
            "--case",
            str(case_path),
            "--run",
            str(run.resolve()),
            "--nonce-hex",
            "d" * 64,
        )
        assert initialized.returncode == 0, initialized.stderr
    full_next = _run_runner(
        SKILL_RUNNER,
        "eval-qualify-next",
        "--run",
        str(runs[0].resolve()),
    )
    portable_next = _run_runner(
        PORTABLE_RUNNER,
        "eval-qualify-next",
        "--run",
        str(runs[1].resolve()),
    )
    assert full_next.stdout == portable_next.stdout
    request = json.loads(full_next.stdout)
    null_field = "receipt"

    response = tmp_path / f"{command}-{transport}.json"
    if transport == "dev-null":
        response = Path(os.devnull)
    elif transport == "invalid-json":
        response.write_bytes(b"{")
    elif transport == "missing":
        assert not response.exists()
    elif transport == "large-integer":
        response.write_bytes(b'{"value":' + b"9" * 5000 + b"}")
    elif transport == "nonfinite":
        response.write_bytes(b'{"value":NaN}')
    elif transport == "noncanonical":
        response.write_bytes(b'{ "value":1}')
    elif transport == "oversize":
        response.write_bytes(b"{" + b" " * (1024 * 1024) + b"}")
    else:
        nested: object = []
        for _ in range(65):
            nested = [nested]
        response.write_bytes(_canonical_bytes({"nested": nested}))
    before = [_run_snapshot(run) for run in runs]

    results = [
        _run_runner(
            runner,
            command,
            "--run",
            str(run.resolve()),
            "--response",
            str(response),
        )
        for runner, run in zip(runners, runs, strict=True)
    ]

    assert results[0].returncode == results[1].returncode == 2
    assert results[0].stdout == results[1].stdout
    assert results[0].stderr == results[1].stderr == ""
    payload = json.loads(results[0].stdout)
    assert set(payload) == {"accepted", "preflight", "schema_version", null_field}
    assert payload["schema_version"] == "1.0"
    assert payload["accepted"] is False
    assert payload[null_field] is None
    assert payload["preflight"] == {
        "diagnostic_fingerprint": hashlib.sha256(
            _canonical_bytes(
                {
                    "issues": [
                        {
                            "code": "EVALUATION_RESPONSE_SCHEMA_INVALID",
                            "message": (
                                "The response does not satisfy the canonical response schema."
                            ),
                            "related_ids": [],
                        }
                    ],
                    "operation": "admit_case",
                    "request_fingerprint": request["request_fingerprint"],
                }
            )
        ).hexdigest(),
        "issues": [
            {
                "code": "EVALUATION_RESPONSE_SCHEMA_INVALID",
                "message": "The response does not satisfy the canonical response schema.",
                "related_ids": [],
            }
        ],
        "ok": False,
        "operation": "admit_case",
        "request_fingerprint": request["request_fingerprint"],
        "schema_version": "1.0",
    }
    assert [_run_snapshot(run) for run in runs] == before


@pytest.mark.parametrize(
    "transport",
    [
        "dev-null",
        "invalid-json",
        "missing",
        "large-integer",
        "nonfinite",
        "noncanonical",
        "oversize",
        "too-deep",
    ],
)
def test_full_protocol_2_submit_safe_transport_refusals_are_write_free(
    transport: str,
    tmp_path: Path,
) -> None:
    """The full v2 surface rejects malformed transport before evaluator state changes."""
    run = tmp_path / "full-v2-run"
    initialized = _run_runner(
        SKILL_RUNNER,
        "eval-init",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(run),
        "--seed-hex",
        "d" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    response = tmp_path / f"v2-{transport}.json"
    if transport == "dev-null":
        response = Path(os.devnull)
    elif transport == "invalid-json":
        response.write_bytes(b"{")
    elif transport == "missing":
        assert not response.exists()
    elif transport == "large-integer":
        response.write_bytes(b'{"value":' + b"9" * 5000 + b"}")
    elif transport == "nonfinite":
        response.write_bytes(b'{"value":NaN}')
    elif transport == "noncanonical":
        response.write_bytes(b'{ "value":1}')
    elif transport == "oversize":
        response.write_bytes(b"{" + b" " * (1024 * 1024) + b"}")
    else:
        nested: object = []
        for _ in range(65):
            nested = [nested]
        response.write_bytes(_canonical_bytes({"nested": nested}))

    before = _run_snapshot(run)
    result = _run_runner(
        SKILL_RUNNER,
        "eval-submit-safe",
        "--run",
        str(run),
        "--response",
        str(response),
    )

    assert result.returncode == 2
    assert result.stdout == (
        '{"accepted":false,"preflight":{"diagnostics":["MECHANICAL_RESPONSE_INVALID"],"valid":false}}\n'
    )
    assert result.stderr == ""
    assert _run_snapshot(run) == before


def _macos_alias(path: Path) -> Path:
    # Keep later path components lexical so this helper does not hide whether
    # production normalization followed a user-owned symlink.
    physical = str(path.absolute())
    for prefix in ("/private/var/", "/private/tmp/"):
        if physical.startswith(prefix):
            return Path(physical.removeprefix("/private"))
    pytest.skip("the test path has no ordinary macOS root alias")


def test_eval_run_normalization_resolves_root_alias_before_parent_segments() -> None:
    """Dot-segment collapse must happen after the trusted root alias is physical."""
    lexical_root = Path("/tmp")
    if not lexical_root.is_symlink():
        pytest.skip("/tmp is not a root-level alias on this platform")
    lexical = lexical_root / ".." / "Users" / "synthetic-evaluation-run"
    physical_root = Path(os.path.realpath(lexical_root))
    expected = Path(os.path.abspath(physical_root / ".." / "Users" / lexical.name))
    full_runner = skill_runner._full_evaluation_runner()

    full = full_runner._physical_run_path(str(lexical))
    portable = portable_runner._physical_eval_run_path(str(lexical))

    assert full == portable == expected
    assert full != Path(os.path.abspath(lexical))


def test_eval_qualify_routes_resolve_macos_root_alias_before_no_follow_storage(
    tmp_path: Path,
) -> None:
    """Lexical /var or /tmp aliases must bind the same physical capsule roots."""
    case_path = _write_qualification_fixture(tmp_path / "fixture")
    runs = (tmp_path / "full-alias-run", tmp_path / "portable-alias-run")
    aliases = tuple(_macos_alias(run) for run in runs)
    runners = (SKILL_RUNNER, PORTABLE_RUNNER)
    results = [
        _run_runner(
            runner,
            "eval-qualify-init",
            "--case",
            str(case_path),
            "--run",
            str(alias),
            "--nonce-hex",
            "e" * 64,
        )
        for runner, alias in zip(runners, aliases, strict=True)
    ]

    assert results[0].returncode == results[1].returncode == 0
    assert results[0].stdout == results[1].stdout
    assert results[0].stderr == results[1].stderr == ""
    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])

    next_results = [
        _run_runner(runner, "eval-qualify-next", "--run", str(alias))
        for runner, alias in zip(runners, aliases, strict=True)
    ]
    assert next_results[0].returncode == next_results[1].returncode == 0
    assert next_results[0].stdout == next_results[1].stdout
    assert next_results[0].stderr == next_results[1].stderr == ""
    request = json.loads(next_results[0].stdout)
    response = tmp_path / "alias-qualification-response.json"
    response.write_bytes(_canonical_bytes(_admission_payload(request)))

    for command in (
        "eval-qualify-submit",
        "eval-qualify-status",
        "eval-qualify-verify",
    ):
        extra_args = ("--response", str(response)) if command.endswith("submit") else ()
        route_results = [
            _run_runner(runner, command, "--run", str(alias), *extra_args)
            for runner, alias in zip(runners, aliases, strict=True)
        ]
        assert route_results[0].returncode == route_results[1].returncode == 0
        assert route_results[0].stdout == route_results[1].stdout
        assert route_results[0].stderr == route_results[1].stderr == ""
        assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])


def test_eval_qualify_alias_normalization_does_not_follow_user_symlinks(
    tmp_path: Path,
) -> None:
    """Resolving the trusted root alias must not resolve a later user-owned link."""
    case_path = _write_qualification_fixture(tmp_path / "fixture")
    results: list[subprocess.CompletedProcess[str]] = []
    outside_roots: list[Path] = []
    for runner_name, runner in (("full", SKILL_RUNNER), ("portable", PORTABLE_RUNNER)):
        parent = tmp_path / f"{runner_name}-parent"
        outside = tmp_path / f"{runner_name}-outside"
        parent.mkdir()
        outside.mkdir()
        try:
            (parent / "linked").symlink_to(outside, target_is_directory=True)
        except OSError as error:
            pytest.skip(f"directory symlinks are unavailable: {error}")
        outside_roots.append(outside)
        results.append(
            _run_runner(
                runner,
                "eval-qualify-init",
                "--case",
                str(case_path),
                "--run",
                str(_macos_alias(parent / "linked" / "run")),
                "--nonce-hex",
                "f" * 64,
            )
        )

    assert results[0].returncode == results[1].returncode == 5
    assert results[0].stdout == results[1].stdout == ""
    assert results[0].stderr == results[1].stderr
    assert all(list(outside.iterdir()) == [] for outside in outside_roots)


@pytest.mark.parametrize("runner", [SKILL_RUNNER, PORTABLE_RUNNER])
def test_eval_init_exposes_only_a_source_record_admission_packet(
    runner: Path, tmp_path: Path
) -> None:
    """Routing a new evaluation through research code would leak report text to admission."""
    run = tmp_path / "run"

    result = _run_runner(
        runner,
        "eval-init",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(run),
        "--seed-hex",
        "3" * 64,
    )

    assert result.returncode == 0, result.stderr
    packet = _next_packet(runner, run)
    assert packet["operation"] == "source_review"
    serialized = json.dumps(packet, sort_keys=True)
    assert "report_text" not in serialized
    assert "regulatory_harvest" not in serialized.casefold()


def test_eval_submit_rejects_a_noncanonical_or_unbound_response_without_advancing(
    tmp_path: Path,
) -> None:
    """A bad v2 envelope must not consume the pending source-review request."""
    runner = SKILL_RUNNER
    run = tmp_path / "run"
    initialized = _run_runner(
        runner,
        "eval-init",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(run),
        "--seed-hex",
        "4" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    packet = _next_packet(runner, run)
    before = _run_snapshot(run)
    bad_response = tmp_path / "bad-response.json"
    bad_response.write_text(
        json.dumps(
            {
                "schema_version": "2.0",
                "operation": packet["operation"],
                "request_fingerprint": "0" * 64,
                "provider_name": "local-scripted-fixture",
                "model_name": "no-provider",
                "judge_isolation": "scripted_fixture",
                "payload": {},
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    rejected = _run_runner(
        runner, "eval-submit", "--run", str(run), "--response", str(bad_response)
    )

    assert rejected.returncode == 2
    status = json.loads(_run_runner(runner, "eval-status", "--run", str(run)).stdout)
    assert status["phase"] == "source_review"
    assert status["current_call_id"] is not None
    assert _next_packet(runner, run) == packet
    assert _run_snapshot(run) == before


def test_eval_preflight_is_canonical_read_only_parity_and_submit_ready(
    tmp_path: Path,
) -> None:
    """The full protocol-2.1 preflight is read-only and permits the same submit."""
    full_run = tmp_path / "full-preflight"
    initialized = _run_runner(
        SKILL_RUNNER,
        "eval-init",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(full_run),
        "--seed-hex",
        "0" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    packet = _next_packet(SKILL_RUNNER, full_run)
    assert packet["operation"] == "source_review"
    response = tmp_path / "valid-preflight.json"
    response.write_bytes(_canonical_bytes(_v21_source_review_response(packet)))
    before = _run_snapshot(full_run)
    result = _run_runner(
        SKILL_RUNNER,
        "eval-preflight",
        "--run",
        str(full_run),
        "--response",
        str(response),
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"valid": True, "diagnostics": []}
    assert _run_snapshot(full_run) == before

    submitted = _run_runner(
        SKILL_RUNNER,
        "eval-submit",
        "--run",
        str(full_run),
        "--response",
        str(response),
    )
    assert submitted.returncode == 0, submitted.stderr
    assert json.loads(submitted.stdout)["phase"] == "source_audit"


@pytest.mark.parametrize(
    "mutation",
    [
        "schema",
        "request",
        "semantic",
    ],
)
def test_eval_preflight_failures_are_safe_read_only_and_portable(
    mutation: str, tmp_path: Path
) -> None:
    """Malformed v2 drafts yield the bounded diagnostic and preserve the request."""
    run = tmp_path / f"full-{mutation}"
    initialized = _run_runner(
        SKILL_RUNNER,
        "eval-init",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(run),
        "--seed-hex",
        "f" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    packet = _next_packet(SKILL_RUNNER, run)
    response_value = _v2_source_review_response(packet)
    if mutation == "schema":
        response_value.pop("provider_name")
    elif mutation == "request":
        response_value["request_fingerprint"] = "0" * 64
    else:
        payload = response_value["payload"]
        assert isinstance(payload, dict)
        proposals = payload["proposals"]
        assert isinstance(proposals, list) and proposals
        proposals[0]["statement"] = ""
    response = tmp_path / f"{mutation}.json"
    response.write_bytes(_canonical_bytes(response_value))
    before = _run_snapshot(run)
    result = _run_runner(
        SKILL_RUNNER, "eval-preflight", "--run", str(run), "--response", str(response)
    )

    assert result.returncode == 2
    assert json.loads(result.stdout) == {
        "valid": False,
        "diagnostics": ["MECHANICAL_RESPONSE_INVALID"],
    }
    assert result.stderr == ""
    assert _next_packet(SKILL_RUNNER, run) == packet
    assert _run_snapshot(run) == before


def test_eval_preflight_terminal_refusal_and_integrity_failure_are_read_only(
    tmp_path: Path,
) -> None:
    """A terminal v2 run rejects preflight and a tamper remains integrity-only."""
    run = tmp_path / "full-terminal"
    initialized = _run_runner(
        SKILL_RUNNER, "eval-init", "--case", str(EVALUATION_FIXTURE / "case.json"),
        "--run", str(run), "--seed-hex", "1" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    stopped = _run_runner(
        SKILL_RUNNER, "eval-stop-inconclusive", "--run", str(run),
        "--reason", "MECHANICAL_RESPONSE_INVALID",
    )
    assert stopped.returncode == 3
    response = tmp_path / "terminal-response.json"
    response.write_bytes(b"{}")
    before = _run_snapshot(run)
    refused = _run_runner(
        SKILL_RUNNER, "eval-preflight", "--run", str(run), "--response", str(response)
    )
    assert refused.returncode == 2
    assert json.loads(refused.stdout) == {
        "valid": False, "diagnostics": ["MECHANICAL_RESPONSE_INVALID"]
    }
    assert _run_snapshot(run) == before

    envelope = run / "inputs" / "case.json"
    envelope.write_bytes(b"{}")
    tampered_before = _run_snapshot(run)
    integrity = _run_runner(SKILL_RUNNER, "eval-status", "--run", str(run))
    assert integrity.returncode == 5
    assert _run_snapshot(run) == tampered_before


def test_eval_submit_refuses_a_tampered_v21_transition_without_writes(
    tmp_path: Path,
) -> None:
    """A tampered v2.1 transition is refused before a response artifact can be written."""
    full_run = tmp_path / "full-integrity"
    initialized = _run_runner(
        SKILL_RUNNER, "eval-init", "--case", str(EVALUATION_FIXTURE / "case.json"),
        "--run", str(full_run), "--seed-hex", "2" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    packet = _next_packet(SKILL_RUNNER, full_run)
    response = tmp_path / "integrity-response.json"
    response.write_bytes(_canonical_bytes(_v21_source_review_response(packet)))
    envelope = full_run / "inputs" / "case.json"
    envelope.write_bytes(envelope.read_bytes() + b"\n")
    before = _run_snapshot(full_run)
    result = _run_runner(
        SKILL_RUNNER, "eval-submit", "--run", str(full_run), "--response", str(response)
    )
    assert result.returncode == 5
    assert result.stdout == ""
    assert json.loads(result.stderr)["code"] == "EVALUATION_INTEGRITY_INVALID"
    assert _run_snapshot(full_run) == before


def test_eval_case_invalid_is_terminal_inconclusive_not_input(tmp_path: Path) -> None:
    """Protocol 2.1 exposes only the generic pending-run inconclusive terminal path."""
    run = tmp_path / "full-inconclusive"
    initialized = _run_runner(
        SKILL_RUNNER, "eval-init", "--case", str(EVALUATION_FIXTURE / "case.json"),
        "--run", str(run), "--seed-hex", "3" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    stopped = _run_runner(
        SKILL_RUNNER,
        "eval-stop-inconclusive",
        "--run",
        str(run),
        "--reason",
        "MECHANICAL_RESPONSE_INVALID",
    )
    assert stopped.returncode == 3
    assert json.loads(stopped.stdout)["terminal_status"] == "INCONCLUSIVE_MECHANICAL"
    for command in ("eval-status", "eval-next", "eval-verify"):
        result = _run_runner(SKILL_RUNNER, command, "--run", str(run))
        assert result.returncode == 3


def test_eval_full_runner_falls_back_without_site_packages(tmp_path: Path) -> None:
    """Task8: the dependency-minimal fallback must create the protocol-2 surface."""
    run = tmp_path / "fallback-run"
    initialized = subprocess.run(
        [
            sys.executable,
            "-S",
            str(SKILL_RUNNER),
            "eval-init",
            "--case",
            str(EVALUATION_FIXTURE / "case.json"),
            "--run",
            str(run),
            "--seed-hex",
            "6" * 64,
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert initialized.returncode == 0, initialized.stderr
    packet = subprocess.run(
        [sys.executable, "-S", str(SKILL_RUNNER), "eval-next", "--run", str(run)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert packet.returncode == 0, packet.stderr
    assert json.loads(packet.stdout)["operation"] == "source_review"


def test_portable_v2_source_review_transition_matches_full_bytes(tmp_path: Path) -> None:
    """The embedded audit schema is hash-pinned and yields the full next packet."""
    runs = (tmp_path / "full", tmp_path / "portable")
    for runner, run in zip((SKILL_RUNNER, PORTABLE_RUNNER), runs, strict=True):
        initialized = _run_runner(
            runner,
            "eval-init",
            "--case",
            str(EVALUATION_FIXTURE / "case.json"),
            "--run",
            str(run),
            "--seed-hex",
            "d" * 64,
        )
        assert initialized.returncode == 0, initialized.stderr
        response = tmp_path / f"{run.name}.json"
        response.write_bytes(
            _canonical_bytes(_v2_source_review_response(_next_packet(runner, run)))
        )
        submitted = _run_runner(
            runner, "eval-submit-safe", "--run", str(run), "--response", str(response)
        )
        assert submitted.returncode == 0, submitted.stderr
    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])
    assert _next_packet(SKILL_RUNNER, runs[0]) == _next_packet(PORTABLE_RUNNER, runs[1])


def test_v2_controller_wraps_payload_only_source_review_for_full_and_portable(
    tmp_path: Path,
) -> None:
    runs = (tmp_path / "full", tmp_path / "portable")
    for runner, run in zip((SKILL_RUNNER, PORTABLE_RUNNER), runs, strict=True):
        initialized = _run_runner(
            runner,
            "eval-init",
            "--case",
            str(EVALUATION_FIXTURE / "case.json"),
            "--run",
            str(run),
            "--seed-hex",
            "a" * 64,
        )
        assert initialized.returncode == 0, initialized.stderr
        packet = _next_packet(runner, run)
        response = tmp_path / f"{run.name}-payload.json"
        response.write_bytes(
            _canonical_bytes(_v2_source_review_response(packet)["payload"])
        )
        preflight = _run_runner(
            runner,
            "eval-preflight",
            "--run",
            str(run),
            "--response",
            str(response),
            "--provider-name",
            "local-scripted-fixture",
            "--model-name",
            "no-provider",
            "--judge-isolation",
            "scripted_fixture",
        )
        assert preflight.returncode == 0, preflight.stderr
        assert json.loads(preflight.stdout) == {"diagnostics": [], "valid": True}
        submitted = _run_runner(
            runner,
            "eval-submit-safe",
            "--run",
            str(run),
            "--response",
            str(response),
            "--provider-name",
            "local-scripted-fixture",
            "--model-name",
            "no-provider",
            "--judge-isolation",
            "scripted_fixture",
        )
        assert submitted.returncode == 0, submitted.stderr
        assert json.loads(submitted.stdout)["accepted"] is True
        stored = json.loads((run / "responses" / "source-review.json").read_bytes())
        assert set(stored) == {
            "judge_isolation",
            "model_name",
            "operation",
            "payload",
            "provider_name",
            "request_fingerprint",
            "schema_version",
        }
        assert stored["payload"] == json.loads(response.read_bytes())
    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])


@pytest.mark.parametrize("runner", [SKILL_RUNNER, PORTABLE_RUNNER])
def test_v2_payload_only_submission_requires_complete_controller_metadata(
    tmp_path: Path, runner: Path
) -> None:
    run = tmp_path / runner.stem
    initialized = _run_runner(
        runner,
        "eval-init",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(run),
        "--seed-hex",
        "b" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    packet = _next_packet(runner, run)
    response = tmp_path / f"{runner.stem}-payload.json"
    response.write_bytes(_canonical_bytes(_v2_source_review_response(packet)["payload"]))
    before = _run_snapshot(run)

    submitted = _run_runner(
        runner,
        "eval-submit-safe",
        "--run",
        str(run),
        "--response",
        str(response),
        "--provider-name",
        "local-scripted-fixture",
    )

    assert submitted.returncode == 2
    assert submitted.stderr == ""
    assert json.loads(submitted.stdout) == {
        "accepted": False,
        "preflight": {
            "diagnostics": ["MECHANICAL_RESPONSE_INVALID"],
            "valid": False,
        },
    }
    assert _run_snapshot(run) == before


def test_portable_v2_empty_audit_transition_matches_full_grade_request(tmp_path: Path) -> None:
    runs = (tmp_path / "full", tmp_path / "portable")
    for runner, run in zip((SKILL_RUNNER, PORTABLE_RUNNER), runs, strict=True):
        assert (
            _run_runner(
                runner,
                "eval-init",
                "--case",
                str(EVALUATION_FIXTURE / "case.json"),
                "--run",
                str(run),
                "--seed-hex",
                "e" * 64,
            ).returncode
            == 0
        )
        for index, factory in enumerate((_v2_source_review_response, _v2_empty_audit_response)):
            response = tmp_path / f"{run.name}-{index}.json"
            response.write_bytes(_canonical_bytes(factory(_next_packet(runner, run))))
            submitted = _run_runner(
                runner, "eval-submit-safe", "--run", str(run), "--response", str(response)
            )
            assert submitted.returncode == 0, (
                f"{runner.name} {factory.__name__}: {submitted.stdout} {submitted.stderr}"
            )
    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])
    assert _next_packet(SKILL_RUNNER, runs[0]) == _next_packet(PORTABLE_RUNNER, runs[1])


def test_portable_v2_grade_lifecycle_matches_full_single_report(tmp_path: Path) -> None:
    """A portable grade transition must produce the same sealed terminal bytes as full."""
    runs = (tmp_path / "full", tmp_path / "portable")
    for runner, run in zip((SKILL_RUNNER, PORTABLE_RUNNER), runs, strict=True):
        initialized = _run_runner(
            runner,
            "eval-init",
            "--case",
            str(EVALUATION_FIXTURE / "case.json"),
            "--run",
            str(run),
            "--seed-hex",
            "f" * 64,
        )
        assert initialized.returncode == 0, initialized.stderr
        for index, factory in enumerate(
            (
                _v2_source_review_response,
                _v2_empty_audit_response,
                _v2_grade_response,
                _v2_grade_response,
            )
        ):
            response = tmp_path / f"{run.name}-{index}.json"
            response.write_bytes(_canonical_bytes(factory(_next_packet(runner, run))))
            submitted = _run_runner(
                runner, "eval-submit-safe", "--run", str(run), "--response", str(response)
            )
            assert submitted.returncode == 0, (
                f"{runner.name} {factory.__name__}: {submitted.stdout} {submitted.stderr}"
            )
    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])


def test_portable_v2_two_report_lifecycle_matches_full_bytes(tmp_path: Path) -> None:
    """A second anonymous report is graded twice and produces the same comparison."""
    case_path = _write_exact_evaluation_fixture(tmp_path / "two-report-fixture")
    runs = (tmp_path / "full-two", tmp_path / "portable-two")
    for runner, run in zip((SKILL_RUNNER, PORTABLE_RUNNER), runs, strict=True):
        assert (
            _run_runner(
                runner,
                "eval-init",
                "--case",
                str(case_path),
                "--run",
                str(run),
                "--seed-hex",
                "a" * 64,
            ).returncode
            == 0
        )
        for index, factory in enumerate(
            (
                _v2_source_review_response,
                _v2_empty_audit_response,
                _v2_grade_response,
                _v2_grade_response,
                _v2_grade_response,
                _v2_grade_response,
            )
        ):
            response = tmp_path / f"{run.name}-two-{index}.json"
            response.write_bytes(_canonical_bytes(factory(_next_packet(runner, run))))
            submitted = _run_runner(
                runner, "eval-submit-safe", "--run", str(run), "--response", str(response)
            )
            assert submitted.returncode == 0, submitted.stderr
    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])


def test_portable_v2_disputed_source_referee_matches_full_bytes(tmp_path: Path) -> None:
    """Every material audit concern requires one complete referee response."""
    runs = (tmp_path / "full-referee", tmp_path / "portable-referee")
    sequence = (
        _v2_source_review_response,
        _v2_disputed_audit_response,
        _v2_referee_accept_reviewer_response,
        _v2_grade_response,
        _v2_grade_response,
    )
    for runner, run in zip((SKILL_RUNNER, PORTABLE_RUNNER), runs, strict=True):
        assert (
            _run_runner(
                runner,
                "eval-init",
                "--case",
                str(EVALUATION_FIXTURE / "case.json"),
                "--run",
                str(run),
                "--seed-hex",
                "b" * 64,
            ).returncode
            == 0
        )
        for index, factory in enumerate(sequence):
            response = tmp_path / f"{run.name}-referee-{index}.json"
            response.write_bytes(_canonical_bytes(factory(_next_packet(runner, run))))
            submitted = _run_runner(
                runner, "eval-submit-safe", "--run", str(run), "--response", str(response)
            )
            assert submitted.returncode == 0, (
                f"{runner.name} {factory.__name__}: {submitted.stdout} {submitted.stderr}"
            )
    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])


def test_portable_v2_unresolved_referee_matches_full_inconclusive_bytes(tmp_path: Path) -> None:
    """An unresolved material dispute is retained and scores the report inconclusive."""
    runs = (tmp_path / "full-unresolved", tmp_path / "portable-unresolved")
    for runner, run in zip((SKILL_RUNNER, PORTABLE_RUNNER), runs, strict=True):
        assert (
            _run_runner(
                runner,
                "eval-init",
                "--case",
                str(EVALUATION_FIXTURE / "case.json"),
                "--run",
                str(run),
                "--seed-hex",
                "c" * 64,
            ).returncode
            == 0
        )
        for index, factory in enumerate((_v2_source_review_response, _v2_disputed_audit_response)):
            response = tmp_path / f"{run.name}-unresolved-{index}.json"
            response.write_bytes(_canonical_bytes(factory(_next_packet(runner, run))))
            assert (
                _run_runner(
                    runner, "eval-submit-safe", "--run", str(run), "--response", str(response)
                ).returncode
                == 0
            )
        referee = _v2_referee_accept_reviewer_response(_next_packet(runner, run))
        referee_payload = referee["payload"]
        assert isinstance(referee_payload, dict)
        if referee["schema_version"] == "2.1":
            referee_payload["decision"] = "unresolved"
            referee_payload["unresolved_reason"] = "SOURCE_AMBIGUITY"
        else:
            referee_payload["decisions"][0]["decision"] = "unresolved"  # type: ignore[index]
        for index, response in enumerate((referee, _v2_grade_response, _v2_grade_response)):
            value = response if isinstance(response, dict) else response(_next_packet(runner, run))
            response_path = tmp_path / f"{run.name}-unresolved-final-{index}.json"
            response_path.write_bytes(_canonical_bytes(value))
            assert (
                _run_runner(
                    runner, "eval-submit-safe", "--run", str(run), "--response", str(response_path)
                ).returncode
                == 0
            )
    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])


def test_portable_v2_second_mechanical_refusal_then_stop_matches_full(tmp_path: Path) -> None:
    """Refusals retain no repair details; only the explicit second-stop seals the run."""
    runs = (tmp_path / "full-stop", tmp_path / "portable-stop")
    invalid = tmp_path / "invalid-response.json"
    invalid.write_bytes(b"[]")
    for runner, run in zip((SKILL_RUNNER, PORTABLE_RUNNER), runs, strict=True):
        assert (
            _run_runner(
                runner,
                "eval-init",
                "--case",
                str(EVALUATION_FIXTURE / "case.json"),
                "--run",
                str(run),
                "--seed-hex",
                "c" * 64,
            ).returncode
            == 0
        )
        before = _run_snapshot(run)
        for _ in range(2):
            refusal = _run_runner(
                runner, "eval-submit-safe", "--run", str(run), "--response", str(invalid)
            )
            assert refusal.returncode == 2
            assert json.loads(refusal.stdout) == {
                "accepted": False,
                "preflight": {"diagnostics": ["MECHANICAL_RESPONSE_INVALID"], "valid": False},
            }
            assert _run_snapshot(run) == before
        stopped = _run_runner(
            runner,
            "eval-stop-inconclusive",
            "--run",
            str(run),
            "--reason",
            "MECHANICAL_RESPONSE_INVALID",
        )
        assert stopped.returncode == 3
    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])


def test_portable_v2_wrong_grade_label_refuses_without_writing(tmp_path: Path) -> None:
    """A grade payload must bind its semantic label to the pending call, not itself."""
    runs = (tmp_path / "full-label", tmp_path / "portable-label")
    for runner, run in zip((SKILL_RUNNER, PORTABLE_RUNNER), runs, strict=True):
        assert (
            _run_runner(
                runner,
                "eval-init",
                "--case",
                str(EVALUATION_FIXTURE / "case.json"),
                "--run",
                str(run),
                "--seed-hex",
                "d" * 64,
            ).returncode
            == 0
        )
        for index, factory in enumerate((_v2_source_review_response, _v2_empty_audit_response)):
            response = tmp_path / f"{run.name}-label-{index}.json"
            response.write_bytes(_canonical_bytes(factory(_next_packet(runner, run))))
            assert (
                _run_runner(
                    runner, "eval-submit-safe", "--run", str(run), "--response", str(response)
                ).returncode
                == 0
            )
        response = _v2_grade_response(_next_packet(runner, run))
        response["payload"]["anonymous_label"] = "B"  # type: ignore[index]
        response_path = tmp_path / f"{run.name}-wrong-label.json"
        response_path.write_bytes(_canonical_bytes(response))
        before = _run_snapshot(run)
        refused = _run_runner(
            runner, "eval-submit-safe", "--run", str(run), "--response", str(response_path)
        )
        assert refused.returncode == 2
        assert _run_snapshot(run) == before
    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])


@pytest.mark.parametrize("vector", ("grader_disagreement", "material_unsupported_assertion"))
def test_portable_v2_substantive_grade_results_match_full(vector: str, tmp_path: Path) -> None:
    """Substantive FAIL/INCONCLUSIVE results seal after two grades without retry."""
    if vector == "grader_disagreement":
        full_root = tmp_path / "full-fixtures"
        portable_root = tmp_path / "portable-fixtures"
        full_root.mkdir()
        portable_root.mkdir()
        assert _protocol_21_scenario(
            SKILL_RUNNER, tmp_path / "full-grader-disagreement", full_root,
            "outcome_changing_inconclusive",
        ) == _protocol_21_scenario(
            PORTABLE_RUNNER, tmp_path / "portable-grader-disagreement", portable_root,
            "outcome_changing_inconclusive",
        )
        return
    runs = (tmp_path / f"full-{vector}", tmp_path / f"portable-{vector}")
    for runner, run in zip((SKILL_RUNNER, PORTABLE_RUNNER), runs, strict=True):
        assert (
            _run_runner(
                runner,
                "eval-init",
                "--case",
                str(EVALUATION_FIXTURE / "case.json"),
                "--run",
                str(run),
                "--seed-hex",
                "e" * 64,
            ).returncode
            == 0
        )
        for index, factory in enumerate((_v2_source_review_response, _v2_empty_audit_response)):
            response = tmp_path / f"{run.name}-substantive-{index}.json"
            response.write_bytes(_canonical_bytes(factory(_next_packet(runner, run))))
            assert (
                _run_runner(
                    runner, "eval-submit-safe", "--run", str(run), "--response", str(response)
                ).returncode
                == 0
            )
        for grade_index in range(2):
            response = _v2_grade_response(_next_packet(runner, run))
            payload = response["payload"]
            assert isinstance(payload, dict)
            if vector == "grader_disagreement" and grade_index == 1:
                payload["requirement_grades"][0]["disposition"] = "not_met"  # type: ignore[index]
            if vector == "material_unsupported_assertion":
                if response["schema_version"] == "2.1":
                    payload["requirement_grades"][0]["disposition"] = "not_met"  # type: ignore[index]
                else:
                    payload["unsupported_assertions"] = [
                        {
                            "report_passage": "civil penalty of $500",
                            "importance": "material",
                            "rationale": "The report makes a material unsupported assertion.",
                        }
                    ]
            response_path = tmp_path / f"{run.name}-substantive-grade-{grade_index}.json"
            response_path.write_bytes(_canonical_bytes(response))
            assert (
                _run_runner(
                    runner, "eval-submit-safe", "--run", str(run), "--response", str(response_path)
                ).returncode
                == 0
            )
    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])


@pytest.mark.parametrize("boundary", ("ambiguous_source_quote", "ambiguous_report_quote"))
def test_portable_v2_ambiguous_evidence_refuses_without_writing(
    boundary: str, tmp_path: Path
) -> None:
    """Exact quotation ambiguity is mechanical and leaves the current tree untouched."""
    runs = (tmp_path / f"full-{boundary}", tmp_path / f"portable-{boundary}")
    for runner, run in zip((SKILL_RUNNER, PORTABLE_RUNNER), runs, strict=True):
        assert (
            _run_runner(
                runner,
                "eval-init",
                "--case",
                str(EVALUATION_FIXTURE / "case.json"),
                "--run",
                str(run),
                "--seed-hex",
                "f" * 64,
            ).returncode
            == 0
        )
        review = _v2_source_review_response(_next_packet(runner, run))
        if boundary == "ambiguous_source_quote":
            review["payload"]["proposals"][0]["passages"][0]["quote"] = "A covered operator"  # type: ignore[index]
        review_path = tmp_path / f"{run.name}-{boundary}-review.json"
        review_path.write_bytes(_canonical_bytes(review))
        assert (
            _run_runner(
                runner, "eval-submit-safe", "--run", str(run), "--response", str(review_path)
            ).returncode
            == 0
        )
        if boundary == "ambiguous_source_quote":
            response = _v2_empty_audit_response(_next_packet(runner, run))
        else:
            response = _v2_empty_audit_response(_next_packet(runner, run))
            response_path = tmp_path / f"{run.name}-{boundary}-audit.json"
            response_path.write_bytes(_canonical_bytes(response))
            assert (
                _run_runner(
                    runner, "eval-submit-safe", "--run", str(run), "--response", str(response_path)
                ).returncode
                == 0
            )
            response = _v2_grade_response(_next_packet(runner, run))
            response["payload"]["requirement_grades"][0]["report_passages"] = ["a"]  # type: ignore[index]
        response_path = tmp_path / f"{run.name}-{boundary}-response.json"
        response_path.write_bytes(_canonical_bytes(response))
        before = _run_snapshot(run)
        refused = _run_runner(
            runner, "eval-submit-safe", "--run", str(run), "--response", str(response_path)
        )
        assert refused.returncode == 2
        assert _run_snapshot(run) == before
    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])


def test_portable_v2_init_refuses_retained_13_run_exactly_like_full(tmp_path: Path) -> None:
    """New protocol initialization cannot overwrite a retained 1.3 run."""
    runs = (tmp_path / "full-legacy-init", tmp_path / "portable-legacy-init")
    for runner, run in zip((SKILL_RUNNER, PORTABLE_RUNNER), runs, strict=True):
        _initialize_eval_run(runner, run)
        before = _run_snapshot(run)
        result = _run_runner(
            runner,
            "eval-init",
            "--case",
            str(EVALUATION_FIXTURE / "case.json"),
            "--run",
            str(run),
            "--seed-hex",
            "1" * 64,
        )
        assert result.returncode == 2
        assert result.stdout == ""
        assert json.loads(result.stderr)["code"] == "EVALUATION_LEGACY_READ_ONLY"
        assert _run_snapshot(run) == before


def test_portable_v2_first_mechanical_repair_uses_identical_pending_packet(tmp_path: Path) -> None:
    """The one permitted repair receives exactly the pending request again."""
    runs = (tmp_path / "full-repair", tmp_path / "portable-repair")
    invalid = tmp_path / "invalid.json"
    invalid.write_bytes(b"[]")
    for runner, run in zip((SKILL_RUNNER, PORTABLE_RUNNER), runs, strict=True):
        initialized = _run_runner(
            runner,
            "eval-init",
            "--case",
            str(EVALUATION_FIXTURE / "case.json"),
            "--run",
            str(run),
            "--seed-hex",
            "2" * 64,
        )
        assert initialized.returncode == 0
        request, before = _next_packet(runner, run), _run_snapshot(run)
        refused = _run_runner(
            runner,
            "eval-submit-safe",
            "--run",
            str(run),
            "--response",
            str(invalid),
        )
        assert refused.returncode == 2
        assert _next_packet(runner, run) == request
        assert _run_snapshot(run) == before
        response = tmp_path / f"{run.name}-repair.json"
        response.write_bytes(_canonical_bytes(_v2_source_review_response(request)))
        accepted = _run_runner(
            runner,
            "eval-submit-safe",
            "--run",
            str(run),
            "--response",
            str(response),
        )
        assert accepted.returncode == 0
    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])


def test_portable_v2_tampered_baseline_verify_matches_full_no_write(tmp_path: Path) -> None:
    """A retained baseline byte change is never silently repaired."""
    runs = (tmp_path / "full-tamper", tmp_path / "portable-tamper")
    for runner, run in zip((SKILL_RUNNER, PORTABLE_RUNNER), runs, strict=True):
        initialized = _run_runner(
            runner,
            "eval-init",
            "--case",
            str(EVALUATION_FIXTURE / "case.json"),
            "--run",
            str(run),
            "--seed-hex",
            "3" * 64,
        )
        assert initialized.returncode == 0
        for index, factory in enumerate((_v2_source_review_response, _v2_empty_audit_response)):
            response = tmp_path / f"{run.name}-{index}.json"
            response.write_bytes(_canonical_bytes(factory(_next_packet(runner, run))))
            assert (
                _run_runner(
                    runner, "eval-submit-safe", "--run", str(run), "--response", str(response)
                ).returncode
                == 0
            )
        baseline = run / "baseline.json"
        baseline.write_bytes(baseline.read_bytes() + b" ")
        before = _run_snapshot(run)
        assert _run_runner(runner, "eval-verify", "--run", str(run)).returncode == 5
        assert _run_snapshot(run) == before
    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])


@pytest.mark.parametrize("kind", ("unknown", "noncanonical", "ordinary_nonempty"))
def test_portable_v2_init_nonlegacy_existing_controls_match_full(kind: str, tmp_path: Path) -> None:
    """Only a sealed canonical 1.3 run receives the legacy-init refusal."""
    outputs: list[tuple[int, str, str]] = []
    snapshots: list[dict[str, bytes]] = []
    for runner, run in zip(
        (SKILL_RUNNER, PORTABLE_RUNNER), (tmp_path / "full", tmp_path / "portable"), strict=True
    ):
        run.mkdir()
        if kind == "unknown":
            (run / "run-manifest.json").write_bytes(b'{"protocol_version":"9.9"}')
        elif kind == "noncanonical":
            (run / "run-manifest.json").write_bytes(b"{}\n")
        else:
            (run / "ordinary.txt").write_bytes(b"keep")
        before = _run_snapshot(run)
        result = _run_runner(
            runner,
            "eval-init",
            "--case",
            str(EVALUATION_FIXTURE / "case.json"),
            "--run",
            str(run),
            "--seed-hex",
            "4" * 64,
        )
        outputs.append((result.returncode, result.stdout, result.stderr))
        if result.returncode != 0:
            assert _run_snapshot(run) == before
        snapshots.append(_run_snapshot(run))
    assert outputs[0] == outputs[1]
    assert snapshots[0] == snapshots[1]


def test_portable_v2_audited_correction_pair_fail_and_pass_matches_full(
    tmp_path: Path,
) -> None:
    """A referee-approved correction changes the baseline before A-fail/B-pass."""
    case_path = _write_exact_evaluation_fixture(tmp_path / "correction-fixture")
    runs = (tmp_path / "full-correction", tmp_path / "portable-correction")
    reviewer_run = tmp_path / "reviewer-baseline"
    reviewer_sequence = (
        _v2_source_review_response,
        _v2_disputed_audit_response,
        _v2_referee_accept_reviewer_response,
    )
    with _suspend_v2_runner_capture():
        initialized = _run_runner(
            SKILL_RUNNER,
            "eval-init",
            "--case",
            str(case_path),
            "--run",
            str(reviewer_run),
            "--seed-hex",
            "5" * 64,
        )
        assert initialized.returncode == 0, initialized.stderr
        for index, factory in enumerate(reviewer_sequence):
            response_path = tmp_path / f"reviewer-baseline-{index}.json"
            response_path.write_bytes(
                _canonical_bytes(factory(_next_packet(SKILL_RUNNER, reviewer_run)))
            )
            accepted = _run_runner(
                SKILL_RUNNER,
                "eval-submit-safe",
                "--run",
                str(reviewer_run),
                "--response",
                str(response_path),
            )
            assert accepted.returncode == 0, accepted.stderr
    reviewer_baseline = (reviewer_run / "baseline.json").read_bytes()

    sequence = (
        _v2_source_review_response,
        _v2_corrected_disputed_audit_response,
        _v2_referee_accept_auditor_response,
        _v2_grade_response,
        _v2_grade_response,
        _v2_grade_response,
        _v2_grade_response,
    )
    for runner, run in zip((SKILL_RUNNER, PORTABLE_RUNNER), runs, strict=True):
        initialized = _run_runner(
            runner,
            "eval-init",
            "--case",
            str(case_path),
            "--run",
            str(run),
            "--seed-hex",
            "5" * 64,
        )
        assert initialized.returncode == 0, initialized.stderr
        for index, factory in enumerate(sequence):
            response = factory(_next_packet(runner, run))
            payload = response["payload"]
            assert isinstance(payload, dict)
            if factory is _v2_grade_response and payload["anonymous_label"] == "A":
                payload["requirement_grades"][0]["disposition"] = "not_met"  # type: ignore[index]
            response_path = tmp_path / f"{run.name}-correction-{index}.json"
            response_path.write_bytes(_canonical_bytes(response))
            accepted = _run_runner(
                runner,
                "eval-submit-safe",
                "--run",
                str(run),
                "--response",
                str(response_path),
            )
            assert accepted.returncode == 0, accepted.stderr
        corrected_baseline = (run / "baseline.json").read_bytes()
        corrected_payload = json.loads(corrected_baseline)
        assert corrected_baseline != reviewer_baseline
        assert corrected_payload["baseline_fingerprint"] != json.loads(reviewer_baseline)[
            "baseline_fingerprint"
        ]
        requirement = corrected_payload["requirements"][0]
        assert requirement["statement"] == "A covered operator must file notice."
        assert requirement["passages"][0]["quote"] == "A covered operator must file notice."
        result = json.loads((run / "result.json").read_bytes())
        reports = result["reports"]
        assert reports[0]["anonymous_label"] == "A"
        assert reports[0]["reconciliation"]["absolute_disposition"] == "FAIL"
        assert reports[1]["anonymous_label"] == "B"
        assert reports[1]["reconciliation"]["absolute_disposition"] == "PASS"
    assert _run_snapshot(runs[0]) == _run_snapshot(runs[1])


_V2_VECTOR_EXECUTORS = {
    "empty_audit_single_report_pass": test_portable_v2_grade_lifecycle_matches_full_single_report,
    "audited_correction_pair_fail_and_pass": (
        test_portable_v2_audited_correction_pair_fail_and_pass_matches_full
    ),
    "unresolved_source_dispute": (
        test_portable_v2_unresolved_referee_matches_full_inconclusive_bytes
    ),
    "grader_disagreement": lambda path: test_portable_v2_substantive_grade_results_match_full(
        "grader_disagreement", path
    ),
    "material_unsupported_assertion": (
        lambda path: test_portable_v2_substantive_grade_results_match_full(
            "material_unsupported_assertion", path
        )
    ),
    "ambiguous_source_quote": (
        lambda path: test_portable_v2_ambiguous_evidence_refuses_without_writing(
            "ambiguous_source_quote", path
        )
    ),
    "ambiguous_report_quote": (
        lambda path: test_portable_v2_ambiguous_evidence_refuses_without_writing(
            "ambiguous_report_quote", path
        )
    ),
    "first_mechanical_repair": (
        test_portable_v2_first_mechanical_repair_uses_identical_pending_packet
    ),
    "second_mechanical_failure": test_portable_v2_second_mechanical_refusal_then_stop_matches_full,
    "tampered_baseline": test_portable_v2_tampered_baseline_verify_matches_full_no_write,
}


def _protocol_21_run_command(
    runner: Path, *args: str
) -> subprocess.CompletedProcess[str]:
    python = [sys.executable]
    if runner == PORTABLE_RUNNER:
        python.extend(("-I", "-S"))
    result = subprocess.run(
        [*python, str(runner), *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if _V2_RUNNER_RECORDS is not None:
        runner_name = "full" if runner == SKILL_RUNNER else "portable"
        _V2_RUNNER_RECORDS.append(
            (runner_name, args[0], (result.returncode, result.stdout, result.stderr))
        )
    return result


def _protocol_21_scenario(
    runner: Path,
    run: Path,
    response_root: Path,
    vector: str,
) -> tuple[list[tuple[str, int, str, str]], dict[str, bytes]]:
    transcript: list[tuple[str, int, str, str]] = []

    def command(*args: str) -> subprocess.CompletedProcess[str]:
        completed = _protocol_21_run_command(runner, *args)
        transcript.append((args[0], completed.returncode, completed.stdout, completed.stderr))
        return completed

    invalid = response_root / "invalid.json"
    invalid.write_bytes(b"[]")

    if vector == "retained_2_0":
        _initialize_v2_eval_run(run)
        before = _run_snapshot(run)
        command("eval-status", "--run", str(run))
        command("eval-verify", "--run", str(run))
        command("eval-submit-safe", "--run", str(run), "--response", str(invalid))
        command(
            "eval-stop-inconclusive", "--run", str(run),
            "--reason", "MECHANICAL_RESPONSE_INVALID",
        )
        assert _run_snapshot(run) == before
        return transcript, _run_snapshot(run)
    if vector == "retained_1_3":
        _initialize_eval_run(runner, run)
        before = _run_snapshot(run)
        command("eval-status", "--run", str(run))
        command("eval-verify", "--run", str(run))
        command("eval-submit-safe", "--run", str(run), "--response", str(invalid))
        command(
            "eval-stop-inconclusive", "--run", str(run),
            "--reason", "MECHANICAL_RESPONSE_INVALID",
        )
        assert _run_snapshot(run) == before
        return transcript, _run_snapshot(run)
    if vector == "unknown":
        run.mkdir()
        (run / "run-manifest.json").write_bytes(
            _canonical_bytes({"protocol_version": "9.9"})
        )
        command("eval-status", "--run", str(run))
        return transcript, _run_snapshot(run)
    if vector == "symlink_path_refusal":
        target = response_root / "real-run"
        target.mkdir()
        run.symlink_to(target, target_is_directory=True)
        command("eval-status", "--run", str(run))
        return transcript, _run_snapshot(target)

    initialized = command(
        "eval-init",
        "--case", str(EVALUATION_FIXTURE / "case.json"),
        "--run", str(run),
        "--seed-hex", "7" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    if vector == "mechanical_terminal":
        command("eval-submit-safe", "--run", str(run), "--response", str(invalid))
        command("eval-submit-safe", "--run", str(run), "--response", str(invalid))
        command(
            "eval-stop-inconclusive", "--run", str(run),
            "--reason", "MECHANICAL_RESPONSE_INVALID",
        )
        command("eval-verify", "--run", str(run))
        return transcript, _run_snapshot(run)

    proposal_count = (
        6
        if vector in {
            "no_dispute", "partial_grade_resume", "cross_label_metadata",
            "cross_lane_metadata", "cross_batch_metadata",
        }
        else 3
        if vector == "mixed_referee_reviewer_auditor_unresolved"
        else 2 if vector in {"partial_referee_resume", "swapped_fragment"} else 1
    )
    disputed = vector in {
        "stable_pass", "stable_fail", "outcome_changing_inconclusive",
        "referee_repair", "partial_referee_resume", "swapped_fragment",
        "tampered_aggregate", "tampered_result",
    }
    mixed_referee = vector == "mixed_referee_reviewer_auditor_unresolved"
    repaired = False
    accepted = 0
    referee_accepted = 0
    while True:
        next_result = command("eval-next", "--run", str(run))
        if next_result.returncode != 0 or not next_result.stdout.strip():
            break
        request = json.loads(next_result.stdout)
        if request is None:
            break
        assert isinstance(request, dict)
        operation = request["operation"]
        if (
            vector == "partial_referee_resume"
            and operation == "source_referee_fragment"
            and referee_accepted == 1
        ):
            command("eval-status", "--run", str(run))
            command("eval-next", "--run", str(run))
            command("eval-verify", "--run", str(run))
            break
        repair_operation = (
            "source_referee_fragment" if vector == "referee_repair"
            else "ordinary_grade_fragment" if vector == "grade_repair"
            else None
        )
        if operation == repair_operation and not repaired:
            command("eval-submit-safe", "--run", str(run), "--response", str(invalid))
            command("eval-next", "--run", str(run))
            repaired = True
        response = _v21_response(
            request,
            proposal_count=proposal_count,
            disputed=disputed,
            mixed_referee=mixed_referee,
            stable_fail=vector == "stable_fail",
            outcome_changing=vector == "outcome_changing_inconclusive",
        )
        response_path = response_root / f"response-{accepted:02d}.json"
        response_path.write_bytes(_canonical_bytes(response))
        submitted = command(
            "eval-submit-safe", "--run", str(run), "--response", str(response_path)
        )
        assert submitted.returncode in {0, 3, 4}, submitted.stderr or submitted.stdout
        accepted += 1
        if operation == "source_referee_fragment":
            referee_accepted += 1
        partial_grade_vectors = {
            "partial_grade_resume", "cross_label_metadata",
            "cross_lane_metadata", "cross_batch_metadata",
        }
        if vector in partial_grade_vectors and operation == "ordinary_grade_fragment":
            if vector != "partial_grade_resume":
                manifest_path = run / "run-manifest.json"
                manifest = json.loads(manifest_path.read_bytes())
                accepted_grade = next(
                    call for call in manifest["calls"]
                    if call["operation"] == "ordinary_grade_fragment"
                    and call["state"] == "accepted"
                )
                if vector == "cross_label_metadata":
                    accepted_grade["anonymous_label"] = "B"
                elif vector == "cross_lane_metadata":
                    accepted_grade["grader_lane"] = 2
                else:
                    accepted_grade["batch_ref"] = "GB-A-1-0002"
                manifest_path.write_bytes(_canonical_bytes(manifest))
                _reseal_protocol_21_run(run)
            command("eval-status", "--run", str(run))
            command("eval-next", "--run", str(run))
            command("eval-verify", "--run", str(run))
            break
        if accepted > 24:
            raise AssertionError("Protocol 2.1 scenario did not terminate")

    if vector == "swapped_fragment":
        manifest = json.loads((run / "run-manifest.json").read_bytes())
        calls = [
            call
            for call in manifest["calls"]
            if call["operation"] == "source_referee_fragment" and call["state"] == "accepted"
        ]
        assert len(calls) >= 2
        calls[0]["dispute_id"], calls[1]["dispute_id"] = (
            calls[1]["dispute_id"], calls[0]["dispute_id"]
        )
        (run / "run-manifest.json").write_bytes(_canonical_bytes(manifest))
        _reseal_protocol_21_run(run)
        command("eval-verify", "--run", str(run))
    elif vector == "tampered_aggregate":
        aggregate = run / "aggregates" / "referee.json"
        assert aggregate.is_file()
        value = json.loads(aggregate.read_bytes())
        manifest_path = run / "run-manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        value["fragments"][0]["decision"]["decision"] = "accept_reviewer"
        value["fragments"][0]["decision"]["unresolved_reason"] = None
        body = {
            "schema_version": "2.1",
            "disputes": manifest["referee_disputes"],
            "fragments": value["fragments"],
        }
        value["aggregate_fingerprint"] = hashlib.sha256(_canonical_bytes(body)).hexdigest()
        aggregate.write_bytes(_canonical_bytes(value))
        manifest["referee_aggregate_fingerprint"] = value["aggregate_fingerprint"]
        manifest_path.write_bytes(_canonical_bytes(manifest))
        _reseal_protocol_21_run(run)
        command("eval-verify", "--run", str(run))
    elif vector == "tampered_lane_aggregate":
        aggregate_path = run / "aggregates" / "grade-A-1.json"
        value = json.loads(aggregate_path.read_bytes())
        value["ordinary_fragments"][0]["rationale"] = (
            "A forged but canonically re-sealed lane rationale."
        )
        body = dict(value)
        old_fingerprint = body.pop("aggregate_fingerprint")
        value["aggregate_fingerprint"] = hashlib.sha256(_canonical_bytes(body)).hexdigest()
        aggregate_path.write_bytes(_canonical_bytes(value))
        manifest_path = run / "run-manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["grader_aggregate_fingerprints"] = [
            value["aggregate_fingerprint"] if item == old_fingerprint else item
            for item in manifest["grader_aggregate_fingerprints"]
        ]
        manifest_path.write_bytes(_canonical_bytes(manifest))
        _reseal_protocol_21_run(run)
        command("eval-verify", "--run", str(run))
    elif vector in {"tampered_reconciliation", "tampered_sensitivity"}:
        _forge_protocol_21_report_derivation(
            run,
            "reconciliation" if vector == "tampered_reconciliation" else "sensitivity",
        )
        command("eval-verify", "--run", str(run))
    elif vector == "tampered_result":
        result_path = run / "result.json"
        value = json.loads(result_path.read_bytes())
        value["terminal_status"] = "INCONCLUSIVE"
        body = dict(value)
        body.pop("result_fingerprint")
        value["result_fingerprint"] = hashlib.sha256(_canonical_bytes(body)).hexdigest()
        result_path.write_bytes(_canonical_bytes(value))
        manifest_path = run / "run-manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest.update(
            {
                "phase": "inconclusive",
                "terminal_status": "INCONCLUSIVE",
                "result_hash": value["result_fingerprint"],
            }
        )
        manifest_path.write_bytes(_canonical_bytes(manifest))
        _reseal_protocol_21_run(run)
        command("eval-status", "--run", str(run))
        command("eval-verify", "--run", str(run))
    elif vector not in {
        "partial_referee_resume", "partial_grade_resume", "cross_label_metadata",
        "cross_lane_metadata", "cross_batch_metadata",
    }:
        command("eval-status", "--run", str(run))
        command("eval-verify", "--run", str(run))
    return transcript, _run_snapshot(run)


@pytest.mark.parametrize("vector", PROTOCOL_21_PORTABLE_PARITY_VECTORS)
def test_protocol_21_portable_parity(vector: str, tmp_path: Path) -> None:
    """The isolated portable CLI exactly mirrors every Protocol 2.1 public boundary."""
    full_root = tmp_path / "full-fixtures"
    portable_root = tmp_path / "portable-fixtures"
    full_root.mkdir()
    portable_root.mkdir()
    full = _protocol_21_scenario(
        SKILL_RUNNER, tmp_path / f"full-{vector}", full_root, vector
    )
    portable = _protocol_21_scenario(
        PORTABLE_RUNNER, tmp_path / f"portable-{vector}", portable_root, vector
    )
    assert full == portable


_V22_TEST_PROVENANCE = EvaluatorProvenanceV22(
    provider_name="local-scripted-fixture",
    model_name="no-provider",
    judge_isolation="scripted_fixture",
)


def _protocol_22_proposal(
    request: dict[str, object],
    ordinal: int,
    *,
    normalized: bool = False,
    low_quality: bool = False,
) -> dict[str, object]:
    payload = request["payload"]
    assert isinstance(payload, dict)
    source_record = payload["source_record"]
    assert isinstance(source_record, dict)
    sources = source_record["sources"]
    assert isinstance(sources, list) and sources
    source = sources[0]
    assert isinstance(source, dict)
    quote = source["normalized_text"]
    assert isinstance(quote, str)
    if normalized:
        quote = "  ".join(quote.split(" "))
    return {
        "statement": f"  Duty {ordinal}: a covered operator must comply.  "
        if normalized
        else f"Duty {ordinal}: a covered operator must comply.",
        "kind": "OBLIGATION" if normalized else "obligation",
        "importance": "CRITICAL" if normalized else "critical",
        "passages": [{"source_id": source["source_id"], "quote": quote}],
        "dependency": None,
        "confidence": "CLEAR" if normalized else "clear",
        "rationale": "Maybe." if low_quality else "The frozen source states the duty.",
    }


def _protocol_22_draft(
    request: dict[str, object], vector: str
) -> dict[str, object]:
    operation = request["operation"]
    payload = request["payload"]
    assert isinstance(operation, str) and isinstance(payload, dict)
    if operation == "source_review_fragment":
        ordinal = payload["fragment_ordinal"]
        assert isinstance(ordinal, int)
        fragmented = vector in {
            "review_fragmentation",
            "partial_source_review_resume",
            "partial_ordinary_grade_resume",
        }
        count = 5 if fragmented and ordinal == 1 else 1
        if vector == "empty_source_inconclusive":
            count = 0
        if vector in {
            "review_cross_fragment_duplicate",
            "review_cross_fragment_conflict",
            "review_nonfinal_fragment_duplicate",
            "review_nonfinal_fragment_conflict",
        }:
            proposal = _protocol_22_proposal(request, 1)
            proposal["statement"] = (
                "Global  review duty."
                if vector in {
                    "review_cross_fragment_conflict",
                    "review_nonfinal_fragment_conflict",
                }
                and ordinal == 2
                else "Global review duty."
            )
            return {
                "proposals": [proposal],
                "review_complete": ordinal == 2
                and not vector.startswith("review_nonfinal_"),
            }
        return {
            "proposals": [
                _protocol_22_proposal(
                    request,
                    (ordinal - 1) * 5 + index,
                    normalized=vector == "normalized_prose_enum_and_quote",
                    low_quality=vector == "low_quality_acceptance",
                )
                for index in range(1, count + 1)
            ],
            "review_complete": not fragmented or ordinal >= 2,
        }
    if operation == "source_audit_fragment":
        ordinal = payload["fragment_ordinal"]
        assert isinstance(ordinal, int)
        fragmented = vector in {
            "audit_fragmentation",
            "partial_source_audit_resume",
        }
        disputed = vector in {
            "stable_pass",
            "stable_fail",
            "outcome_sensitive_inconclusive",
            "insufficient_inconclusive",
            "partial_referee_resume",
            "partial_contested_grade_resume",
            "cross_dispute_swap",
            "nested_missing_audit_dependency_then_accept",
            "nested_missing_audit_dependency_pause",
            "nested_blank_audit_explanation_then_accept",
            "nested_blank_audit_explanation_pause",
        }
        concerns: list[dict[str, object]] = []
        if vector in {
            "audit_cross_fragment_duplicate",
            "audit_cross_fragment_conflict",
            "audit_nonfinal_fragment_duplicate",
            "audit_nonfinal_fragment_conflict",
        }:
            source_record = payload["source_record"]
            indexed = payload["indexed_proposals"]
            assert isinstance(source_record, dict) and isinstance(indexed, list) and indexed
            proposal = indexed[0]
            assert isinstance(proposal, dict)
            semantic = proposal["proposal"]
            assert isinstance(semantic, dict)
            concern = {
                "target_proposal_ordinal": 1,
                "concern_type": "ambiguity",
                "passages": semantic["passages"],
                "explanation": (
                    "A different global explanation."
                    if vector in {
                        "audit_cross_fragment_conflict",
                        "audit_nonfinal_fragment_conflict",
                    }
                    and ordinal == 2
                    else "The global meaning is ambiguous."
                ),
                "correction": None,
            }
            return {
                "concerns": [concern],
                "audit_complete": ordinal == 2
                and not vector.startswith("audit_nonfinal_"),
            }
        if ordinal == 1 and (fragmented or disputed):
            source_record = payload["source_record"]
            indexed = payload["indexed_proposals"]
            assert isinstance(source_record, dict) and isinstance(indexed, list) and indexed
            proposal = indexed[0]
            assert isinstance(proposal, dict)
            semantic = proposal["proposal"]
            assert isinstance(semantic, dict)
            correction = json.loads(json.dumps(semantic))
            correction["statement"] = "Covered operators must comply with the corrected duty."
            concerns.append(
                {
                    "target_proposal_ordinal": 1,
                    "concern_type": "incorrect_statement",
                    "passages": semantic["passages"],
                    "explanation": "The exact formulation is disputed.",
                    "correction": correction,
                }
            )
            if vector in {"partial_referee_resume", "cross_dispute_swap"}:
                second = json.loads(json.dumps(correction))
                second["statement"] = "A second corrected formulation applies."
                concerns.append(
                    {
                        "target_proposal_ordinal": 1,
                        "concern_type": "incorrect_statement",
                        "passages": semantic["passages"],
                        "explanation": "A second material formulation is disputed.",
                        "correction": second,
                    }
                )
        return {
            "concerns": concerns,
            "audit_complete": not fragmented or ordinal >= 2,
        }
    if operation == "source_referee_fragment":
        unresolved = vector == "insufficient_inconclusive"
        return {
            "decision": "unresolved" if unresolved else "accept_reviewer",
            "unresolved_reason": "SOURCE_AMBIGUITY" if unresolved else None,
            "evidence_ordinals": [1],
            "rationale": "The issued source evidence supports this disposition.",
        }
    if operation == "ordinary_grade_fragment":
        disposition = "met"
        label = payload["anonymous_label"]
        if vector == "stable_fail":
            disposition = "not_met"
        elif vector in {"candidate_label_a", "candidate_label_b"}:
            disposition = "met" if label == "A" else "not_met"
        report_text = payload["report_text"]
        requirements = payload["requirements"]
        assert isinstance(report_text, str) and isinstance(requirements, list)
        return {
            "requirement_grades": [
                {
                    "requirement_ordinal": index,
                    "disposition": disposition,
                    "report_passages": []
                    if disposition == "not_met"
                    else [report_text],
                    "rationale": "The report was graded exactly as supplied.",
                    "omission": "The issued duty is absent."
                    if disposition == "not_met"
                    else None,
                }
                for index, _ in enumerate(requirements, 1)
            ],
            "rationale": "Every issued requirement was graded.",
        }
    assert operation == "contested_grade_fragment"
    report_text = payload["report_text"]
    assert isinstance(report_text, str)
    reviewer = "met"
    auditor = "met"
    if vector == "stable_fail":
        reviewer = auditor = "not_met"
    elif vector == "outcome_sensitive_inconclusive":
        auditor = "not_met"
    elif vector == "insufficient_inconclusive":
        reviewer = auditor = "uncertain"

    def alternative(disposition: str) -> dict[str, object]:
        return {
            "disposition": disposition,
            "report_passages": []
            if disposition in {"not_met", "uncertain"}
            else [report_text],
            "rationale": "The issued alternative was graded as supplied.",
        }

    return {
        "reviewer_alternative_grade": alternative(reviewer),
        "auditor_alternative_grade": alternative(auditor),
        "ambiguity_disposition": "uncertain"
        if "uncertain" in {reviewer, auditor}
        else "acknowledged",
        "rationale": "Both issued alternatives were evaluated.",
    }


def _protocol_22_strict_response(
    request: dict[str, object], vector: str
) -> dict[str, object]:
    checked = validate_evaluator_request_v22(request)
    outcome = compile_evaluator_draft_v22(
        checked, _protocol_22_draft(request, vector), _V22_TEST_PROVENANCE
    )
    assert isinstance(outcome, CompiledDraftV22), outcome
    return outcome.response.model_dump(mode="json")


def _protocol_22_script_from_run(run: Path, path: Path, vector: str) -> None:
    probe = path.parent / f"{path.stem}-probe"
    shutil.copytree(run, probe, symlinks=True)
    responses: list[dict[str, object]] = []
    while (request := next_evaluator_request_v22(probe)) is not None:
        request_json = request.model_dump(mode="json")
        draft = _protocol_22_draft(request_json, vector)
        responses.append(
            {
                "draft": draft,
                "expect": {
                    "attempt": 1,
                    "clarification_codes": [],
                    "request_fingerprint": request.request_fingerprint,
                },
                "operation": request.operation.value,
            }
        )
        compiled = compile_evaluator_draft_v22(request, draft, _V22_TEST_PROVENANCE)
        assert isinstance(compiled, CompiledDraftV22), compiled
        submit_evaluator_response_v22(probe, compiled.response)
    path.write_bytes(
        _canonical_bytes(
            {"fixture_type": "local-scripted-drafts-v2.2", "responses": responses}
        )
    )


def _reseal_protocol_22_outer(run: Path) -> None:
    manifest_path = run / "run-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    assert isinstance(manifest, dict)
    artifacts = manifest["artifacts"]
    assert isinstance(artifacts, list)
    for record in artifacts:
        assert isinstance(record, dict)
        artifact_path = record["artifact_path"]
        assert isinstance(artifact_path, str)
        record["artifact_hash"] = hashlib.sha256((run / artifact_path).read_bytes()).hexdigest()
    body = dict(manifest)
    body.pop("manifest_fingerprint")
    manifest["manifest_fingerprint"] = hashlib.sha256(_canonical_bytes(body)).hexdigest()
    manifest_path.write_bytes(_canonical_bytes(manifest))


def _protocol_22_scenario(
    runner: Path,
    run: Path,
    response_root: Path,
    vector: str,
) -> tuple[list[tuple[str, int, str, str]], dict[str, bytes]]:
    transcript: list[tuple[str, int, str, str]] = []

    def command(*args: str) -> subprocess.CompletedProcess[str]:
        completed = _protocol_21_run_command(runner, *args)
        transcript.append((args[0], completed.returncode, completed.stdout, completed.stderr))
        return completed

    if vector in {
        "unknown_protocol",
        "unknown_schema",
        "missing_root",
        "empty_root",
        "absent_protocol_marker",
    }:
        if vector == "empty_root":
            run.mkdir()
        elif vector == "absent_protocol_marker":
            run.mkdir()
            (run / "run-manifest.json").write_bytes(_canonical_bytes({}))
        elif vector == "unknown_protocol":
            run.mkdir()
            (run / "run-manifest.json").write_bytes(
                _canonical_bytes({"protocol_version": "9.9"})
            )
        elif vector == "unknown_schema":
            run.mkdir()
            (run / "run-manifest.json").write_bytes(
                _canonical_bytes({"schema_version": "9.9"})
            )
        before = _run_snapshot(run)
        status = command("eval-status", "--run", str(run))
        verify = command("eval-verify", "--run", str(run))
        if vector in {"unknown_protocol", "unknown_schema"}:
            expected = {
                "code": "EVALUATION_PROTOCOL_UNSUPPORTED",
                "message": "The evaluation run protocol is unsupported.",
            }
            assert status.returncode == verify.returncode == 2
            assert status.stdout == verify.stdout == ""
            assert json.loads(status.stderr) == json.loads(verify.stderr) == expected
        assert _run_snapshot(run) == before
        return transcript, before
    if vector == "symlink_path_refusal":
        target = response_root / "physical-run"
        target.mkdir()
        run.symlink_to(target, target_is_directory=True)
        command("eval-status", "--run", str(run))
        return transcript, _run_snapshot(target)
    if vector.startswith("retained_") or vector.startswith("corrupt_retained_"):
        retained = vector.removeprefix("corrupt_").removeprefix("retained_").replace("_", ".")
        if retained == "1.3":
            _initialize_eval_run(runner, run)
        elif retained == "2.0":
            _initialize_v2_eval_run(run)
        else:
            assert retained == "2.1"
            _initialize_v21_eval_run(run)
        if vector.startswith("corrupt_"):
            manifest_path = run / "run-manifest.json"
            manifest_path.write_bytes(manifest_path.read_bytes() + b" ")
        before = _run_snapshot(run)
        empty_script = response_root / "empty-script.json"
        empty_script.write_bytes(
            _canonical_bytes(
                {"fixture_type": "local-scripted-drafts-v2.2", "responses": []}
            )
        )
        command("eval-status", "--run", str(run))
        command("eval-verify", "--run", str(run))
        command(
            "eval-init",
            "--protocol",
            "2.2",
            "--case",
            str(EVALUATION_FIXTURE / "case.json"),
            "--run",
            str(run),
            "--seed-hex",
            "5" * 64,
        )
        command(
            "eval-resume",
            "--run",
            str(run),
            "--scripted-responses",
            str(empty_script),
        )
        assert _run_snapshot(run) == before
        return transcript, before

    two_reports = vector in {"candidate_label_a", "candidate_label_b"}
    fixture = EVALUATION_FIXTURE_V2 if two_reports else EVALUATION_FIXTURE
    seed = "0" if vector != "candidate_label_b" else "3"
    initialized = command(
        "eval-init",
        "--protocol",
        "2.2",
        "--case",
        str(fixture / "case.json"),
        "--run",
        str(run),
        "--seed-hex",
        seed * 64,
    )
    assert initialized.returncode == 0, initialized.stderr

    if vector in {
        "scripted_exhaustion",
        "scripted_surplus",
        "scripted_malformed",
        "scripted_probe_error",
        "scripted_symlink",
        "scripted_oversize",
    }:
        before = _run_snapshot(run)
        scripted = response_root / f"{vector}.json"
        if vector == "scripted_malformed":
            scripted.write_bytes(b"{not-json")
        elif vector == "scripted_probe_error":
            scripted = response_root / "missing.json"
        elif vector == "scripted_symlink":
            target = response_root / "scripted-target.json"
            _protocol_22_script_from_run(run, target, vector)
            scripted.symlink_to(target)
        elif vector == "scripted_oversize":
            scripted.write_bytes(
                _canonical_bytes(
                    {
                        "fixture_type": "local-scripted-drafts-v2.2",
                        "padding": "x" * (16 * 1024 * 1024),
                        "responses": [],
                    }
                )
            )
        elif vector == "scripted_exhaustion":
            scripted.write_bytes(
                _canonical_bytes(
                    {"fixture_type": "local-scripted-drafts-v2.2", "responses": []}
                )
            )
        else:
            _protocol_22_script_from_run(run, scripted, vector)
            value = json.loads(scripted.read_bytes())
            extra = json.loads(json.dumps(value["responses"][-1]))
            extra["draft"]["rationale"] = "Unused surplus evaluator content."
            value["responses"].append(extra)
            scripted.write_bytes(_canonical_bytes(value))
        refused = command(
            "eval-resume",
            "--run",
            str(run),
            "--scripted-responses",
            str(scripted),
        )
        if vector == "scripted_oversize":
            assert refused.returncode == 2
            assert refused.stdout == ""
            assert json.loads(refused.stderr) == {
                "code": "EVALUATION_INPUT_INVALID",
                "message": "scripted draft fixture is unavailable",
            }
        assert _run_snapshot(run) == before
        return transcript, before

    if vector in {
        "engine_pause",
        "later_resume",
        "clarification_then_accept",
        "nested_engine_pause",
        "nested_clarification_then_accept",
        "nested_missing_passage_pause",
        "nested_missing_passage_then_accept",
        "nested_missing_dependency_pause",
        "nested_missing_dependency_then_accept",
        "nested_missing_audit_dependency_pause",
        "nested_missing_audit_dependency_then_accept",
        "nested_blank_rationale_pause",
        "nested_blank_rationale_then_accept",
        "nested_blank_audit_explanation_pause",
        "nested_blank_audit_explanation_then_accept",
    }:
        if vector.startswith(
            ("nested_missing_audit_dependency_", "nested_blank_audit_explanation_")
        ):
            review_request = json.loads(command("eval-next", "--run", str(run)).stdout)
            assert isinstance(review_request, dict)
            review_response = _protocol_22_strict_response(review_request, vector)
            review_path = response_root / "dependency-review-response.json"
            review_path.write_bytes(_canonical_bytes(review_response))
            submitted = command(
                "eval-submit-safe",
                "--run",
                str(run),
                "--response",
                str(review_path),
            )
            assert submitted.returncode == 0, submitted.stderr or submitted.stdout
        request = json.loads(command("eval-next", "--run", str(run)).stdout)
        assert isinstance(request, dict)
        valid = _protocol_22_draft(request, vector)
        malformed: dict[str, object] = {"malformed": "private-first-draft"}
        clarification_code = "SUBSTANCE_MISSING"
        if vector.startswith("nested_missing_audit_dependency_"):
            malformed = _protocol_22_draft(request, vector)
            concerns = malformed["concerns"]
            assert isinstance(concerns, list) and concerns
            concern = concerns[0]
            assert isinstance(concern, dict)
            correction = concern["correction"]
            assert isinstance(correction, dict)
            correction["dependency"] = {"relationship": "depends_on"}
            clarification_code = "SUBSTANCE_MISSING"
        elif vector.startswith("nested_blank_audit_explanation_"):
            malformed = _protocol_22_draft(request, vector)
            concerns = malformed["concerns"]
            assert isinstance(concerns, list) and concerns
            concern = concerns[0]
            assert isinstance(concern, dict)
            concern["explanation"] = "   "
            clarification_code = "DRAFT_INVALID"
        elif vector.startswith("nested_"):
            malformed = _protocol_22_draft(request, vector)
            proposals = malformed["proposals"]
            assert isinstance(proposals, list) and proposals
            proposal = proposals[0]
            assert isinstance(proposal, dict)
            if vector.startswith("nested_missing_passage_"):
                passages = proposal["passages"]
                assert isinstance(passages, list) and passages
                passage = passages[0]
                assert isinstance(passage, dict)
                passage.pop("quote")
                clarification_code = "SUBSTANCE_MISSING"
            elif vector.startswith("nested_missing_dependency_"):
                proposal["dependency"] = {"relationship": "depends_on"}
                clarification_code = "SUBSTANCE_MISSING"
            elif vector.startswith("nested_blank_rationale_"):
                proposal["rationale"] = "   "
                clarification_code = "DRAFT_INVALID"
            else:
                proposal["passages"] = {}
                clarification_code = "DRAFT_INVALID"
        responses: list[dict[str, object]] = [
            {
                "draft": malformed,
                "expect": {
                    "attempt": 1,
                    "clarification_codes": [],
                    "request_fingerprint": request["request_fingerprint"],
                },
                "operation": request["operation"],
            }
        ]
        if vector in {
            "clarification_then_accept",
            "nested_clarification_then_accept",
            "nested_missing_passage_then_accept",
            "nested_missing_dependency_then_accept",
            "nested_missing_audit_dependency_then_accept",
            "nested_blank_rationale_then_accept",
            "nested_blank_audit_explanation_then_accept",
        }:
            tail = response_root / "clarification-tail.json"
            _protocol_22_script_from_run(run, tail, vector)
            tail_value = json.loads(tail.read_bytes())
            first = tail_value["responses"][0]
            first["draft"] = valid
            first["expect"]["attempt"] = 2
            first["expect"]["clarification_codes"] = [clarification_code]
            responses.extend(tail_value["responses"])
        else:
            responses.append(
                {
                    "draft": malformed,
                    "expect": {
                        "attempt": 2,
                        "clarification_codes": [clarification_code],
                        "request_fingerprint": request["request_fingerprint"],
                    },
                    "operation": request["operation"],
                }
            )
        scripted = response_root / f"{vector}.json"
        scripted.write_bytes(
            _canonical_bytes(
                {"fixture_type": "local-scripted-drafts-v2.2", "responses": responses}
            )
        )
        paused = command(
            "eval-resume",
            "--run",
            str(run),
            "--scripted-responses",
            str(scripted),
        )
        if vector in {
            "clarification_then_accept",
            "nested_clarification_then_accept",
            "nested_missing_passage_then_accept",
            "nested_missing_dependency_then_accept",
            "nested_missing_audit_dependency_then_accept",
            "nested_blank_rationale_then_accept",
            "nested_blank_audit_explanation_then_accept",
        }:
            assert paused.returncode in {0, 3, 4}, paused.stderr
            return transcript, _run_snapshot(run)
        assert paused.returncode == 6, paused.stderr
        command("eval-status", "--run", str(run))
        command("eval-verify", "--run", str(run))
        if vector == "later_resume":
            resumed_script = response_root / "later-resume.json"
            _protocol_22_script_from_run(run, resumed_script, vector)
            command(
                "eval-resume",
                "--run",
                str(run),
                "--scripted-responses",
                str(resumed_script),
            )
        return transcript, _run_snapshot(run)

    stop_operation = {
        "partial_source_review_resume": ("source_review_fragment", 2),
        "partial_source_audit_resume": ("source_audit_fragment", 2),
        "partial_referee_resume": ("source_referee_fragment", 2),
        "partial_ordinary_grade_resume": ("ordinary_grade_fragment", 2),
        "partial_contested_grade_resume": ("contested_grade_fragment", 2),
    }.get(vector)
    operation_counts: dict[str, int] = {}
    accepted = 0
    while True:
        next_result = command("eval-next", "--run", str(run))
        if next_result.returncode != 0:
            break
        request = json.loads(next_result.stdout)
        if request is None:
            break
        assert isinstance(request, dict)
        operation = request["operation"]
        assert isinstance(operation, str)
        operation_counts[operation] = operation_counts.get(operation, 0) + 1
        if stop_operation == (operation, operation_counts[operation]):
            command("eval-status", "--run", str(run))
            command("eval-next", "--run", str(run))
            command("eval-verify", "--run", str(run))
            scripted = response_root / f"resume-{vector}.json"
            _protocol_22_script_from_run(run, scripted, vector)
            command(
                "eval-resume",
                "--run",
                str(run),
                "--scripted-responses",
                str(scripted),
            )
            return transcript, _run_snapshot(run)
        response = _protocol_22_strict_response(request, vector)
        response_path = response_root / f"response-{accepted:03d}.json"
        response_path.write_bytes(_canonical_bytes(response))
        submitted = command(
            "eval-submit-safe",
            "--run",
            str(run),
            "--response",
            str(response_path),
        )
        if vector in {
            "review_cross_fragment_duplicate",
            "review_cross_fragment_conflict",
            "review_nonfinal_fragment_duplicate",
            "review_nonfinal_fragment_conflict",
            "audit_cross_fragment_duplicate",
            "audit_cross_fragment_conflict",
            "audit_nonfinal_fragment_duplicate",
            "audit_nonfinal_fragment_conflict",
        } and operation_counts[operation] == 2:
            assert submitted.returncode == 2, submitted.stderr or submitted.stdout
            assert submitted.stdout
            assert json.loads(submitted.stdout) == {
                "accepted": False,
                "preflight": {
                    "diagnostics": ["EXTERNAL_RESPONSE_INVALID"],
                    "valid": False,
                },
            }
            assert submitted.stderr == ""
            same_request = command("eval-next", "--run", str(run))
            assert same_request.returncode == 0
            assert json.loads(same_request.stdout) == request
            command("eval-status", "--run", str(run))
            command("eval-verify", "--run", str(run))
            return transcript, _run_snapshot(run)
        assert submitted.returncode in {0, 3, 4}, submitted.stderr or submitted.stdout
        accepted += 1
        if accepted > 80:
            raise AssertionError("Protocol 2.2 scenario did not terminate")

    manifest_path = run / "run-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    if vector in {
        "cross_case_swap",
        "cross_lane_swap",
        "cross_dispute_swap",
        "cross_batch_swap",
        "cross_fragment_swap",
        "compiler_contract_tamper",
    }:
        if vector == "compiler_contract_tamper":
            manifest["compiler_contract_fingerprint"] = "0" * 64
        elif vector == "cross_case_swap":
            manifest["case_fingerprint"] = "0" * 64
        else:
            calls = manifest["calls"]
            assert isinstance(calls, list) and calls
            call = calls[-1]
            assert isinstance(call, dict)
            if vector == "cross_lane_swap":
                call["grader_lane"] = 2 if call.get("grader_lane") == 1 else 1
            elif vector == "cross_dispute_swap":
                call["dispute_id"] = "D9999"
            elif vector == "cross_batch_swap":
                call["batch_ref"] = "GB-A-1-9999"
            else:
                call["fragment_ordinal"] = 99
        manifest_path.write_bytes(_canonical_bytes(manifest))
        _reseal_protocol_22_outer(run)
    elif vector == "aggregate_reseal":
        aggregate_path = sorted((run / "aggregates").glob("grade-*.json"))[0]
        aggregate = json.loads(aggregate_path.read_bytes())
        aggregate["ordinary_fragments"][0]["rationale"] = "Re-sealed forged rationale."
        body = dict(aggregate)
        old = body.pop("aggregate_fingerprint")
        aggregate["aggregate_fingerprint"] = hashlib.sha256(_canonical_bytes(body)).hexdigest()
        aggregate_path.write_bytes(_canonical_bytes(aggregate))
        manifest["grader_aggregate_fingerprints"] = [
            aggregate["aggregate_fingerprint"] if item == old else item
            for item in manifest["grader_aggregate_fingerprints"]
        ]
        manifest_path.write_bytes(_canonical_bytes(manifest))
        _reseal_protocol_22_outer(run)
    elif vector == "result_reseal":
        result_path = run / "result.json"
        result = json.loads(result_path.read_bytes())
        result["terminal_status"] = "INCONCLUSIVE"
        body = dict(result)
        body.pop("result_fingerprint")
        result["result_fingerprint"] = hashlib.sha256(_canonical_bytes(body)).hexdigest()
        result_path.write_bytes(_canonical_bytes(result))
        manifest["terminal_status"] = "INCONCLUSIVE"
        manifest["phase"] = "inconclusive"
        manifest["result_hash"] = result["result_fingerprint"]
        manifest_path.write_bytes(_canonical_bytes(manifest))
        _reseal_protocol_22_outer(run)

    command("eval-status", "--run", str(run))
    command("eval-verify", "--run", str(run))
    return transcript, _run_snapshot(run)


@pytest.mark.parametrize("vector", PROTOCOL_22_PORTABLE_PARITY_VECTORS)
def test_protocol_22_portable_parity(vector: str, tmp_path: Path) -> None:
    """Mirror every Protocol 2.2 command and complete tree byte-for-byte."""
    full_fixtures = tmp_path / "full-fixtures"
    portable_fixtures = tmp_path / "portable-fixtures"
    full_fixtures.mkdir()
    portable_fixtures.mkdir()
    full = _protocol_22_scenario(
        SKILL_RUNNER, tmp_path / f"full-{vector}", full_fixtures, vector
    )
    portable = _protocol_22_scenario(
        PORTABLE_RUNNER,
        tmp_path / f"portable-{vector}",
        portable_fixtures,
        vector,
    )
    assert full == portable
    if vector in {
        "scripted_malformed",
        "scripted_probe_error",
        "scripted_symlink",
        "scripted_oversize",
        "scripted_surplus",
    }:
        rendered = "".join(stdout + stderr for _, _, stdout, stderr in full[0])
        assert str(tmp_path) not in rendered


def test_protocol_22_portable_scripted_fixture_uses_secure_regular_file_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Portable fixture reads never delegate to the following Path.read_bytes surface."""
    substrate = portable_runner._evaluation_substrate()
    fixture = tmp_path / "scripted.json"
    fixture.write_bytes(
        _canonical_bytes(
            {"fixture_type": "local-scripted-drafts-v2.2", "responses": []}
        )
    )

    def reject_following_read(_path: Path) -> bytes:
        raise AssertionError("Path.read_bytes must not load a scripted fixture")

    monkeypatch.setattr(Path, "read_bytes", reject_following_read)
    assert portable_runner._v22_scripted_fixture(substrate, fixture) == []


@pytest.mark.parametrize("vector", V2_PARITY_VECTORS)
def test_v2_parity_public_runner_contract(vector: str, tmp_path: Path) -> None:
    """Every protocol-2 vector has identical CLI bytes and a write-free refusal edge.

    The semantic payload variants live in the substrate differential table.  This
    public table deliberately runs under the two actual runners so a portable
    implementation cannot satisfy parity by borrowing the full controller.
    """
    full_run = tmp_path / f"full-{vector}"
    portable_run = tmp_path / f"portable-{vector}"
    if vector in _V2_VECTOR_EXECUTORS:
        vector_root = tmp_path / vector
        vector_root.mkdir()
        with _assert_v2_runner_command_parity():
            _V2_VECTOR_EXECUTORS[vector](vector_root)
        return
    if vector == "retained_protocol_1_3_replay":
        with _assert_v2_runner_command_parity():
            _initialize_eval_run(SKILL_RUNNER, full_run)
            _initialize_eval_run(PORTABLE_RUNNER, portable_run)
            for command in ("eval-status", "eval-verify"):
                full = _run_runner(SKILL_RUNNER, command, "--run", str(full_run))
                portable = _run_runner(PORTABLE_RUNNER, command, "--run", str(portable_run))
                assert (full.returncode, full.stdout, full.stderr) == (
                    portable.returncode,
                    portable.stdout,
                    portable.stderr,
                )
            assert _run_snapshot(full_run) == _run_snapshot(portable_run)
        return
    if vector == "unknown_protocol":
        with _assert_v2_runner_command_parity():
            for run in (full_run, portable_run):
                run.mkdir()
                (run / "run-manifest.json").write_bytes(
                    _canonical_bytes({"protocol_version": "9.9"})
                )
            before = (_run_snapshot(full_run), _run_snapshot(portable_run))
            full = _run_runner(SKILL_RUNNER, "eval-status", "--run", str(full_run))
            portable = _run_runner(PORTABLE_RUNNER, "eval-status", "--run", str(portable_run))
            assert (full.returncode, full.stdout, full.stderr) == (
                portable.returncode,
                portable.stdout,
                portable.stderr,
            )
            assert (_run_snapshot(full_run), _run_snapshot(portable_run)) == before
        return

    initialized: list[subprocess.CompletedProcess[str]] = []
    for runner, run in ((SKILL_RUNNER, full_run), (PORTABLE_RUNNER, portable_run)):
        initialized.append(
            _run_runner(
                runner,
                "eval-init",
                "--case",
                str(EVALUATION_FIXTURE / "case.json"),
                "--run",
                str(run),
                "--seed-hex",
                "6" * 64,
            )
        )
    full_init, portable_init = initialized
    assert (full_init.returncode, full_init.stdout, full_init.stderr) == (
        portable_init.returncode,
        portable_init.stdout,
        portable_init.stderr,
    )
    assert _run_snapshot(full_run) == _run_snapshot(portable_run)
    full_packet = _next_packet(SKILL_RUNNER, full_run)
    portable_packet = _next_packet(PORTABLE_RUNNER, portable_run)
    assert _canonical_bytes(full_packet) == _canonical_bytes(portable_packet)
    assert full_packet["operation"] == "source_review"
    assert (full_run / "result.json").exists() is (portable_run / "result.json").exists()

    invalid = tmp_path / f"invalid-{vector}.json"
    invalid.write_bytes(b"[]")
    before = (_run_snapshot(full_run), _run_snapshot(portable_run))
    full_refusal = _run_runner(
        SKILL_RUNNER, "eval-submit-safe", "--run", str(full_run), "--response", str(invalid)
    )
    portable_refusal = _run_runner(
        PORTABLE_RUNNER,
        "eval-submit-safe",
        "--run",
        str(portable_run),
        "--response",
        str(invalid),
    )
    assert (full_refusal.returncode, full_refusal.stdout, full_refusal.stderr) == (
        portable_refusal.returncode,
        portable_refusal.stdout,
        portable_refusal.stderr,
    )
    assert (_run_snapshot(full_run), _run_snapshot(portable_run)) == before


@pytest.mark.parametrize(
    ("core_issue", "safe_code"),
    [
        ("artifact hash mismatch: /private/report.md", "EVALUATION_INTEGRITY_INVALID"),
        ("run inventory changed during verification", "EVALUATION_INTEGRITY_INVALID"),
        (
            "EVALUATION_ARTIFACT_SCHEMA_UNSUPPORTED: run-manifest.json",
            "EVALUATION_ARTIFACT_SCHEMA_UNSUPPORTED",
        ),
        ("resolved grade schema version is unsupported", "EVALUATION_ARTIFACT_SCHEMA_UNSUPPORTED"),
        (
            "secure evaluation storage is unavailable on platform: simulated",
            "EVALUATION_STORAGE_PLATFORM_UNSUPPORTED",
        ),
        (
            "POSIX storage is unavailable on this platform",
            "EVALUATION_STORAGE_PLATFORM_UNSUPPORTED",
        ),
    ],
)
def test_eval_full_verification_mapping_has_only_portable_safe_codes(
    core_issue: str, safe_code: str
) -> None:
    """Core implementation detail must never become a runner-visible verification diagnostic."""
    assert skill_runner._safe_evaluation_verification_issues((core_issue,)) == [safe_code]


def test_eval_verify_simulated_unsupported_storage_is_a_safe_full_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A legacy storage boundary never causes protocol guessing or a write."""
    from regulatory_harvest.evaluation import attorney_artifacts

    full_run = tmp_path / "full-platform"
    _initialize_eval_run(SKILL_RUNNER, full_run)
    before = _run_snapshot(full_run)
    monkeypatch.setattr(attorney_artifacts, "_storage_platform", lambda: "simulated")

    assert skill_runner.main(["eval-verify", "--run", str(full_run)]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert json.loads(output.err)["code"] == "EVALUATION_PROTOCOL_UNSUPPORTED"
    assert _run_snapshot(full_run) == before


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("artifact", "EVALUATION_INTEGRITY_INVALID"),
        ("manifest", "EVALUATION_INTEGRITY_INVALID"),
        ("old-schema", "EVALUATION_ARTIFACT_SCHEMA_UNSUPPORTED"),
        ("mixed-schema", "EVALUATION_ARTIFACT_SCHEMA_UNSUPPORTED"),
        ("extra", "EVALUATION_INTEGRITY_INVALID"),
        ("missing", "EVALUATION_INTEGRITY_INVALID"),
    ],
)
def test_eval_verify_failure_surface_matches_portable_and_is_read_only(
    mutation: str, expected_code: str, tmp_path: Path
) -> None:
    """Malformed retained artifacts refuse safely and never mutate the run tree."""
    full_run = tmp_path / f"full-{mutation}"
    portable_run = tmp_path / f"portable-{mutation}"
    _initialize_eval_run(SKILL_RUNNER, full_run)
    _initialize_eval_run(PORTABLE_RUNNER, portable_run)

    def mutate(run: Path) -> None:
        if mutation == "artifact":
            target = run / "case-envelope.json"
            target.write_bytes(target.read_bytes() + b" ")
        elif mutation == "manifest":
            target = run / "run-manifest.json"
            target.write_bytes(target.read_bytes() + b" ")
        elif mutation in {"old-schema", "mixed-schema"}:
            target = run / "run-manifest.json"
            manifest = json.loads(target.read_text(encoding="utf-8"))
            manifest["schema_version"] = "1.0" if mutation == "old-schema" else "2.0"
            target.write_text(
                json.dumps(manifest, separators=(",", ":"), sort_keys=True), encoding="utf-8"
            )
        elif mutation == "extra":
            (run / "unexpected.json").write_text("{}", encoding="utf-8")
        else:
            (run / "judge-requests" / "admission-attempt-1.json").unlink()

    mutate(full_run)
    mutate(portable_run)

    full_before = _run_snapshot(full_run)
    portable_before = _run_snapshot(portable_run)
    full = _run_runner(SKILL_RUNNER, "eval-verify", "--run", str(full_run))
    portable = _run_runner(PORTABLE_RUNNER, "eval-verify", "--run", str(portable_run))
    assert (full.returncode, full.stdout, full.stderr) == (
        portable.returncode,
        portable.stdout,
        portable.stderr,
    )
    assert full.returncode == 5
    assert json.loads(full.stdout) == {"issues": [expected_code], "ok": False}
    assert full.stderr == ""
    assert _run_snapshot(full_run) == full_before
    assert _run_snapshot(portable_run) == portable_before


def test_retained_13_full_and_portable_replay_artifacts_match(tmp_path: Path) -> None:
    """A deterministically materialized 1.3 replay has identical read-only views."""
    full_run = tmp_path / "full"
    portable_run = tmp_path / "portable"
    _initialize_eval_run(SKILL_RUNNER, full_run)
    _initialize_eval_run(PORTABLE_RUNNER, portable_run)
    for command in ("eval-status", "eval-verify"):
        full = _run_runner(SKILL_RUNNER, command, "--run", str(full_run))
        portable = _run_runner(PORTABLE_RUNNER, command, "--run", str(portable_run))
        assert full.returncode == portable.returncode == 0
        assert full.stdout == portable.stdout
        assert full.stderr == portable.stderr == ""
    assert _run_snapshot(full_run) == _run_snapshot(portable_run)


def test_eval_cli_normalizes_omitted_defaults_and_preserves_raw_response_parity(
    tmp_path: Path,
) -> None:
    """Protocol-2.1 full submissions preserve their explicit semantic response bytes."""
    full_run = tmp_path / "full-defaults"
    initialized = _run_runner(
        SKILL_RUNNER, "eval-init", "--case", str(EVALUATION_FIXTURE / "case.json"),
        "--run", str(full_run), "--seed-hex", "0" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    packet = _next_packet(SKILL_RUNNER, full_run)
    response = _v21_source_review_response(packet)
    response_path = tmp_path / "source-review.json"
    response_path.write_bytes(_canonical_bytes(response))
    submitted = _run_runner(
        SKILL_RUNNER, "eval-submit", "--run", str(full_run), "--response", str(response_path)
    )
    assert submitted.returncode == 0, submitted.stderr
    stored = next((full_run / "responses").glob("*.json"))
    assert stored.read_bytes() == _canonical_bytes(response)


def test_eval_terminal_exit_codes_cover_fail_inconclusive_and_integrity(
    tmp_path: Path,
) -> None:
    """V2 exposes inconclusive and integrity exits without a legacy fail lifecycle."""
    inconclusive_run = tmp_path / "inconclusive"
    initialized = _run_runner(
        SKILL_RUNNER,
        "eval-init",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(inconclusive_run),
        "--seed-hex",
        "5" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    stopped = _run_runner(
        SKILL_RUNNER, "eval-stop-inconclusive", "--run", str(inconclusive_run),
        "--reason", "MECHANICAL_RESPONSE_INVALID",
    )
    assert stopped.returncode == 3
    (inconclusive_run / "inputs" / "case.json").write_text("{}", encoding="utf-8")
    tampered = _run_runner(SKILL_RUNNER, "eval-verify", "--run", str(inconclusive_run))
    assert tampered.returncode == 5


def test_full_eval_init_defaults_to_protocol_21_and_stop_is_bounded(tmp_path: Path) -> None:
    """The full entry point creates only Protocol 2.1 runs and exposes its stop edge."""
    run = tmp_path / "v21-run"
    initialized = _run_runner(
        SKILL_RUNNER,
        "eval-init",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(run),
        "--seed-hex",
        "7" * 64,
    )

    assert initialized.returncode == 0, initialized.stderr
    manifest = json.loads((run / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["protocol_version"] == "2.1"
    before = _run_snapshot(run)
    bad_stop = _run_runner(
        SKILL_RUNNER,
        "eval-stop-inconclusive",
        "--run",
        str(run),
        "--reason",
        "other",
    )
    assert bad_stop.returncode == 2
    assert json.loads(bad_stop.stderr)["code"] == "INVALID_ARGUMENTS"
    assert _run_snapshot(run) == before

    stopped = _run_runner(
        SKILL_RUNNER,
        "eval-stop-inconclusive",
        "--run",
        str(run),
        "--reason",
        "MECHANICAL_RESPONSE_INVALID",
    )
    assert stopped.returncode == 3, stopped.stderr
    assert json.loads(stopped.stdout)["terminal_status"] == "INCONCLUSIVE_MECHANICAL"


def test_full_retains_protocol_1_3_for_read_only_replay(tmp_path: Path) -> None:
    """A sealed legacy run can be read and replayed but never mutated by the full CLI."""
    run = tmp_path / "legacy-run"
    _initialize_eval_run(PORTABLE_RUNNER, run)
    before = _run_snapshot(run)

    status = _run_runner(SKILL_RUNNER, "eval-status", "--run", str(run))
    verified = _run_runner(SKILL_RUNNER, "eval-verify", "--run", str(run))
    mutation = _run("eval-next", "--run", str(run))

    assert status.returncode == verified.returncode == 0
    assert mutation.returncode == 2
    assert json.loads(mutation.stderr) == {
        "code": "EVALUATION_LEGACY_READ_ONLY",
        "message": "Protocol 1.3 evaluation runs are read-only.",
    }
    assert _run_snapshot(run) == before


@pytest.mark.parametrize(
    ("protocol", "initializer"),
    [
        ("1.3", _initialize_eval_run),
        ("2.0", lambda _runner, run: _initialize_v2_eval_run(run)),
    ],
)
def test_full_retained_protocols_preserve_status_verify_and_refuse_every_mutation(
    tmp_path: Path,
    protocol: str,
    initializer: object,
) -> None:
    """Retained runs are replay-only, including init when it targets their sealed root."""
    run = tmp_path / protocol.replace(".", "")
    assert callable(initializer)
    initializer(SKILL_RUNNER, run)
    before = _run_snapshot(run)
    first_status = _run_runner(SKILL_RUNNER, "eval-status", "--run", str(run))
    first_verify = _run_runner(SKILL_RUNNER, "eval-verify", "--run", str(run))
    second_status = _run_runner(SKILL_RUNNER, "eval-status", "--run", str(run))
    second_verify = _run_runner(SKILL_RUNNER, "eval-verify", "--run", str(run))
    assert (first_status.returncode, first_status.stdout, first_status.stderr) == (
        second_status.returncode,
        second_status.stdout,
        second_status.stderr,
    )
    assert (first_verify.returncode, first_verify.stdout, first_verify.stderr) == (
        second_verify.returncode,
        second_verify.stdout,
        second_verify.stderr,
    )
    response = tmp_path / "response.json"
    response.write_bytes(_canonical_bytes({}))
    mutations = (
        ("eval-init", "--case", str(EVALUATION_FIXTURE / "case.json"), "--seed-hex", "a" * 64),
        ("eval-next",),
        ("eval-preflight", "--response", str(response)),
        ("eval-submit", "--response", str(response)),
        ("eval-submit-safe", "--response", str(response)),
        ("eval-stop-inconclusive", "--reason", "MECHANICAL_RESPONSE_INVALID"),
        ("eval-resume", "--scripted-responses", str(response)),
    )
    for command in mutations:
        result = _run_runner(SKILL_RUNNER, *command, "--run", str(run))
        assert result.returncode == 2
        assert result.stdout == ""
        assert json.loads(result.stderr) == {
            "code": "EVALUATION_LEGACY_READ_ONLY",
            "message": f"Protocol {protocol} evaluation runs are read-only.",
        }
        assert _run_snapshot(run) == before


def test_retained_protocol_21_refuses_v22_init_and_resume_write_free(
    tmp_path: Path,
) -> None:
    run = tmp_path / "21"
    _initialize_v21_eval_run(run)
    before = _run_snapshot(run)
    fixture = tmp_path / "drafts.json"
    fixture.write_bytes(
        _canonical_bytes(
            {"fixture_type": "local-scripted-drafts-v2.2", "responses": []}
        )
    )

    init = _run_runner(
        SKILL_RUNNER,
        "eval-init",
        "--protocol",
        "2.2",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(run),
        "--seed-hex",
        "a" * 64,
    )
    resume = _run_runner(
        SKILL_RUNNER,
        "eval-resume",
        "--run",
        str(run),
        "--scripted-responses",
        str(fixture),
    )

    assert init.returncode == resume.returncode == 2
    assert json.loads(init.stderr)["code"] == "EVALUATION_LEGACY_READ_ONLY"
    assert json.loads(resume.stderr)["code"] == "EVALUATION_LEGACY_READ_ONLY"
    assert _run_snapshot(run) == before


def test_protocol_22_eval_init_is_explicit_and_default_remains_byte_exact_21(
    tmp_path: Path,
) -> None:
    omitted = tmp_path / "omitted"
    explicit = tmp_path / "explicit"
    experimental = tmp_path / "experimental"
    common = (
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--seed-hex",
        "4" * 64,
    )

    omitted_result = _run_runner(
        SKILL_RUNNER, "eval-init", *common, "--run", str(omitted)
    )
    explicit_result = _run_runner(
        SKILL_RUNNER,
        "eval-init",
        *common,
        "--run",
        str(explicit),
        "--protocol",
        "2.1",
    )
    experimental_result = _run_runner(
        SKILL_RUNNER,
        "eval-init",
        *common,
        "--run",
        str(experimental),
        "--protocol",
        "2.2",
    )

    assert omitted_result.returncode == explicit_result.returncode == 0
    assert _run_snapshot(omitted) == _run_snapshot(explicit)
    assert json.loads((omitted / "run-manifest.json").read_bytes())["protocol_version"] == "2.1"
    assert experimental_result.returncode == 0, experimental_result.stderr
    experimental_manifest = json.loads(
        (experimental / "run-manifest.json").read_bytes()
    )
    assert experimental_manifest["protocol_version"] == "2.2"
    assert experimental_manifest["terminal_status"] is None
    assert not (experimental / "result.json").exists()


def test_protocol_22_status_verify_and_external_refusal_are_safe_and_write_free(
    tmp_path: Path,
) -> None:
    run = tmp_path / "v22"
    initialized = _run_runner(
        SKILL_RUNNER,
        "eval-init",
        "--protocol",
        "2.2",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(run),
        "--seed-hex",
        "3" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    before = _run_snapshot(run)

    status = _run_runner(SKILL_RUNNER, "eval-status", "--run", str(run))
    verified = _run_runner(SKILL_RUNNER, "eval-verify", "--run", str(run))
    assert status.returncode == verified.returncode == 0
    expected_keys = {
        "compiler_contract_fingerprint",
        "manifest_root",
        "pending_call",
        "phase",
    }
    assert set(json.loads(status.stdout)) == expected_keys
    assert set(json.loads(verified.stdout)) == expected_keys
    assert str(tmp_path) not in status.stdout + verified.stdout
    assert _run_snapshot(run) == before

    invalid = tmp_path / "invalid.json"
    invalid.write_bytes(_canonical_bytes({"payload": "not-a-strict-envelope"}))
    for command in ("eval-preflight", "eval-submit", "eval-submit-safe"):
        refused = _run_runner(
            SKILL_RUNNER,
            command,
            "--run",
            str(run),
            "--response",
            str(invalid),
        )
        assert refused.returncode == 2
        assert _run_snapshot(run) == before
    assert not (run / "result.json").exists()


def test_protocol_22_full_resume_pauses_with_exact_pending_request(
    tmp_path: Path,
) -> None:
    run = tmp_path / "v22-resume"
    initialized = _run_runner(
        SKILL_RUNNER,
        "eval-init",
        "--protocol",
        "2.2",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(run),
        "--seed-hex",
        "2" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    pending = run / "requests" / "source-review-0001.json"
    pending_before = pending.read_bytes()
    request = json.loads(pending_before)
    scripted = tmp_path / "two-invalid-drafts.json"
    scripted.write_bytes(
        _canonical_bytes(
            {
                "fixture_type": "local-scripted-drafts-v2.2",
                "responses": [
                    {
                        "draft": {"malformed": "first-private-draft"},
                        "expect": {
                            "attempt": 1,
                            "clarification_codes": [],
                            "request_fingerprint": request["request_fingerprint"],
                        },
                        "operation": "source_review_fragment",
                    },
                    {
                        "draft": {"malformed": "second-private-draft"},
                        "expect": {
                            "attempt": 2,
                            "clarification_codes": ["SUBSTANCE_MISSING"],
                            "request_fingerprint": request["request_fingerprint"],
                        },
                        "operation": "source_review_fragment",
                    },
                ],
            }
        )
    )

    resumed = _run_runner(
        SKILL_RUNNER,
        "eval-resume",
        "--run",
        str(run),
        "--scripted-responses",
        str(scripted),
    )

    assert resumed.returncode == 6, resumed.stderr
    assert json.loads(resumed.stdout) == {
        "error": "evaluation_engine_paused",
        "ok": False,
        "pending_call": "source-review-fragment-0001",
    }
    assert pending.read_bytes() == pending_before
    assert not (run / "result.json").exists()


@pytest.mark.parametrize(
    "fixture_error", ["initial_exhaustion", "clarification_exhaustion", "malformed", "extra"]
)
def test_protocol_22_full_resume_scripted_input_errors_are_write_free(
    tmp_path: Path,
    fixture_error: str,
) -> None:
    run = tmp_path / f"v22-{fixture_error}"
    initialized = _run_runner(
        SKILL_RUNNER,
        "eval-init",
        "--protocol",
        "2.2",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(run),
        "--seed-hex",
        "1" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    request = json.loads((run / "requests" / "source-review-0001.json").read_bytes())
    first = {
        "draft": {"malformed": "first-private-draft"},
        "expect": {
            "attempt": 1,
            "clarification_codes": [],
            "request_fingerprint": request["request_fingerprint"],
        },
        "operation": "source_review_fragment",
    }
    second = {
        "draft": {"malformed": "second-private-draft"},
        "expect": {
            "attempt": 2,
            "clarification_codes": ["SUBSTANCE_MISSING"],
            "request_fingerprint": request["request_fingerprint"],
        },
        "operation": "source_review_fragment",
    }
    responses: object
    if fixture_error == "initial_exhaustion":
        responses = []
    elif fixture_error == "clarification_exhaustion":
        responses = [first]
    elif fixture_error == "malformed":
        responses = "not-an-array"
    else:
        responses = [
            first,
            second,
            {
                "draft": {"proposals": [], "review_complete": True},
                "expect": {
                    "attempt": 1,
                    "clarification_codes": [],
                    "request_fingerprint": "f" * 64,
                },
                "operation": "source_review_fragment",
            },
        ]
    scripted = tmp_path / f"{fixture_error}.json"
    scripted.write_bytes(
        _canonical_bytes(
            {"fixture_type": "local-scripted-drafts-v2.2", "responses": responses}
        )
    )
    before = _run_snapshot(run)

    resumed = _run_runner(
        SKILL_RUNNER,
        "eval-resume",
        "--run",
        str(run),
        "--scripted-responses",
        str(scripted),
    )

    assert resumed.returncode == 2
    assert resumed.stdout == ""
    assert json.loads(resumed.stderr)["code"] == "EVALUATION_INPUT_INVALID"
    assert _run_snapshot(run) == before


@pytest.mark.parametrize("probe_failure", ["construct", "copy", "read"])
def test_protocol_22_full_resume_probe_oserror_is_input_write_free(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    probe_failure: str,
) -> None:
    from regulatory_harvest.evaluation import attorney_cli

    run = tmp_path / f"full-probe-{probe_failure}"
    initialized = _run_runner(
        SKILL_RUNNER,
        "eval-init",
        "--protocol",
        "2.2",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(run),
        "--seed-hex",
        "1" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    request = json.loads(next((run / "requests").glob("*.json")).read_bytes())
    scripted = tmp_path / f"full-probe-{probe_failure}.json"
    scripted.write_bytes(
        _canonical_bytes(
            {
                "fixture_type": "local-scripted-drafts-v2.2",
                "responses": [
                    {
                        "draft": {"malformed": "first-private-draft"},
                        "expect": {
                            "attempt": 1,
                            "clarification_codes": [],
                            "request_fingerprint": request["request_fingerprint"],
                        },
                        "operation": request["operation"],
                    },
                    {
                        "draft": {"malformed": "second-private-draft"},
                        "expect": {
                            "attempt": 2,
                            "clarification_codes": ["SUBSTANCE_MISSING"],
                            "request_fingerprint": request["request_fingerprint"],
                        },
                        "operation": request["operation"],
                    },
                ],
            }
        )
    )
    if probe_failure == "construct":
        def fail_temporary_directory(*args: object, **kwargs: object) -> object:
            del args, kwargs
            raise OSError("synthetic probe construction failure")

        monkeypatch.setattr(
            attorney_cli.tempfile, "TemporaryDirectory", fail_temporary_directory
        )
    elif probe_failure == "copy":
        def fail_copy(*args: object, **kwargs: object) -> object:
            del args, kwargs
            raise OSError("synthetic probe copy failure")

        monkeypatch.setattr(attorney_cli.shutil, "copytree", fail_copy)
    else:
        async def fail_probe_read(*args: object, **kwargs: object) -> object:
            del args, kwargs
            try:
                raise OSError("synthetic probe read failure")
            except OSError as error:
                raise attorney_workflow.EvaluationIntegrityError(
                    "evaluation storage read failed"
                ) from error

        monkeypatch.setattr(attorney_cli, "continue_evaluation_v22", fail_probe_read)
    before = _run_snapshot(run)

    status = skill_runner.main(
        [
            "eval-resume",
            "--run",
            str(run),
            "--scripted-responses",
            str(scripted),
        ]
    )

    captured = capsys.readouterr()
    assert status == 2
    assert captured.out == ""
    assert json.loads(captured.err)["code"] == "EVALUATION_INPUT_INVALID"
    assert _run_snapshot(run) == before


def test_protocol_22_full_resume_provider_oserror_remains_verified_pause(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from regulatory_harvest.evaluation import attorney_cli

    run = tmp_path / "full-provider-oserror"
    initialized = _run_runner(
        SKILL_RUNNER,
        "eval-init",
        "--protocol",
        "2.2",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(run),
        "--seed-hex",
        "1" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    request = json.loads(next((run / "requests").glob("*.json")).read_bytes())
    scripted = tmp_path / "provider-oserror.json"
    scripted.write_bytes(
        _canonical_bytes(
            {
                "fixture_type": "local-scripted-drafts-v2.2",
                "responses": [
                    {
                        "draft": {"proposals": [], "review_complete": True},
                        "expect": {
                            "attempt": 1,
                            "clarification_codes": [],
                            "request_fingerprint": request["request_fingerprint"],
                        },
                        "operation": request["operation"],
                    }
                ],
            }
        )
    )
    original = attorney_cli._ScriptedFixtureDraftEvaluatorV22.evaluate_draft
    calls: dict[object, int] = {}

    async def provider_oserror(self: object, prompt: object) -> object:
        calls[self] = calls.get(self, 0) + 1
        raise OSError("synthetic provider failure")

    monkeypatch.setattr(
        attorney_cli._ScriptedFixtureDraftEvaluatorV22,
        "evaluate_draft",
        provider_oserror,
    )
    before = _run_snapshot(run)

    status = skill_runner.main(
        [
            "eval-resume",
            "--run",
            str(run),
            "--scripted-responses",
            str(scripted),
        ]
    )

    captured = capsys.readouterr()
    assert status == 6
    assert json.loads(captured.out)["pending_call"] == "source-review-fragment-0001"
    assert captured.err == ""
    assert _run_snapshot(run) == before
    assert calls
    monkeypatch.setattr(
        attorney_cli._ScriptedFixtureDraftEvaluatorV22,
        "evaluate_draft",
        original,
    )


def test_protocol_22_full_resume_corrupt_stored_run_is_integrity_write_free(
    tmp_path: Path,
) -> None:
    run = tmp_path / "full-corrupt-stored-resume"
    initialized = _run_runner(
        SKILL_RUNNER,
        "eval-init",
        "--protocol",
        "2.2",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(run),
        "--seed-hex",
        "1" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    pending = next((run / "requests").glob("*.json"))
    pending.write_bytes(pending.read_bytes() + b"\n")
    scripted = tmp_path / "corrupt-stored-resume.json"
    scripted.write_bytes(
        _canonical_bytes({"fixture_type": "local-scripted-drafts-v2.2", "responses": []})
    )
    before = _run_snapshot(run)

    resumed = _run_runner(
        SKILL_RUNNER,
        "eval-resume",
        "--run",
        str(run),
        "--scripted-responses",
        str(scripted),
    )

    assert resumed.returncode == 5
    assert resumed.stdout == ""
    assert json.loads(resumed.stderr)["code"] == "EVALUATION_INTEGRITY_INVALID"
    assert _run_snapshot(run) == before


@pytest.mark.parametrize("protocol", ["1.3", "2.0", "2.1"])
def test_protocol_22_full_eval_init_verifies_valid_retained_root_read_only(
    tmp_path: Path,
    protocol: str,
) -> None:
    run = tmp_path / f"full-valid-retained-{protocol.replace('.', '')}"
    if protocol == "1.3":
        _initialize_eval_run(SKILL_RUNNER, run)
    elif protocol == "2.0":
        _initialize_v2_eval_run(run)
    else:
        _initialize_v21_eval_run(run)
    before = _run_snapshot(run)

    result = _run_runner(
        SKILL_RUNNER,
        "eval-init",
        "--protocol",
        "2.2",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(run),
        "--seed-hex",
        "a" * 64,
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert json.loads(result.stderr)["code"] == "EVALUATION_LEGACY_READ_ONLY"
    assert _run_snapshot(run) == before


@pytest.mark.parametrize(
    ("protocol", "corruption"),
    [("1.3", "missing"), ("2.0", "tampered"), ("2.1", "mixed_inventory")],
)
def test_protocol_22_full_eval_init_rejects_corrupt_retained_root_integrity_write_free(
    tmp_path: Path,
    protocol: str,
    corruption: str,
) -> None:
    run = tmp_path / f"full-corrupt-retained-{protocol.replace('.', '')}"
    if protocol == "1.3":
        _initialize_eval_run(SKILL_RUNNER, run)
    elif protocol == "2.0":
        _initialize_v2_eval_run(run)
    else:
        _initialize_v21_eval_run(run)
    artifact = next(
        path for path in sorted(run.rglob("*"))
        if path.is_file() and path.name != "run-manifest.json"
    )
    if corruption == "missing":
        artifact.unlink()
    elif corruption == "tampered":
        artifact.write_bytes(artifact.read_bytes() + b"\n")
    else:
        (run / "v22-mixed-inventory.json").write_bytes(_canonical_bytes({}))
    before = _run_snapshot(run)

    result = _run_runner(
        SKILL_RUNNER,
        "eval-init",
        "--protocol",
        "2.2",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(run),
        "--seed-hex",
        "a" * 64,
    )

    assert result.returncode == 5
    assert result.stdout == ""
    assert json.loads(result.stderr)["code"] == "EVALUATION_INTEGRITY_INVALID"
    assert _run_snapshot(run) == before


@pytest.mark.parametrize(
    "manifest",
    [
        {"protocol_version": "9.9"},
        {
            "protocol_version": "2.1",
            "compiler_contract_fingerprint": "0" * 64,
        },
    ],
)
def test_protocol_22_full_eval_init_unknown_or_downgraded_marker_is_integrity_write_free(
    tmp_path: Path,
    manifest: dict[str, object],
) -> None:
    run = tmp_path / "full-invalid-marker"
    run.mkdir()
    (run / "run-manifest.json").write_bytes(_canonical_bytes(manifest))
    before = _run_snapshot(run)

    result = _run_runner(
        SKILL_RUNNER,
        "eval-init",
        "--protocol",
        "2.2",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(run),
        "--seed-hex",
        "a" * 64,
    )

    assert result.returncode == 5
    assert result.stdout == ""
    assert json.loads(result.stderr)["code"] == "EVALUATION_INTEGRITY_INVALID"
    assert _run_snapshot(run) == before


def test_full_eval_init_refuses_existing_sealed_13_before_empty_directory_guard(
    tmp_path: Path,
) -> None:
    """Init must recognize a sealed 1.3 target before attempting a v2 write."""
    legacy_run = tmp_path / "legacy-run"
    _initialize_eval_run(SKILL_RUNNER, legacy_run)
    before = _run_snapshot(legacy_run)
    refused = _run_runner(
        SKILL_RUNNER,
        "eval-init",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(legacy_run),
        "--seed-hex",
        "a" * 64,
    )
    assert refused.returncode == 2
    assert json.loads(refused.stderr) == {
        "code": "EVALUATION_LEGACY_READ_ONLY",
        "message": "Protocol 1.3 evaluation runs are read-only.",
    }
    assert refused.stdout == ""
    assert _run_snapshot(legacy_run) == before

    for name, manifest in (
        ("unknown", {"protocol_version": "9.9"}),
        ("noncanonical", {"protocol_version": "1.3", "padding": " "}),
    ):
        run = tmp_path / name
        run.mkdir()
        (run / "run-manifest.json").write_bytes(_canonical_bytes(manifest))
        before = _run_snapshot(run)
        result = _run_runner(
            SKILL_RUNNER,
            "eval-init",
            "--case",
            str(EVALUATION_FIXTURE / "case.json"),
            "--run",
            str(run),
            "--seed-hex",
            "b" * 64,
        )
        assert result.returncode == 2
        assert json.loads(result.stderr)["code"] == "EVALUATION_INPUT_INVALID"
        assert _run_snapshot(run) == before

    ordinary = tmp_path / "ordinary"
    ordinary.mkdir()
    (ordinary / "unrelated.txt").write_text("ordinary", encoding="utf-8")
    before = _run_snapshot(ordinary)
    result = _run_runner(
        SKILL_RUNNER,
        "eval-init",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(ordinary),
        "--seed-hex",
        "c" * 64,
    )
    assert result.returncode == 2
    assert json.loads(result.stderr)["code"] == "EVALUATION_INPUT_INVALID"
    assert _run_snapshot(ordinary) == before


def test_full_protocol_detector_refuses_unknown_manifest_without_writing(tmp_path: Path) -> None:
    """Manifest dispatch must not confuse an arbitrary run for either evaluator protocol."""
    run = tmp_path / "unknown-run"
    run.mkdir()
    (run / "run-manifest.json").write_bytes(_canonical_bytes({"protocol_version": "9.9"}))
    before = _run_snapshot(run)

    result = _run_runner(SKILL_RUNNER, "eval-status", "--run", str(run))

    assert result.returncode == 2
    assert json.loads(result.stderr) == {
        "code": "EVALUATION_PROTOCOL_UNSUPPORTED",
        "message": "The evaluation run protocol is unsupported.",
    }
    assert _run_snapshot(run) == before


@pytest.mark.parametrize(
    "response_bytes",
    [b"[]", b"{" + b"[" * 80 + b"]" * 80 + b"}", b"x" * (1024 * 1024 + 1)],
    ids=("raw", "deep", "oversized"),
)
def test_full_protocol_2_refusal_is_write_free_and_stable(
    tmp_path: Path, response_bytes: bytes
) -> None:
    """Raw, deeply nested, and oversized CLI inputs cannot alter a pending v2 run."""
    run = tmp_path / "v2-refusal"
    _initialize = _run_runner(
        SKILL_RUNNER,
        "eval-init",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(run),
        "--seed-hex",
        "8" * 64,
    )
    assert _initialize.returncode == 0, _initialize.stderr
    response = tmp_path / "invalid-response.json"
    response.write_bytes(response_bytes)
    before = _run_snapshot(run)

    first = _run_runner(
        SKILL_RUNNER, "eval-submit-safe", "--run", str(run), "--response", str(response)
    )
    second = _run_runner(
        SKILL_RUNNER, "eval-submit-safe", "--run", str(run), "--response", str(response)
    )

    assert first.returncode == second.returncode == 2
    assert first.stdout == second.stdout == (
        '{"accepted":false,"preflight":{"diagnostics":["MECHANICAL_RESPONSE_INVALID"],"valid":false}}\n'
    )
    assert first.stderr == second.stderr == ""
    assert _run_snapshot(run) == before


def test_full_protocol_2_normalizes_only_root_aliases_and_refuses_run_symlinks(
    tmp_path: Path,
) -> None:
    """Trusted root aliases read one run; an arbitrary run symlink is never followed."""
    run = tmp_path / "v2-root"
    initialized = _run_runner(
        SKILL_RUNNER,
        "eval-init",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(run),
        "--seed-hex",
        "9" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    before = _run_snapshot(run)
    direct = _run_runner(SKILL_RUNNER, "eval-status", "--run", str(run))
    assert direct.returncode == 0, direct.stderr
    if str(run).startswith("/private/") and Path("/var").is_symlink():
        root_alias = Path("/var" + str(run).removeprefix("/private/var"))
        aliased = _run_runner(SKILL_RUNNER, "eval-status", "--run", str(root_alias))
        assert aliased.returncode == 0
        assert aliased.stdout == direct.stdout
        assert aliased.stderr == direct.stderr == ""

    linked = tmp_path / "linked-run"
    try:
        linked.symlink_to(run, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"run symlinks are unavailable: {error}")
    refused = _run_runner(SKILL_RUNNER, "eval-status", "--run", str(linked))
    assert refused.returncode == 2
    assert json.loads(refused.stderr) == {
        "code": "EVALUATION_PROTOCOL_UNSUPPORTED",
        "message": "The evaluation run protocol is unsupported.",
    }
    assert _run_snapshot(run) == before


def _coverage_elements() -> dict[str, object]:
    return {
        "subject": {"status": "stated", "text": "controller"},
        "operative_rule": {"status": "stated", "text": "must comply"},
        "object": {"status": "stated", "text": "the stated requirement"},
        "trigger_or_threshold": {"status": "not_applicable", "text": None},
        "conditions_or_exceptions": {"status": "not_applicable", "text": None},
        "timing": {"status": "not_applicable", "text": None},
        "consequence_or_remedy": {"status": "not_applicable", "text": None},
        "authority_or_route": {"status": "not_applicable", "text": None},
    }


def _attach_covered_requirement(
    payload: dict[str, object],
    dossier: dict[str, Any],
    quote: str,
    claim_id: str,
) -> dict[str, object]:
    unit_ids = [
        str(unit["unit_id"])
        for unit in dossier["source_unit_inventory"]["units"]
        if quote in str(unit["excerpt"])
    ]
    lead_ids = [
        str(lead["lead_id"])
        for lead in dossier["evidence_inventory"]["leads"]
        if quote in str(lead["excerpt"])
    ]
    payload["coverage_contract_version"] = "proposition-coverage-v1"
    payload["proposition_coverage"] = [
        {
            "coverage_id": "coverage-requirement",
            "unit_ids": unit_ids,
            "lead_ids": lead_ids,
            "category": "requirements",
            "proposition_type": "duty",
            "disposition": "covered",
            "elements": _coverage_elements(),
            "claim_ids": [claim_id],
            "gap_codes": [],
            "rationale": None,
        }
    ]
    return payload


def _draft(dossier: dict[str, Any], quote: str) -> dict[str, object]:
    source_id = str(dossier["sources"][0]["source_id"])
    payload = {
        "issues": [
            {
                "issue_id": "issue-1",
                "title": "Documentation",
                "category": "requirements",
                "jurisdictions": ["US"],
            }
        ],
        "findings": [
            {
                "finding_id": "finding-1",
                "issue_id": "issue-1",
                "title": "Documentation finding",
                "jurisdiction": "US",
                "authority": "Synthetic Rule 1",
                "severity": "info",
                "practical_implication": "Document the requirement.",
                "claims": [
                    {
                        "claim_id": "claim-1",
                        "text": quote,
                        "kind": "source_supported",
                        "proposed_citations": [
                            {
                                "source_id": source_id,
                                "quote": quote,
                            }
                        ],
                    }
                ],
            }
        ],
        "gaps": [],
        "brief": {
            "structure_profile": "regulatory-walk-v1",
            "executive_summary": [
                {
                    "kind": "paragraph",
                    "purpose": "legal_analysis",
                    "text": quote,
                    "finding_ids": ["finding-1"],
                    "claim_ids": ["claim-1"],
                }
            ],
            "sections": [
                {
                    "section_id": "key-requirements",
                    "title": "Key Requirements",
                    "role": "key_requirements",
                    "blocks": [
                        {
                            "kind": "bullet_list",
                            "purpose": "legal_analysis",
                            "items": [
                                {
                                    "text": quote,
                                    "finding_ids": ["finding-1"],
                                    "claim_ids": ["claim-1"],
                                }
                            ],
                        }
                    ],
                },
                {
                    "section_id": "penalties-and-enforcement",
                    "title": "Penalties and Enforcement",
                    "role": "penalties_enforcement",
                    "blocks": [
                        {
                            "kind": "paragraph",
                            "purpose": "limitation",
                            "text": (
                                "Not established: The retained authority does not "
                                "establish penalties or enforcement mechanisms."
                            ),
                        }
                    ],
                },
                {
                    "section_id": "implementation-workplan",
                    "title": "Implementation Workplan",
                    "role": "implementation",
                    "blocks": [
                        {
                            "kind": "paragraph",
                            "purpose": "application",
                            "text": "Assign ownership and timing for the documentation duty.",
                            "finding_ids": ["finding-1"],
                        }
                    ],
                },
            ],
        },
    }
    return _attach_covered_requirement(payload, dossier, quote, "claim-1")


_ATOMIC_ELEMENT_FIELDS = (
    "actor",
    "modality",
    "operative_action",
    "object",
    "trigger",
    "threshold",
    "condition",
    "exception",
    "timing",
    "authority",
    "route",
    "consequence",
    "defined_term",
    "defined_meaning",
)


def _complete_v2_draft(dossier: dict[str, Any], quote: str) -> dict[str, object]:
    """Build one complete literal v2 duty over a one-unit synthetic source."""
    payload = _draft(dossier, quote)
    payload["coverage_contract_version"] = "proposition-coverage-v2"
    payload.pop("proposition_coverage")
    unit_ids = [
        str(unit["unit_id"])
        for unit in dossier["source_unit_inventory"]["units"]
    ]
    leads = list(dossier["evidence_inventory"]["leads"])
    lead_ids = [
        str(lead["lead_id"])
        for lead in leads
        if lead["issue_category"] == "requirements"
    ]
    dimensions = {
        "authority_status_timing": {"disposition": "not_present"},
        "actors_scope_activities": {
            "disposition": "mapped",
            "atom_ids": ["atom-duty"],
        },
        "definitions_categories": {"disposition": "not_present"},
        "duties_rights_prohibitions": {
            "disposition": "mapped",
            "atom_ids": ["atom-duty"],
        },
        "triggers_thresholds": {"disposition": "not_present"},
        "conditions_exceptions_defenses": {"disposition": "not_present"},
        "deadlines_transitions": {"disposition": "not_present"},
        "enforcement_remedies_consequences": {"disposition": "not_present"},
        "cross_references_dependencies": {"disposition": "not_present"},
    }
    elements = {
        field: {"status": "not_applicable"} for field in _ATOMIC_ELEMENT_FIELDS
    }
    for field, text in (
        ("actor", "a controller"),
        ("modality", "must"),
        ("operative_action", "document"),
        ("object", "risks"),
    ):
        elements[field] = {
            "status": "stated",
            "text": text,
            "claim_ids": ["claim-1"],
        }
    payload["unit_reviews"] = [
        {"unit_id": unit_id, "dimensions": dimensions} for unit_id in unit_ids
    ]
    payload["lead_dispositions_v2"] = [
        (
            {
                "lead_id": str(lead["lead_id"]),
                "disposition": "mapped",
                "atom_ids": ["atom-duty"],
            }
            if lead["issue_category"] == "requirements"
            else {
                "lead_id": str(lead["lead_id"]),
                "disposition": "not_material",
                "rationale": "The lead is navigational context for this synthetic duty.",
            }
        )
        for lead in leads
    ]
    payload["rule_atoms"] = [
        {
            "atom_id": "atom-duty",
            "unit_ids": unit_ids,
            "lead_ids": lead_ids,
            "category": "requirements",
            "proposition_type": "duty",
            "materiality": "critical",
            "elements": elements,
            "omission_rationale": "Omission would hide the operative duty.",
        }
    ]
    payload["rule_relationships"] = []
    brief = payload["brief"]
    assert isinstance(brief, dict)
    summary = brief["executive_summary"]
    assert isinstance(summary, list) and isinstance(summary[0], dict)
    summary[0]["atom_ids"] = ["atom-duty"]
    sections = brief["sections"]
    assert isinstance(sections, list) and isinstance(sections[0], dict)
    blocks = sections[0]["blocks"]
    assert isinstance(blocks, list) and isinstance(blocks[0], dict)
    items = blocks[0]["items"]
    assert isinstance(items, list) and isinstance(items[0], dict)
    items[0]["atom_ids"] = ["atom-duty"]
    return payload


def _set_dossier_contract(matter: Path, contract: object) -> dict[str, Any]:
    dossier_path = matter / "agent-dossier.json"
    dossier = json.loads(dossier_path.read_text(encoding="utf-8"))
    dossier["coverage_contract_version"] = contract
    dossier_path.write_text(json.dumps(dossier), encoding="utf-8")
    return dossier


def _append_covered_requirement(
    payload: dict[str, object],
    dossier: dict[str, Any],
    quote: str,
    index: int,
) -> None:
    claim_id = f"claim-{index}"
    source_id = next(
        str(source["source_id"])
        for source in dossier["sources"]
        if quote in str(source["normalized_text"])
    )
    findings = payload["findings"]
    assert isinstance(findings, list)
    finding = findings[0]
    assert isinstance(finding, dict)
    claims = finding["claims"]
    assert isinstance(claims, list)
    claims.append(
        {
            "claim_id": claim_id,
            "text": quote,
            "kind": "source_supported",
            "proposed_citations": [{"source_id": source_id, "quote": quote}],
        }
    )
    coverage_rows = payload["proposition_coverage"]
    assert isinstance(coverage_rows, list)
    unit_ids = [
        str(unit["unit_id"])
        for unit in dossier["source_unit_inventory"]["units"]
        if quote in str(unit["excerpt"])
    ]
    lead_ids = [
        str(lead["lead_id"])
        for lead in dossier["evidence_inventory"]["leads"]
        if quote in str(lead["excerpt"])
    ]
    coverage_rows.append(
        {
            "coverage_id": f"coverage-requirement-{index}",
            "unit_ids": unit_ids,
            "lead_ids": lead_ids,
            "category": "requirements",
            "proposition_type": "duty",
            "disposition": "covered",
            "elements": _coverage_elements(),
            "claim_ids": [claim_id],
            "gap_codes": [],
            "rationale": None,
        }
    )
    brief = payload["brief"]
    assert isinstance(brief, dict)
    executive_summary = brief["executive_summary"]
    assert isinstance(executive_summary, list)
    summary_block = executive_summary[0]
    assert isinstance(summary_block, dict)
    summary_claim_ids = summary_block["claim_ids"]
    assert isinstance(summary_claim_ids, list)
    summary_claim_ids.append(claim_id)
    sections = brief["sections"]
    assert isinstance(sections, list)
    requirements = sections[0]
    assert isinstance(requirements, dict)
    blocks = requirements["blocks"]
    assert isinstance(blocks, list)
    items = blocks[0]["items"]
    assert isinstance(items, list)
    item_claim_ids = items[0]["claim_ids"]
    assert isinstance(item_claim_ids, list)
    item_claim_ids.append(claim_id)


def test_prepare_turns_a_research_charter_into_an_agent_dossier(tmp_path: Path) -> None:
    """Requiring attorney-authored engine JSON would break the skill's natural-language shell."""
    source = tmp_path / "rule.txt"
    source.write_text(
        "A controller must document material risks before deployment.\n",
        encoding="utf-8",
    )
    charter = tmp_path / "research-charter.json"
    charter.write_text(json.dumps(_charter(source.name)), encoding="utf-8")
    matter = tmp_path / "matter"

    result = _run("prepare", "--charter", str(charter), "--matter", str(matter))

    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["status"] == "prepared"
    assert receipt["source_counts"] == {"failed": 0, "succeeded": 1}
    assert Path(receipt["dossier"]) == matter / "agent-dossier.json"

    request = json.loads((matter / "request.json").read_text(encoding="utf-8"))
    dossier = json.loads((matter / "agent-dossier.json").read_text(encoding="utf-8"))
    assert request["request_id"] == "synthetic-matter"
    assert request["question"] == _charter(source.name)["question"]
    assert request["source_mode"] == "provided-only"
    assert dossier["source_mode"] == "provided-only"
    assert dossier["sources"][0]["source_id"].startswith("src_")
    assert dossier["sources"][0]["normalized_text"] == (
        "A controller must document material risks before deployment."
    )
    inventory = dossier["evidence_inventory"]
    assert inventory["inventory_version"] == "provision-leads-v2"
    assert inventory["notice"] == "Heuristic research leads, not legal conclusions."
    assert {lead["topic"] for lead in inventory["leads"]} == {"duties"}
    assert receipt["evidence_lead_counts"] == {"duties": 1}
    assert receipt["priority_evidence_lead_counts"] == {"duties": 1}
    assert dossier["coverage_contract_version"] == "proposition-coverage-v2"
    source_units = dossier["source_unit_inventory"]
    assert source_units["inventory_version"] == "source-units-v1"
    assert source_units["required_unit_count"] >= 1
    assert receipt["source_unit_count"] == source_units["unit_count"]
    for unit in source_units["units"]:
        source_text = dossier["sources"][0]["normalized_text"]
        assert unit["excerpt"] == source_text[unit["start_char"] : unit["end_char"]]
    assert (matter / "runs" / "synthetic-matter" / "checkpoints" / "organize.json").is_file()


def test_prepare_source_unit_inventory_has_full_portable_parity(tmp_path: Path) -> None:
    """A portable prepare path must emit the same complete multilingual coverage target set."""
    source = tmp_path / "multilingual-rule.txt"
    source.write_text(
        "第十二条\n事業者は記録を保存する。監督機関は命令を発する。\n",
        encoding="utf-8",
    )
    charter = tmp_path / "research-charter.json"
    charter.write_text(json.dumps(_charter(source.name)), encoding="utf-8")
    full_matter = tmp_path / "full-matter"
    portable_matter = tmp_path / "portable-matter"

    full_result = _run("prepare", "--charter", str(charter), "--matter", str(full_matter))
    portable_result = _run_runner(
        PORTABLE_RUNNER,
        "prepare",
        "--charter",
        str(charter),
        "--matter",
        str(portable_matter),
    )

    assert full_result.returncode == 0, full_result.stderr
    assert portable_result.returncode == 0, portable_result.stderr
    full_dossier = json.loads((full_matter / "agent-dossier.json").read_text(encoding="utf-8"))
    portable_dossier = json.loads(
        (portable_matter / "agent-dossier.json").read_text(encoding="utf-8")
    )
    assert full_dossier["coverage_contract_version"] == "proposition-coverage-v2"
    assert portable_dossier["coverage_contract_version"] == "proposition-coverage-v2"
    assert full_dossier["source_unit_inventory"] == portable_dossier["source_unit_inventory"]


def _source_unit_source(
    text: str,
    *,
    source_id: str = "src_rule",
    source_role: str | None = "official_primary",
    source_quality: str | None = "primary",
) -> dict[str, object]:
    source: dict[str, object] = {
        "source_id": source_id,
        "fetch_status": "succeeded",
        "normalized_text": text,
    }
    if source_role is not None:
        source["source_role"] = source_role
    if source_quality is not None:
        source["source_quality"] = source_quality
    return source


@pytest.mark.parametrize(
    ("sources", "expected_eligible_count", "expected_unit_count", "expected_headings"),
    [
        pytest.param(
            [_source_unit_source("a," * 900)],
            1,
            2,
            [None, None],
            id="long-punctuation-boundary",
        ),
        pytest.param(
            [
                _source_unit_source(
                    "第十二条\n事業者は記録を保存する。監督機関は命令を発する\uff01\n\n"
                    "المادة 1\nيجب الاحتفاظ بالسجلات\u061b وتصدر الهيئة أمراً\u0964"
                )
            ],
            1,
            4,
            ["第十二条", "第十二条", "المادة 1", "المادة 1"],
            id="unicode-punctuation-and-headings",
        ),
        pytest.param(
            [
                _source_unit_source("A commentary summary.", source_role="commentary_analysis"),
                _source_unit_source(
                    "Unreadable.", source_id="src_unusable", source_quality="unusable"
                ),
            ],
            0,
            0,
            [],
            id="commentary-and-unusable-excluded",
        ),
        pytest.param(
            [
                _source_unit_source(
                    "Article 1\nA duty applies.\n\nArticle 1\nA second duty applies."
                )
            ],
            1,
            2,
            ["Article 1", "Article 1"],
            id="repeated-headings",
        ),
        pytest.param(
            [
                _source_unit_source(
                    "Unclassified source text remains reviewable.",
                    source_role=None,
                    source_quality=None,
                )
            ],
            1,
            1,
            [None],
            id="unknown-eligibility-defaults-to-covered",
        ),
    ],
)
def test_source_unit_inventory_has_full_portable_parity_at_required_boundaries(
    sources: list[dict[str, object]],
    expected_eligible_count: int,
    expected_unit_count: int,
    expected_headings: list[str | None],
) -> None:
    """The duplicated portable partitioner must not drift at required coverage boundaries."""
    full_inventory = build_source_unit_inventory(sources)
    portable_inventory = portable_runner._build_source_unit_inventory(sources)

    assert portable_inventory == full_inventory
    assert full_inventory["eligible_source_count"] == expected_eligible_count
    assert full_inventory["unit_count"] == expected_unit_count
    assert full_inventory["required_unit_count"] == expected_unit_count
    assert [unit["heading"] for unit in full_inventory["units"]] == expected_headings
    source_text_by_id = {source["source_id"]: source["normalized_text"] for source in sources}
    for unit in full_inventory["units"]:
        source_text = source_text_by_id[unit["source_id"]]
        assert isinstance(source_text, str)
        assert unit["excerpt"] == source_text[unit["start_char"] : unit["end_char"]]
        assert 0 <= unit["start_char"] < unit["end_char"] <= len(source_text)
        assert unit["end_char"] - unit["start_char"] <= 1_600


def test_prepare_rejects_an_unknown_source_mode_without_a_traceback(tmp_path: Path) -> None:
    """Silently treating an unknown mode as web-enabled could disclose matter information."""
    source = tmp_path / "rule.txt"
    source.write_text("Synthetic rule.\n", encoding="utf-8")
    payload = _charter(source.name)
    payload["source_mode"] = "surprise-network-mode"
    charter = tmp_path / "research-charter.json"
    charter.write_text(json.dumps(payload), encoding="utf-8")

    result = _run(
        "prepare",
        "--charter",
        str(charter),
        "--matter",
        str(tmp_path / "matter"),
    )

    assert result.returncode == 2
    error = json.loads(result.stderr)
    assert error["code"] == "INVALID_CHARTER"
    assert "source_mode" in error["message"]
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("matter_title", [None, "   "])
def test_prepare_requires_a_concrete_matter_title(
    tmp_path: Path,
    matter_title: str | None,
) -> None:
    """A new report must not fall back to a generic title because scoping omitted it."""
    source = tmp_path / "rule.txt"
    source.write_text("Synthetic rule.\n", encoding="utf-8")
    payload = _charter(source.name)
    if matter_title is None:
        payload.pop("matter_title")
    else:
        payload["matter_title"] = matter_title
    charter = tmp_path / "research-charter.json"
    charter.write_text(json.dumps(payload), encoding="utf-8")

    result = _run(
        "prepare",
        "--charter",
        str(charter),
        "--matter",
        str(tmp_path / "matter"),
    )

    assert result.returncode == 2
    error = json.loads(result.stderr)
    assert error["code"] == "INVALID_CHARTER"
    assert "matter_title" in error["message"]


def test_prepare_reports_an_invalid_as_of_date_as_a_charter_error(tmp_path: Path) -> None:
    """A bad date must be reported as a charter error, not an engine failure."""
    source = tmp_path / "rule.txt"
    source.write_text("Synthetic rule.\n", encoding="utf-8")
    payload = _charter(source.name)
    payload["as_of"] = "not-a-date"
    charter = tmp_path / "research-charter.json"
    charter.write_text(json.dumps(payload), encoding="utf-8")

    result = _run(
        "prepare",
        "--charter",
        str(charter),
        "--matter",
        str(tmp_path / "matter"),
    )

    assert result.returncode == 2
    error = json.loads(result.stderr)
    assert error["code"] == "INVALID_CHARTER"
    assert "as_of" in error["message"]


def test_prepare_can_rerun_after_the_charter_is_corrected(tmp_path: Path) -> None:
    """The documented source-repair loop must not conflict with an earlier checkpoint."""
    source = tmp_path / "rule.txt"
    source.write_text("Original synthetic rule.\n", encoding="utf-8")
    charter = tmp_path / "research-charter.json"
    payload = _charter(source.name)
    charter.write_text(json.dumps(payload), encoding="utf-8")
    matter = tmp_path / "matter"
    first = _run("prepare", "--charter", str(charter), "--matter", str(matter))
    assert first.returncode == 0, first.stderr

    source.write_text("Corrected synthetic rule.\n", encoding="utf-8")
    payload["question"] = "What does the corrected rule require?"
    charter.write_text(json.dumps(payload), encoding="utf-8")

    second = _run("prepare", "--charter", str(charter), "--matter", str(matter))

    assert second.returncode == 0, second.stderr
    dossier = json.loads((matter / "agent-dossier.json").read_text(encoding="utf-8"))
    assert dossier["request"]["question"] == "What does the corrected rule require?"
    assert dossier["sources"][0]["normalized_text"] == "Corrected synthetic rule."


def test_prepare_recognizes_a_windows_drive_path_as_a_local_source(tmp_path: Path) -> None:
    """A Windows drive letter must not be misclassified as a URL scheme."""
    payload = _charter("C:\\" + "Users\\Attorney\\rule.txt")
    charter = tmp_path / "research-charter.json"
    charter.write_text(json.dumps(payload), encoding="utf-8")

    result = _run(
        "prepare",
        "--charter",
        str(charter),
        "--matter",
        str(tmp_path / "matter"),
    )

    assert result.returncode == 2
    error = json.loads(result.stderr)
    assert error["code"] == "SOURCE_NOT_FOUND"


@pytest.mark.parametrize("managed_name", ["inputs", "runs", ".regulatory-harvest"])
def test_prepare_rejects_symlinked_managed_directories(
    tmp_path: Path,
    managed_name: str,
) -> None:
    """Managed writes must not escape the selected matter through a symlink."""
    source = tmp_path / "rule.txt"
    source.write_text("Synthetic rule.\n", encoding="utf-8")
    charter = tmp_path / "research-charter.json"
    charter.write_text(json.dumps(_charter(source.name)), encoding="utf-8")
    matter = tmp_path / "matter"
    matter.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        os.symlink(outside, matter / managed_name, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("directory symlinks are unavailable")

    result = _run("prepare", "--charter", str(charter), "--matter", str(matter))

    assert result.returncode == 2
    error = json.loads(result.stderr)
    assert error["code"] == "INVALID_MATTER"
    assert list(outside.iterdir()) == []


def test_new_prepare_and_matching_v2_finalize_complete(tmp_path: Path) -> None:
    quote = "A controller must document risks."
    source = tmp_path / "rule.txt"
    source.write_text(quote + "\n", encoding="utf-8")
    charter = tmp_path / "research-charter.json"
    charter.write_text(json.dumps(_charter(source.name)), encoding="utf-8")
    matter = tmp_path / "matter"

    prepared = _run("prepare", "--charter", str(charter), "--matter", str(matter))

    assert prepared.returncode == 0, prepared.stderr
    dossier = json.loads((matter / "agent-dossier.json").read_text(encoding="utf-8"))
    assert dossier["coverage_contract_version"] == "proposition-coverage-v2"
    draft = tmp_path / "draft.json"
    draft.write_text(json.dumps(_complete_v2_draft(dossier, quote)), encoding="utf-8")

    finalized = _run("finalize", "--matter", str(matter), "--draft", str(draft))

    assert finalized.returncode == 0, finalized.stderr
    receipt = json.loads(finalized.stdout)
    review_path = Path(receipt["coverage_review"])
    review = json.loads(review_path.read_text(encoding="utf-8"))
    assert review["schema_version"] == "3.0"
    assert review["coverage_contract_version"] == "proposition-coverage-v2"
    assert review["valid"] is True
    assert receipt["proposition_coverage_valid"] is True
    assert receipt["provision_recall_valid"] is True
    assert receipt["status"] == "completed"


def test_v2_finalize_coerces_numeric_source_datetime_with_portable_parity(
    tmp_path: Path,
) -> None:
    """A valid Pydantic-coercible dossier source must not strand portable review."""
    quote = "A controller must document risks."
    source = tmp_path / "rule.txt"
    source.write_text(quote + "\n", encoding="utf-8")
    charter = tmp_path / "research-charter.json"
    charter.write_text(json.dumps(_charter(source.name)), encoding="utf-8")
    matters = (tmp_path / "full-matter", tmp_path / "portable-matter")
    runners = (SKILL_RUNNER, PORTABLE_RUNNER)
    for runner, matter in zip(runners, matters, strict=True):
        prepared = _run_runner(
            runner,
            "prepare",
            "--charter",
            str(charter),
            "--matter",
            str(matter),
        )
        assert prepared.returncode == 0, prepared.stderr

    dossiers: list[dict[str, Any]] = []
    for matter in matters:
        dossier_path = matter / "agent-dossier.json"
        dossier = json.loads(dossier_path.read_text(encoding="utf-8"))
        dossier["sources"][0]["retrieved_at"] = 0
        dossier_path.write_text(json.dumps(dossier), encoding="utf-8")
        dossiers.append(dossier)
    assert dossiers[0]["coverage_contract_version"] == "proposition-coverage-v2"
    assert dossiers[0]["source_unit_inventory"] == dossiers[1]["source_unit_inventory"]
    assert dossiers[0]["evidence_inventory"] == dossiers[1]["evidence_inventory"]

    payload = _complete_v2_draft(dossiers[0], quote)
    drafts = (tmp_path / "full-draft.json", tmp_path / "portable-draft.json")
    for draft in drafts:
        draft.write_text(json.dumps(payload), encoding="utf-8")
    before = {
        path: path.read_bytes()
        for path in (
            matters[0] / "agent-dossier.json",
            matters[1] / "agent-dossier.json",
            *drafts,
        )
    }

    results = [
        _run_runner(
            runner,
            "finalize",
            "--matter",
            str(matter),
            "--draft",
            str(draft),
        )
        for runner, matter, draft in zip(runners, matters, drafts, strict=True)
    ]

    assert [result.returncode for result in results] == [0, 0]
    receipts = [json.loads(result.stdout) for result in results]
    reviews = [Path(receipt["coverage_review"]) for receipt in receipts]
    assert reviews[0].read_bytes() == reviews[1].read_bytes()
    for field in (
        "coverage_review_hash",
        "proposition_coverage_valid",
        "provision_recall_valid",
        "coverage_issue_count",
        "status",
    ):
        assert receipts[0][field] == receipts[1][field]
    portable_bundle_path = Path(receipts[1]["bundle"])
    portable_bundle = json.loads(portable_bundle_path.read_text(encoding="utf-8"))
    assert portable_bundle["sources"][0]["retrieved_at"] == "1970-01-01T00:00:00Z"
    assert portable_bundle["manifest"]["created_at"] == "1970-01-01T00:00:00Z"
    assert portable_bundle_path.read_bytes() == _canonical_bytes(portable_bundle) + b"\n"
    assert (matters[1] / "validation-receipt.json").read_bytes() == (
        _canonical_bytes(receipts[1]) + b"\n"
    )
    assert {path: path.read_bytes() for path in before} == before


@pytest.mark.parametrize(
    "draft_contract",
    [pytest.param("missing", id="missing"), None, "proposition-coverage-v1", "v3", ["v2"]],
)
def test_v2_dossier_draft_contract_variants_are_bounded_review(
    tmp_path: Path,
    draft_contract: object,
) -> None:
    quote = "A controller must document risks."
    source = tmp_path / "rule.txt"
    source.write_text(quote + "\n", encoding="utf-8")
    charter = tmp_path / "research-charter.json"
    charter.write_text(json.dumps(_charter(source.name)), encoding="utf-8")
    matter = tmp_path / "matter"
    prepared = _run("prepare", "--charter", str(charter), "--matter", str(matter))
    assert prepared.returncode == 0, prepared.stderr
    dossier = json.loads((matter / "agent-dossier.json").read_text(encoding="utf-8"))
    payload = _complete_v2_draft(dossier, quote)
    if draft_contract == "missing":
        payload.pop("coverage_contract_version")
    else:
        payload["coverage_contract_version"] = draft_contract
    draft = tmp_path / "draft.json"
    draft.write_text(json.dumps(payload), encoding="utf-8")
    before_dossier = (matter / "agent-dossier.json").read_bytes()
    before_draft = draft.read_bytes()

    result = _run("finalize", "--matter", str(matter), "--draft", str(draft))

    assert result.returncode == 4, result.stderr
    assert result.stderr == ""
    receipt = json.loads(result.stdout)
    review_path = Path(receipt["coverage_review"])
    review_bytes = review_path.read_bytes()
    review = json.loads(review_bytes)
    assert review["schema_version"] == "3.0"
    assert review["coverage_contract_version"] == "proposition-coverage-v2"
    assert review["valid"] is False
    assert {issue["code"] for issue in review["issues"]} >= {
        "ATOMIC_REVIEW_INVALID",
        "ATOMIC_RULE_INVALID",
    }
    frozen = dict(review)
    review_hash = frozen.pop("coverage_review_hash")
    assert review_hash == hashlib.sha256(_canonical_bytes(frozen)).hexdigest()
    assert receipt["coverage_review_hash"] == review_hash
    assert receipt["coverage_issue_count"] == len(review["issues"])
    assert receipt["proposition_coverage_valid"] is False
    assert receipt["provision_recall_valid"] is False
    assert receipt["status"] == "review-required"
    assert (matter / "agent-dossier.json").read_bytes() == before_dossier
    assert draft.read_bytes() == before_draft
    assert b"INVALID_DRAFT" not in result.stdout.encode() + result.stderr.encode()
    assert b"ENGINE_FAILURE" not in result.stdout.encode() + result.stderr.encode()


def test_v2_dossier_finalization_blocks_hybrid_legacy_ledgers_with_parity(
    tmp_path: Path,
) -> None:
    quote = "A controller must document risks."
    source = tmp_path / "rule.txt"
    source.write_text(quote + "\n", encoding="utf-8")
    charter = tmp_path / "research-charter.json"
    charter.write_text(json.dumps(_charter(source.name)), encoding="utf-8")
    full_matter = tmp_path / "full-matter"
    portable_matter = tmp_path / "portable-matter"
    assert _run(
        "prepare", "--charter", str(charter), "--matter", str(full_matter)
    ).returncode == 0
    assert _run_runner(
        PORTABLE_RUNNER,
        "prepare",
        "--charter",
        str(charter),
        "--matter",
        str(portable_matter),
    ).returncode == 0
    dossier = json.loads((full_matter / "agent-dossier.json").read_text(encoding="utf-8"))
    payload = _complete_v2_draft(dossier, quote)
    units = dossier["source_unit_inventory"]["units"]
    assert isinstance(units, list) and units
    payload["lead_reviews"] = [
        {
            "lead_id": "lead-legacy",
            "disposition": "not_material",
            "rationale": "Legacy review data cannot coexist with atomic coverage.",
        }
    ]
    payload["proposition_coverage"] = [
        {
            "coverage_id": "coverage-legacy",
            "unit_ids": [units[0]["unit_id"]],
            "category": "other",
            "proposition_type": "other",
            "disposition": "not_material",
            "rationale": "Legacy coverage data cannot coexist with atomic coverage.",
        }
    ]
    full_draft = tmp_path / "full-draft.json"
    portable_draft = tmp_path / "portable-draft.json"
    full_draft.write_text(json.dumps(payload), encoding="utf-8")
    portable_draft.write_text(json.dumps(payload), encoding="utf-8")
    before = {
        full_draft: full_draft.read_bytes(),
        portable_draft: portable_draft.read_bytes(),
        full_matter / "agent-dossier.json": (
            full_matter / "agent-dossier.json"
        ).read_bytes(),
        portable_matter / "agent-dossier.json": (
            portable_matter / "agent-dossier.json"
        ).read_bytes(),
    }

    full_result = _run(
        "finalize", "--matter", str(full_matter), "--draft", str(full_draft)
    )
    portable_result = _run_runner(
        PORTABLE_RUNNER,
        "finalize",
        "--matter",
        str(portable_matter),
        "--draft",
        str(portable_draft),
    )

    assert full_result.returncode == portable_result.returncode == 4
    assert full_result.stderr == portable_result.stderr == ""
    receipts = [json.loads(result.stdout) for result in (full_result, portable_result)]
    reviews = [json.loads(Path(receipt["coverage_review"]).read_bytes()) for receipt in receipts]
    assert reviews[0] == reviews[1]
    assert reviews[0]["issues"] == [
        {
            "code": "ATOMIC_REVIEW_INVALID",
            "message": (
                "A proposition-coverage-v2 draft cannot include legacy "
                "lead_reviews or proposition_coverage rows."
            ),
            "related_ids": [],
        }
    ]
    for receipt in receipts:
        assert receipt["coverage_issue_count"] == 1
        assert receipt["proposition_coverage_valid"] is False
        assert receipt["provision_recall_valid"] is False
        assert receipt["status"] == "review-required"
        assert Path(receipt["analysis_draft"]).is_file()
        assert Path(receipt["coverage_review"]).is_file()
        assert Path(receipt["report"]).is_file()
        assert Path(receipt["audit"]).is_file()
        assert Path(receipt["bundle"]).is_file()
    assert Path(receipts[0]["analysis_draft"]).read_bytes() == Path(
        receipts[1]["analysis_draft"]
    ).read_bytes()
    assert Path(receipts[0]["coverage_review"]).read_bytes() == Path(
        receipts[1]["coverage_review"]
    ).read_bytes()
    assert {path: path.read_bytes() for path in before} == before


def test_explicit_v1_dossier_selects_v1_when_draft_declares_v2(
    tmp_path: Path,
) -> None:
    quote = "A controller must document risks."
    source = tmp_path / "rule.txt"
    source.write_text(quote + "\n", encoding="utf-8")
    charter = tmp_path / "research-charter.json"
    charter.write_text(json.dumps(_charter(source.name)), encoding="utf-8")
    matter = tmp_path / "matter"
    prepared = _run("prepare", "--charter", str(charter), "--matter", str(matter))
    assert prepared.returncode == 0, prepared.stderr
    dossier = _set_dossier_contract(matter, "proposition-coverage-v1")
    draft = tmp_path / "draft.json"
    draft.write_text(json.dumps(_complete_v2_draft(dossier, quote)), encoding="utf-8")

    result = _run("finalize", "--matter", str(matter), "--draft", str(draft))

    assert result.returncode == 4, result.stderr
    receipt = json.loads(result.stdout)
    review = json.loads(Path(receipt["coverage_review"]).read_text(encoding="utf-8"))
    assert review["schema_version"] == "2.0"
    assert review["coverage_contract_version"] == "proposition-coverage-v1"
    assert review["valid"] is False
    assert receipt["status"] == "review-required"


def test_finalize_rejects_an_empty_source_inventory_draft(tmp_path: Path) -> None:
    """A hash-valid source inventory must not be delivered as substantive legal analysis."""
    source = tmp_path / "rule.txt"
    source.write_text("Synthetic rule.\n", encoding="utf-8")
    charter = tmp_path / "research-charter.json"
    charter.write_text(json.dumps(_charter(source.name)), encoding="utf-8")
    matter = tmp_path / "matter"
    prepared = _run("prepare", "--charter", str(charter), "--matter", str(matter))
    assert prepared.returncode == 0, prepared.stderr
    draft = tmp_path / "draft.json"
    draft.write_text('{"issues":[],"findings":[],"gaps":[]}', encoding="utf-8")

    result = _run("finalize", "--matter", str(matter), "--draft", str(draft))

    assert result.returncode == 2
    error = json.loads(result.stderr)
    assert error["code"] == "INCOMPLETE_DRAFT"
    assert "substantive finding" in error["message"]


def test_finalize_rejects_a_finding_without_source_supported_evidence(
    tmp_path: Path,
) -> None:
    """An empty finding shell must not turn a source inventory into completed research."""
    source = tmp_path / "rule.txt"
    source.write_text("Synthetic rule.\n", encoding="utf-8")
    charter = tmp_path / "research-charter.json"
    charter.write_text(json.dumps(_charter(source.name)), encoding="utf-8")
    matter = tmp_path / "matter"
    prepared = _run("prepare", "--charter", str(charter), "--matter", str(matter))
    assert prepared.returncode == 0, prepared.stderr
    draft = tmp_path / "draft.json"
    draft.write_text(
        json.dumps(
            {
                "issues": [
                    {
                        "issue_id": "issue-1",
                        "title": "Documentation",
                        "jurisdictions": ["US"],
                    }
                ],
                "findings": [
                    {
                        "finding_id": "finding-1",
                        "issue_id": "issue-1",
                        "title": "Empty finding",
                        "jurisdiction": "US",
                        "authority": "Synthetic Rule 1",
                        "severity": "info",
                        "practical_implication": "No supported implication.",
                        "claims": [],
                    }
                ],
                "gaps": [],
            }
        ),
        encoding="utf-8",
    )

    result = _run("finalize", "--matter", str(matter), "--draft", str(draft))

    assert result.returncode == 2
    error = json.loads(result.stderr)
    assert error["code"] == "INCOMPLETE_DRAFT"
    assert "source-supported claim" in error["message"]


def test_finalize_rejects_supported_findings_without_an_authored_brief(
    tmp_path: Path,
) -> None:
    """The installed skill must not fall back to the rejected generic report shape."""
    quote = "A controller must document risks."
    source = tmp_path / "rule.txt"
    source.write_text(quote + "\n", encoding="utf-8")
    charter = tmp_path / "research-charter.json"
    charter.write_text(json.dumps(_charter(source.name)), encoding="utf-8")
    matter = tmp_path / "matter"
    prepared = _run("prepare", "--charter", str(charter), "--matter", str(matter))
    assert prepared.returncode == 0, prepared.stderr
    dossier = json.loads((matter / "agent-dossier.json").read_text(encoding="utf-8"))
    payload = _draft(dossier, quote)
    payload.pop("brief")
    draft = tmp_path / "draft.json"
    draft.write_text(json.dumps(payload), encoding="utf-8")

    result = _run("finalize", "--matter", str(matter), "--draft", str(draft))

    assert result.returncode == 2
    error = json.loads(result.stderr)
    assert error["code"] == "INCOMPLETE_DRAFT"
    assert "attorney brief" in error["message"]


def test_finalize_recomputes_provenance_when_host_identity_changes(tmp_path: Path) -> None:
    """Corrected host/model provenance must invalidate the prior analysis checkpoints."""
    quote = "A controller must document risks."
    source = tmp_path / "rule.txt"
    source.write_text(quote + "\n", encoding="utf-8")
    charter = tmp_path / "research-charter.json"
    charter.write_text(json.dumps(_charter(source.name)), encoding="utf-8")
    matter = tmp_path / "matter"
    prepared = _run("prepare", "--charter", str(charter), "--matter", str(matter))
    assert prepared.returncode == 0, prepared.stderr
    dossier = json.loads((matter / "agent-dossier.json").read_text(encoding="utf-8"))
    draft = tmp_path / "draft.json"
    draft.write_text(
        json.dumps(_complete_v2_draft(dossier, quote)),
        encoding="utf-8",
    )
    first = _run(
        "finalize",
        "--matter",
        str(matter),
        "--draft",
        str(draft),
        "--host",
        "first-host",
        "--model",
        "first-model",
    )
    assert first.returncode == 0, first.stderr

    second = _run(
        "finalize",
        "--matter",
        str(matter),
        "--draft",
        str(draft),
        "--host",
        "corrected-host",
        "--model",
        "corrected-model",
    )

    assert second.returncode == 0, second.stderr
    receipt = json.loads(second.stdout)
    bundle = json.loads(Path(receipt["bundle"]).read_text(encoding="utf-8"))
    coverage_review = json.loads(Path(receipt["coverage_review"]).read_text(encoding="utf-8"))
    assert receipt["evidence_precision_valid"] is True
    assert receipt["provision_recall_valid"] is True
    assert coverage_review["valid"] is True
    assert coverage_review["schema_version"] == "3.0"
    assert coverage_review["counts"]["atoms"] == 1
    assert receipt["proposition_coverage_valid"] is True
    assert bundle["manifest"]["provider_metadata"] == {
        "model": "corrected-model",
        "model_provider": "corrected-host",
    }


def test_finalize_requires_review_for_an_unresolved_proposed_citation(
    tmp_path: Path,
) -> None:
    """One valid quote must not hide another unresolved evidence proposal."""
    quote = "A controller must document risks."
    source = tmp_path / "rule.txt"
    source.write_text(quote + "\n", encoding="utf-8")
    charter = tmp_path / "research-charter.json"
    charter.write_text(json.dumps(_charter(source.name)), encoding="utf-8")
    matter = tmp_path / "matter"
    prepared = _run("prepare", "--charter", str(charter), "--matter", str(matter))
    assert prepared.returncode == 0, prepared.stderr
    dossier = json.loads((matter / "agent-dossier.json").read_text(encoding="utf-8"))
    source_id = dossier["sources"][0]["source_id"]
    payload = _complete_v2_draft(dossier, quote)
    claims = payload["findings"][0]["claims"]  # type: ignore[index]
    claims[0]["proposed_citations"].append(  # type: ignore[index]
        {"source_id": source_id, "quote": "Text that is not in the source."}
    )
    draft = tmp_path / "draft.json"
    draft.write_text(json.dumps(payload), encoding="utf-8")

    result = _run("finalize", "--matter", str(matter), "--draft", str(draft))

    assert result.returncode == 4, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["valid"] is True
    assert receipt["status"] == "review-required"


def test_finalize_blocks_a_silent_penalty_omission_despite_a_category_gap(
    tmp_path: Path,
) -> None:
    """Precision-valid claims must not hide responsive enforcement text left untreated."""
    quote = "A controller must document risks."
    penalty = "A violation is subject to a civil penalty of $10,000."
    source = tmp_path / "rule.txt"
    source.write_text(f"{quote}\n\n{penalty}\n", encoding="utf-8")
    charter = tmp_path / "research-charter.json"
    charter.write_text(json.dumps(_charter(source.name)), encoding="utf-8")
    matter = tmp_path / "matter"
    prepared = _run("prepare", "--charter", str(charter), "--matter", str(matter))
    assert prepared.returncode == 0, prepared.stderr
    dossier = json.loads((matter / "agent-dossier.json").read_text(encoding="utf-8"))
    dossier = _set_dossier_contract(matter, "proposition-coverage-v1")
    payload = _draft(dossier, quote)
    draft = tmp_path / "draft.json"
    draft.write_text(json.dumps(payload), encoding="utf-8")

    result = _run("finalize", "--matter", str(matter), "--draft", str(draft))

    assert result.returncode == 4, result.stderr
    receipt = json.loads(result.stdout)
    review = json.loads(Path(receipt["coverage_review"]).read_text(encoding="utf-8"))
    assert receipt["valid"] is True
    assert receipt["evidence_precision_valid"] is True
    assert receipt["provision_recall_valid"] is False
    assert receipt["status"] == "review-required"
    unresolved = [
        item
        for item in review["lead_recall"]["issues"]
        if item["code"] == "PROVISION_LEAD_UNRESOLVED"
    ]
    assert len(unresolved) == 1
    lead_by_id = {lead["lead_id"]: lead for lead in dossier["evidence_inventory"]["leads"]}
    assert lead_by_id[unresolved[0]["lead_id"]]["topic"] == "remedies_penalties"


def test_new_contract_finalization_blocks_nonpriority_omission_then_repairs_with_parity(
    tmp_path: Path,
) -> None:
    """A failed complete-target sweep must stay repairable in both runtimes."""
    duties = [
        "A controller must document material risks before deployment.",
        "A controller shall retain the risk record for five years.",
        "A controller must review the record after a material change.",
        "A controller shall notify the oversight committee of the review.",
        "A controller must provide the record to an inspector on request.",
    ]
    source = tmp_path / "five-duties.txt"
    source.write_text("\n\n".join(duties) + "\n", encoding="utf-8")
    charter = tmp_path / "research-charter.json"
    charter.write_text(json.dumps(_charter(source.name)), encoding="utf-8")
    full_matter = tmp_path / "full-matter"
    portable_matter = tmp_path / "portable-matter"
    full_prepare = _run(
        "prepare", "--charter", str(charter), "--matter", str(full_matter)
    )
    portable_prepare = _run_runner(
        PORTABLE_RUNNER,
        "prepare",
        "--charter",
        str(charter),
        "--matter",
        str(portable_matter),
    )
    assert full_prepare.returncode == portable_prepare.returncode == 0
    dossier = _set_dossier_contract(full_matter, "proposition-coverage-v1")
    portable_dossier = _set_dossier_contract(
        portable_matter, "proposition-coverage-v1"
    )
    assert dossier["evidence_inventory"] == portable_dossier["evidence_inventory"]
    assert dossier["source_unit_inventory"] == portable_dossier["source_unit_inventory"]
    nonpriority = [
        lead
        for lead in dossier["evidence_inventory"]["leads"]
        if lead["review_required"] is False
    ]
    assert len(nonpriority) == 2

    payload = _draft(dossier, duties[0])
    for index, quote in enumerate(duties[1:4], start=2):
        _append_covered_requirement(payload, dossier, quote, index)
    full_draft = tmp_path / "full-draft.json"
    portable_draft = tmp_path / "portable-draft.json"
    full_draft.write_text(json.dumps(payload), encoding="utf-8")
    portable_draft.write_text(json.dumps(payload), encoding="utf-8")

    full_failed = _run(
        "finalize", "--matter", str(full_matter), "--draft", str(full_draft)
    )
    portable_failed = _run_runner(
        PORTABLE_RUNNER,
        "finalize",
        "--matter",
        str(portable_matter),
        "--draft",
        str(portable_draft),
    )

    assert full_failed.returncode == portable_failed.returncode == 4
    full_failed_receipt = json.loads(full_failed.stdout)
    portable_failed_receipt = json.loads(portable_failed.stdout)
    full_failed_review_path = Path(full_failed_receipt["coverage_review"])
    portable_failed_review_path = Path(portable_failed_receipt["coverage_review"])
    assert full_failed_review_path.read_bytes() == portable_failed_review_path.read_bytes()
    full_failed_review = json.loads(full_failed_review_path.read_text(encoding="utf-8"))
    assert full_failed_receipt["proposition_coverage_valid"] is False
    assert full_failed_receipt["provision_recall_valid"] is False
    assert full_failed_receipt["status"] == "review-required"
    assert full_failed_review["schema_version"] == "2.0"
    assert full_failed_review["lead_recall"]["valid"] is True
    assert full_failed_review["proposition_coverage"]["valid"] is False
    assert "COVERAGE_TARGET_UNRESOLVED" in {
        issue["code"]
        for issue in full_failed_review["proposition_coverage"]["issues"]
    }
    assert full_failed_receipt["coverage_issue_count"] == len(
        full_failed_review["lead_recall"]["issues"]
    ) + len(full_failed_review["proposition_coverage"]["issues"])
    for field in (
        "coverage_review_hash",
        "proposition_coverage_valid",
        "provision_recall_valid",
        "coverage_issue_count",
        "status",
    ):
        assert full_failed_receipt[field] == portable_failed_receipt[field]

    _append_covered_requirement(payload, dossier, duties[4], 5)
    full_draft.write_text(json.dumps(payload), encoding="utf-8")
    portable_draft.write_text(json.dumps(payload), encoding="utf-8")
    full_repaired = _run(
        "finalize", "--matter", str(full_matter), "--draft", str(full_draft)
    )
    portable_repaired = _run_runner(
        PORTABLE_RUNNER,
        "finalize",
        "--matter",
        str(portable_matter),
        "--draft",
        str(portable_draft),
    )

    assert full_repaired.returncode == portable_repaired.returncode == 0
    full_repaired_receipt = json.loads(full_repaired.stdout)
    portable_repaired_receipt = json.loads(portable_repaired.stdout)
    assert Path(full_repaired_receipt["coverage_review"]).read_bytes() == Path(
        portable_repaired_receipt["coverage_review"]
    ).read_bytes()
    assert full_repaired_receipt["proposition_coverage_valid"] is True
    assert full_repaired_receipt["provision_recall_valid"] is True
    assert full_repaired_receipt["status"] == "completed"
    assert full_repaired_receipt["coverage_issue_count"] == 0
    for field in (
        "coverage_review_hash",
        "proposition_coverage_valid",
        "provision_recall_valid",
        "coverage_issue_count",
        "status",
    ):
        assert full_repaired_receipt[field] == portable_repaired_receipt[field]


def test_legacy_finalization_preserves_schema_one_and_null_proposition_status(
    tmp_path: Path,
) -> None:
    quote = "A controller must document risks."
    source = tmp_path / "legacy-rule.txt"
    source.write_text(quote + "\n", encoding="utf-8")
    charter = tmp_path / "research-charter.json"
    charter.write_text(json.dumps(_charter(source.name)), encoding="utf-8")
    full_matter = tmp_path / "full-legacy-matter"
    portable_matter = tmp_path / "portable-legacy-matter"
    prepared = _run(
        "prepare", "--charter", str(charter), "--matter", str(full_matter)
    )
    portable_prepared = _run_runner(
        PORTABLE_RUNNER,
        "prepare",
        "--charter",
        str(charter),
        "--matter",
        str(portable_matter),
    )
    assert prepared.returncode == portable_prepared.returncode == 0
    full_dossier_path = full_matter / "agent-dossier.json"
    portable_dossier_path = portable_matter / "agent-dossier.json"
    dossier = json.loads(full_dossier_path.read_text(encoding="utf-8"))
    portable_dossier = json.loads(portable_dossier_path.read_text(encoding="utf-8"))
    payload = _draft(dossier, quote)
    dossier.pop("coverage_contract_version")
    dossier.pop("source_unit_inventory")
    portable_dossier.pop("coverage_contract_version")
    portable_dossier.pop("source_unit_inventory")
    payload.pop("coverage_contract_version")
    payload.pop("proposition_coverage")
    full_dossier_path.write_text(json.dumps(dossier), encoding="utf-8")
    portable_dossier_path.write_text(json.dumps(portable_dossier), encoding="utf-8")
    full_draft = tmp_path / "full-legacy-draft.json"
    portable_draft = tmp_path / "portable-legacy-draft.json"
    full_draft.write_text(json.dumps(payload), encoding="utf-8")
    portable_draft.write_text(json.dumps(payload), encoding="utf-8")

    result = _run(
        "finalize", "--matter", str(full_matter), "--draft", str(full_draft)
    )
    portable_result = _run_runner(
        PORTABLE_RUNNER,
        "finalize",
        "--matter",
        str(portable_matter),
        "--draft",
        str(portable_draft),
    )

    assert result.returncode == portable_result.returncode == 0
    receipt = json.loads(result.stdout)
    portable_receipt = json.loads(portable_result.stdout)
    review = json.loads(Path(receipt["coverage_review"]).read_text(encoding="utf-8"))
    assert Path(receipt["coverage_review"]).read_bytes() == Path(
        portable_receipt["coverage_review"]
    ).read_bytes()
    assert receipt["proposition_coverage_valid"] is None
    assert receipt["provision_recall_valid"] is True
    assert receipt["status"] == "completed"
    assert review["schema_version"] == "1.0"
    assert review["resolved_counts"] == {"finding": 1}
    assert "proposition_coverage" not in review
    for field in (
        "coverage_review_hash",
        "proposition_coverage_valid",
        "provision_recall_valid",
        "coverage_issue_count",
        "status",
    ):
        assert receipt[field] == portable_receipt[field]


def test_explicit_v1_legacy_replay_preserves_every_finalization_byte(
    tmp_path: Path,
) -> None:
    quote = "A controller must document risks."
    source = tmp_path / "legacy-rule.txt"
    source.write_text(quote + "\n", encoding="utf-8")
    charter = tmp_path / "research-charter.json"
    charter.write_text(json.dumps(_charter(source.name)), encoding="utf-8")
    matter = tmp_path / "matter"
    prepared = _run("prepare", "--charter", str(charter), "--matter", str(matter))
    assert prepared.returncode == 0, prepared.stderr
    dossier = _set_dossier_contract(matter, "proposition-coverage-v1")
    draft = tmp_path / "legacy-draft.json"
    draft.write_text(json.dumps(_draft(dossier, quote)), encoding="utf-8")
    dossier_before = (matter / "agent-dossier.json").read_bytes()
    draft_before = draft.read_bytes()

    first = _run(
        "finalize",
        "--matter",
        str(matter),
        "--draft",
        str(draft),
        "--host",
        "legacy-host",
        "--model",
        "legacy-model",
    )

    assert first.returncode == 0, first.stderr
    first_receipt = json.loads(first.stdout)
    paths = {
        "analysis_draft": Path(first_receipt["analysis_draft"]),
        "audit": Path(first_receipt["audit"]),
        "bundle": Path(first_receipt["bundle"]),
        "coverage_review": Path(first_receipt["coverage_review"]),
        "report": Path(first_receipt["report"]),
        "validation_receipt": matter / "validation-receipt.json",
    }
    first_bytes = {name: path.read_bytes() for name, path in paths.items()}

    replay = _run(
        "finalize",
        "--matter",
        str(matter),
        "--draft",
        str(draft),
        "--host",
        "legacy-host",
        "--model",
        "legacy-model",
    )

    assert replay.returncode == 0, replay.stderr
    assert replay.stdout == first.stdout
    assert {name: path.read_bytes() for name, path in paths.items()} == first_bytes
    assert (matter / "agent-dossier.json").read_bytes() == dossier_before
    assert draft.read_bytes() == draft_before
    review = json.loads(first_bytes["coverage_review"])
    assert review["schema_version"] == "2.0"
    assert review["coverage_contract_version"] == "proposition-coverage-v1"
    assert first_receipt["proposition_coverage_valid"] is True
    assert first_receipt["status"] == "completed"


def test_multi_source_structured_brief_finalization_has_canonical_portable_parity(
    tmp_path: Path,
) -> None:
    first_quote = "A controller must maintain a written register."
    second_quote = "A controller must notify affected persons."
    first_source = tmp_path / "first-rule.txt"
    second_source = tmp_path / "second-rule.txt"
    first_source.write_text(first_quote + "\n", encoding="utf-8")
    second_source.write_text(second_quote + "\n", encoding="utf-8")
    charter_payload = _charter(first_source.name)
    sources = charter_payload["sources"]
    assert isinstance(sources, list)
    second_input = dict(sources[0])
    second_input["location"] = second_source.name
    second_input["title"] = "Synthetic Notice Rule"
    second_input["citation"] = "Synthetic Rule 2"
    sources.append(second_input)
    charter = tmp_path / "research-charter.json"
    charter.write_text(json.dumps(charter_payload), encoding="utf-8")
    full_matter = tmp_path / "full-matter"
    portable_matter = tmp_path / "portable-matter"
    assert _run(
        "prepare", "--charter", str(charter), "--matter", str(full_matter)
    ).returncode == 0
    assert _run_runner(
        PORTABLE_RUNNER,
        "prepare",
        "--charter",
        str(charter),
        "--matter",
        str(portable_matter),
    ).returncode == 0
    dossier = _set_dossier_contract(full_matter, "proposition-coverage-v1")
    _set_dossier_contract(portable_matter, "proposition-coverage-v1")
    first_quote = str(dossier["sources"][0]["normalized_text"])
    second_quote = str(dossier["sources"][1]["normalized_text"])
    payload = _draft(dossier, first_quote)
    _append_covered_requirement(payload, dossier, second_quote, 2)
    brief = payload["brief"]
    assert isinstance(brief, dict)
    sections = brief["sections"]
    assert isinstance(sections, list)
    requirements = sections[0]
    requirements["subsections"] = [
        {
            "subsection_id": "cross-source-duties",
            "title": "Cross-source duties",
            "blocks": [
                {
                    "kind": "table",
                    "purpose": "legal_analysis",
                        "columns": ["Duty", "Status"],
                        "rows": [
                            {
                                "cells": [first_quote, second_quote],
                                "claim_ids": ["claim-1", "claim-2"],
                                "finding_ids": ["finding-1"],
                        }
                    ],
                }
            ],
        }
    ]
    full_draft = tmp_path / "full-draft.json"
    portable_draft = tmp_path / "portable-draft.json"
    full_draft.write_text(json.dumps(payload), encoding="utf-8")
    portable_draft.write_text(json.dumps(payload), encoding="utf-8")

    full_result = _run(
        "finalize", "--matter", str(full_matter), "--draft", str(full_draft)
    )
    portable_result = _run_runner(
        PORTABLE_RUNNER,
        "finalize",
        "--matter",
        str(portable_matter),
        "--draft",
        str(portable_draft),
    )

    assert full_result.returncode == portable_result.returncode == 0
    full_receipt = json.loads(full_result.stdout)
    portable_receipt = json.loads(portable_result.stdout)
    full_review_path = Path(full_receipt["coverage_review"])
    portable_review_path = Path(portable_receipt["coverage_review"])
    assert full_review_path.read_bytes() == portable_review_path.read_bytes()
    review = json.loads(full_review_path.read_text(encoding="utf-8"))
    assert review["proposition_coverage"]["valid"] is True
    locations = {
        location
        for row in review["proposition_coverage"]["rows"]
        for location in row["brief_locations"]
    }
    assert "brief.sections[0].subsections[0].blocks[0].rows[0]" in locations
    for field in (
        "coverage_review_hash",
        "proposition_coverage_valid",
        "provision_recall_valid",
        "coverage_issue_count",
        "status",
    ):
        assert full_receipt[field] == portable_receipt[field]


@pytest.mark.parametrize(
    "dossier_mutation",
    [
        "missing_contract_only",
        "mismatched_contract",
        "missing_units_only",
        "malformed_units",
        "null_contract_without_units",
    ],
)
def test_only_dossiers_lacking_both_new_fields_may_use_legacy_finalization(
    tmp_path: Path,
    dossier_mutation: str,
) -> None:
    quote = "A controller must document risks."
    source = tmp_path / "rule.txt"
    source.write_text(quote + "\n", encoding="utf-8")
    charter = tmp_path / "research-charter.json"
    charter.write_text(json.dumps(_charter(source.name)), encoding="utf-8")
    full_matter = tmp_path / "full-matter"
    portable_matter = tmp_path / "portable-matter"
    assert _run(
        "prepare", "--charter", str(charter), "--matter", str(full_matter)
    ).returncode == 0
    assert _run_runner(
        PORTABLE_RUNNER,
        "prepare",
        "--charter",
        str(charter),
        "--matter",
        str(portable_matter),
    ).returncode == 0
    full_dossier_path = full_matter / "agent-dossier.json"
    portable_dossier_path = portable_matter / "agent-dossier.json"
    dossier = json.loads(full_dossier_path.read_text(encoding="utf-8"))
    payload = _draft(dossier, quote)
    if dossier_mutation == "missing_contract_only":
        dossier.pop("coverage_contract_version")
    elif dossier_mutation == "mismatched_contract":
        dossier["coverage_contract_version"] = "proposition-coverage-v3"
    elif dossier_mutation == "missing_units_only":
        dossier.pop("source_unit_inventory")
    elif dossier_mutation == "malformed_units":
        dossier["source_unit_inventory"] = []
    else:
        dossier["coverage_contract_version"] = None
        dossier.pop("source_unit_inventory")
    full_dossier_path.write_text(json.dumps(dossier), encoding="utf-8")
    portable_dossier_path.write_text(json.dumps(dossier), encoding="utf-8")
    full_draft = tmp_path / "full-draft.json"
    portable_draft = tmp_path / "portable-draft.json"
    full_draft.write_text(json.dumps(payload), encoding="utf-8")
    portable_draft.write_text(json.dumps(payload), encoding="utf-8")

    full_result = _run(
        "finalize", "--matter", str(full_matter), "--draft", str(full_draft)
    )
    portable_result = _run_runner(
        PORTABLE_RUNNER,
        "finalize",
        "--matter",
        str(portable_matter),
        "--draft",
        str(portable_draft),
    )

    assert full_result.returncode == portable_result.returncode == 2
    full_error = json.loads(full_result.stderr)
    portable_error = json.loads(portable_result.stderr)
    assert full_error["code"] == portable_error["code"] == "INVALID_DOSSIER"
    assert not (full_matter / "coverage-review.json").exists()
    assert not (portable_matter / "coverage-review.json").exists()


@pytest.mark.parametrize(
    ("draft_contract", "expected_valid"),
    [("proposition-coverage-v2", True), ("missing", False)],
)
def test_full_v2_finalization_writes_coverage_review_before_report_pipeline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    draft_contract: str,
    expected_valid: bool,
) -> None:
    quote = "A controller must document risks."
    source = tmp_path / "rule.txt"
    source.write_text(quote + "\n", encoding="utf-8")
    charter = tmp_path / "research-charter.json"
    charter.write_text(json.dumps(_charter(source.name)), encoding="utf-8")
    matter = tmp_path / "matter"
    prepared = _run("prepare", "--charter", str(charter), "--matter", str(matter))
    assert prepared.returncode == 0, prepared.stderr
    dossier = json.loads((matter / "agent-dossier.json").read_text(encoding="utf-8"))
    draft = tmp_path / "draft.json"
    payload = _complete_v2_draft(dossier, quote)
    if draft_contract == "missing":
        payload.pop("coverage_contract_version")
    draft.write_text(json.dumps(payload), encoding="utf-8")

    def fail_report_pipeline(*args: object, **kwargs: object) -> None:
        raise RuntimeError("synthetic report pipeline failure")

    monkeypatch.setattr(skill_runner, "run_research_sync", fail_report_pipeline)
    with pytest.raises(RuntimeError, match="synthetic report pipeline failure"):
        skill_runner.finalize(
            matter,
            draft,
            host_name="test-host",
            model_name="test-model",
        )

    review = json.loads((matter / "coverage-review.json").read_text(encoding="utf-8"))
    assert review["schema_version"] == "3.0"
    assert review["valid"] is expected_valid


def test_full_v2_report_validation_failure_preserves_the_written_coverage_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    quote = "A controller must document risks."
    source = tmp_path / "rule.txt"
    source.write_text(quote + "\n", encoding="utf-8")
    charter = tmp_path / "research-charter.json"
    charter.write_text(json.dumps(_charter(source.name)), encoding="utf-8")
    matter = tmp_path / "matter"
    prepared = _run("prepare", "--charter", str(charter), "--matter", str(matter))
    assert prepared.returncode == 0, prepared.stderr
    dossier = json.loads((matter / "agent-dossier.json").read_text(encoding="utf-8"))
    draft = tmp_path / "draft.json"
    draft.write_text(json.dumps(_complete_v2_draft(dossier, quote)), encoding="utf-8")

    class InvalidReportValidation:
        valid = False
        issues = ("synthetic report validation failure",)

    monkeypatch.setattr(
        skill_runner,
        "validate_research_bundle",
        lambda path: InvalidReportValidation(),
    )

    receipt, status = skill_runner.finalize(
        matter,
        draft,
        host_name="test-host",
        model_name="test-model",
    )

    review = json.loads((matter / "coverage-review.json").read_text(encoding="utf-8"))
    assert review["schema_version"] == "3.0"
    assert review["valid"] is True
    assert receipt["coverage_review_hash"] == review["coverage_review_hash"]
    assert receipt["validation_issue_count"] == 1
    assert receipt["status"] == "review-required"
    assert status == 4
