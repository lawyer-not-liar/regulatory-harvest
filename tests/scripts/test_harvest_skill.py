import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from regulatory_harvest.analysis import (
    AnalysisDraft,
    build_source_unit_inventory,
    evaluate_atomic_coverage,
)
from regulatory_harvest.evaluation import attorney_generation, attorney_workflow
from regulatory_harvest.models import SourceRecord
from regulatory_harvest.storage import canonical_json_bytes

ROOT = Path(__file__).parents[2]
SKILL_RUNNER = ROOT / "scripts" / "harvest_skill.py"
PORTABLE_RUNNER = ROOT / "scripts" / "harvest_portable.py"
EVALUATION_FIXTURE = ROOT / "tests" / "fixtures" / "attorney-eval"
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


def _run_runner(runner: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(runner), *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


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


def _initialize_eval_run(runner: Path, run: Path) -> None:
    initialized = _run_runner(
        runner,
        "eval-init",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(run),
        "--seed-hex",
        "7" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr


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
        "one initial response and at most two mechanical repairs",
        "stop when the same diagnostic code occurs twice",
        "never retry an unfavorable substantive judgment",
        "accept an unfavorable substantive result without retry",
        "verify terminal evaluation artifacts",
        "start every mechanical repair in a genuinely fresh role context",
        "stop rather than repair in the same role context",
    ):
        assert required_contract in instructions
    assert "qualification readiness is not a report-quality pass" in instructions
    assert "changing any source byte creates a new versioned case" in instructions


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
    evaluation_initialized = _run_runner(
        SKILL_RUNNER,
        "eval-init",
        "--case",
        str(fixture["evaluation_case"]),
        "--run",
        str(evaluation_run.resolve()),
        "--seed-hex",
        "7" * 64,
    )
    assert evaluation_initialized.returncode == 0, evaluation_initialized.stderr
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
    scripted = json.loads(
        (EVALUATION_FIXTURE / "responses" / "scripted-responses.json").read_text(
            encoding="utf-8"
        )
    )["responses"]
    role_context_ids: list[str] = []
    for index, scripted_response in enumerate(scripted[:2], start=1):
        request = _next_packet(SKILL_RUNNER, evaluation_run)
        if index == 1:
            qualification_record = dict(qualification_request["payload"])
            evaluation_record = dict(request["payload"])
            assert qualification_record.pop("source_record_fingerprint") == (
                qualification_receipt["source_record_fingerprint"]
            )
            assert evaluation_record.pop("source_record_fingerprint") == (
                request["safe_metadata"]["source_record_fingerprint"]
            )
            assert qualification_record.pop("schema_version") == "1.0"
            assert evaluation_record.pop("schema_version") == "1.1"
            assert qualification_record == evaluation_record
        authored = _fresh_role_response_bytes(
            request,
            _bound_scripted_payload(request, scripted_response["payload"]),
            prior_context_ids=set(role_context_ids),
        )
        assert authored is not None
        response_bytes, context_id = authored
        assert context_id not in role_context_ids
        role_context_ids.append(context_id)
        response = tmp_path / f"accepted-response-{index}.json"
        response.write_bytes(response_bytes)
        accepted = _run_runner(
            SKILL_RUNNER,
            "eval-submit-safe",
            "--run",
            str(evaluation_run.resolve()),
            "--response",
            str(response),
        )
        assert accepted.returncode == 0, accepted.stderr
        assert json.loads(accepted.stdout)["accepted"] is True

    audit_request = _next_packet(SKILL_RUNNER, evaluation_run)
    assert audit_request["operation"] == "audit_ledger"
    invalid_audit_payload = {
        "complete": True,
        "disputes": [
            {
                "action": "materiality",
                "dispute_id": "audit-1",
                "materiality": "supporting",
                "proposed_entries": [],
                "rationale": "brief",
                "target_ledger_ids": ["file-notice"],
            }
        ],
        "request_fingerprint": audit_request["request_fingerprint"],
    }
    offered_responses: list[tuple[str, Path]] = []
    for attempt in range(1, 4):
        authored = _fresh_role_response_bytes(
            audit_request,
            invalid_audit_payload,
            prior_context_ids=set(role_context_ids),
        )
        assert authored is not None
        response_bytes, context_id = authored
        assert context_id not in role_context_ids
        role_context_ids.append(context_id)
        response = tmp_path / f"rejected-audit-response-{attempt}.json"
        response.write_bytes(response_bytes)
        offered_responses.append((context_id, response))

    before_rejections = _run_snapshot(evaluation_run)
    consumed: list[Path] = []
    diagnostic_counts: dict[str, int] = {}
    for context_id, response in offered_responses:
        refused = _run_runner(
            SKILL_RUNNER,
            "eval-submit-safe",
            "--run",
            str(evaluation_run.resolve()),
            "--response",
            str(response),
        )
        consumed.append(response)
        assert json.loads(response.read_bytes())["model_name"] == (
            f"synthetic-role-{context_id}"
        )
        assert json.loads(response.read_bytes())["judge_isolation"] == "fresh_context"
        assert refused.returncode == 2, refused.stderr
        result = json.loads(refused.stdout)
        assert result["accepted"] is False
        code = result["preflight"]["issues"][0]["code"]
        diagnostic_counts[code] = diagnostic_counts.get(code, 0) + 1
        if diagnostic_counts[code] == 2:
            break

    assert consumed == [path for _, path in offered_responses[:2]]
    assert diagnostic_counts == {"EVALUATION_AUDIT_RATIONALE_INSUFFICIENT": 2}
    assert _run_snapshot(evaluation_run) == before_rejections
    assert not (
        evaluation_run / "judge-responses" / "ledger-audit-attempt-1.json"
    ).exists()
    manifest = json.loads(
        (evaluation_run / "run-manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["state"] == "ledger-audit"
    assert manifest["judge_calls"][-1]["attempt"] == 1
    assert manifest["judge_calls"][-1]["response_artifact_path"] is None


def test_controller_overrides_template_default_and_verifies_case_invalid(
    tmp_path: Path,
) -> None:
    """A reused initial context must be labeled truthfully and an invalid case must stop."""
    run = tmp_path / "case-invalid-evaluation"
    _initialize_eval_run(SKILL_RUNNER, run)
    request = _next_packet(SKILL_RUNNER, run)
    scripted = json.loads(
        (EVALUATION_FIXTURE / "responses" / "scripted-responses.json").read_bytes()
    )["responses"]
    payload = _bound_scripted_payload(request, scripted[0]["payload"])
    payload["checks"][1]["satisfied"] = False
    observed_context_id = str(os.getpid())
    response_bytes = _observed_controller_response_bytes(
        request,
        payload,
        observed_context_id=observed_context_id,
        prior_context_ids={observed_context_id},
        mechanical_repair=False,
    )
    assert response_bytes is not None
    response = tmp_path / "case-invalid-response.json"
    response.write_bytes(response_bytes)
    assert json.loads(
        (ROOT / "assets" / "attorney-evaluation-response.template.json").read_bytes()
    )["judge_isolation"] == "fresh_context"
    assert json.loads(response.read_bytes())["judge_isolation"] == (
        "sequential_same_context"
    )

    submitted = _run_runner(
        SKILL_RUNNER,
        "eval-submit-safe",
        "--run",
        str(run.resolve()),
        "--response",
        str(response),
    )
    assert submitted.returncode == 0, submitted.stderr
    submission = json.loads(submitted.stdout)
    assert submission["accepted"] is True
    assert submission["state"]["state"] == "case-invalid"
    assert submission["state"]["terminal_status"] == "case-invalid"
    assert _run_runner(
        SKILL_RUNNER, "eval-next", "--run", str(run.resolve())
    ).returncode == 3
    result = json.loads((run / "evaluation-result.json").read_bytes())
    assert result["readiness"]["status"] == "CASE_INVALID"
    assert result["judge_isolation"] == "sequential_same_context"
    assert result["reports"] == []
    verified = _run_runner(
        SKILL_RUNNER, "eval-verify", "--run", str(run.resolve())
    )
    assert verified.returncode == 3, verified.stderr
    assert json.loads(verified.stdout)["ok"] is True


def test_controller_stops_on_integrity_failure_without_consuming_response(
    tmp_path: Path,
) -> None:
    """An integrity failure is never a mechanical-repair opportunity."""
    run = tmp_path / "integrity-stop"
    _initialize_eval_run(SKILL_RUNNER, run)
    request = _next_packet(SKILL_RUNNER, run)
    scripted = json.loads(
        (EVALUATION_FIXTURE / "responses" / "scripted-responses.json").read_bytes()
    )["responses"]
    authored = _fresh_role_response_bytes(
        request,
        _bound_scripted_payload(request, scripted[0]["payload"]),
        prior_context_ids=set(),
    )
    assert authored is not None
    response_bytes, _ = authored
    response = tmp_path / "unused-integrity-response.json"
    response.write_bytes(response_bytes)
    envelope = run / "case-envelope.json"
    envelope.write_bytes(envelope.read_bytes() + b"\n")
    after_tamper = _run_snapshot(run)

    stopped = _run_runner(
        SKILL_RUNNER,
        "eval-submit-safe",
        "--run",
        str(run.resolve()),
        "--response",
        str(response),
    )
    assert stopped.returncode == 5
    assert _run_snapshot(run) == after_tamper
    assert not (run / "judge-responses" / "admission-attempt-1.json").exists()


def test_controller_stops_when_fresh_repair_executor_is_unavailable(
    tmp_path: Path,
) -> None:
    """A refused response is not repaired when no fresh executor can start."""
    run = tmp_path / "fresh-repair-unavailable"
    _initialize_eval_run(SKILL_RUNNER, run)
    request = _next_packet(SKILL_RUNNER, run)
    invalid_payload = {
        "checks": [],
        "issues": [],
        "request_fingerprint": request["request_fingerprint"],
    }
    initial_context_id = str(os.getpid())
    initial_response = _observed_controller_response_bytes(
        request,
        invalid_payload,
        observed_context_id=initial_context_id,
        prior_context_ids={initial_context_id},
        mechanical_repair=False,
    )
    assert initial_response is not None
    initial_path = tmp_path / "refused-initial-response.json"
    initial_path.write_bytes(initial_response)
    refused = _run_runner(
        SKILL_RUNNER,
        "eval-submit-safe",
        "--run",
        str(run.resolve()),
        "--response",
        str(initial_path),
    )
    assert refused.returncode == 2, refused.stderr
    before_repair = _run_snapshot(run)

    relabeled_repair = _observed_controller_response_bytes(
        request,
        invalid_payload,
        observed_context_id=initial_context_id,
        prior_context_ids={initial_context_id},
        mechanical_repair=True,
    )
    assert relabeled_repair is None
    assert _run_snapshot(run) == before_repair

    repair = _fresh_role_response_bytes(
        request,
        invalid_payload,
        prior_context_ids={initial_context_id},
        python_executable=tmp_path / "missing-python",
    )
    assert repair is None
    assert _run_snapshot(run) == before_repair
    assert not (tmp_path / "repair-response.json").exists()


def test_submit_safe_controller_accepts_fail_once_and_verifies_terminal_artifacts(
    tmp_path: Path,
) -> None:
    """An unfavorable accepted judgment is a terminal result, not a repair trigger."""
    run = tmp_path / "failed-evaluation"
    _initialize_eval_run(SKILL_RUNNER, run)
    scripted = json.loads(
        (EVALUATION_FIXTURE / "responses" / "scripted-responses.json").read_text(
            encoding="utf-8"
        )
    )["responses"]
    consumed_request_fingerprints: list[str] = []
    role_context_ids: set[str] = set()

    for index, scripted_response in enumerate(scripted):
        request = _next_packet(SKILL_RUNNER, run)
        consumed_request_fingerprints.append(str(request["request_fingerprint"]))
        payload = json.loads(json.dumps(scripted_response["payload"]))
        if index >= len(scripted) - 2:
            payload["entry_grades"][0].update(
                {
                    "disposition": "MISSING",
                    "finding_codes": ["CRITICAL_LEDGER_ENTRY_MISSING"],
                    "report_location": None,
                    "report_passage": None,
                }
            )
        authored = _fresh_role_response_bytes(
            request,
            _bound_scripted_payload(request, payload),
            prior_context_ids=role_context_ids,
        )
        assert authored is not None
        response_bytes, context_id = authored
        assert context_id not in role_context_ids
        role_context_ids.add(context_id)
        response = tmp_path / f"response-{index}.json"
        response.write_bytes(response_bytes)
        submitted = _run_runner(
            SKILL_RUNNER,
            "eval-submit-safe",
            "--run",
            str(run.resolve()),
            "--response",
            str(response),
        )
        assert json.loads(submitted.stdout)["accepted"] is True
        assert submitted.returncode == 0, submitted.stderr

    manifest = json.loads((run / "run-manifest.json").read_text(encoding="utf-8"))
    assert len(consumed_request_fingerprints) == len(manifest["judge_calls"])
    assert all(call["attempt"] == 1 for call in manifest["judge_calls"])
    assert all(call["retry_count"] == 0 for call in manifest["judge_calls"])
    assert manifest["terminal_status"] == "completed"
    result = json.loads((run / "evaluation-result.json").read_text(encoding="utf-8"))
    assert result["reports"][0]["absolute_disposition"] == "FAIL"
    assert result["judge_isolation"] == "fresh_context"

    verified = _run_runner(
        SKILL_RUNNER,
        "eval-verify",
        "--run",
        str(run.resolve()),
    )
    assert verified.returncode == 4, verified.stderr
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
        result = _run_runner(
            runner,
            "eval-init",
            "--case",
            str(case_path),
            "--run",
            str(run),
            "--seed-hex",
            "8" * 64,
        )
        assert result.returncode == 0, result.stderr

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
        result = _run_runner(
            runner,
            "eval-init",
            "--case",
            str(case_path),
            "--run",
            str(run),
            "--seed-hex",
            "6" * 64,
        )
        assert result.returncode == 0, result.stderr

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
            result = _run_runner(
                runner,
                "eval-init",
                "--case",
                str(case_path),
                "--run",
                str(run),
                "--seed-hex",
                "9" * 64,
            )
            assert result.returncode == 0, result.stderr
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
        result = _run_runner(
            SKILL_RUNNER,
            "eval-init",
            "--case",
            str(case_path),
            "--run",
            str(run),
            "--seed-hex",
            "9" * 64,
        )
        assert result.returncode == 0, result.stderr
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
    """The loader admits two reports only after verifying their generation capsules."""
    case_path = _write_exact_evaluation_fixture(tmp_path / "fixture")
    outputs: list[str] = []
    for runner_name, runner in (("full", SKILL_RUNNER), ("portable", PORTABLE_RUNNER)):
        run = tmp_path / f"{runner_name}-run"
        initialized = _run_runner(
            runner,
            "eval-init",
            "--case",
            str(case_path),
            "--run",
            str(run),
            "--seed-hex",
            "a" * 64,
        )
        assert initialized.returncode == 0, initialized.stderr
        submitted = _submit_synthetic_admission(
            runner,
            run,
            tmp_path / f"{runner_name}-admission.json",
        )
        assert submitted.returncode == 0, submitted.stderr
        outputs.append(submitted.stdout)
        state = json.loads(submitted.stdout)
        assert state["current_operation"] == "build_ledger"
        assert state["terminal_status"] is None

    assert outputs[0] == outputs[1]


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

    for runner_name, runner in (("full", SKILL_RUNNER), ("portable", PORTABLE_RUNNER)):
        result = _run_runner(
            runner,
            "eval-init",
            "--case",
            str(case_path),
            "--run",
            str(tmp_path / f"{runner_name}-run"),
            "--seed-hex",
            "e" * 64,
        )
        expected = 5 if mutation == "capsule-dir-symlink" else 2
        assert result.returncode == expected


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
    """The disclosed repair contract must accept one globally coherent repair."""
    runners = (SKILL_RUNNER, PORTABLE_RUNNER)
    runs = (tmp_path / "full-stopped-shape", tmp_path / "portable-stopped-shape")
    repair_requests = [
        _advance_to_stopped_shape_repair(runner, run)
        for runner, run in zip(runners, runs, strict=True)
    ]

    assert repair_requests[0] == repair_requests[1]
    requests_before = json.loads(json.dumps(repair_requests))
    audit_actions = {
        dispute["action"] for dispute in repair_requests[0]["payload"]["audit"]["disputes"]
    }
    assert {"add", "edit", "split"} <= audit_actions
    repair_payload = _stopped_shape_repair_payload(repair_requests[0])
    original_ids = {
        entry["ledger_id"]
        for entry in repair_requests[0]["payload"]["proposed_ledger"]["entries"]
    }
    repaired_entries = repair_payload["repaired_ledger"]["entries"]
    repaired_ids = {entry["ledger_id"] for entry in repaired_entries}
    assert {
        "covered-operator-scope-added",
        "notice-filing-duty-split",
        "notice-filing-deadline-split",
    }.isdisjoint(original_ids)
    assert "file-notice" not in repaired_ids
    assert [entry["walk_order"] for entry in repaired_entries] == list(
        range(len(repaired_entries))
    )
    assert all(
        "file-notice" not in entry["relationship_ids"] for entry in repaired_entries
    )
    assert all(
        entry["citations"]
        == repair_requests[0]["payload"]["proposed_ledger"]["entries"][0]["citations"]
        for entry in repaired_entries
    )
    assert all(
        len(entry["materiality_rationale"].split()) >= 5
        and entry["materiality_rationale"].casefold()
        not in {"critical", "high priority", "important", "material", "significant"}
        for entry in repaired_entries
    )
    repaired_by_id = {entry["ledger_id"]: entry for entry in repaired_entries}
    assert repaired_by_id["notice-filing-duty-split"]["actor"] == "covered operator"
    assert repaired_by_id["notice-filing-duty-split"]["object"] == "registry notice"
    assert repaired_by_id["notice-filing-deadline-split"]["timing"] == "within 10 days"
    assert repaired_by_id["emergency-exception"]["conditions"] == [
        "during an emergency"
    ]
    assert repaired_by_id["bureau-order"]["enforcing_authority"] == "Bureau"
    assert repaired_by_id["bureau-order"]["enforcement_route"] == (
        "administrative order"
    )
    assert repaired_by_id["civil-penalty"]["consequence"] == "civil penalty of $500"
    assert repaired_by_id["bureau-order"]["relationship_ids"] == [
        "notice-filing-duty-split"
    ]
    assert repaired_by_id["civil-penalty"]["relationship_ids"] == [
        "notice-filing-duty-split"
    ]
    assert repair_payload["remaining_audit"] == {
        "request_fingerprint": repair_requests[0]["request_fingerprint"],
        "complete": True,
        "disputes": [],
    }

    payload_before = json.loads(json.dumps(repair_payload))
    response_paths = [tmp_path / f"{run.name}-repair.json" for run in runs]
    submitted = [
        _submit_eval_payload(
            runner,
            run,
            request,
            repair_payload,
            response_path=response_path,
        )
        for runner, run, request, response_path in zip(
            runners, runs, repair_requests, response_paths, strict=True
        )
    ]

    assert submitted[0].returncode == submitted[1].returncode == 0
    assert submitted[0].stdout == submitted[1].stdout
    assert submitted[0].stderr == submitted[1].stderr == ""
    assert json.loads(submitted[0].stdout)["accepted"] is True
    assert repair_requests == requests_before
    assert repair_payload == payload_before
    assert response_paths[0].read_bytes() == response_paths[1].read_bytes()
    for name in ("legal-ledger.repaired.json", "legal-ledger.json"):
        assert (runs[0] / name).read_bytes() == (runs[1] / name).read_bytes()

    grade_requests = [
        _next_packet(runner, run)
        for runner, run in zip(runners, runs, strict=True)
    ]
    assert grade_requests[0] == grade_requests[1]
    assert grade_requests[0]["operation"] == "grade_report"
    before_verify = [_run_snapshot(run) for run in runs]
    verified = [
        _run_runner(runner, "eval-verify", "--run", str(run.resolve()))
        for runner, run in zip(runners, runs, strict=True)
    ]
    assert verified[0].returncode == verified[1].returncode == 0
    assert verified[0].stdout == verified[1].stdout
    assert all(json.loads(result.stdout)["ok"] is True for result in verified)
    assert [_run_snapshot(run) for run in runs] == before_verify


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
    """Each isolated repair-contract breach must refuse identically without writes."""
    runners = (SKILL_RUNNER, PORTABLE_RUNNER)
    runs = (
        tmp_path / f"full-stopped-shape-{corruption}",
        tmp_path / f"portable-stopped-shape-{corruption}",
    )
    repair_requests = [
        _advance_to_stopped_shape_repair(runner, run)
        for runner, run in zip(runners, runs, strict=True)
    ]
    assert repair_requests[0] == repair_requests[1]
    repair_payload = _stopped_shape_repair_payload(
        repair_requests[0], corruption=corruption
    )
    response_path = tmp_path / f"stopped-shape-{corruption}.json"
    response_bytes = _canonical_response(repair_requests[0], repair_payload).encode()
    response_path.write_bytes(response_bytes)
    before = [_run_snapshot(run) for run in runs]

    refused = [
        _run_runner(
            runner,
            "eval-submit-safe",
            "--run",
            str(run.resolve()),
            "--response",
            str(response_path),
        )
        for runner, run in zip(runners, runs, strict=True)
    ]

    assert refused[0].returncode == refused[1].returncode == 2
    assert refused[0].stdout == refused[1].stdout
    assert refused[0].stderr == refused[1].stderr == ""
    refusal = json.loads(refused[0].stdout)
    assert refusal["accepted"] is False
    assert refusal["state"] is None
    assert refusal["preflight"]["issues"] == [
        {
            "code": "EVALUATION_RESPONSE_SEMANTIC_INVALID",
            "message": "The response does not satisfy the pending operation contract.",
            "related_ids": [],
        }
    ]
    assert refusal["preflight"]["diagnostic_fingerprint"] is not None
    assert [_run_snapshot(run) for run in runs] == before
    assert response_path.read_bytes() == response_bytes
    assert all(not (run / "legal-ledger.repaired.json").exists() for run in runs)

    verified = [
        _run_runner(runner, "eval-verify", "--run", str(run.resolve()))
        for runner, run in zip(runners, runs, strict=True)
    ]
    assert verified[0].returncode == verified[1].returncode == 0
    assert verified[0].stdout == verified[1].stdout
    assert all(json.loads(result.stdout)["ok"] is True for result in verified)
    assert [_run_snapshot(run) for run in runs] == before


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
    ("mutation", "expected_code"),
    [
        ("schema", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("request", "EVALUATION_RESPONSE_REQUEST_MISMATCH"),
        ("semantic", "EVALUATION_RESPONSE_SEMANTIC_INVALID"),
    ],
)
def test_eval_submit_safe_is_read_only_on_refusal_and_matches_explicit_submit(
    mutation: str,
    expected_code: str,
    tmp_path: Path,
) -> None:
    """The guarded route must return its full result and commit only an accepted response."""
    full_run = tmp_path / "full-safe"
    portable_run = tmp_path / "portable-safe"
    explicit_run = tmp_path / "explicit"
    for runner, run in (
        (SKILL_RUNNER, full_run),
        (PORTABLE_RUNNER, portable_run),
        (SKILL_RUNNER, explicit_run),
    ):
        _initialize_eval_run(runner, run)
    request = _next_packet(SKILL_RUNNER, full_run)
    assert request == _next_packet(PORTABLE_RUNNER, portable_run)
    assert request == _next_packet(SKILL_RUNNER, explicit_run)

    valid_payload = json.loads(
        (EVALUATION_FIXTURE / "responses" / "scripted-responses.json").read_text(
            encoding="utf-8"
        )
    )["responses"][0]["payload"]
    invalid = json.loads(_canonical_response(request, valid_payload))
    if mutation == "schema":
        invalid.pop("provider_name")
    elif mutation == "request":
        invalid["request_fingerprint"] = "0" * 64
    else:
        invalid["payload"] = {"malformed": True}
    invalid_path = tmp_path / "invalid-safe.json"
    invalid_path.write_bytes(_canonical_bytes(invalid))
    before = [_run_snapshot(full_run), _run_snapshot(portable_run)]
    refused = [
        _run_runner(
            runner,
            "eval-submit-safe",
            "--run",
            str(run.resolve()),
            "--response",
            str(invalid_path),
        )
        for runner, run in ((SKILL_RUNNER, full_run), (PORTABLE_RUNNER, portable_run))
    ]

    assert refused[0].returncode == refused[1].returncode == 2
    assert refused[0].stdout == refused[1].stdout
    assert refused[0].stderr == refused[1].stderr == ""
    refused_payload = json.loads(refused[0].stdout)
    assert refused_payload["accepted"] is False
    assert refused_payload["state"] is None
    assert refused_payload["preflight"]["issues"][0]["code"] == expected_code
    assert [_run_snapshot(full_run), _run_snapshot(portable_run)] == before

    response_path = tmp_path / "accepted-safe.json"
    response_path.write_text(
        _canonical_response(request, valid_payload),
        encoding="utf-8",
    )
    accepted = [
        _run_runner(
            runner,
            "eval-submit-safe",
            "--run",
            str(run.resolve()),
            "--response",
            str(response_path),
        )
        for runner, run in ((SKILL_RUNNER, full_run), (PORTABLE_RUNNER, portable_run))
    ]
    explicit = _run_runner(
        SKILL_RUNNER,
        "eval-submit",
        "--run",
        str(explicit_run.resolve()),
        "--response",
        str(response_path),
    )

    assert accepted[0].returncode == accepted[1].returncode == explicit.returncode == 0
    assert accepted[0].stdout == accepted[1].stdout
    assert accepted[0].stderr == accepted[1].stderr == explicit.stderr == ""
    accepted_payload = json.loads(accepted[0].stdout)
    assert accepted_payload["accepted"] is True
    assert accepted_payload["preflight"]["ok"] is True
    assert accepted_payload["state"] == json.loads(explicit.stdout)
    assert _run_snapshot(full_run) == _run_snapshot(portable_run)
    assert _run_snapshot(full_run) == _run_snapshot(explicit_run)


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


@pytest.mark.parametrize("command", ["eval-submit-safe", "eval-qualify-submit"])
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
    command: str,
    transport: str,
    tmp_path: Path,
) -> None:
    """Transport failures must become one fixed safe result, never runtime stderr."""
    runners = (SKILL_RUNNER, PORTABLE_RUNNER)
    runs = (tmp_path / f"full-{command}", tmp_path / f"portable-{command}")
    if command == "eval-submit-safe":
        for runner, run in zip(runners, runs, strict=True):
            _initialize_eval_run(runner, run)
        request = _next_packet(SKILL_RUNNER, runs[0])
        assert request == _next_packet(PORTABLE_RUNNER, runs[1])
        null_field = "state"
    else:
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
    assert packet["operation"] == "admit_case"
    serialized = json.dumps(packet, sort_keys=True)
    assert "report_text" not in serialized
    assert "regulatory_harvest" not in serialized.casefold()


@pytest.mark.parametrize("runner", [SKILL_RUNNER, PORTABLE_RUNNER])
def test_eval_submit_rejects_a_noncanonical_or_unbound_response_without_advancing(
    runner: Path, tmp_path: Path
) -> None:
    """A bad transport envelope must not consume the protocol's one repair attempt."""
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
    bad_response = tmp_path / "bad-response.json"
    bad_response.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
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
    assert status["attempt"] == 1
    assert status["current_operation"] == "admit_case"


def test_eval_preflight_is_canonical_read_only_parity_and_submit_ready(
    tmp_path: Path,
) -> None:
    """Both runners must validate one response identically before the normal submit path."""
    full_run = tmp_path / "full-preflight"
    portable_run = tmp_path / "portable-preflight"
    scripted = json.loads(
        (EVALUATION_FIXTURE / "responses" / "scripted-responses.json").read_text(
            encoding="utf-8"
        )
    )["responses"]
    for runner, run in ((SKILL_RUNNER, full_run), (PORTABLE_RUNNER, portable_run)):
        initialized = _run_runner(
            runner,
            "eval-init",
            "--case",
            str(EVALUATION_FIXTURE / "case.json"),
            "--run",
            str(run),
            "--seed-hex",
            "0" * 64,
        )
        assert initialized.returncode == 0, initialized.stderr
    for index, item in enumerate(scripted[:3]):
        packet = _next_packet(SKILL_RUNNER, full_run)
        assert packet == _next_packet(PORTABLE_RUNNER, portable_run)
        response = tmp_path / f"advance-{index}.json"
        response.write_text(
            _canonical_response(packet, item["payload"]), encoding="utf-8"
        )
        submissions = [
            _run_runner(
                runner,
                "eval-submit",
                "--run",
                str(run),
                "--response",
                str(response),
            )
            for runner, run in ((SKILL_RUNNER, full_run), (PORTABLE_RUNNER, portable_run))
        ]
        assert submissions[0].returncode == submissions[1].returncode == 0
        assert submissions[0].stdout == submissions[1].stdout
    packet = _next_packet(SKILL_RUNNER, full_run)
    assert packet == _next_packet(PORTABLE_RUNNER, portable_run)
    assert packet["operation"] == "grade_report"
    response = tmp_path / "valid-preflight.json"
    response.write_text(
        _canonical_response(packet, scripted[3]["payload"]), encoding="utf-8"
    )
    expected = (
        json.dumps(
            {
                "diagnostic_fingerprint": None,
                "issues": [],
                "ok": True,
                "operation": "grade_report",
                "request_fingerprint": packet["request_fingerprint"],
                "schema_version": "1.0",
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )
    before = {full_run: _run_snapshot(full_run), portable_run: _run_snapshot(portable_run)}

    results = [
        _run_runner(runner, "eval-preflight", "--run", str(run), "--response", str(response))
        for runner, run in ((SKILL_RUNNER, full_run), (PORTABLE_RUNNER, portable_run))
    ]

    assert results[0].returncode == results[1].returncode == 0
    assert results[0].stdout == results[1].stdout == expected
    assert results[0].stderr == results[1].stderr == ""
    assert _run_snapshot(full_run) == before[full_run]
    assert _run_snapshot(portable_run) == before[portable_run]

    submitted = [
        _run_runner(runner, "eval-submit", "--run", str(run), "--response", str(response))
        for runner, run in ((SKILL_RUNNER, full_run), (PORTABLE_RUNNER, portable_run))
    ]
    assert submitted[0].returncode == submitted[1].returncode == 0
    assert submitted[0].stdout == submitted[1].stdout
    submitted_state = json.loads(submitted[0].stdout)
    assert submitted_state["state"] == "grade-a"
    assert submitted_state["attempt"] == 1


@pytest.mark.parametrize(
    ("mutation", "code", "message"),
    [
        (
            "schema",
            "EVALUATION_RESPONSE_SCHEMA_INVALID",
            "The response does not satisfy the canonical response schema.",
        ),
        (
            "request",
            "EVALUATION_RESPONSE_REQUEST_MISMATCH",
            "The response does not bind the pending request.",
        ),
        (
            "semantic",
            "EVALUATION_RESPONSE_SEMANTIC_INVALID",
            "The response does not satisfy the pending operation contract.",
        ),
    ],
)
def test_eval_preflight_failures_are_safe_read_only_and_portable(
    mutation: str, code: str, message: str, tmp_path: Path
) -> None:
    """Malformed drafts must expose only stable diagnostics and consume no attempt."""
    runs = (tmp_path / f"full-{mutation}", tmp_path / f"portable-{mutation}")
    for runner, run in zip((SKILL_RUNNER, PORTABLE_RUNNER), runs, strict=True):
        _initialize_eval_run(runner, run)
    packet = _next_packet(SKILL_RUNNER, runs[0])
    assert packet == _next_packet(PORTABLE_RUNNER, runs[1])
    admission = json.loads(
        (EVALUATION_FIXTURE / "responses" / "scripted-responses.json").read_text(
            encoding="utf-8"
        )
    )["responses"][0]["payload"]
    admission["request_fingerprint"] = packet["request_fingerprint"]
    response_value = json.loads(_canonical_response(packet, admission))
    if mutation == "schema":
        response_value.pop("provider_name")
    elif mutation == "request":
        response_value["request_fingerprint"] = "0" * 64
    else:
        response_value["payload"] = {"malformed": True}
    response = tmp_path / f"{mutation}.json"
    response.write_bytes(_canonical_bytes(response_value))
    issue = {"code": code, "message": message, "related_ids": []}
    diagnostic_fingerprint = hashlib.sha256(
        _canonical_bytes(
            {
                "issues": [issue],
                "operation": "admit_case",
                "request_fingerprint": packet["request_fingerprint"],
            }
        )
    ).hexdigest()
    expected = (
        json.dumps(
            {
                "diagnostic_fingerprint": diagnostic_fingerprint,
                "issues": [issue],
                "ok": False,
                "operation": "admit_case",
                "request_fingerprint": packet["request_fingerprint"],
                "schema_version": "1.0",
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )
    before = [_run_snapshot(run) for run in runs]

    results = [
        _run_runner(runner, "eval-preflight", "--run", str(run), "--response", str(response))
        for runner, run in zip((SKILL_RUNNER, PORTABLE_RUNNER), runs, strict=True)
    ]

    assert results[0].returncode == results[1].returncode == 2
    assert results[0].stdout == results[1].stdout == expected
    assert results[0].stderr == results[1].stderr == ""
    assert [_run_snapshot(run) for run in runs] == before


def test_eval_preflight_terminal_refusal_and_integrity_failure_are_read_only(
    tmp_path: Path,
) -> None:
    """Terminal refusal is input status while an untrusted run remains integrity status."""
    runs = (tmp_path / "full-terminal", tmp_path / "portable-terminal")
    scripted = json.loads(
        (EVALUATION_FIXTURE / "responses" / "scripted-responses.json").read_text(
            encoding="utf-8"
        )
    )
    response_paths: list[Path] = []
    for runner, run in zip((SKILL_RUNNER, PORTABLE_RUNNER), runs, strict=True):
        _initialize_eval_run(runner, run)
        packet = _next_packet(runner, run)
        payload = json.loads(json.dumps(scripted["responses"][0]["payload"]))
        payload["request_fingerprint"] = packet["request_fingerprint"]
        payload["checks"][0]["satisfied"] = False
        response = tmp_path / f"{run.name}.json"
        response.write_text(_canonical_response(packet, payload), encoding="utf-8")
        submitted = _run_runner(
            runner, "eval-submit", "--run", str(run), "--response", str(response)
        )
        assert submitted.returncode == 3
        response_paths.append(response)
    before = [_run_snapshot(run) for run in runs]

    refused = [
        _run_runner(
            runner,
            "eval-preflight",
            "--run",
            str(run),
            "--response",
            str(response),
        )
        for runner, run, response in zip(
            (SKILL_RUNNER, PORTABLE_RUNNER), runs, response_paths, strict=True
        )
    ]

    assert refused[0].returncode == refused[1].returncode == 2
    assert refused[0].stdout == refused[1].stdout
    assert json.loads(refused[0].stdout) == {
        "schema_version": "1.0",
        "ok": False,
        "operation": None,
        "request_fingerprint": None,
        "diagnostic_fingerprint": None,
        "issues": [
            {
                "code": "EVALUATION_NO_PENDING_REQUEST",
                "message": "The evaluation run has no pending request.",
                "related_ids": [],
            }
        ],
    }
    assert [_run_snapshot(run) for run in runs] == before

    malformed_response = tmp_path / "malformed-terminal.json"
    malformed_response.write_bytes(b"{")
    malformed_before = [_run_snapshot(run) for run in runs]
    malformed_refusal = [
        _run_runner(
            runner,
            "eval-preflight",
            "--run",
            str(run),
            "--response",
            str(malformed_response),
        )
        for runner, run in zip((SKILL_RUNNER, PORTABLE_RUNNER), runs, strict=True)
    ]
    assert malformed_refusal[0].returncode == malformed_refusal[1].returncode == 2
    assert malformed_refusal[0].stdout == malformed_refusal[1].stdout == refused[0].stdout
    assert malformed_refusal[0].stderr == malformed_refusal[1].stderr == ""
    assert [_run_snapshot(run) for run in runs] == malformed_before

    for run in runs:
        (run / "case-envelope.json").write_bytes(b"{}")
    tampered_before = [_run_snapshot(run) for run in runs]
    integrity = [
        _run_runner(
            runner,
            "eval-preflight",
            "--run",
            str(run),
            "--response",
            str(response),
        )
        for runner, run, response in zip(
            (SKILL_RUNNER, PORTABLE_RUNNER), runs, response_paths, strict=True
        )
    ]
    assert integrity[0].returncode == integrity[1].returncode == 5
    assert integrity[0].stdout == integrity[1].stdout == ""
    assert [_run_snapshot(run) for run in runs] == tampered_before


@pytest.mark.parametrize("command", ["eval-preflight", "eval-submit-safe"])
def test_eval_preflight_and_submit_safe_transition_integrity_exit_five_without_writes(
    command: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Runner boundaries must preserve integrity status from accepted-transition calculation."""
    full_run = tmp_path / "full-integrity"
    portable_run = tmp_path / "portable-integrity"
    for runner, run in ((SKILL_RUNNER, full_run), (PORTABLE_RUNNER, portable_run)):
        _initialize_eval_run(runner, run)
    packet = _next_packet(SKILL_RUNNER, full_run)
    assert packet == _next_packet(PORTABLE_RUNNER, portable_run)
    payload = json.loads(
        (EVALUATION_FIXTURE / "responses" / "scripted-responses.json").read_text(
            encoding="utf-8"
        )
    )["responses"][0]["payload"]
    payload["request_fingerprint"] = packet["request_fingerprint"]
    response = tmp_path / "integrity-response.json"
    response.write_text(_canonical_response(packet, payload), encoding="utf-8")
    before = {full_run: _run_snapshot(full_run), portable_run: _run_snapshot(portable_run)}
    full_runner = skill_runner._full_evaluation_runner()
    portable_substrate = portable_runner._evaluation_substrate()

    def fail_core_integrity(*args: object, **kwargs: object) -> None:
        raise attorney_workflow.EvaluationIntegrityError("injected transition failure")

    def fail_portable_integrity(*args: object, **kwargs: object) -> None:
        raise portable_substrate.EvaluationIntegrityError("injected transition failure")

    monkeypatch.setattr(attorney_workflow, "_accepted_transition", fail_core_integrity)
    monkeypatch.setattr(
        portable_substrate,
        "_accepted_transition",
        fail_portable_integrity,
    )
    monkeypatch.setattr(
        portable_runner,
        "_evaluation_substrate",
        lambda: portable_substrate,
    )

    full_status = full_runner.main(
        [command, "--run", str(full_run), "--response", str(response)]
    )
    full_output = capsys.readouterr()
    portable_status = portable_runner.main(
        [command, "--run", str(portable_run), "--response", str(response)]
    )
    portable_output = capsys.readouterr()

    assert full_status == portable_status == 5
    assert full_output.out == portable_output.out == ""
    assert (
        full_output.err
        == portable_output.err
        == (
            '{"code": "EVALUATION_INTEGRITY_INVALID", '
            '"message": "The evaluation run failed integrity checks."}\n'
        )
    )
    assert _run_snapshot(full_run) == before[full_run]
    assert _run_snapshot(portable_run) == before[portable_run]


def test_eval_case_invalid_is_terminal_inconclusive_not_input(tmp_path: Path) -> None:
    """A failed admission is a completed, reviewable evaluation rather than malformed CLI input."""
    scripted = json.loads(
        (EVALUATION_FIXTURE / "responses" / "scripted-responses.json").read_text(encoding="utf-8")
    )
    full_run = tmp_path / "full-case-invalid"
    portable_run = tmp_path / "portable-case-invalid"
    for runner, run in ((SKILL_RUNNER, full_run), (PORTABLE_RUNNER, portable_run)):
        _initialize_eval_run(runner, run)

    full_packet = _next_packet(SKILL_RUNNER, full_run)
    portable_packet = _next_packet(PORTABLE_RUNNER, portable_run)
    assert full_packet == portable_packet
    admission = json.loads(json.dumps(scripted["responses"][0]["payload"]))
    admission["request_fingerprint"] = full_packet["request_fingerprint"]
    admission["checks"][0]["satisfied"] = False
    submissions: list[subprocess.CompletedProcess[str]] = []
    for runner, run in ((SKILL_RUNNER, full_run), (PORTABLE_RUNNER, portable_run)):
        response = tmp_path / f"{run.name}-case-invalid.json"
        response.write_text(_canonical_response(full_packet, admission), encoding="utf-8")
        submissions.append(
            _run_runner(runner, "eval-submit", "--run", str(run), "--response", str(response))
        )
    assert submissions[0].returncode == submissions[1].returncode == 3
    assert submissions[0].stdout == submissions[1].stdout
    assert json.loads(submissions[0].stdout)["state"] == "case-invalid"

    for command in ("eval-status", "eval-next", "eval-verify"):
        full = _run_runner(SKILL_RUNNER, command, "--run", str(full_run))
        portable = _run_runner(PORTABLE_RUNNER, command, "--run", str(portable_run))
        assert full.returncode == portable.returncode == 3
        assert full.stdout == portable.stdout
        assert full.stderr == portable.stderr == ""


def test_eval_full_runner_falls_back_without_site_packages(tmp_path: Path) -> None:
    """An unavailable Pydantic runtime must preserve the portable evaluation command surface."""
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
    assert json.loads(packet.stdout)["operation"] == "admit_case"


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


def test_eval_verify_simulated_unsupported_storage_matches_portable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A platform boundary remains a closed, portable code rather than OS diagnostic prose."""
    from regulatory_harvest.evaluation import attorney_artifacts

    full_run = tmp_path / "full-platform"
    portable_run = tmp_path / "portable-platform"
    _initialize_eval_run(SKILL_RUNNER, full_run)
    _initialize_eval_run(PORTABLE_RUNNER, portable_run)
    substrate = portable_runner._evaluation_substrate()
    monkeypatch.setattr(attorney_artifacts, "_storage_platform", lambda: "simulated")
    monkeypatch.setattr(substrate, "_storage_platform", lambda: "simulated")
    monkeypatch.setattr(portable_runner, "_evaluation_substrate", lambda: substrate)

    assert skill_runner.main(["eval-verify", "--run", str(full_run)]) == 5
    full_output = capsys.readouterr().out
    assert portable_runner.main(["eval-verify", "--run", str(portable_run)]) == 5
    portable_output = capsys.readouterr().out

    assert (
        full_output
        == portable_output
        == ('{"issues":["EVALUATION_STORAGE_PLATFORM_UNSUPPORTED"],"ok":false}\n')
    )


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
    """Verification diagnostics must not reveal core paths or vary by installed runtime."""
    full_run = tmp_path / f"full-{mutation}"
    portable_run = tmp_path / f"portable-{mutation}"
    for runner, run in ((SKILL_RUNNER, full_run), (PORTABLE_RUNNER, portable_run)):
        _initialize_eval_run(runner, run)
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

    full_before = _run_snapshot(full_run)
    portable_before = _run_snapshot(portable_run)
    full = _run_runner(SKILL_RUNNER, "eval-verify", "--run", str(full_run))
    portable = _run_runner(PORTABLE_RUNNER, "eval-verify", "--run", str(portable_run))

    assert full.returncode == portable.returncode == 5
    assert (
        full.stdout
        == portable.stdout
        == (
            json.dumps(
                {"issues": [expected_code], "ok": False}, separators=(",", ":"), sort_keys=True
            )
            + "\n"
        )
    )
    full_status = _run_runner(SKILL_RUNNER, "eval-status", "--run", str(full_run))
    portable_status = _run_runner(PORTABLE_RUNNER, "eval-status", "--run", str(portable_run))
    assert full_status.returncode == portable_status.returncode == 5
    assert full_status.stdout == portable_status.stdout == ""
    assert (
        full_status.stderr
        == portable_status.stderr
        == (
            '{"code": "EVALUATION_INTEGRITY_INVALID", '
            '"message": "The evaluation run failed integrity checks."}\n'
        )
    )
    assert _run_snapshot(full_run) == full_before
    assert _run_snapshot(portable_run) == portable_before


def test_eval_full_and_portable_runs_produce_identical_public_artifacts(tmp_path: Path) -> None:
    """A fallback that changes evaluation evidence would make offline review non-reproducible."""
    full_run = tmp_path / "full"
    portable_run = tmp_path / "portable"
    scripted = json.loads(
        (EVALUATION_FIXTURE / "responses" / "scripted-responses.json").read_text(encoding="utf-8")
    )
    for runner, run in ((SKILL_RUNNER, full_run), (PORTABLE_RUNNER, portable_run)):
        initialized = _run_runner(
            runner,
            "eval-init",
            "--case",
            str(EVALUATION_FIXTURE / "case.json"),
            "--run",
            str(run),
            "--seed-hex",
            "0" * 64,
        )
        assert initialized.returncode == 0, initialized.stderr
    assert (
        _run_runner(SKILL_RUNNER, "eval-status", "--run", str(full_run)).stdout
        == _run_runner(PORTABLE_RUNNER, "eval-status", "--run", str(portable_run)).stdout
    )

    response_dirs = {
        runner: tmp_path / f"responses-{run.name}"
        for runner, run in ((SKILL_RUNNER, full_run), (PORTABLE_RUNNER, portable_run))
    }
    for directory in response_dirs.values():
        directory.mkdir()
    for index, scripted_response in enumerate(scripted["responses"]):
        full_next = _run_runner(SKILL_RUNNER, "eval-next", "--run", str(full_run))
        portable_next = _run_runner(PORTABLE_RUNNER, "eval-next", "--run", str(portable_run))
        assert full_next.returncode == portable_next.returncode == 0
        assert full_next.stdout == portable_next.stdout
        packet = json.loads(full_next.stdout)
        submissions: list[subprocess.CompletedProcess[str]] = []
        for runner, run in ((SKILL_RUNNER, full_run), (PORTABLE_RUNNER, portable_run)):
            response = response_dirs[runner] / f"response-{index}.json"
            response.write_text(_canonical_response(packet, scripted_response["payload"]))
            submissions.append(
                _run_runner(runner, "eval-submit", "--run", str(run), "--response", str(response))
            )
        assert submissions[0].returncode == submissions[1].returncode == 0
        assert submissions[0].stdout == submissions[1].stdout

    full_verified = _run_runner(SKILL_RUNNER, "eval-verify", "--run", str(full_run))
    portable_verified = _run_runner(PORTABLE_RUNNER, "eval-verify", "--run", str(portable_run))
    assert full_verified.returncode == portable_verified.returncode == 0
    assert full_verified.stdout == portable_verified.stdout

    for name in (
        "case-readiness.json",
        "legal-ledger.json",
        "evaluation-result.json",
        "evaluation-report.md",
    ):
        assert (full_run / name).read_bytes() == (portable_run / name).read_bytes()


def test_eval_cli_normalizes_omitted_defaults_and_preserves_raw_response_parity(
    tmp_path: Path,
) -> None:
    """Valid implicit defaults must not strand a full run that portable can resume."""
    full_run = tmp_path / "full-defaults"
    portable_run = tmp_path / "portable-defaults"
    scripted = json.loads(
        (EVALUATION_FIXTURE / "responses" / "scripted-responses.json").read_text(
            encoding="utf-8"
        )
    )
    for runner, run in ((SKILL_RUNNER, full_run), (PORTABLE_RUNNER, portable_run)):
        _initialize_eval_run(runner, run)

    for index, scripted_response in enumerate(scripted["responses"]):
        full_packet = _next_packet(SKILL_RUNNER, full_run)
        portable_packet = _next_packet(PORTABLE_RUNNER, portable_run)
        assert full_packet == portable_packet
        payload = json.loads(json.dumps(scripted_response["payload"]))
        _omit_valid_evaluation_defaults(payload)
        submissions: list[subprocess.CompletedProcess[str]] = []
        for runner, run in ((SKILL_RUNNER, full_run), (PORTABLE_RUNNER, portable_run)):
            response_path = tmp_path / f"{run.name}-response-{index}.json"
            response_path.write_text(
                _canonical_response(full_packet, payload), encoding="utf-8"
            )
            submissions.append(
                _run_runner(
                    runner,
                    "eval-submit",
                    "--run",
                    str(run),
                    "--response",
                    str(response_path),
                )
            )
        assert submissions[0].returncode == submissions[1].returncode == 0
        assert submissions[0].stdout == submissions[1].stdout
        if full_packet["operation"] == "grade_report" and index < len(
            scripted["responses"]
        ) - 1:
            for command in ("eval-status", "eval-verify"):
                full = _run_runner(SKILL_RUNNER, command, "--run", str(full_run))
                portable = _run_runner(PORTABLE_RUNNER, command, "--run", str(portable_run))
                assert full.returncode == portable.returncode == 0
                assert full.stdout == portable.stdout

    for command in ("eval-status", "eval-verify"):
        full = _run_runner(SKILL_RUNNER, command, "--run", str(full_run))
        portable = _run_runner(PORTABLE_RUNNER, command, "--run", str(portable_run))
        assert full.returncode == portable.returncode == 0
        assert full.stdout == portable.stdout

    raw_response = json.loads(
        (full_run / "judge-responses" / "grade-A-1-attempt-1.json").read_text(
            encoding="utf-8"
        )
    )
    normalized_grade = json.loads(
        (full_run / "grader-1-report-A.json").read_text(encoding="utf-8")
    )
    assert raw_response["schema_version"] == "1.0"
    assert raw_response["payload"]["schema_version"] == "1.3"
    assert normalized_grade["schema_version"] == "1.3"
    assert "out_of_ledger_claims" not in raw_response["payload"]
    assert "finding_codes" not in raw_response["payload"]["narrative_scores"][0]
    assert normalized_grade["out_of_ledger_claims"] == []
    assert normalized_grade["narrative_scores"][0]["finding_codes"] == []


@pytest.mark.parametrize("runner", [SKILL_RUNNER, PORTABLE_RUNNER])
def test_eval_terminal_exit_codes_cover_fail_inconclusive_and_integrity(
    runner: Path, tmp_path: Path
) -> None:
    """Flattening terminal states to success would hide a failed or untrustworthy evaluation."""
    scripted = json.loads(
        (EVALUATION_FIXTURE / "responses" / "scripted-responses.json").read_text(encoding="utf-8")
    )
    failed_run = tmp_path / "failed"
    initialized = _run_runner(
        runner,
        "eval-init",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(failed_run),
        "--seed-hex",
        "0" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    responses_dir = tmp_path / "failed-responses"
    responses_dir.mkdir()
    for index, scripted_response in enumerate(scripted["responses"]):
        payload = scripted_response["payload"]
        if index >= len(scripted["responses"]) - 2:
            payload = json.loads(json.dumps(payload))
            payload["entry_grades"][0]["disposition"] = "MISSING"
            payload["entry_grades"][0]["report_location"] = None
            payload["entry_grades"][0]["report_passage"] = None
            payload["entry_grades"][0]["finding_codes"] = ["CRITICAL_LEDGER_ENTRY_MISSING"]
        response = responses_dir / f"response-{index}.json"
        response.write_text(_canonical_response(_next_packet(runner, failed_run), payload))
        completed = _run_runner(
            runner, "eval-submit", "--run", str(failed_run), "--response", str(response)
        )
    assert completed.returncode == 4, completed.stderr

    inconclusive_run = tmp_path / "inconclusive"
    initialized = _run_runner(
        runner,
        "eval-init",
        "--case",
        str(EVALUATION_FIXTURE / "case.json"),
        "--run",
        str(inconclusive_run),
        "--seed-hex",
        "5" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    for attempt in range(2):
        response = tmp_path / f"invalid-{attempt}.json"
        response.write_text(_canonical_response(_next_packet(runner, inconclusive_run), {}))
        completed = _run_runner(
            runner, "eval-submit", "--run", str(inconclusive_run), "--response", str(response)
        )
    assert completed.returncode == 3, completed.stderr

    (failed_run / "case-readiness.json").write_text("{}", encoding="utf-8")
    tampered = _run_runner(runner, "eval-verify", "--run", str(failed_run))
    assert tampered.returncode == 5


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
