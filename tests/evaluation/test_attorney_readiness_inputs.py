"""Admission tests for verified delivery-readiness inputs."""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, asdict, replace
from datetime import UTC, date, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Literal, cast

import pytest
import test_attorney_baseline_artifacts as baseline_artifact_tests
from test_attorney_baseline_artifacts import _baseline_input, _complete_graph

import regulatory_harvest.evaluation.attorney_readiness_inputs as inputs_module
from regulatory_harvest.analysis import (
    AnalysisDraft,
    build_analysis,
    build_evidence_inventory,
    build_source_unit_inventory,
    evaluate_atomic_coverage,
)
from regulatory_harvest.analysis.report import render_markdown
from regulatory_harvest.combine.stages import note_stage
from regulatory_harvest.evaluation.attorney_artifacts import (
    EvaluationIntegrityError,
)
from regulatory_harvest.evaluation.attorney_baseline_artifacts import (
    VerifiedBaselineContextV1,
    initialize_baseline_storage_v1,
    load_verified_baseline_run,
)
from regulatory_harvest.evaluation.attorney_baseline_models import BaselineInputV1
from regulatory_harvest.evaluation.attorney_baseline_projection import (
    project_gradeable_baseline_v1,
)
from regulatory_harvest.evaluation.attorney_generation import (
    GenerationInputError,
    canonical_json_bytes,
    initialize_generation,
    load_completed_generation_capsule_context,
    next_generation_request,
    submit_generation_response,
)
from regulatory_harvest.evaluation.attorney_models import (
    AdmissionCheck,
    CaseAdmissionJudgment,
    EvaluationMode,
    JudgeIsolation,
    JudgeOperation,
    JudgeResponse,
    QualificationCase,
    QualificationLanguageTreatment,
)
from regulatory_harvest.evaluation.attorney_qualification import (
    initialize_case_qualification,
    load_verified_qualification_context,
    next_qualification_request,
    submit_case_qualification,
)
from regulatory_harvest.evaluation.attorney_readiness_inputs import (
    QualificationAdmissionIssueV1,
    ReadinessInputError,
    build_verified_readiness_input_v1,
)
from regulatory_harvest.models import (
    CitationSpan,
    Claim,
    ClaimKind,
    Finding,
    Gap,
    IssueCategory,
    ResearchBundle,
    ResearchIssue,
    ResearchRequest,
    RunManifest,
    Severity,
    SourceInput,
    SourceQuality,
    SourceRecord,
)
from regulatory_harvest.storage import calculate_bundle_hash, sha256_digest
from regulatory_harvest.validation import validate_bundle


def _canonical_file(value: object) -> bytes:
    return canonical_json_bytes(value) + b"\n"


def _tree(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


_DECLARED_LIMITATION = "Review was limited to the retained fictional English text."


def _write_qualification(
    run_dir: Path,
    *,
    language: str = "en",
    limitations: str | None = _DECLARED_LIMITATION,
) -> BaselineInputV1:
    seed = _baseline_input()
    source_payloads = [source.model_dump(mode="json") for source in seed.sources]
    for source in source_payloads:
        source["language"] = language
        source["version"] = "2026-08-24"
    case = QualificationCase.model_validate(
        {
            "schema_version": "1.1",
            "case_id": "synthetic-readiness-qualification",
            "mode": EvaluationMode.CURRENT_LAW,
            "question": seed.question,
            "jurisdiction": seed.jurisdiction,
            "as_of": seed.as_of,
            "requested_authorities": [
                item.model_dump(mode="json") for item in seed.requested_authorities
            ],
            "sources": source_payloads,
            "build_binding": {
                "commit": "a" * 40,
                "archive_sha256": "b" * 64,
            },
            "language_treatments": [
                {
                    "source_ids": [cast(str, source["source_id"]) for source in source_payloads],
                    "method": f"Original-language review of the fictional {language} source.",
                    "rationale": f"The retained fictional source declares language {language}.",
                    "limitations": limitations,
                }
            ],
        }
    )
    initialize_case_qualification(case, run_dir, nonce_hex="1" * 64)
    request = next_qualification_request(run_dir)
    assert request is not None
    source_ids = [source.source_id for source in case.sources]
    checks = [
        AdmissionCheck(
            code=code,
            satisfied=True,
            material=True,
            rationale=f"The retained sources satisfy {code} for this fictional case.",
            source_ids=source_ids,
        )
        for code in (
            "AUTHORITY_ALIGNMENT",
            "OPERATIVE_TEXT",
            "CURRENTNESS_EVIDENCE",
            "LANGUAGE_RESOLUTION",
            "SOURCE_PARITY",
        )
    ]
    judgment = CaseAdmissionJudgment(
        request_fingerprint=request.request_fingerprint,
        checks=checks,
        issues=[],
    )
    submit_case_qualification(
        run_dir,
        JudgeResponse(
            operation=JudgeOperation.ADMIT_CASE,
            request_fingerprint=request.request_fingerprint,
            provider_name="private-fixture-provider",
            model_name="private-fixture-model",
            judge_isolation=JudgeIsolation.FRESH_CONTEXT,
            payload=judgment.model_dump(mode="json"),
        ),
    )
    qualification = load_verified_qualification_context(run_dir)
    assert qualification.receipt.readiness.status.value == "ADMITTED", (
        qualification.receipt.readiness.issue_codes
    )
    return BaselineInputV1.from_verified_qualification(
        qualification,
        client_facts=seed.client_facts,
        compiler_contract=seed.compiler_contract,
        evaluation_rubric=seed.evaluation_rubric_bytes,
        importance_policy=seed.importance_policy_bytes,
    )


class VerifiedInputsFixture:
    def __init__(
        self,
        *,
        qualification_run_dir: Path,
        baseline_run_dir: Path,
        generation_run_dir: Path,
        validation_receipt_path: Path,
        baseline_context: VerifiedBaselineContextV1,
        report_text: str,
    ) -> None:
        self.qualification_run_dir = qualification_run_dir
        self.baseline_run_dir = baseline_run_dir
        self.generation_run_dir = generation_run_dir
        self.validation_receipt_path = validation_receipt_path
        self.baseline_context = baseline_context
        self.report_text = report_text

    def without_history(self) -> dict[str, object]:
        return {
            "qualification_run_dir": self.qualification_run_dir,
            "baseline_run_dir": self.baseline_run_dir,
            "generation_run_dir": self.generation_run_dir,
            "validation_receipt_path": self.validation_receipt_path,
        }

    def receipt(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            json.loads(self.validation_receipt_path.read_text(encoding="utf-8")),
        )

    def write_receipt(self, value: dict[str, object]) -> None:
        self.validation_receipt_path.write_bytes(_canonical_file(value))

    def update_receipt(self, field: str, value: object) -> None:
        receipt = self.receipt()
        receipt[field] = value
        self.write_receipt(receipt)


def _write_generation_capsule(
    root: Path,
    context: VerifiedBaselineContextV1,
    report_text: str,
) -> Path:
    input_root = root / "generation-input"
    input_root.mkdir()
    sources: list[dict[str, str]] = []
    for source in context.baseline_input.sources:
        source_path = Path("sources") / f"{source.source_id}.txt"
        target = input_root / source_path
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(source.normalized_text.encode("utf-8"))
        sources.append({"source_id": source.source_id, "path": source_path.as_posix()})
    facts_path: str | None = None
    if context.baseline_input.client_facts is not None:
        facts_path = "client-facts.txt"
        (input_root / facts_path).write_bytes(context.baseline_input.client_facts.encode("utf-8"))
    generator_path = input_root / "generator" / "descriptor.bin"
    generator_path.parent.mkdir()
    generator_path.write_bytes(b"synthetic readiness generator")
    input_path = input_root / "generation-input.json"
    input_path.write_bytes(
        canonical_json_bytes(
            {
                "schema_version": "1.0",
                "candidate_id": "revised-report",
                "question": context.baseline_input.question,
                "generation_instructions": "Write a synthetic attorney report.",
                "sources": sources,
                "client_facts_path": facts_path,
                "generator_artifacts": [
                    {"artifact_id": "generator", "path": "generator/descriptor.bin"}
                ],
            }
        )
    )
    run_dir = root / "generation-capsule"
    initialize_generation(input_path, run_dir, nonce_hex="1" * 64)
    request = next_generation_request(run_dir)
    assert request is not None
    response_path = root / "generation-response.json"
    response_path.write_bytes(
        canonical_json_bytes(
            {
                "schema_version": "1.0",
                "operation": "generate_report",
                "request_fingerprint": request["request_fingerprint"],
                "provider_name": "synthetic-provider",
                "model_name": "synthetic-model",
                "generation_isolation": "scripted_fixture",
                "response_id": None,
                "usage": {},
                "payload": {"report_text": report_text},
            }
        )
    )
    submit_generation_response(run_dir, response_path)
    return run_dir


def _validation_bundle(context: VerifiedBaselineContextV1) -> ResearchBundle:
    now = datetime(2026, 8, 25, tzinfo=UTC)
    baseline_source = context.baseline_input.sources[0]
    source = SourceRecord(
        source_id=baseline_source.source_id,
        origin=f"captures/{baseline_source.source_id}.txt",
        display_name=baseline_source.title,
        retrieved_at=now,
        content_hash=baseline_source.content_hash,
        media_type="text/plain",
        normalized_text=baseline_source.normalized_text,
        title=baseline_source.title,
        publisher=baseline_source.publisher,
        jurisdiction=baseline_source.jurisdiction,
        authority_type=baseline_source.authority_type,
        source_quality=SourceQuality.PRIMARY,
    )
    quote = source.normalized_text
    citation = CitationSpan(
        citation_id="cite-1",
        source_id=source.source_id,
        start_char=0,
        end_char=len(quote),
        quote=quote,
    )
    claim = Claim(
        claim_id="claim-1",
        text=quote,
        kind=ClaimKind.SOURCE_SUPPORTED,
        citation_ids=[citation.citation_id],
    )
    finding = Finding(
        finding_id="finding-1",
        issue_id="issue-1",
        title="Synthetic requirement",
        jurisdiction=context.baseline_input.jurisdiction,
        authority=source.display_name,
        severity=Severity.MEDIUM,
        practical_implication="Review the synthetic requirement.",
        claims=[claim],
    )
    bundle = ResearchBundle(
        generator_version="0.1.0",
        request=ResearchRequest(
            request_id="synthetic-run",
            question=context.baseline_input.question,
            matter_title="Synthetic Regulation",
            jurisdictions=[context.baseline_input.jurisdiction],
            as_of=date.fromisoformat(context.baseline_input.as_of),
            source_inputs=[SourceInput(location=f"{source.source_id}.txt")],
        ),
        manifest=RunManifest(
            run_id="synthetic-run",
            generator_version="0.1.0",
            created_at=now,
            updated_at=now,
        ),
        sources=[source],
        issues=[
            ResearchIssue(
                issue_id="issue-1",
                title="Synthetic requirement",
                jurisdictions=[context.baseline_input.jurisdiction],
                category=IssueCategory.REQUIREMENTS,
            )
        ],
        findings=[finding],
        citations=[citation],
        gaps=[
            Gap(
                gap_id=f"gap-{category.value}",
                code=f"COVERAGE_{category.value.upper()}_NOT_ESTABLISHED",
                message=f"The synthetic record does not establish {category.value}.",
                category=category,
            )
            for category in (
                IssueCategory.STATUS,
                IssueCategory.SCOPE,
                IssueCategory.ENFORCEMENT,
                IssueCategory.DEADLINES,
                IssueCategory.IMPLEMENTATION,
            )
        ],
    )
    validation = validate_bundle(bundle)
    assert validation.valid is True
    bundle.validation = validation
    bundle.bundle_hash = calculate_bundle_hash(bundle)
    assert validate_bundle(bundle, require_bundle_hash=True).valid is True
    return bundle


def _coverage_artifacts(
    bundle: ResearchBundle,
) -> tuple[AnalysisDraft, dict[str, object], dict[str, object]]:
    source_payloads = [source.model_dump(mode="json") for source in bundle.sources]
    evidence_inventory = build_evidence_inventory(source_payloads)
    source_unit_inventory = build_source_unit_inventory(source_payloads)
    quote = bundle.sources[0].normalized_text
    dimensions: dict[str, object] = {
        name: {"disposition": "not_present"}
        for name in (
            "authority_status_timing",
            "actors_scope_activities",
            "definitions_categories",
            "duties_rights_prohibitions",
            "triggers_thresholds",
            "conditions_exceptions_defenses",
            "deadlines_transitions",
            "enforcement_remedies_consequences",
            "cross_references_dependencies",
        )
    }
    dimensions["actors_scope_activities"] = {
        "disposition": "mapped",
        "atom_ids": ["atom-duty"],
    }
    dimensions["duties_rights_prohibitions"] = {
        "disposition": "mapped",
        "atom_ids": ["atom-duty"],
    }
    elements: dict[str, object] = {
        name: {"status": "not_applicable"}
        for name in (
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
    }
    for name, text in (
        ("actor", "covered operator"),
        ("modality", "must"),
        ("operative_action", "file"),
        ("object", "a notice"),
    ):
        elements[name] = {
            "status": "stated",
            "text": text,
            "claim_ids": ["claim-1"],
        }
    unit_ids = [cast(str, row["unit_id"]) for row in source_unit_inventory["units"]]
    leads = cast(list[dict[str, object]], evidence_inventory["leads"])
    requirement_lead_ids = [
        cast(str, row["lead_id"]) for row in leads if row["issue_category"] == "requirements"
    ]
    draft = AnalysisDraft.model_validate(
        {
            "coverage_contract_version": "proposition-coverage-v2",
            "issues": [
                {
                    "issue_id": "issue-1",
                    "title": "Notice duties",
                    "category": "requirements",
                    "jurisdictions": [bundle.request.jurisdictions[0]],
                }
            ],
            "findings": [
                {
                    "finding_id": "finding-1",
                    "issue_id": "issue-1",
                    "title": "Notice duties",
                    "jurisdiction": bundle.request.jurisdictions[0],
                    "authority": bundle.sources[0].display_name,
                    "severity": "info",
                    "practical_implication": "File and identify the notice.",
                    "claims": [
                        {
                            "claim_id": "claim-1",
                            "text": quote,
                            "kind": "source_supported",
                            "proposed_citations": [
                                {
                                    "source_id": bundle.sources[0].source_id,
                                    "quote": quote,
                                }
                            ],
                        }
                    ],
                }
            ],
            "gaps": [],
            "unit_reviews": [
                {"unit_id": unit_id, "dimensions": dimensions} for unit_id in unit_ids
            ],
            "lead_dispositions_v2": [
                (
                    {
                        "lead_id": row["lead_id"],
                        "disposition": "mapped",
                        "atom_ids": ["atom-duty"],
                    }
                    if row["issue_category"] == "requirements"
                    else {
                        "lead_id": row["lead_id"],
                        "disposition": "not_material",
                        "rationale": "The lead is context for the notice duty.",
                    }
                )
                for row in leads
            ],
            "rule_atoms": [
                {
                    "atom_id": "atom-duty",
                    "unit_ids": unit_ids,
                    "lead_ids": requirement_lead_ids,
                    "category": "requirements",
                    "proposition_type": "duty",
                    "materiality": "critical",
                    "elements": elements,
                    "omission_rationale": "Omission would hide the notice duty.",
                }
            ],
            "rule_relationships": [],
            "brief": {
                "structure_profile": "regulatory-walk-v1",
                "executive_summary": [
                    {
                        "kind": "paragraph",
                        "purpose": "legal_analysis",
                        "text": quote,
                        "finding_ids": ["finding-1"],
                        "claim_ids": ["claim-1"],
                        "atom_ids": ["atom-duty"],
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
                                        "atom_ids": ["atom-duty"],
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
                                "text": "Not established: no penalties are retained.",
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
                                "text": "Assign ownership for the notice duty.",
                                "finding_ids": ["finding-1"],
                            }
                        ],
                    },
                ],
            },
        }
    )
    dossier: dict[str, object] = {
        "schema_version": "1.0",
        "coverage_contract_version": "proposition-coverage-v2",
        "source_mode": bundle.request.source_mode,
        "request": bundle.request.model_dump(mode="json"),
        "sources": [source.model_dump(mode="json") for source in bundle.sources],
        "gaps": [gap.model_dump(mode="json") for gap in bundle.gaps],
        "evidence_inventory": evidence_inventory,
        "source_unit_inventory": source_unit_inventory,
    }
    review = evaluate_atomic_coverage(
        source_unit_inventory,
        evidence_inventory,
        draft,
        bundle.sources,
    )
    assert review["valid"] is True
    return draft, dossier, review


def _bind_bundle_to_draft(
    bundle: ResearchBundle,
    draft: AnalysisDraft,
) -> ResearchBundle:
    built = build_analysis(draft, bundle.sources)
    bound = bundle.model_copy(
        update={
            "issues": built.issues,
            "findings": built.findings,
            "citations": built.citations,
            "gaps": built.gaps,
            "review_items": built.review_items,
            "brief": built.brief,
            "validation": None,
            "bundle_hash": None,
        },
    )
    bound = note_stage(bound).bundle
    assert bound.validation is not None
    assert bound.validation.valid is True
    bound.bundle_hash = calculate_bundle_hash(bound)
    assert validate_bundle(bound, require_bundle_hash=True).valid is True
    return bound


def _write_validation_matter(
    root: Path,
    context: VerifiedBaselineContextV1,
) -> tuple[Path, str]:
    matter = root / "matter"
    run = matter / "runs" / "synthetic-run"
    run.mkdir(parents=True)
    bundle = _validation_bundle(context)
    draft, dossier, coverage = _coverage_artifacts(bundle)
    bundle = _bind_bundle_to_draft(bundle, draft)
    report_text = render_markdown(bundle)
    report_path = run / "report.md"
    report_path.write_bytes(report_text.encode("utf-8"))
    bundle_path = run / "bundle.json"
    bundle_path.write_bytes(canonical_json_bytes(bundle.model_dump(mode="json")))
    dossier_path = matter / "agent-dossier.json"
    dossier_path.write_bytes(_canonical_file(dossier))
    coverage_hash = cast(str, coverage["coverage_review_hash"])
    coverage_path = matter / "coverage-review.json"
    coverage_path.write_bytes(_canonical_file(coverage))
    audit_path = run / "audit.md"
    audit_path.write_text("# Synthetic audit\n", encoding="utf-8")
    draft_path = matter / "analysis-draft.json"
    draft_path.write_bytes(_canonical_file(draft.model_dump(mode="json")))
    receipt_path = matter / "validation-receipt.json"
    receipt_path.write_bytes(
        _canonical_file(
            {
                "analysis_draft": str(draft_path),
                "audit": str(audit_path),
                "blocking_review_count": 0,
                "bundle": str(bundle_path),
                "coverage_issue_count": 0,
                "coverage_review": str(coverage_path),
                "coverage_review_hash": coverage_hash,
                "evidence_precision_valid": True,
                "proposition_coverage_valid": True,
                "provision_recall_valid": True,
                "report": str(report_path),
                "status": "completed",
                "valid": True,
                "validation_issue_count": len(
                    validate_bundle(bundle, require_bundle_hash=True).issues
                ),
            }
        )
    )
    return receipt_path, report_text


def _make_verified_inputs(
    root: Path,
    *,
    language: str = "en",
    limitations: str | None = _DECLARED_LIMITATION,
) -> VerifiedInputsFixture:
    qualification_run = root / "qualification-run"
    baseline_input = _write_qualification(
        qualification_run,
        language=language,
        limitations=limitations,
    )
    original = baseline_artifact_tests._baseline_input
    baseline_artifact_tests._baseline_input = lambda: baseline_input
    try:
        _, files_by_path, manifest = _complete_graph()
    finally:
        baseline_artifact_tests._baseline_input = original
    baseline_run = root / "baseline-run"
    initialize_baseline_storage_v1(baseline_run, manifest, files_by_path)
    context = load_verified_baseline_run(baseline_run)
    receipt_path, report_text = _write_validation_matter(root, context)
    generation_run = _write_generation_capsule(root, context, report_text)
    return VerifiedInputsFixture(
        qualification_run_dir=qualification_run,
        baseline_run_dir=baseline_run,
        generation_run_dir=generation_run,
        validation_receipt_path=receipt_path,
        baseline_context=context,
        report_text=report_text,
    )


@pytest.fixture
def verified_inputs(tmp_path: Path) -> VerifiedInputsFixture:
    return _make_verified_inputs(tmp_path)


def _historical_context(
    fixture: VerifiedInputsFixture,
    *,
    disposition: Literal["PASS", "FAIL", "INCONCLUSIVE"] = "FAIL",
    report_hash: str | None = None,
    baseline_comparable: bool = True,
    label: Literal["A", "B"] = "A",
) -> SimpleNamespace:
    stable = fixture.baseline_context.baseline

    def field(value: object, name: str) -> object:
        return getattr(value, name)

    def requirement(value: object) -> SimpleNamespace:
        return SimpleNamespace(
            requirement_id=field(value, "requirement_id"),
            canonical_order=field(value, "canonical_order"),
            statement=field(value, "statement"),
            kind=field(value, "kind"),
            importance=field(value, "importance"),
            importance_basis=field(value, "importance_basis"),
            importance_rationale=field(value, "importance_rationale"),
            passages=field(value, "passages"),
            dependency=field(value, "dependency"),
            confidence=field(value, "confidence"),
            rationale=field(value, "substantive_rationale"),
        )

    requirements = tuple(requirement(item) for item in stable.requirements)
    if not baseline_comparable and requirements:
        requirements = (
            SimpleNamespace(
                **{
                    **vars(requirements[0]),
                    "statement": requirements[0].statement + " Changed.",
                }
            ),
            *requirements[1:],
        )
    contests = tuple(
        SimpleNamespace(
            contested_requirement_id=item.contested_requirement_id,
            reviewer_alternative=(
                None
                if item.reviewer_alternative is None
                else requirement(item.reviewer_alternative)
            ),
            auditor_alternative=(
                None if item.auditor_alternative is None else requirement(item.auditor_alternative)
            ),
            unresolved_reason=item.unresolved_reason,
            importance=item.importance,
            importance_basis=item.importance_basis,
            importance_rationale=item.importance_rationale,
            rationale=item.substantive_rationale,
            referee_fragment_fingerprint=item.referee_fragment_fingerprint,
        )
        for item in stable.contested_requirements
    )
    selected_report_hash = report_hash or sha256_digest(fixture.report_text.encode("utf-8"))
    aggregates = (
        SimpleNamespace(aggregate_fingerprint="1" * 64, report_fingerprint=selected_report_hash),
        SimpleNamespace(aggregate_fingerprint="2" * 64, report_fingerprint=selected_report_hash),
    )
    sensitivity = SimpleNamespace(
        absolute_disposition=disposition,
        reason_codes=("SYNTHETIC_REASON",),
        sensitivity_fingerprint="3" * 64,
    )
    report = SimpleNamespace(
        anonymous_label=label,
        reconciliation=SimpleNamespace(grader_aggregates=aggregates),
        sensitivity=sensitivity,
        result_fingerprint="4" * 64,
    )
    result = SimpleNamespace(
        reports=(report,),
        result_fingerprint="5" * 64,
        terminal_status="COMPLETED",
    )
    baseline = SimpleNamespace(
        requirements=requirements,
        relationships=stable.relationships,
        contested_requirements=contests,
        baseline_fingerprint="6" * 64,
    )
    case = SimpleNamespace(
        question=fixture.baseline_context.baseline_input.question,
        jurisdiction=fixture.baseline_context.baseline_input.jurisdiction,
        as_of=date.fromisoformat(fixture.baseline_context.baseline_input.as_of),
        sources=fixture.baseline_context.baseline_input.sources,
        requested_authorities=fixture.baseline_context.baseline_input.requested_authorities,
        client_facts=fixture.baseline_context.baseline_input.client_facts,
    )
    case_envelope = SimpleNamespace(case=case)
    return SimpleNamespace(
        manifest=SimpleNamespace(
            manifest_fingerprint="7" * 64,
            baseline_fingerprint=baseline.baseline_fingerprint,
            grader_aggregate_fingerprints=("1" * 64, "2" * 64),
            sensitivity_fingerprints=("3" * 64,),
        ),
        result=result,
        baseline=baseline,
        rubric=json.loads(
            fixture.baseline_context.baseline_input.evaluation_rubric_bytes.decode("utf-8")
        ),
        load_case_envelope=lambda: case_envelope,
    )


def test_new_report_requires_no_protocol_22_result(
    verified_inputs: VerifiedInputsFixture,
) -> None:
    admitted = build_verified_readiness_input_v1(**verified_inputs.without_history())
    assert admitted.historical_v22 is None
    assert admitted.readiness_input.historical_v22_cross_check is None


def test_valid_admission_preserves_exact_verified_objects_and_bindings(
    verified_inputs: VerifiedInputsFixture,
) -> None:
    before = _tree(verified_inputs.baseline_run_dir.parent)
    admitted = build_verified_readiness_input_v1(**verified_inputs.without_history())
    assert admitted.baseline_context == verified_inputs.baseline_context
    assert admitted.gradeable_baseline == project_gradeable_baseline_v1(
        verified_inputs.baseline_context
    )
    assert admitted.report_text == verified_inputs.report_text
    assert admitted.report_hash == sha256_digest(verified_inputs.report_text.encode())
    assert admitted.readiness_input.report_text == verified_inputs.report_text
    assert admitted.readiness_input.generation_validation.status == "completed"
    assert not hasattr(admitted, "grader_lanes")
    assert _tree(verified_inputs.baseline_run_dir.parent) == before


def test_qualification_limits_preserve_checks_receipt_and_declared_language_limit(
    verified_inputs: VerifiedInputsFixture,
) -> None:
    admitted = build_verified_readiness_input_v1(**verified_inputs.without_history())
    limits = admitted.qualification_limits
    qualification = load_verified_qualification_context(verified_inputs.qualification_run_dir)
    baseline_input = verified_inputs.baseline_context.baseline_input

    assert limits.qualification_readiness == "ADMITTED"
    assert limits.qualification_root == qualification.manifest.root_hash
    assert limits.qualification_receipt_fingerprint == (qualification.receipt.receipt_fingerprint)
    assert limits.source_record_fingerprint == baseline_input.source_record_fingerprint
    assert limits.request_fingerprint == qualification.receipt.request_fingerprint
    assert limits.judgment_fingerprint == qualification.receipt.judgment_fingerprint
    assert [item.code for item in limits.admission_checks] == [
        "AUTHORITY_ALIGNMENT",
        "OPERATIVE_TEXT",
        "CURRENTNESS_EVIDENCE",
        "LANGUAGE_RESOLUTION",
        "SOURCE_PARITY",
    ]
    assert all(item.satisfied is True and item.material is True for item in limits.admission_checks)
    assert limits.admission_issues == ()
    assert limits.receipt_readiness.status == "ADMITTED"
    assert limits.receipt_readiness.issue_codes == ()
    assert limits.receipt_readiness.rationale == (qualification.receipt.readiness.rationale)
    assert not hasattr(limits, "qualification_finding")
    assert tuple(asdict(item) for item in limits.requested_authorities) == tuple(
        {
            "authority_id": item.authority_id,
            "title": item.title,
            "jurisdiction": item.jurisdiction,
            "authority_type": item.authority_type,
            "source_ids": tuple(item.source_ids),
        }
        for item in baseline_input.requested_authorities
    )
    assert len(limits.language_treatments) == 1
    treatment = limits.language_treatments[0]
    assert treatment.method == "Original-language review of the fictional en source."
    assert treatment.rationale == "The retained fictional source declares language en."
    assert treatment.limitation_status == "DECLARED"
    assert treatment.limitation_text == _DECLARED_LIMITATION
    assert tuple(
        (item.source_id, item.content_hash, item.language) for item in treatment.sources
    ) == (
        (
            baseline_input.sources[0].source_id,
            baseline_input.sources[0].content_hash,
            "en",
        ),
    )


def test_non_english_qualification_without_declared_limit_does_not_invent_one(
    tmp_path: Path,
) -> None:
    fixture = _make_verified_inputs(tmp_path, language="fr", limitations=None)
    admitted = build_verified_readiness_input_v1(**fixture.without_history())

    treatment = admitted.qualification_limits.language_treatments[0]
    assert treatment.sources[0].language == "fr"
    assert treatment.limitation_status == "NOT_DECLARED"
    assert treatment.limitation_text is None


def test_resealed_qualification_treatment_change_is_rejected(
    verified_inputs: VerifiedInputsFixture,
    tmp_path: Path,
) -> None:
    changed_run = tmp_path / "resealed-qualification"
    _write_qualification(
        changed_run,
        limitations="A different declared qualification limitation.",
    )
    kwargs = verified_inputs.without_history()
    kwargs["qualification_run_dir"] = changed_run

    with pytest.raises(ReadinessInputError, match="READINESS_QUALIFICATION_INVALID"):
        build_verified_readiness_input_v1(**kwargs)


def test_missing_or_invalid_qualification_capsule_is_wrapped_and_write_free(
    verified_inputs: VerifiedInputsFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = _tree(verified_inputs.baseline_run_dir.parent)

    def fail(_: Path) -> object:
        raise EvaluationIntegrityError("qualification capsule is not terminal")

    monkeypatch.setattr(inputs_module, "load_verified_qualification_context", fail)
    with pytest.raises(ReadinessInputError, match="READINESS_QUALIFICATION_INVALID"):
        build_verified_readiness_input_v1(**verified_inputs.without_history())
    assert _tree(verified_inputs.baseline_run_dir.parent) == before


@pytest.mark.parametrize(
    "mutation",
    [
        "root",
        "receipt",
        "readiness",
        "source-record",
        "request",
        "judgment",
        "question",
        "jurisdiction",
        "as-of",
        "requested-authorities",
        "sources",
    ],
)
def test_qualification_capsule_must_exactly_bind_verified_baseline(
    verified_inputs: VerifiedInputsFixture,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    context = load_verified_qualification_context(verified_inputs.qualification_run_dir)
    manifest = context.manifest
    receipt = context.receipt
    case = context.case
    artifacts = dict(context.artifact_bytes)
    if mutation == "root":
        manifest = manifest.model_copy(update={"root_hash": "0" * 64})
    elif mutation == "receipt":
        receipt = receipt.model_copy(update={"receipt_fingerprint": "0" * 64})
    elif mutation == "readiness":
        readiness = receipt.readiness.model_copy(update={"status": "CASE_INVALID"})
        receipt = receipt.model_copy(update={"readiness": readiness})
    elif mutation == "source-record":
        receipt = receipt.model_copy(update={"source_record_fingerprint": "0" * 64})
    elif mutation == "request":
        receipt = receipt.model_copy(update={"request_fingerprint": "0" * 64})
    elif mutation == "judgment":
        receipt = receipt.model_copy(update={"judgment_fingerprint": "0" * 64})
    elif mutation == "question":
        case = case.model_copy(update={"question": "A different legal question?"})
    elif mutation == "jurisdiction":
        case = case.model_copy(update={"jurisdiction": "Different"})
    elif mutation == "as-of":
        case = case.model_copy(update={"as_of": date(2026, 8, 23)})
    elif mutation == "requested-authorities":
        authority = case.requested_authorities[0].model_copy(
            update={"title": "Different authority"}
        )
        case = case.model_copy(update={"requested_authorities": [authority]})
    else:
        source = case.sources[0].model_copy(update={"title": "Different source"})
        case = case.model_copy(update={"sources": [source]})
    if mutation in {
        "question",
        "jurisdiction",
        "as-of",
        "requested-authorities",
        "sources",
    }:
        artifacts["qualification-case.json"] = canonical_json_bytes(case.model_dump(mode="json"))
    changed = replace(
        context,
        manifest=manifest,
        receipt=receipt,
        case=case,
        artifact_bytes=artifacts,
    )
    monkeypatch.setattr(
        inputs_module,
        "load_verified_qualification_context",
        lambda _: changed,
    )

    with pytest.raises(ReadinessInputError, match="READINESS_QUALIFICATION_INVALID"):
        build_verified_readiness_input_v1(**verified_inputs.without_history())


@pytest.mark.parametrize("field", ["method", "rationale", "limitations"])
def test_tampered_qualification_language_treatment_is_rejected(
    verified_inputs: VerifiedInputsFixture,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    context = load_verified_qualification_context(verified_inputs.qualification_run_dir)
    treatment = context.case.language_treatments[0].model_copy(
        update={field: "Tampered treatment evidence."}
    )
    changed_case = context.case.model_copy(update={"language_treatments": [treatment]})
    monkeypatch.setattr(
        inputs_module,
        "load_verified_qualification_context",
        lambda _: replace(context, case=changed_case),
    )

    with pytest.raises(ReadinessInputError, match="READINESS_QUALIFICATION_INVALID"):
        build_verified_readiness_input_v1(**verified_inputs.without_history())


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "native-bool"])
def test_qualification_admission_checks_are_strict_and_exact(
    verified_inputs: VerifiedInputsFixture,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    context = load_verified_qualification_context(verified_inputs.qualification_run_dir)
    raw = json.loads(context.artifact_bytes["admission-response.json"])
    checks = raw["payload"]["checks"]
    if mutation == "missing":
        checks.pop()
    elif mutation == "duplicate":
        checks[-1] = checks[0]
    else:
        checks[0]["satisfied"] = 1
    artifacts = dict(context.artifact_bytes)
    artifacts["admission-response.json"] = canonical_json_bytes(raw)
    monkeypatch.setattr(
        inputs_module,
        "load_verified_qualification_context",
        lambda _: replace(context, artifact_bytes=artifacts),
    )

    with pytest.raises(ReadinessInputError, match="READINESS_QUALIFICATION_INVALID"):
        build_verified_readiness_input_v1(**verified_inputs.without_history())


@pytest.mark.parametrize("mutation", ["missing", "extra", "duplicate", "wrong-source"])
def test_qualification_language_treatment_coverage_is_revalidated(
    verified_inputs: VerifiedInputsFixture,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    context = load_verified_qualification_context(verified_inputs.qualification_run_dir)
    original = context.case.language_treatments[0]
    wrong = original.model_copy(update={"source_ids": ["wrong-source"]})
    if mutation == "missing":
        treatments: list[QualificationLanguageTreatment] = []
    elif mutation == "extra":
        treatments = [original, wrong]
    elif mutation == "duplicate":
        treatments = [original, original]
    else:
        treatments = [wrong]
    changed_case = context.case.model_copy(update={"language_treatments": treatments})
    monkeypatch.setattr(
        inputs_module,
        "load_verified_qualification_context",
        lambda _: replace(context, case=changed_case),
    )

    with pytest.raises(ReadinessInputError, match="READINESS_QUALIFICATION_INVALID"):
        build_verified_readiness_input_v1(**verified_inputs.without_history())


def test_qualification_limits_are_detached_immutable_and_path_free(
    verified_inputs: VerifiedInputsFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = load_verified_qualification_context(verified_inputs.qualification_run_dir)
    monkeypatch.setattr(
        inputs_module,
        "load_verified_qualification_context",
        lambda _: context,
    )
    admitted = build_verified_readiness_input_v1(**verified_inputs.without_history())
    limits = admitted.qualification_limits
    limitation = limits.language_treatments[0].limitation_text
    context.case.language_treatments[0].limitations = "Mutated after admission."

    assert limits.language_treatments[0].limitation_text == limitation
    with pytest.raises(FrozenInstanceError):
        limits.qualification_root = "0" * 64  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        limits.language_treatments[0].limitation_text = None  # type: ignore[misc]
    wire = json.dumps(asdict(limits), sort_keys=True).encode("utf-8")
    assert str(verified_inputs.qualification_run_dir).encode("utf-8") not in wire
    assert b"private-fixture-provider" not in wire
    assert b"private-fixture-model" not in wire
    assert verified_inputs.report_text.encode("utf-8") not in wire
    for source in verified_inputs.baseline_context.baseline_input.sources:
        assert source.normalized_text.encode("utf-8") not in wire


def _qualification_limits_with_text(
    limits: object,
    *,
    surface: str,
    value: str,
) -> object:
    if surface == "check-rationale":
        checks = list(limits.admission_checks)  # type: ignore[attr-defined]
        checks[0] = replace(checks[0], rationale=value)
        return replace(limits, admission_checks=tuple(checks))
    if surface == "issue-message":
        issue = QualificationAdmissionIssueV1(
            code="SYNTHETIC_ISSUE",
            severity="warning",
            message=value,
            related_ids=(),
        )
        return replace(limits, admission_issues=(issue,))
    if surface == "receipt-rationale":
        receipt = replace(limits.receipt_readiness, rationale=value)  # type: ignore[attr-defined]
        return replace(limits, receipt_readiness=receipt)
    if surface == "authority-title":
        authorities = list(limits.requested_authorities)  # type: ignore[attr-defined]
        authorities[0] = replace(authorities[0], title=value)
        return replace(limits, requested_authorities=tuple(authorities))
    treatments = list(limits.language_treatments)  # type: ignore[attr-defined]
    if surface == "language-method":
        treatments[0] = replace(treatments[0], method=value)
    elif surface == "language-rationale":
        treatments[0] = replace(treatments[0], rationale=value)
    else:
        treatments[0] = replace(
            treatments[0],
            limitation_status="DECLARED",
            limitation_text=value,
        )
    return replace(limits, language_treatments=tuple(treatments))


@pytest.mark.parametrize(
    "surface",
    [
        "check-rationale",
        "issue-message",
        "receipt-rationale",
        "authority-title",
        "language-method",
        "language-rationale",
        "language-limitations",
    ],
)
@pytest.mark.parametrize("payload", ["private-path", "complete-source", "complete-report"])
def test_qualification_public_text_rejects_private_paths_and_complete_payload_duplicates(
    verified_inputs: VerifiedInputsFixture,
    monkeypatch: pytest.MonkeyPatch,
    surface: str,
    payload: str,
) -> None:
    admitted = build_verified_readiness_input_v1(**verified_inputs.without_history())
    if payload == "private-path":
        value = "Inspect /private/var/folders/secret/client-matter.json for support."
    elif payload == "complete-source":
        value = verified_inputs.baseline_context.baseline_input.sources[0].normalized_text
    else:
        value = verified_inputs.report_text
    unsafe = _qualification_limits_with_text(
        admitted.qualification_limits,
        surface=surface,
        value=value,
    )
    monkeypatch.setattr(
        inputs_module,
        "_load_qualification_limits",
        lambda *_: unsafe,
    )

    with pytest.raises(ReadinessInputError, match="READINESS_QUALIFICATION_INVALID"):
        build_verified_readiness_input_v1(**verified_inputs.without_history())


def test_qualification_public_text_preserves_safe_bytes_without_substring_false_positives(
    verified_inputs: VerifiedInputsFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admitted = build_verified_readiness_input_v1(**verified_inputs.without_history())
    source = verified_inputs.baseline_context.baseline_input.sources[0].normalized_text
    safe = (
        "  Compare https://public.example/source, section 1/2, /single-token, and this "
        f"non-complete source prefix: {source[:-1]}  "
    )
    limits = _qualification_limits_with_text(
        admitted.qualification_limits,
        surface="check-rationale",
        value=safe,
    )
    monkeypatch.setattr(inputs_module, "_load_qualification_limits", lambda *_: limits)

    rebuilt = build_verified_readiness_input_v1(**verified_inputs.without_history())

    assert rebuilt.qualification_limits.admission_checks[0].rationale == safe


@pytest.mark.parametrize(
    "unsafe_value",
    [
        "C:\\Users\\private\\client-matter.json",
        "file:///Users/private/client-matter.json",
        "/home/private/client-matter.json",
    ],
)
def test_qualification_public_text_rejects_cross_platform_absolute_paths(
    verified_inputs: VerifiedInputsFixture,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_value: str,
) -> None:
    admitted = build_verified_readiness_input_v1(**verified_inputs.without_history())
    limits = _qualification_limits_with_text(
        admitted.qualification_limits,
        surface="language-rationale",
        value=f"Inspect {unsafe_value} for support.",
    )
    monkeypatch.setattr(inputs_module, "_load_qualification_limits", lambda *_: limits)

    with pytest.raises(ReadinessInputError, match="READINESS_QUALIFICATION_INVALID"):
        build_verified_readiness_input_v1(**verified_inputs.without_history())


def test_qualification_public_text_rejects_non_native_and_oversize_values(
    verified_inputs: VerifiedInputsFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class TextSubclass(str):
        pass

    admitted = build_verified_readiness_input_v1(**verified_inputs.without_history())
    for value in (TextSubclass("apparently safe"), "x" * (64 * 1024 + 1)):
        limits = _qualification_limits_with_text(
            admitted.qualification_limits,
            surface="receipt-rationale",
            value=value,
        )
        monkeypatch.setattr(
            inputs_module,
            "_load_qualification_limits",
            lambda *_, candidate=limits: candidate,
        )
        with pytest.raises(ReadinessInputError, match="READINESS_QUALIFICATION_INVALID"):
            build_verified_readiness_input_v1(**verified_inputs.without_history())


@pytest.mark.parametrize("container", ["list", "tuple-subclass", "generator", "cycle"])
def test_qualification_public_projection_rejects_unsafe_containers_boundedly(
    verified_inputs: VerifiedInputsFixture,
    monkeypatch: pytest.MonkeyPatch,
    container: str,
) -> None:
    class TupleSubclass(tuple):
        pass

    admitted = build_verified_readiness_input_v1(**verified_inputs.without_history())
    checks = admitted.qualification_limits.admission_checks
    if container == "list":
        unsafe_checks: object = list(checks)
    elif container == "tuple-subclass":
        unsafe_checks = TupleSubclass(checks)
    elif container == "generator":
        unsafe_checks = (item for item in checks)
    else:
        cyclic: list[object] = []
        cyclic.append(cyclic)
        unsafe_checks = cyclic
    unsafe = replace(
        admitted.qualification_limits,
        admission_checks=cast(tuple[object, ...], unsafe_checks),
    )
    monkeypatch.setattr(inputs_module, "_load_qualification_limits", lambda *_: unsafe)

    with pytest.raises(ReadinessInputError, match="READINESS_QUALIFICATION_INVALID"):
        build_verified_readiness_input_v1(**verified_inputs.without_history())


def test_qualification_public_projection_rejects_excessive_text_inventory(
    verified_inputs: VerifiedInputsFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admitted = build_verified_readiness_input_v1(**verified_inputs.without_history())
    issue = QualificationAdmissionIssueV1(
        code="SYNTHETIC_ISSUE",
        severity="warning",
        message="Bounded safe issue.",
        related_ids=(),
    )
    unsafe = replace(
        admitted.qualification_limits,
        admission_issues=(issue,) * 1025,
    )
    monkeypatch.setattr(inputs_module, "_load_qualification_limits", lambda *_: unsafe)

    with pytest.raises(ReadinessInputError, match="READINESS_QUALIFICATION_INVALID"):
        build_verified_readiness_input_v1(**verified_inputs.without_history())


def test_persistable_input_contains_no_private_path(
    verified_inputs: VerifiedInputsFixture,
) -> None:
    admitted = build_verified_readiness_input_v1(**verified_inputs.without_history())
    wire = canonical_json_bytes(admitted.readiness_input.model_dump(mode="json"))
    assert str(verified_inputs.baseline_run_dir.parent).encode() not in wire


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("status", "review-required"),
        ("evidence_precision_valid", False),
        ("proposition_coverage_valid", False),
        ("provision_recall_valid", False),
    ],
)
def test_generation_validation_must_be_deterministically_complete(
    verified_inputs: VerifiedInputsFixture,
    field: str,
    value: object,
) -> None:
    verified_inputs.update_receipt(field, value)
    with pytest.raises(ReadinessInputError, match="READINESS_VALIDATION_RECEIPT_INVALID"):
        build_verified_readiness_input_v1(**verified_inputs.without_history())


def test_baseline_loader_failure_is_wrapped_and_write_free(
    verified_inputs: VerifiedInputsFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = _tree(verified_inputs.baseline_run_dir.parent)

    def fail(_: Path) -> object:
        raise EvaluationIntegrityError("BASELINE_RESULT_REQUIRED")

    monkeypatch.setattr(inputs_module, "load_verified_baseline_run", fail)
    with pytest.raises(ReadinessInputError, match="READINESS_BASELINE_INVALID"):
        build_verified_readiness_input_v1(**verified_inputs.without_history())
    assert _tree(verified_inputs.baseline_run_dir.parent) == before


def test_baseline_verification_must_be_native_true(
    verified_inputs: VerifiedInputsFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = verified_inputs.baseline_context
    invalid = replace(
        context,
        verification=context.verification.model_copy(
            update={"valid": False, "issues": ("BASELINE_REPLAY_INVALID",)}
        ),
    )
    monkeypatch.setattr(inputs_module, "load_verified_baseline_run", lambda _: invalid)
    with pytest.raises(ReadinessInputError, match="READINESS_BASELINE_INVALID"):
        build_verified_readiness_input_v1(**verified_inputs.without_history())


@pytest.mark.parametrize("qualification_readiness", [None, "REJECTED"])
def test_baseline_requires_admitted_qualification_binding(
    verified_inputs: VerifiedInputsFixture,
    monkeypatch: pytest.MonkeyPatch,
    qualification_readiness: str | None,
) -> None:
    context = verified_inputs.baseline_context
    raw = context.baseline_input.model_dump(mode="python")
    raw["qualification_readiness"] = qualification_readiness
    forged = BaselineInputV1.model_construct(**raw)
    monkeypatch.setattr(
        inputs_module,
        "load_verified_baseline_run",
        lambda _: replace(context, baseline_input=forged),
    )
    with pytest.raises(ReadinessInputError, match="READINESS_BASELINE_INVALID"):
        build_verified_readiness_input_v1(**verified_inputs.without_history())


def test_generation_capsule_must_be_completed(
    verified_inputs: VerifiedInputsFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(_: Path) -> object:
        raise GenerationInputError("generation capsule is not completed")

    monkeypatch.setattr(inputs_module, "load_completed_generation_capsule_context", fail)
    with pytest.raises(ReadinessInputError, match="READINESS_GENERATION_INVALID"):
        build_verified_readiness_input_v1(**verified_inputs.without_history())


@pytest.mark.parametrize("mutation", ["record-hash", "report-bytes"])
def test_generation_report_bytes_and_hash_are_exactly_bound(
    verified_inputs: VerifiedInputsFixture,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    provenance, report, request = load_completed_generation_capsule_context(
        verified_inputs.generation_run_dir
    )
    if mutation == "record-hash":
        provenance = dict(provenance)
        record = dict(cast(dict[str, object], provenance["generation_record"]))
        record["report_hash"] = "0" * 64
        provenance["generation_record"] = record
    else:
        report += b" changed"
    monkeypatch.setattr(
        inputs_module,
        "load_completed_generation_capsule_context",
        lambda _: (provenance, report, request),
    )
    with pytest.raises(ReadinessInputError, match="READINESS_GENERATION_INVALID"):
        build_verified_readiness_input_v1(**verified_inputs.without_history())


@pytest.mark.parametrize("kind", ["noncanonical", "duplicate", "oversize"])
def test_validation_receipt_rejects_noncanonical_duplicate_and_oversize_bytes(
    verified_inputs: VerifiedInputsFixture,
    kind: str,
) -> None:
    receipt = verified_inputs.receipt()
    if kind == "noncanonical":
        data = json.dumps(receipt, indent=2, sort_keys=True).encode()
    elif kind == "duplicate":
        canonical = canonical_json_bytes(receipt)
        data = (
            canonical.replace(
                b'{"analysis_draft":',
                b'{"status":"completed","analysis_draft":',
                1,
            )
            + b"\n"
        )
    else:
        data = b"{" + b" " * (16 * 1024 * 1024 + 1) + b"}"
    verified_inputs.validation_receipt_path.write_bytes(data)
    with pytest.raises(ReadinessInputError, match="READINESS_VALIDATION_RECEIPT_INVALID"):
        build_verified_readiness_input_v1(**verified_inputs.without_history())


def test_validation_receipt_rejects_coverage_review_hash_mismatch(
    verified_inputs: VerifiedInputsFixture,
) -> None:
    verified_inputs.update_receipt("coverage_review_hash", "0" * 64)
    with pytest.raises(ReadinessInputError, match="READINESS_VALIDATION_RECEIPT_INVALID"):
        build_verified_readiness_input_v1(**verified_inputs.without_history())


@pytest.mark.parametrize("mutation", ["extra", "missing", "type", "version", "hash"])
def test_coverage_review_requires_exact_supported_versioned_replay(
    verified_inputs: VerifiedInputsFixture,
    mutation: str,
) -> None:
    receipt = verified_inputs.receipt()
    coverage_path = Path(cast(str, receipt["coverage_review"]))
    coverage = cast(
        dict[str, object],
        json.loads(coverage_path.read_text(encoding="utf-8")),
    )
    if mutation == "extra":
        coverage["untrusted_extension"] = {}
    elif mutation == "missing":
        coverage.pop("target_review")
    elif mutation == "type":
        coverage["schema_version"] = ["3.0"]
    elif mutation == "version":
        coverage["coverage_contract_version"] = "proposition-coverage-v999"
    else:
        coverage["coverage_review_hash"] = "0" * 64
        coverage_path.write_bytes(_canonical_file(coverage))
        verified_inputs.update_receipt("coverage_review_hash", "0" * 64)
        with pytest.raises(
            ReadinessInputError,
            match="READINESS_VALIDATION_RECEIPT_INVALID",
        ):
            build_verified_readiness_input_v1(**verified_inputs.without_history())
        return
    coverage.pop("coverage_review_hash")
    coverage_hash = sha256_digest(canonical_json_bytes(coverage))
    coverage["coverage_review_hash"] = coverage_hash
    coverage_path.write_bytes(_canonical_file(coverage))
    verified_inputs.update_receipt("coverage_review_hash", coverage_hash)

    with pytest.raises(ReadinessInputError, match="READINESS_VALIDATION_RECEIPT_INVALID"):
        build_verified_readiness_input_v1(**verified_inputs.without_history())


def test_coverage_review_rejects_duplicate_keys(
    verified_inputs: VerifiedInputsFixture,
) -> None:
    receipt = verified_inputs.receipt()
    coverage_path = Path(cast(str, receipt["coverage_review"]))
    canonical = coverage_path.read_bytes()
    coverage_path.write_bytes(
        canonical.replace(
            b'{"coverage_contract_version":',
            b'{"valid":true,"coverage_contract_version":',
            1,
        )
    )

    with pytest.raises(ReadinessInputError, match="READINESS_VALIDATION_RECEIPT_INVALID"):
        build_verified_readiness_input_v1(**verified_inputs.without_history())


@pytest.mark.parametrize("artifact", ["analysis-draft.json", "agent-dossier.json"])
def test_coverage_replay_rejects_tampered_typed_inputs(
    verified_inputs: VerifiedInputsFixture,
    artifact: str,
) -> None:
    path = verified_inputs.validation_receipt_path.parent / artifact
    payload = cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))
    payload["untrusted_extension"] = True
    path.write_bytes(_canonical_file(payload))

    with pytest.raises(ReadinessInputError, match="READINESS_VALIDATION_RECEIPT_INVALID"):
        build_verified_readiness_input_v1(**verified_inputs.without_history())


def test_coverage_replay_rejects_a_different_legal_input_transplant(
    verified_inputs: VerifiedInputsFixture,
) -> None:
    bundle = _validation_bundle(verified_inputs.baseline_context)
    request_payload = bundle.request.model_dump(mode="json")
    request_payload["question"] = "What different duty applies?"
    source_payload = bundle.sources[0].model_dump(mode="json")
    source_payload["normalized_text"] = (
        "Section 1. A different entity must keep a record. "
        "Section 2. The record must identify the entity."
    )
    source_payload["content_hash"] = sha256_digest(
        cast(str, source_payload["normalized_text"]).encode("utf-8")
    )
    transplanted_bundle = bundle.model_copy(
        update={
            "request": ResearchRequest.model_validate(request_payload),
            "sources": [SourceRecord.model_validate(source_payload)],
        },
    )
    draft, dossier, coverage = _coverage_artifacts(transplanted_bundle)
    matter = verified_inputs.validation_receipt_path.parent
    (matter / "analysis-draft.json").write_bytes(_canonical_file(draft.model_dump(mode="json")))
    (matter / "agent-dossier.json").write_bytes(_canonical_file(dossier))
    (matter / "coverage-review.json").write_bytes(_canonical_file(coverage))
    verified_inputs.update_receipt(
        "coverage_review_hash",
        coverage["coverage_review_hash"],
    )

    with pytest.raises(ReadinessInputError, match="READINESS_VALIDATION_RECEIPT_INVALID"):
        build_verified_readiness_input_v1(**verified_inputs.without_history())


def test_coverage_replay_rejects_a_different_draft_transplant(
    verified_inputs: VerifiedInputsFixture,
) -> None:
    bundle = _validation_bundle(verified_inputs.baseline_context)
    draft, dossier, _ = _coverage_artifacts(bundle)
    draft_payload = draft.model_dump(mode="json")
    brief = cast(dict[str, object], draft_payload["brief"])
    sections = cast(list[dict[str, object]], brief["sections"])
    blocks = cast(list[dict[str, object]], sections[-1]["blocks"])
    blocks[0]["text"] = "Use a different implementation plan."
    transplanted_draft = AnalysisDraft.model_validate(draft_payload)
    coverage = evaluate_atomic_coverage(
        cast(dict[str, object], dossier["source_unit_inventory"]),
        cast(dict[str, object], dossier["evidence_inventory"]),
        transplanted_draft,
        bundle.sources,
    )
    assert coverage["valid"] is True
    matter = verified_inputs.validation_receipt_path.parent
    (matter / "analysis-draft.json").write_bytes(
        _canonical_file(transplanted_draft.model_dump(mode="json"))
    )
    (matter / "coverage-review.json").write_bytes(_canonical_file(coverage))
    verified_inputs.update_receipt(
        "coverage_review_hash",
        coverage["coverage_review_hash"],
    )

    with pytest.raises(ReadinessInputError, match="READINESS_VALIDATION_RECEIPT_INVALID"):
        build_verified_readiness_input_v1(**verified_inputs.without_history())


def test_validation_receipt_counts_must_match_replayed_artifacts(
    verified_inputs: VerifiedInputsFixture,
) -> None:
    receipt = verified_inputs.receipt()
    verified_inputs.update_receipt(
        "validation_issue_count",
        cast(int, receipt["validation_issue_count"]) + 1,
    )
    with pytest.raises(ReadinessInputError, match="READINESS_VALIDATION_RECEIPT_INVALID"):
        build_verified_readiness_input_v1(**verified_inputs.without_history())


def test_validation_receipt_rejects_report_path_escape(
    verified_inputs: VerifiedInputsFixture,
    tmp_path: Path,
) -> None:
    escaped = tmp_path / "escaped-report.md"
    escaped.write_text(verified_inputs.report_text, encoding="utf-8")
    verified_inputs.update_receipt("report", str(escaped))
    with pytest.raises(ReadinessInputError, match="READINESS_VALIDATION_RECEIPT_INVALID"):
        build_verified_readiness_input_v1(**verified_inputs.without_history())


@pytest.mark.parametrize("attack", ["symlink", "fifo", "hardlink"])
def test_validation_receipt_rejects_nonregular_and_aliased_files(
    verified_inputs: VerifiedInputsFixture,
    attack: str,
) -> None:
    path = verified_inputs.validation_receipt_path
    original = path.with_name("receipt-original.json")
    path.rename(original)
    if attack == "symlink":
        path.symlink_to(original.name)
    elif attack == "fifo":
        os.mkfifo(path)
    else:
        os.link(original, path)
    with pytest.raises(ReadinessInputError, match="READINESS_VALIDATION_RECEIPT_INVALID"):
        build_verified_readiness_input_v1(**verified_inputs.without_history())


def test_validation_receipt_rejects_root_replacement_during_anchored_read(
    verified_inputs: VerifiedInputsFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_open = inputs_module._open_validation_reader
    root = verified_inputs.validation_receipt_path.parent
    parked = root.with_name("matter-parked")

    @contextmanager
    def replacing_open(path: Path) -> Iterator[object]:
        with real_open(path) as storage:

            class Proxy:
                def __init__(self) -> None:
                    self.reads = 0

                def read_artifact(
                    self,
                    artifact_path: str,
                    *,
                    max_bytes: int | None = None,
                ) -> bytes:
                    data = storage.read_artifact(artifact_path, max_bytes=max_bytes)
                    self.reads += 1
                    if self.reads == 1:
                        root.rename(parked)
                        shutil.copytree(parked, root)
                    return data

                def assert_root_identity(self) -> None:
                    storage.assert_root_identity()

            yield Proxy()

    monkeypatch.setattr(inputs_module, "_open_validation_reader", replacing_open)
    with pytest.raises(ReadinessInputError, match="READINESS_VALIDATION_RECEIPT_INVALID"):
        build_verified_readiness_input_v1(**verified_inputs.without_history())


def test_validation_bundle_is_semantically_replayed_after_self_hash_verification(
    verified_inputs: VerifiedInputsFixture,
) -> None:
    receipt = verified_inputs.receipt()
    bundle_path = Path(cast(str, receipt["bundle"]))
    bundle = cast(
        dict[str, object],
        json.loads(bundle_path.read_text(encoding="utf-8")),
    )
    findings = cast(list[dict[str, object]], bundle["findings"])
    claims = cast(list[dict[str, object]], findings[0]["claims"])
    claims[0]["citation_ids"] = ["missing-citation"]
    bundle["bundle_hash"] = None
    forged = ResearchBundle.model_validate(bundle)
    bundle["bundle_hash"] = calculate_bundle_hash(forged)
    bundle_path.write_bytes(canonical_json_bytes(bundle))

    with pytest.raises(ReadinessInputError, match="READINESS_VALIDATION_RECEIPT_INVALID"):
        build_verified_readiness_input_v1(**verified_inputs.without_history())


@pytest.mark.parametrize("replacement", ["fifo", "symlink"])
def test_validation_leaf_replacement_between_anchor_and_open_is_bounded(
    verified_inputs: VerifiedInputsFixture,
    monkeypatch: pytest.MonkeyPatch,
    replacement: str,
) -> None:
    target = verified_inputs.validation_receipt_path
    parked = target.with_name("validation-receipt-parked.json")
    real_open = inputs_module.os.open
    replaced = False

    def racing_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal replaced
        if path == target.name and dir_fd is not None and not replaced:
            replaced = True
            target.rename(parked)
            if replacement == "fifo":
                os.mkfifo(target)
            else:
                target.symlink_to(parked.name)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(inputs_module.os, "open", racing_open)
    with pytest.raises(ReadinessInputError, match="READINESS_VALIDATION_RECEIPT_INVALID"):
        build_verified_readiness_input_v1(**verified_inputs.without_history())
    assert replaced is True


@pytest.mark.parametrize(
    ("run", "label"),
    [(Path("history"), None), (None, "A")],
)
def test_optional_history_requires_both_arguments_or_neither(
    verified_inputs: VerifiedInputsFixture,
    run: Path | None,
    label: Literal["A", "B"] | None,
) -> None:
    kwargs = verified_inputs.without_history()
    kwargs.update(
        historical_v22_run_dir=run,
        historical_anonymous_label=label,
    )
    with pytest.raises(ReadinessInputError, match="READINESS_HISTORICAL_ARGUMENTS_INVALID"):
        build_verified_readiness_input_v1(**kwargs)


def test_baseline_projection_precedes_optional_history_argument_rejection(
    verified_inputs: VerifiedInputsFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    real_load = inputs_module.load_verified_baseline_run
    real_project = inputs_module.project_gradeable_baseline_v1
    real_verify = inputs_module.verify_gradeable_baseline_projection_v1
    real_qualification = inputs_module.load_verified_qualification_context

    def load(path: Path):
        calls.append("load")
        return real_load(path)

    def project(context: VerifiedBaselineContextV1):
        calls.append("project")
        return real_project(context)

    def verify(context: VerifiedBaselineContextV1, candidate: object):
        calls.append("verify")
        return real_verify(context, candidate)

    def qualification(path: Path):
        calls.append("qualification")
        return real_qualification(path)

    monkeypatch.setattr(inputs_module, "load_verified_baseline_run", load)
    monkeypatch.setattr(inputs_module, "project_gradeable_baseline_v1", project)
    monkeypatch.setattr(
        inputs_module,
        "verify_gradeable_baseline_projection_v1",
        verify,
    )
    monkeypatch.setattr(
        inputs_module,
        "load_verified_qualification_context",
        qualification,
    )
    with pytest.raises(ReadinessInputError, match="READINESS_HISTORICAL_ARGUMENTS_INVALID"):
        build_verified_readiness_input_v1(
            **verified_inputs.without_history(),
            historical_v22_run_dir=Path("history"),
        )
    assert calls == ["load", "project", "verify", "qualification"]


def _admit_history(
    verified_inputs: VerifiedInputsFixture,
    monkeypatch: pytest.MonkeyPatch,
    context: object,
    *,
    label: Literal["A", "B"] = "A",
):
    monkeypatch.setattr(inputs_module, "load_verified_v22_context", lambda _: context)
    return build_verified_readiness_input_v1(
        **verified_inputs.without_history(),
        historical_v22_run_dir=Path("historical-v22"),
        historical_anonymous_label=label,
    )


def test_historical_fail_is_preserved_without_becoming_fresh_grade(
    verified_inputs: VerifiedInputsFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    admitted = _admit_history(
        verified_inputs,
        monkeypatch,
        _historical_context(verified_inputs, disposition="FAIL"),
    )
    assert admitted.historical_v22 is not None
    assert admitted.historical_v22.strict_disposition == "FAIL"
    assert not hasattr(admitted, "grader_lanes")


def test_pending_or_missing_historical_report_is_refused(
    verified_inputs: VerifiedInputsFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _historical_context(verified_inputs)
    context.result = None
    with pytest.raises(ReadinessInputError, match="READINESS_HISTORICAL_INVALID"):
        _admit_history(verified_inputs, monkeypatch, context)
    context = _historical_context(verified_inputs)
    with pytest.raises(ReadinessInputError, match="READINESS_HISTORICAL_INVALID"):
        _admit_history(verified_inputs, monkeypatch, context, label="B")


def test_historical_loader_tamper_failure_is_fail_closed(
    verified_inputs: VerifiedInputsFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(_: Path) -> object:
        raise EvaluationIntegrityError("EVALUATOR_V22_SEMANTIC_REPLAY_INVALID")

    monkeypatch.setattr(inputs_module, "load_verified_v22_context", fail)
    with pytest.raises(ReadinessInputError, match="READINESS_HISTORICAL_INVALID"):
        build_verified_readiness_input_v1(
            **verified_inputs.without_history(),
            historical_v22_run_dir=Path("historical-v22"),
            historical_anonymous_label="A",
        )


@pytest.mark.parametrize("mutation", ["result", "aggregate", "sensitivity"])
def test_historical_result_aggregate_and_sensitivity_tamper_is_refused(
    verified_inputs: VerifiedInputsFixture,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    context = _historical_context(verified_inputs)
    if mutation == "result":
        context.result.result_fingerprint = "not-a-hash"
    elif mutation == "aggregate":
        context.manifest.grader_aggregate_fingerprints = ("9" * 64, "2" * 64)
    else:
        context.manifest.sensitivity_fingerprints = ("9" * 64,)

    with pytest.raises(ReadinessInputError, match="READINESS_HISTORICAL_INVALID"):
        _admit_history(verified_inputs, monkeypatch, context)


def test_prior_report_revision_is_admitted_as_not_report_comparable(
    verified_inputs: VerifiedInputsFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    admitted = _admit_history(
        verified_inputs,
        monkeypatch,
        _historical_context(verified_inputs, report_hash="8" * 64),
    )
    assert admitted.historical_v22 is not None
    assert admitted.historical_v22.baseline_comparable is True
    assert admitted.historical_v22.report_comparable is False


def test_exact_historical_baseline_and_report_are_separately_comparable(
    verified_inputs: VerifiedInputsFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    admitted = _admit_history(
        verified_inputs,
        monkeypatch,
        _historical_context(verified_inputs),
    )
    assert admitted.historical_v22 is not None
    assert admitted.historical_v22.baseline_comparable is True
    assert admitted.historical_v22.report_comparable is True


def test_changed_historical_baseline_is_preserved_without_crosswalk(
    verified_inputs: VerifiedInputsFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    admitted = _admit_history(
        verified_inputs,
        monkeypatch,
        _historical_context(verified_inputs, baseline_comparable=False),
    )
    assert admitted.historical_v22 is not None
    assert admitted.historical_v22.baseline_comparable is False
    assert admitted.historical_v22.report_comparable is True


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("question", "A different question"),
        ("jurisdiction", "Different"),
        ("as_of", date(2025, 1, 1)),
        ("requested_authorities", ()),
        ("client_facts", "Different facts"),
    ],
)
def test_different_historical_legal_input_is_not_baseline_comparable(
    verified_inputs: VerifiedInputsFixture,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    context = _historical_context(verified_inputs)
    setattr(context.load_case_envelope().case, field, value)
    admitted = _admit_history(verified_inputs, monkeypatch, context)
    assert admitted.historical_v22 is not None
    assert admitted.historical_v22.baseline_comparable is False


def test_unproved_stable_importance_basis_is_not_baseline_comparable(
    verified_inputs: VerifiedInputsFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _historical_context(verified_inputs)
    del context.baseline.requirements[0].importance_basis
    admitted = _admit_history(verified_inputs, monkeypatch, context)
    assert admitted.historical_v22 is not None
    assert admitted.historical_v22.baseline_comparable is False


def test_different_historical_rubric_is_not_baseline_comparable(
    verified_inputs: VerifiedInputsFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _historical_context(verified_inputs)
    context.rubric = {**context.rubric, "version": "different-rubric"}
    admitted = _admit_history(verified_inputs, monkeypatch, context)
    assert admitted.historical_v22 is not None
    assert admitted.historical_v22.baseline_comparable is False


def test_different_historical_source_record_is_not_baseline_comparable(
    verified_inputs: VerifiedInputsFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _historical_context(verified_inputs)
    case = context.load_case_envelope().case
    sources = list(case.sources)
    sources[0] = sources[0].model_copy(update={"title": "Different authority"})
    case.sources = tuple(sources)
    admitted = _admit_history(verified_inputs, monkeypatch, context)
    assert admitted.historical_v22 is not None
    assert admitted.historical_v22.baseline_comparable is False


@pytest.mark.parametrize("disposition", ["PASS", "FAIL", "INCONCLUSIVE"])
def test_historical_disposition_is_candid_evidence_only(
    verified_inputs: VerifiedInputsFixture,
    monkeypatch: pytest.MonkeyPatch,
    disposition: Literal["PASS", "FAIL", "INCONCLUSIVE"],
) -> None:
    admitted = _admit_history(
        verified_inputs,
        monkeypatch,
        _historical_context(verified_inputs, disposition=disposition),
    )
    assert admitted.historical_v22 is not None
    assert admitted.historical_v22.strict_disposition == disposition
    assert admitted.readiness_input.historical_v22_cross_check == admitted.historical_v22
