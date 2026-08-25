"""Admission tests for verified delivery-readiness inputs."""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, date, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Literal, cast

import pytest
from test_attorney_baseline_artifacts import _complete_graph

import regulatory_harvest.evaluation.attorney_readiness_inputs as inputs_module
from regulatory_harvest.analysis.report import render_markdown
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
from regulatory_harvest.evaluation.attorney_readiness_inputs import (
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


class VerifiedInputsFixture:
    def __init__(
        self,
        *,
        baseline_run_dir: Path,
        generation_run_dir: Path,
        validation_receipt_path: Path,
        baseline_context: VerifiedBaselineContextV1,
        report_text: str,
    ) -> None:
        self.baseline_run_dir = baseline_run_dir
        self.generation_run_dir = generation_run_dir
        self.validation_receipt_path = validation_receipt_path
        self.baseline_context = baseline_context
        self.report_text = report_text

    def without_history(self) -> dict[str, object]:
        return {
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


def _write_validation_matter(
    root: Path,
    context: VerifiedBaselineContextV1,
) -> tuple[Path, str]:
    matter = root / "matter"
    run = matter / "runs" / "synthetic-run"
    run.mkdir(parents=True)
    bundle = _validation_bundle(context)
    report_text = render_markdown(bundle)
    report_path = run / "report.md"
    report_path.write_bytes(report_text.encode("utf-8"))
    bundle_path = run / "bundle.json"
    bundle_path.write_bytes(canonical_json_bytes(bundle.model_dump(mode="json")))
    coverage_without_hash: dict[str, object] = {
        "schema_version": "3.0",
        "coverage_contract_version": "proposition-coverage-v2",
        "valid": True,
        "target_review": {},
        "rule_graph": {},
        "counts": {},
        "issues": [],
    }
    coverage_hash = sha256_digest(canonical_json_bytes(coverage_without_hash))
    coverage_path = matter / "coverage-review.json"
    coverage_path.write_bytes(
        _canonical_file({**coverage_without_hash, "coverage_review_hash": coverage_hash})
    )
    audit_path = run / "audit.md"
    audit_path.write_text("# Synthetic audit\n", encoding="utf-8")
    draft_path = matter / "analysis-draft.json"
    draft_path.write_bytes(_canonical_file({"fixture": "synthetic-draft"}))
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


@pytest.fixture
def verified_inputs(tmp_path: Path) -> VerifiedInputsFixture:
    _, files_by_path, manifest = _complete_graph()
    baseline_run = tmp_path / "baseline-run"
    initialize_baseline_storage_v1(baseline_run, manifest, files_by_path)
    context = load_verified_baseline_run(baseline_run)
    receipt_path, report_text = _write_validation_matter(tmp_path, context)
    generation_run = _write_generation_capsule(tmp_path, context, report_text)
    return VerifiedInputsFixture(
        baseline_run_dir=baseline_run,
        generation_run_dir=generation_run,
        validation_receipt_path=receipt_path,
        baseline_context=context,
        report_text=report_text,
    )


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
    return SimpleNamespace(
        manifest=SimpleNamespace(
            manifest_fingerprint="7" * 64,
            baseline_fingerprint=baseline.baseline_fingerprint,
            grader_aggregate_fingerprints=("1" * 64, "2" * 64),
            sensitivity_fingerprints=("3" * 64,),
        ),
        result=result,
        baseline=baseline,
        load_case_envelope=lambda: SimpleNamespace(
            case=SimpleNamespace(
                question=fixture.baseline_context.baseline_input.question,
                jurisdiction=fixture.baseline_context.baseline_input.jurisdiction,
                as_of=fixture.baseline_context.baseline_input.as_of,
                sources=fixture.baseline_context.baseline_input.sources,
                requested_authorities=fixture.baseline_context.baseline_input.requested_authorities,
                client_facts=fixture.baseline_context.baseline_input.client_facts,
            )
        ),
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
