"""Verified, lossless grade-target projection for evaluation-baseline-v1."""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import fields, replace
from pathlib import Path
from typing import Any, cast

import pytest
from test_attorney_baseline_artifacts import (
    _complete_graph,
    _correction,
    _manifest,
    _referee_graph,
)

from regulatory_harvest.evaluation.attorney_baseline_artifacts import (
    BASELINE_INPUT_PATH,
    BASELINE_MANIFEST_PATH,
    BASELINE_REFEREES_PATH,
    CANONICAL_BASELINE_PATH,
    VerifiedBaselineContextV1,
    initialize_baseline_storage_v1,
    initialize_corrected_baseline_storage_v1,
    load_verified_baseline_run,
)
from regulatory_harvest.evaluation.attorney_baseline_compiler import (
    aggregate_baseline_referees_v1,
    build_baseline_disputes_v1,
    compile_canonical_baseline_v1,
)
from regulatory_harvest.evaluation.attorney_baseline_input import (
    legal_input_fingerprint_v1,
)
from regulatory_harvest.evaluation.attorney_baseline_models import (
    AcceptedBaselineRefereeFragmentV1,
    BaselineAuditAggregateV1,
    BaselineEvaluatorRequestV1,
    BaselineEvaluatorResponseV1,
    BaselineGradeTargetBindingV1,
    BaselineInputV1,
    BaselineManifestV1,
    BaselineRefereeDecisionV1,
    BaselineRequirementV1,
    BaselineReviewAggregateV1,
    CanonicalBaselineV1,
    GradeableBaselineProjectionV1,
    GradeableContestedRequirementV1,
    GradeableRequirementV1,
)
from regulatory_harvest.evaluation.attorney_baseline_projection import (
    project_gradeable_baseline_v1,
    verify_gradeable_baseline_projection_v1,
)
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

_ROOT = Path(__file__).resolve().parents[2]
_PROJECTION_MODULE = (
    _ROOT / "src/regulatory_harvest/evaluation/attorney_baseline_projection.py"
)
_REPORT_BOUND_KEYS = {
    "anonymous_label",
    "candidate",
    "candidate_id",
    "case_fingerprint",
    "generation",
    "generation_metadata",
    "grader",
    "grader_responses",
    "label",
    "report",
    "report_hash",
    "report_text",
    "run_seed",
}


def _snapshot_tree(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _hash_model(value: object) -> str:
    assert hasattr(value, "model_dump")
    return sha256_digest(
        canonical_json_bytes(value.model_dump(mode="json", warnings="error"))  # type: ignore[union-attr]
    )


def _baseline_fingerprint(raw: dict[str, object]) -> str:
    return sha256_digest(
        canonical_json_bytes(
            {key: value for key, value in raw.items() if key != "baseline_fingerprint"}
        )
    )


def _resealed_manifest(
    context: VerifiedBaselineContextV1,
    baseline_input: BaselineInputV1,
    baseline: CanonicalBaselineV1,
) -> BaselineManifestV1:
    raw = context.manifest.model_dump(mode="python", warnings="error")
    raw["legal_input_fingerprint"] = baseline_input.legal_input_fingerprint
    raw["baseline_fingerprint"] = baseline.baseline_fingerprint
    raw["source_review_aggregate_fingerprint"] = (
        baseline.provenance.source_review_aggregate_fingerprint
    )
    raw["source_audit_aggregate_fingerprint"] = (
        baseline.provenance.source_audit_aggregate_fingerprint
    )
    raw["source_referee_aggregate_fingerprint"] = (
        baseline.provenance.source_referee_aggregate_fingerprint
    )
    replacement_hashes = {
        BASELINE_INPUT_PATH: _hash_model(baseline_input),
        CANONICAL_BASELINE_PATH: _hash_model(baseline),
    }
    for artifact in cast(list[dict[str, object]], raw["artifacts"]):
        path = cast(str, artifact["artifact_path"])
        if path in replacement_hashes:
            artifact["artifact_hash"] = replacement_hashes[path]
    raw["manifest_fingerprint"] = "0" * 64
    raw["root_hash"] = "0" * 64
    provisional = BaselineManifestV1.model_validate(raw)
    raw["manifest_fingerprint"] = sha256_digest(
        canonical_json_bytes(
            provisional.model_dump(
                mode="json", exclude={"manifest_fingerprint", "root_hash"}
            )
        )
    )
    with_fingerprint = BaselineManifestV1.model_validate(raw)
    raw["root_hash"] = sha256_digest(
        canonical_json_bytes(
            with_fingerprint.model_dump(mode="json", exclude={"root_hash"})
        )
    )
    return BaselineManifestV1.model_validate(raw)


def _resealed_context(
    context: VerifiedBaselineContextV1,
    *,
    input_mutation: dict[str, object] | None = None,
    baseline_mutation: dict[str, object] | None = None,
) -> VerifiedBaselineContextV1:
    input_raw = context.baseline_input.model_dump(mode="python", warnings="error")
    input_raw.update(input_mutation or {})
    input_raw["compiler_contract"] = json.loads(
        canonical_json_bytes(input_raw["compiler_contract"])
    )
    input_raw["legal_input_fingerprint"] = "0" * 64
    provisional_input = BaselineInputV1.model_validate(input_raw)
    input_raw["legal_input_fingerprint"] = legal_input_fingerprint_v1(provisional_input)
    baseline_input = BaselineInputV1.model_validate(input_raw)

    baseline_raw = context.baseline.model_dump(mode="python", warnings="error")
    baseline_raw.update(baseline_mutation or {})
    baseline_raw["legal_input_fingerprint"] = baseline_input.legal_input_fingerprint
    provenance = cast(dict[str, object], baseline_raw["provenance"])
    provenance["legal_input_fingerprint"] = baseline_input.legal_input_fingerprint
    provenance["importance_policy_fingerprint"] = (
        baseline_input.importance_policy_fingerprint
    )
    provenance["compiler_contract_fingerprint"] = (
        baseline_input.compiler_contract_fingerprint
    )
    baseline_raw["baseline_fingerprint"] = "0" * 64
    provisional_baseline = CanonicalBaselineV1.model_validate(baseline_raw)
    baseline_raw = provisional_baseline.model_dump(mode="python", warnings="error")
    baseline_raw["baseline_fingerprint"] = _baseline_fingerprint(baseline_raw)
    baseline = CanonicalBaselineV1.model_validate(baseline_raw)
    manifest = _resealed_manifest(context, baseline_input, baseline)
    return replace(
        context,
        manifest=manifest,
        baseline_input=baseline_input,
        baseline=baseline,
    )


@pytest.fixture
def verified_run(tmp_path: Path) -> tuple[Path, VerifiedBaselineContextV1]:
    _, files_by_path, manifest = _complete_graph()
    run_dir = tmp_path / "verified-baseline"
    initialize_baseline_storage_v1(run_dir, manifest, files_by_path)
    return run_dir, load_verified_baseline_run(run_dir)


@pytest.fixture
def verified_context(
    verified_run: tuple[Path, VerifiedBaselineContextV1],
) -> VerifiedBaselineContextV1:
    return verified_run[1]


@pytest.fixture
def contested_context(tmp_path: Path) -> VerifiedBaselineContextV1:
    baseline_input, files_by_path, _ = _referee_graph()
    review = BaselineReviewAggregateV1.model_validate_json(
        files_by_path["source-review.json"]
    )
    audit = BaselineAuditAggregateV1.model_validate_json(
        files_by_path["source-audit.json"]
    )
    disputes = build_baseline_disputes_v1(baseline_input, review, audit)
    assert len(disputes) == 1
    dispute = disputes[0]
    request_path = f"requests/source-referee-{dispute.dispute_id}.json"
    response_path = f"responses/source-referee-{dispute.dispute_id}.json"
    request = BaselineEvaluatorRequestV1.model_validate_json(files_by_path[request_path])
    decision = BaselineRefereeDecisionV1(
        dispute_id=dispute.dispute_id,
        decision="unresolved",
        passages=({"source_id": "rule-1", "quote": "must file a notice"},),
        importance="critical",
        importance_basis=("legal_bottom_line",),
        importance_rationale="The disputed frequency could change the legal bottom line.",
        substantive_rationale="The retained source does not resolve the two proposed readings.",
    )
    response = BaselineEvaluatorResponseV1(
        operation=request.operation,
        request_fingerprint=request.request_fingerprint,
        provider_name="fixture",
        model_name="fixture-model",
        judge_isolation="scripted_fixture",
        payload=decision.model_dump(mode="json"),
    )
    response_bytes = canonical_json_bytes(response.model_dump(mode="json"))
    referee = AcceptedBaselineRefereeFragmentV1(
        dispute_id=dispute.dispute_id,
        dispute_fingerprint=dispute.dispute_fingerprint,
        response_fingerprint=sha256_digest(response_bytes),
        decision=decision,
    )
    referees = aggregate_baseline_referees_v1(
        baseline_input, disputes, (referee,)
    )
    baseline = compile_canonical_baseline_v1(baseline_input, review, audit, referees)
    files_by_path[response_path] = response_bytes
    files_by_path[BASELINE_REFEREES_PATH] = canonical_json_bytes(
        referees.model_dump(mode="json")
    )
    files_by_path[CANONICAL_BASELINE_PATH] = canonical_json_bytes(
        baseline.model_dump(mode="json")
    )
    run_dir = tmp_path / "contested-baseline"
    initialize_baseline_storage_v1(
        run_dir,
        _manifest(
            baseline_input,
            baseline_fingerprint=baseline.baseline_fingerprint,
            phase="completed",
            terminal_status="COMPLETED",
        ),
        files_by_path,
    )
    return load_verified_baseline_run(run_dir)


@pytest.fixture
def corrected_context(tmp_path: Path) -> VerifiedBaselineContextV1:
    baseline_input, files_by_path, manifest = _complete_graph()
    prior_dir = tmp_path / "prior-baseline"
    initialize_baseline_storage_v1(prior_dir, manifest, files_by_path)
    prior = load_verified_baseline_run(prior_dir)
    quote = "must identify the operator"
    start = baseline_input.sources[0].normalized_text.find(quote)
    added = BaselineRequirementV1(
        requirement_id="REQ-9999",
        canonical_order=999,
        statement="The notice must identify the operator.",
        kind="obligation",
        importance="material",
        importance_basis=("attorney_briefing",),
        importance_rationale="The detail is necessary for a competent attorney briefing.",
        passages=(
            {
                "source_id": "rule-1",
                "quote": quote,
                "start_char": start,
                "end_char": start + len(quote),
            },
        ),
        confidence="clear",
        substantive_rationale="The source expressly identifies the required content.",
    )
    correction = _correction(
        prior.manifest.root_hash,
        prior.baseline.baseline_fingerprint,
        added,
    )
    corrected_dir = tmp_path / "corrected-baseline"
    initialize_corrected_baseline_storage_v1(
        prior_dir,
        corrected_dir,
        correction,
    )
    return load_verified_baseline_run(corrected_dir, prior_run_dir=prior_dir)


def test_projection_is_exact_lossless_and_report_independent(
    verified_context: VerifiedBaselineContextV1,
) -> None:
    report_a = b"First report revision."
    report_b = b"Second report revision with different bytes."
    assert report_a != report_b

    left = project_gradeable_baseline_v1(verified_context)
    right = project_gradeable_baseline_v1(verified_context)

    assert canonical_json_bytes(left.model_dump(mode="json")) == canonical_json_bytes(
        right.model_dump(mode="json")
    )
    assert left.binding.grade_target_fingerprint == right.binding.grade_target_fingerprint
    assert left.baseline_input == verified_context.baseline_input
    assert tuple(item.requirement for item in left.requirements) == (
        verified_context.baseline.requirements
    )
    assert left.relationships == verified_context.baseline.relationships
    assert left.baseline_provenance == verified_context.baseline.provenance
    assert left.baseline_input.evaluation_rubric_bytes == (
        verified_context.baseline_input.evaluation_rubric_bytes
    )


def test_projection_preserves_importance_contract(
    verified_context: VerifiedBaselineContextV1,
) -> None:
    projected = project_gradeable_baseline_v1(verified_context)
    assert [
        (
            item.requirement.importance,
            item.requirement.importance_basis,
            item.requirement.importance_rationale,
        )
        for item in projected.requirements
    ] == [
        (item.importance, item.importance_basis, item.importance_rationale)
        for item in verified_context.baseline.requirements
    ]


def test_verified_correction_projects_new_grade_target_without_prior_tree_access(
    corrected_context: VerifiedBaselineContextV1,
) -> None:
    projected = project_gradeable_baseline_v1(corrected_context)
    assert projected.binding.baseline_fingerprint == (
        corrected_context.baseline.baseline_fingerprint
    )
    assert tuple(item.requirement for item in projected.requirements) == (
        corrected_context.baseline.requirements
    )


def test_exact_fingerprint_projections_are_stable_and_independently_checkable(
    contested_context: VerifiedBaselineContextV1,
) -> None:
    projected = project_gradeable_baseline_v1(contested_context)
    assert [item.semantic_identity_fingerprint for item in projected.requirements] == [
        _hash_model(item) for item in contested_context.baseline.requirements
    ]
    assert len(projected.contested_requirements) == 1
    contest = projected.contested_requirements[0]
    expected_contest = contested_context.baseline.contested_requirements[0]
    assert contest.contested_requirement == expected_contest
    assert contest.reviewer_identity_fingerprint == _hash_model(
        cast(BaselineRequirementV1, expected_contest.reviewer_alternative)
    )
    assert contest.auditor_identity_fingerprint == _hash_model(
        cast(BaselineRequirementV1, expected_contest.auditor_alternative)
    )
    assert contest.semantic_identity_fingerprint == _hash_model(expected_contest)

    semantic_raw = {
        "requirements": [item.model_dump(mode="json") for item in projected.requirements],
        "relationships": [
            item.model_dump(mode="json") for item in projected.relationships
        ],
        "contested_requirements": [
            item.model_dump(mode="json") for item in projected.contested_requirements
        ],
    }
    assert projected.binding.semantic_inventory_fingerprint == sha256_digest(
        canonical_json_bytes(semantic_raw)
    )
    binding_raw = projected.binding.model_dump(
        mode="json", exclude={"grade_target_fingerprint"}
    )
    assert projected.binding.grade_target_fingerprint == sha256_digest(
        canonical_json_bytes(binding_raw)
    )
    projection_raw = projected.model_dump(
        mode="json", exclude={"projection_fingerprint"}
    )
    assert projected.projection_fingerprint == sha256_digest(
        canonical_json_bytes(projection_raw)
    )


def test_gradeable_shapes_are_strict_immutable_and_exact(
    verified_context: VerifiedBaselineContextV1,
) -> None:
    projected = project_gradeable_baseline_v1(verified_context)
    assert tuple(GradeableRequirementV1.model_fields) == (
        "requirement",
        "semantic_identity_fingerprint",
    )
    assert tuple(GradeableContestedRequirementV1.model_fields) == (
        "contested_requirement",
        "reviewer_identity_fingerprint",
        "auditor_identity_fingerprint",
        "semantic_identity_fingerprint",
    )
    assert tuple(BaselineGradeTargetBindingV1.model_fields) == (
        "schema_version",
        "legal_input_fingerprint",
        "baseline_fingerprint",
        "source_record_fingerprint",
        "semantic_inventory_fingerprint",
        "evaluation_rubric_fingerprint",
        "importance_policy_fingerprint",
        "compiler_contract_fingerprint",
        "grade_target_fingerprint",
    )
    assert tuple(GradeableBaselineProjectionV1.model_fields) == (
        "schema_version",
        "baseline_protocol_version",
        "binding",
        "baseline_input",
        "requirements",
        "relationships",
        "contested_requirements",
        "baseline_provenance",
        "projection_fingerprint",
    )
    with pytest.raises((AttributeError, TypeError, ValueError)):
        projected.requirements[0].requirement.statement = "forged"
    with pytest.raises((AttributeError, TypeError, ValueError)):
        projected.binding.grade_target_fingerprint = "f" * 64
    with pytest.raises((AttributeError, TypeError, ValueError)):
        projected.baseline_input.sources[0].title = "forged"


@pytest.mark.parametrize(
    "mutation",
    [
        "source_bytes",
        "source_record",
        "question",
        "jurisdiction",
        "as_of",
        "authority_scope",
        "client_facts",
        "qualification",
        "compiler_contract",
        "rubric_bytes",
        "policy_bytes",
        "requirement_semantics",
        "requirement_importance",
        "relationship",
        "baseline_fingerprint",
        "provenance",
    ],
)
def test_every_grade_target_binding_mutation_changes_or_invalidates(
    verified_context: VerifiedBaselineContextV1,
    mutation: str,
) -> None:
    original = project_gradeable_baseline_v1(verified_context)
    input_mutation: dict[str, object] = {}
    baseline_mutation: dict[str, object] = {}
    input_raw = verified_context.baseline_input.model_dump(mode="python")
    baseline_raw = verified_context.baseline.model_dump(mode="python")

    if mutation == "source_bytes":
        sources = cast(list[dict[str, object]], input_raw["sources"])
        sources[0]["normalized_text"] = cast(str, sources[0]["normalized_text"]) + " "
        sources[0]["content_hash"] = hashlib.sha256(
            cast(str, sources[0]["normalized_text"]).encode()
        ).hexdigest()
        input_mutation["sources"] = sources
    elif mutation == "source_record":
        input_mutation["source_record_fingerprint"] = "1" * 64
    elif mutation in {"question", "jurisdiction", "as_of"}:
        input_mutation[mutation] = cast(str, input_raw[mutation]) + " changed"
    elif mutation == "authority_scope":
        authorities = cast(list[dict[str, object]], input_raw["requested_authorities"])
        authorities[0]["title"] = "Changed authority scope"
        input_mutation["requested_authorities"] = authorities
    elif mutation == "client_facts":
        facts = "Changed exact client facts."
        input_mutation.update(
            client_facts=facts,
            client_facts_binding=f"sha256:{sha256_digest(facts.encode())}",
        )
    elif mutation == "qualification":
        input_mutation["qualification_root"] = "1" * 64
    elif mutation == "compiler_contract":
        contract = cast(dict[str, object], input_raw["compiler_contract"])
        contract["projection_test_revision"] = 1
        input_mutation.update(
            compiler_contract=contract,
            compiler_contract_fingerprint=sha256_digest(canonical_json_bytes(contract)),
        )
    elif mutation == "rubric_bytes":
        rubric = json.loads(cast(bytes, input_raw["evaluation_rubric_bytes"]))
        rubric["projection_test_revision"] = 1
        rubric_bytes = canonical_json_bytes(rubric)
        input_mutation.update(
            evaluation_rubric_bytes=rubric_bytes,
            evaluation_rubric_fingerprint=sha256_digest(rubric_bytes),
        )
    elif mutation == "policy_bytes":
        policy = json.loads(cast(bytes, input_raw["importance_policy_bytes"]))
        policy["projection_test_revision"] = 1
        policy_bytes = canonical_json_bytes(policy)
        input_mutation.update(
            importance_policy_bytes=policy_bytes,
            importance_policy_fingerprint=sha256_digest(policy_bytes),
        )
    elif mutation == "requirement_semantics":
        requirements = cast(list[dict[str, object]], baseline_raw["requirements"])
        requirements[0]["statement"] = "A covered operator must file a changed notice."
        baseline_mutation["requirements"] = requirements
    elif mutation == "requirement_importance":
        requirements = cast(list[dict[str, object]], baseline_raw["requirements"])
        requirements[0].update(
            importance="material",
            importance_basis=["attorney_briefing"],
            importance_rationale="Omission would impair a competent attorney briefing.",
        )
        baseline_mutation["requirements"] = requirements
    elif mutation == "relationship":
        requirement = cast(list[dict[str, object]], baseline_raw["requirements"])[0]
        second = dict(requirement)
        second.update(requirement_id="REQ-0002", canonical_order=1)
        baseline_mutation.update(
            requirements=[requirement, second],
            relationships=[
                {
                    "relationship_id": "REL-0001",
                    "relationship": "defines",
                    "source_requirement_id": "REQ-0001",
                    "target_requirement_id": "REQ-0002",
                }
            ],
        )
    elif mutation == "baseline_fingerprint":
        forged = replace(
            verified_context,
            manifest=verified_context.manifest.model_copy(
                update={"baseline_fingerprint": "1" * 64}
            ),
        )
        with pytest.raises(ValueError):
            project_gradeable_baseline_v1(forged)
        return
    elif mutation == "provenance":
        provenance = cast(dict[str, object], baseline_raw["provenance"])
        provenance["source_review_aggregate_fingerprint"] = "1" * 64
        baseline_mutation["provenance"] = provenance

    changed = _resealed_context(
        verified_context,
        input_mutation=input_mutation,
        baseline_mutation=baseline_mutation,
    )
    try:
        projected = project_gradeable_baseline_v1(changed)
    except ValueError:
        return
    assert projected.binding.grade_target_fingerprint != (
        original.binding.grade_target_fingerprint
    )


def test_contested_alternative_mutation_changes_grade_target(
    contested_context: VerifiedBaselineContextV1,
) -> None:
    original = project_gradeable_baseline_v1(contested_context)
    raw = contested_context.baseline.model_dump(mode="python")
    contests = cast(list[dict[str, object]], raw["contested_requirements"])
    reviewer = cast(dict[str, object], contests[0]["reviewer_alternative"])
    reviewer["statement"] = "A covered operator must file a changed disputed notice."
    changed = _resealed_context(
        contested_context,
        baseline_mutation={"contested_requirements": contests},
    )
    projected = project_gradeable_baseline_v1(changed)
    assert projected.binding.grade_target_fingerprint != (
        original.binding.grade_target_fingerprint
    )


def test_projection_rejects_invalid_or_forged_verified_context(
    verified_context: VerifiedBaselineContextV1,
) -> None:
    assert [item.name for item in fields(VerifiedBaselineContextV1)] == [
        "manifest",
        "baseline_input",
        "baseline",
        "verification",
    ]
    forged_verification = verified_context.verification.model_construct(
        valid=True, issues=("FORGED",)
    )
    with pytest.raises(ValueError):
        project_gradeable_baseline_v1(
            replace(verified_context, verification=forged_verification)
        )
    with pytest.raises(ValueError):
        project_gradeable_baseline_v1(cast(Any, object()))


def test_projection_rejects_duplicate_ids_and_orders_from_raw_bypass(
    verified_context: VerifiedBaselineContextV1,
) -> None:
    baseline_raw = verified_context.baseline.model_dump(mode="python")
    first = cast(list[dict[str, object]], baseline_raw["requirements"])[0]
    baseline_raw["requirements"] = [first, first]
    forged = CanonicalBaselineV1.model_construct(**baseline_raw)
    with pytest.raises(ValueError):
        project_gradeable_baseline_v1(replace(verified_context, baseline=forged))


@pytest.mark.parametrize("field", ["quote", "start_char", "end_char"])
def test_projection_rejects_source_quote_and_half_open_offset_mismatch_after_reseal(
    verified_context: VerifiedBaselineContextV1,
    field: str,
) -> None:
    baseline_raw = verified_context.baseline.model_dump(mode="python")
    requirements = cast(list[dict[str, object]], baseline_raw["requirements"])
    passages = cast(list[dict[str, object]], requirements[0]["passages"])
    passages[0][field] = (
        "not the source quote"
        if field == "quote"
        else cast(int, passages[0][field]) + 1
    )
    forged = _resealed_context(
        verified_context,
        baseline_mutation={"requirements": requirements},
    )
    with pytest.raises(ValueError):
        project_gradeable_baseline_v1(forged)


def test_projection_rejects_noncanonical_rubric_json_after_full_reseal(
    verified_context: VerifiedBaselineContextV1,
) -> None:
    rubric = verified_context.baseline_input.evaluation_rubric_bytes
    noncanonical = b" " + rubric
    forged = _resealed_context(
        verified_context,
        input_mutation={
            "evaluation_rubric_bytes": noncanonical,
            "evaluation_rubric_fingerprint": sha256_digest(noncanonical),
        },
    )
    with pytest.raises(ValueError):
        project_gradeable_baseline_v1(forged)


def test_verify_projection_strictly_rehydrates_and_requires_exact_canonical_bytes(
    verified_context: VerifiedBaselineContextV1,
) -> None:
    projected = project_gradeable_baseline_v1(verified_context)
    assert verify_gradeable_baseline_projection_v1(verified_context, projected) == projected
    assert (
        verify_gradeable_baseline_projection_v1(
            verified_context, projected.model_dump(mode="python")
        )
        == projected
    )
    assert (
        verify_gradeable_baseline_projection_v1(
            verified_context, projected.model_dump(mode="json")
        )
        == projected
    )

    nested_extra = projected.model_dump(mode="python")
    cast(list[dict[str, object]], nested_extra["baseline_input"]["sources"])[0][
        "unexpected"
    ] = True
    with pytest.raises(ValueError):
        verify_gradeable_baseline_projection_v1(verified_context, nested_extra)

    report_bound = projected.model_dump(mode="python")
    cast(dict[str, object], report_bound["baseline_input"])["compiler_contract"] = {
        "nested": {"report_text": "forbidden"}
    }
    with pytest.raises(ValueError):
        verify_gradeable_baseline_projection_v1(verified_context, report_bound)

    raw_bypass = GradeableBaselineProjectionV1.model_construct(
        **{
            **projected.model_dump(mode="python"),
            "projection_fingerprint": "0" * 64,
        }
    )
    with pytest.raises(ValueError):
        verify_gradeable_baseline_projection_v1(verified_context, raw_bypass)


def test_projection_exposes_only_stable_baseline_owned_grade_target_contract(
    verified_context: VerifiedBaselineContextV1,
) -> None:
    projected = project_gradeable_baseline_v1(verified_context)
    wire = projected.model_dump(mode="json")

    def walk(value: object) -> None:
        if type(value) is dict:
            assert not (_REPORT_BOUND_KEYS & set(value))
            for child in value.values():
                walk(child)
        elif type(value) is list:
            for child in value:
                walk(child)

    walk(wire)
    assert projected.binding.baseline_fingerprint == (
        verified_context.baseline.baseline_fingerprint
    )
    assert projected.binding.grade_target_fingerprint
    assert not any(
        name.endswith(("RequestV1", "ResultV1")) or "Disposition" in name
        for name in vars(__import__(
            "regulatory_harvest.evaluation.attorney_baseline_projection",
            fromlist=["*"],
        ))
        if not name.startswith("_")
    )


def test_projection_has_no_retained_v22_import_or_write_side_effect(
    verified_run: tuple[Path, VerifiedBaselineContextV1],
) -> None:
    run_dir, context = verified_run
    tree = ast.parse(_PROJECTION_MODULE.read_text(encoding="utf-8"))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    forbidden = {
        "attorney_v22_artifacts",
        "attorney_v22_compiler",
        "attorney_v22_models",
        "attorney_v22_requests",
        "attorney_v22_workflow",
    }
    assert not any(any(name.endswith(item) for item in forbidden) for name in imported)

    retained_paths = (
        *sorted((_ROOT / "src/regulatory_harvest/evaluation").glob("attorney_v22*.py")),
        _ROOT / "assets/attorney-evaluation-v22-response.template.json",
    )
    retained_before = {path: path.read_bytes() for path in retained_paths}
    run_before = _snapshot_tree(run_dir)

    projected = project_gradeable_baseline_v1(context)
    verify_gradeable_baseline_projection_v1(context, projected)

    assert {path: path.read_bytes() for path in retained_paths} == retained_before
    assert _snapshot_tree(run_dir) == run_before
    assert BASELINE_MANIFEST_PATH in run_before
