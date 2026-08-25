"""Verified, report-free grade targets for ``evaluation-baseline-v1``.

This module owns only the stable-baseline projection and its exact verification.
Every fresh readiness grader request must be owned by delivery-readiness code and
embed the complete verified projection, ``projection.binding``, exact report
bytes and hash, and a readiness-owned lane ID.  Every accepted fresh grade must
bind the same grade-target fingerprint, baseline fingerprint, report
fingerprint, and lane, and cover each ordinary requirement and each contested
alternative exactly once.  Delivery-readiness code—not this module—owns those
request/result schemas, two grading lanes, dispositions, reconciliation,
scoring, safety review, matrices, and tiers.

The public adapter accepts the exact four-field context returned by
``load_verified_baseline_run()``.  Its consistency checks do not create a new
attestation mechanism from possession of a structurally similar dataclass.
"""

from __future__ import annotations

import json
from dataclasses import fields
from typing import cast

from pydantic import ValidationError

from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from .attorney_baseline_artifacts import (
    BASELINE_INPUT_PATH,
    BASELINE_VERIFICATION_PATH,
    CANONICAL_BASELINE_PATH,
    VerifiedBaselineContextV1,
)
from .attorney_baseline_input import legal_input_fingerprint_v1
from .attorney_baseline_models import (
    BaselineGradeTargetBindingV1,
    BaselineInputV1,
    BaselineManifestV1,
    BaselinePhaseV1,
    BaselineRelationshipV1,
    BaselineRequirementV1,
    BaselineStrictModel,
    BaselineVerificationV1,
    CanonicalBaselineV1,
    ContestedBaselineRequirementV1,
    GradeableBaselineProjectionV1,
    GradeableContestedRequirementV1,
    GradeableRequirementV1,
    _gradeable_semantic_inventory_v1,
    strict_baseline_model_v1,
)

__all__ = [
    "project_gradeable_baseline_v1",
    "verify_gradeable_baseline_projection_v1",
]


def _projection_invalid() -> ValueError:
    return ValueError("gradeable baseline projection is invalid")


def _canonical_model_hash(value: BaselineStrictModel) -> str:
    return sha256_digest(
        canonical_json_bytes(
            value.model_dump(mode="json", warnings="error")
        )
    )


def _strict_verified_context_v1(
    context: VerifiedBaselineContextV1,
) -> VerifiedBaselineContextV1:
    try:
        if type(context) is not VerifiedBaselineContextV1 or tuple(
            item.name for item in fields(context)
        ) != ("manifest", "baseline_input", "baseline", "verification"):
            raise TypeError
        if not isinstance(context.manifest, BaselineManifestV1):
            raise TypeError
        if not isinstance(context.baseline_input, BaselineInputV1):
            raise TypeError
        if not isinstance(context.baseline, CanonicalBaselineV1):
            raise TypeError
        if not isinstance(context.verification, BaselineVerificationV1):
            raise TypeError
        manifest = cast(
            BaselineManifestV1,
            strict_baseline_model_v1(BaselineManifestV1, context.manifest),
        )
        baseline_input = cast(
            BaselineInputV1,
            strict_baseline_model_v1(BaselineInputV1, context.baseline_input),
        )
        baseline = cast(
            CanonicalBaselineV1,
            strict_baseline_model_v1(CanonicalBaselineV1, context.baseline),
        )
        verification = cast(
            BaselineVerificationV1,
            strict_baseline_model_v1(BaselineVerificationV1, context.verification),
        )
    except (AttributeError, TypeError, ValidationError, ValueError, RecursionError) as error:
        raise _projection_invalid() from error
    return VerifiedBaselineContextV1(
        manifest=manifest,
        baseline_input=baseline_input,
        baseline=baseline,
        verification=verification,
    )


def _require_canonical_json_bytes_v1(value: bytes) -> None:
    try:
        parsed = json.loads(value)
        if type(parsed) is not dict or canonical_json_bytes(parsed) != value:
            raise ValueError
    except (TypeError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise _projection_invalid() from error


def _require_input_integrity_v1(value: BaselineInputV1) -> None:
    _require_canonical_json_bytes_v1(value.evaluation_rubric_bytes)
    _require_canonical_json_bytes_v1(value.importance_policy_bytes)
    source_ids = tuple(source.source_id for source in value.sources)
    authority_ids = tuple(item.authority_id for item in value.requested_authorities)
    try:
        if (
            len(source_ids) != len(set(source_ids))
            or len(authority_ids) != len(set(authority_ids))
            or value.compiler_contract_fingerprint
            != sha256_digest(canonical_json_bytes(value.compiler_contract))
            or value.evaluation_rubric_fingerprint
            != sha256_digest(value.evaluation_rubric_bytes)
            or value.importance_policy_fingerprint
            != sha256_digest(value.importance_policy_bytes)
            or value.legal_input_fingerprint != legal_input_fingerprint_v1(value)
        ):
            raise ValueError
    except (TypeError, ValidationError, ValueError, RecursionError) as error:
        raise _projection_invalid() from error


def _require_passages_match_sources_v1(
    baseline_input: BaselineInputV1,
    baseline: CanonicalBaselineV1,
) -> None:
    source_texts = {
        source.source_id: source.normalized_text for source in baseline_input.sources
    }
    requirements: list[BaselineRequirementV1] = list(baseline.requirements)
    for contested in baseline.contested_requirements:
        requirements.extend(
            item
            for item in (
                contested.reviewer_alternative,
                contested.auditor_alternative,
            )
            if item is not None
        )
    try:
        for requirement in requirements:
            identities: list[tuple[str, int, int, str]] = []
            for passage in requirement.passages:
                text = source_texts[passage.source_id]
                identity = (
                    passage.source_id,
                    passage.start_char,
                    passage.end_char,
                    passage.quote,
                )
                if (
                    text.find(passage.quote) != passage.start_char
                    or text[passage.start_char : passage.end_char] != passage.quote
                    or passage.end_char != passage.start_char + len(passage.quote)
                    or identity in identities
                ):
                    raise ValueError
                identities.append(identity)
    except (KeyError, TypeError, ValueError) as error:
        raise _projection_invalid() from error


def _baseline_fingerprint_v1(value: CanonicalBaselineV1) -> str:
    return sha256_digest(
        canonical_json_bytes(
            value.model_dump(
                mode="json", exclude={"baseline_fingerprint"}, warnings="error"
            )
        )
    )


def _manifest_fingerprint_v1(value: BaselineManifestV1) -> str:
    return sha256_digest(
        canonical_json_bytes(
            value.model_dump(
                mode="json",
                exclude={"manifest_fingerprint", "root_hash"},
                warnings="error",
            )
        )
    )


def _manifest_root_v1(value: BaselineManifestV1) -> str:
    return sha256_digest(
        canonical_json_bytes(
            value.model_dump(mode="json", exclude={"root_hash"}, warnings="error")
        )
    )


def _require_context_fingerprint_consistency_v1(
    context: VerifiedBaselineContextV1,
) -> None:
    manifest = context.manifest
    baseline_input = context.baseline_input
    baseline = context.baseline
    verification = context.verification
    provenance = baseline.provenance
    artifacts = {item.artifact_path: item.artifact_hash for item in manifest.artifacts}
    correction_bindings = (
        manifest.prior_baseline_root,
        manifest.prior_baseline_fingerprint,
        manifest.correction_record_fingerprint,
    )
    try:
        _require_input_integrity_v1(baseline_input)
        _require_passages_match_sources_v1(baseline_input, baseline)
        if (
            verification.valid is not True
            or verification.issues
            or manifest.phase
            not in {BaselinePhaseV1.COMPLETED, BaselinePhaseV1.INCONCLUSIVE}
            or manifest.terminal_status not in {"COMPLETED", "INCONCLUSIVE"}
            or manifest.legal_input_fingerprint
            != baseline_input.legal_input_fingerprint
            or manifest.baseline_fingerprint != baseline.baseline_fingerprint
            or baseline.legal_input_fingerprint
            != baseline_input.legal_input_fingerprint
            or provenance.legal_input_fingerprint
            != baseline_input.legal_input_fingerprint
            or provenance.importance_policy_fingerprint
            != baseline_input.importance_policy_fingerprint
            or provenance.compiler_contract_fingerprint
            != baseline_input.compiler_contract_fingerprint
            or manifest.source_review_aggregate_fingerprint
            != provenance.source_review_aggregate_fingerprint
            or manifest.source_audit_aggregate_fingerprint
            != provenance.source_audit_aggregate_fingerprint
            or manifest.source_referee_aggregate_fingerprint
            != provenance.source_referee_aggregate_fingerprint
            or baseline.baseline_fingerprint != _baseline_fingerprint_v1(baseline)
            or manifest.manifest_fingerprint != _manifest_fingerprint_v1(manifest)
            or manifest.root_hash != _manifest_root_v1(manifest)
            or artifacts.get(BASELINE_INPUT_PATH) != _canonical_model_hash(baseline_input)
            or artifacts.get(CANONICAL_BASELINE_PATH) != _canonical_model_hash(baseline)
            or artifacts.get(BASELINE_VERIFICATION_PATH) != _canonical_model_hash(verification)
            or baseline.prior_baseline_fingerprint
            != manifest.prior_baseline_fingerprint
            or baseline.correction_record_fingerprint
            != manifest.correction_record_fingerprint
            or (baseline.prior_baseline_fingerprint is None)
            != (baseline.correction_record_fingerprint is None)
            or (baseline.prior_baseline_fingerprint is None)
            != (manifest.prior_baseline_root is None)
            or (any(item is None for item in correction_bindings)
                and any(item is not None for item in correction_bindings))
        ):
            raise ValueError
    except (AttributeError, TypeError, ValidationError, ValueError, RecursionError) as error:
        raise _projection_invalid() from error


def _gradeable_requirements_v1(
    requirements: tuple[BaselineRequirementV1, ...],
) -> tuple[GradeableRequirementV1, ...]:
    return tuple(
        GradeableRequirementV1(
            requirement=item,
            semantic_identity_fingerprint=_canonical_model_hash(item),
        )
        for item in requirements
    )


def _alternative_fingerprint_v1(value: BaselineRequirementV1 | None) -> str | None:
    return None if value is None else _canonical_model_hash(value)


def _gradeable_contests_v1(
    contests: tuple[ContestedBaselineRequirementV1, ...],
) -> tuple[GradeableContestedRequirementV1, ...]:
    return tuple(
        GradeableContestedRequirementV1(
            contested_requirement=item,
            reviewer_identity_fingerprint=_alternative_fingerprint_v1(
                item.reviewer_alternative
            ),
            auditor_identity_fingerprint=_alternative_fingerprint_v1(
                item.auditor_alternative
            ),
            semantic_identity_fingerprint=_canonical_model_hash(item),
        )
        for item in contests
    )


def _semantic_inventory_fingerprint_v1(
    requirements: tuple[GradeableRequirementV1, ...],
    relationships: tuple[BaselineRelationshipV1, ...],
    contests: tuple[GradeableContestedRequirementV1, ...],
) -> str:
    return sha256_digest(
        canonical_json_bytes(
            _gradeable_semantic_inventory_v1(requirements, relationships, contests)
        )
    )


def _grade_target_binding_v1(
    baseline_input: BaselineInputV1,
    baseline: CanonicalBaselineV1,
    semantic_inventory_fingerprint: str,
) -> BaselineGradeTargetBindingV1:
    raw = {
        "schema_version": "baseline-grade-target-v1",
        "legal_input_fingerprint": baseline_input.legal_input_fingerprint,
        "baseline_fingerprint": baseline.baseline_fingerprint,
        "source_record_fingerprint": baseline_input.source_record_fingerprint,
        "semantic_inventory_fingerprint": semantic_inventory_fingerprint,
        "evaluation_rubric_fingerprint": baseline_input.evaluation_rubric_fingerprint,
        "importance_policy_fingerprint": baseline_input.importance_policy_fingerprint,
        "compiler_contract_fingerprint": baseline_input.compiler_contract_fingerprint,
    }
    return BaselineGradeTargetBindingV1.model_validate(
        {
            **raw,
            "grade_target_fingerprint": sha256_digest(canonical_json_bytes(raw)),
        }
    )


def _strict_projection_with_fingerprint_v1(
    context: VerifiedBaselineContextV1,
    binding: BaselineGradeTargetBindingV1,
    requirements: tuple[GradeableRequirementV1, ...],
    contests: tuple[GradeableContestedRequirementV1, ...],
) -> GradeableBaselineProjectionV1:
    wire = {
        "schema_version": "baseline-gradeable-projection-v1",
        "baseline_protocol_version": "evaluation-baseline-v1",
        "binding": binding.model_dump(mode="json", warnings="error"),
        "baseline_input": context.baseline_input.model_dump(
            mode="json", warnings="error"
        ),
        "requirements": [
            item.model_dump(mode="json", warnings="error") for item in requirements
        ],
        "relationships": [
            item.model_dump(mode="json", warnings="error")
            for item in context.baseline.relationships
        ],
        "contested_requirements": [
            item.model_dump(mode="json", warnings="error") for item in contests
        ],
        "baseline_provenance": context.baseline.provenance.model_dump(
            mode="json", warnings="error"
        ),
    }
    result = GradeableBaselineProjectionV1(
        schema_version="baseline-gradeable-projection-v1",
        baseline_protocol_version="evaluation-baseline-v1",
        binding=binding,
        baseline_input=context.baseline_input,
        requirements=requirements,
        relationships=context.baseline.relationships,
        contested_requirements=contests,
        baseline_provenance=context.baseline.provenance,
        projection_fingerprint=sha256_digest(canonical_json_bytes(wire)),
    )
    return result.model_copy(update={"baseline_input": context.baseline_input})


def project_gradeable_baseline_v1(
    context: VerifiedBaselineContextV1,
) -> GradeableBaselineProjectionV1:
    """Project one fully verified four-field baseline context without I/O."""
    checked = _strict_verified_context_v1(context)
    _require_context_fingerprint_consistency_v1(checked)
    requirements = _gradeable_requirements_v1(checked.baseline.requirements)
    contested = _gradeable_contests_v1(checked.baseline.contested_requirements)
    semantic_fingerprint = _semantic_inventory_fingerprint_v1(
        requirements, checked.baseline.relationships, contested
    )
    binding = _grade_target_binding_v1(
        checked.baseline_input, checked.baseline, semantic_fingerprint
    )
    projection = _strict_projection_with_fingerprint_v1(
        checked, binding, requirements, contested
    )
    return projection.model_copy(update={"baseline_input": context.baseline_input})


def verify_gradeable_baseline_projection_v1(
    context: VerifiedBaselineContextV1,
    candidate: object,
) -> GradeableBaselineProjectionV1:
    """Return the recomputed projection only after exact canonical equality."""
    try:
        value = candidate
        if type(candidate) is dict:
            raw = dict(cast(dict[object, object], candidate))
            baseline_value = raw.get("baseline_input")
            if type(baseline_value) is dict:
                baseline_raw = dict(cast(dict[object, object], baseline_value))
                if "compiler_contract" in baseline_raw:
                    baseline_raw["compiler_contract"] = json.loads(
                        canonical_json_bytes(baseline_raw["compiler_contract"])
                    )
                for field_name in (
                    "evaluation_rubric_bytes",
                    "importance_policy_bytes",
                ):
                    field_value = baseline_raw.get(field_name)
                    if type(field_value) is str:
                        baseline_raw[field_name] = field_value.encode("utf-8")
                raw["baseline_input"] = baseline_raw
            value = raw
        checked_candidate = GradeableBaselineProjectionV1.model_validate(value)
        expected = project_gradeable_baseline_v1(context)
        if canonical_json_bytes(
            checked_candidate.model_dump(mode="json", warnings="error")
        ) != canonical_json_bytes(expected.model_dump(mode="json", warnings="error")):
            raise ValueError
    except (AttributeError, TypeError, ValidationError, ValueError, RecursionError) as error:
        raise _projection_invalid() from error
    return expected
