# ruff: noqa: E501
"""Wire-boundary tests for fragmented evaluator protocol 2.1 requests."""

from __future__ import annotations

import copy

import pytest
from test_attorney_v21_compiler import audit, audit_with_two_concerns, envelope, review

from regulatory_harvest.evaluation.attorney_admission import freeze_case
from regulatory_harvest.evaluation.attorney_v21_compiler import (
    _dispute_fingerprint,
    build_referee_disputes,
)
from regulatory_harvest.evaluation.attorney_v21_requests import (
    build_contested_grade_request_v21,
    build_ordinary_grade_request_v21,
    build_source_audit_request_v21,
    build_source_referee_fragment_request,
    build_source_review_request_v21,
    mechanical_retry_request_v21,
)
from regulatory_harvest.evaluation.attorney_v21_rubric import RUBRIC_V21, ordinary_grade_batches


def test_source_requests_preserve_v20_semantic_fields_with_literal_v21_schema() -> None:
    source_review = build_source_review_request_v21(envelope())
    source_audit = build_source_audit_request_v21(envelope(), review())

    assert source_review.operation == "source_review"
    assert source_review.json_schema["properties"]["schema_version"]["const"] == "2.1"
    assert set(source_audit.payload) == {"source_record", "indexed_proposals"}
    assert source_audit.json_schema["properties"]["schema_version"]["const"] == "2.1"


def test_referee_request_contains_exactly_one_dispute_and_inner_schema_has_no_id() -> None:
    disputes = build_referee_disputes(envelope(), review(), audit())
    request = build_source_referee_fragment_request(
        envelope(), disputes[0], controller_disputes=disputes
    )

    assert len(request.payload["material_disputes"]) == 1
    assert "dispute_id" not in request.json_schema["properties"]
    assert request.operation == "source_referee_fragment"


def test_referee_request_rejects_a_dispute_from_another_case() -> None:
    disputes = build_referee_disputes(envelope(), review(), audit())
    other_case = envelope().case.model_copy(update={"case_id": "other-v21-request-case"})
    other_envelope = freeze_case(other_case, seed_hex="2" * 64)

    with pytest.raises(ValueError, match="referee dispute must bind the frozen case"):
        build_source_referee_fragment_request(
            other_envelope, disputes[0], controller_disputes=disputes
        )


def test_referee_request_rejects_raw_dispute_payload() -> None:
    disputes = build_referee_disputes(envelope(), review(), audit())

    with pytest.raises(ValueError, match="referee dispute must be a strict controller model"):
        build_source_referee_fragment_request(
            envelope(),
            disputes[0].model_dump(mode="json"),  # type: ignore[arg-type]
            controller_disputes=disputes,
        )


@pytest.mark.parametrize("constructed", [False, True])
@pytest.mark.parametrize("mutation", ["quote", "offset", "fingerprint"])
def test_referee_request_rejects_forged_same_case_evidence(
    constructed: bool,
    mutation: str,
) -> None:
    disputes = build_referee_disputes(envelope(), review(), audit())
    dispute = disputes[0]
    payload = copy.deepcopy(dispute.model_dump(mode="json"))
    evidence = payload["evidence"]
    assert isinstance(evidence, list)
    assert isinstance(evidence[0], dict)
    passage = evidence[0]["passage"]
    assert isinstance(passage, dict)
    if mutation == "quote":
        passage["quote"] = "FABRICATED AUTHORITY"
    elif mutation == "offset":
        passage["start_char"] = 0
    else:
        payload["dispute_fingerprint"] = "f" * 64
    validated = type(dispute).model_validate(payload)
    forged = type(dispute).model_construct(**dict(validated.__dict__)) if constructed else validated

    with pytest.raises(ValueError, match="referee dispute must match frozen evidence"):
        build_source_referee_fragment_request(
            envelope(), forged, controller_disputes=disputes
        )


def test_referee_request_rejects_recomputed_noncanonical_evidence_reference() -> None:
    frozen = envelope()
    disputes = build_referee_disputes(frozen, review(), audit())
    payload = copy.deepcopy(disputes[0].model_dump(mode="json"))
    evidence = payload["evidence"]
    assert isinstance(evidence, list)
    assert isinstance(evidence[0], dict)
    evidence[0]["evidence_ref"] = "EVID-9999"
    material_dispute = payload["material_dispute"]
    assert isinstance(material_dispute, dict)
    payload["dispute_fingerprint"] = _dispute_fingerprint(
        frozen.case_fingerprint,
        type(disputes[0].material_dispute).model_validate(material_dispute),
        tuple(type(disputes[0].evidence[0]).model_validate(item) for item in evidence),
    )
    forged = type(disputes[0]).model_validate(payload)

    with pytest.raises(
        ValueError, match="selected referee dispute must match controller inventory"
    ):
        build_source_referee_fragment_request(
            frozen, forged, controller_disputes=disputes
        )


def test_referee_request_requires_the_matching_controller_inventory() -> None:
    disputes = build_referee_disputes(envelope(), review(), audit())

    with pytest.raises(TypeError):
        build_source_referee_fragment_request(envelope(), disputes[0])
    with pytest.raises(ValueError, match="controller dispute inventory is invalid"):
        build_source_referee_fragment_request(envelope(), disputes[0], controller_disputes=())


@pytest.mark.parametrize("inventory_kind", ["raw", "duplicate", "swapped"])
def test_referee_request_rejects_noncontroller_or_noncanonical_inventory(
    inventory_kind: str,
) -> None:
    disputes = build_referee_disputes(envelope(), review(), audit_with_two_concerns())
    if inventory_kind == "raw":
        inventory: object = tuple(item.model_dump(mode="json") for item in disputes)
    elif inventory_kind == "duplicate":
        inventory = (disputes[0], disputes[0])
    else:
        inventory = tuple(reversed(disputes))

    with pytest.raises(ValueError, match="controller dispute inventory is invalid"):
        build_source_referee_fragment_request(
            envelope(), disputes[0], controller_disputes=inventory  # type: ignore[arg-type]
        )


def test_mechanical_retry_reconstructs_the_exact_original_request() -> None:
    request = build_source_review_request_v21(envelope())

    assert mechanical_retry_request_v21(
        request, expected_request_fingerprint=request.request_fingerprint
    ) == request


def test_grade_requests_are_bounded_and_keep_contested_alternatives_together() -> None:
    from regulatory_harvest.evaluation.attorney_v2_models import (
        CanonicalRequirementV2,
        ResolvedPassageV2,
    )
    from regulatory_harvest.evaluation.attorney_v21_models import (
        CanonicalBaselineV21,
        ContestedRequirementV21,
    )

    alternative = CanonicalRequirementV2(requirement_id="REQ-0001", canonical_order=0, statement="File.", kind="obligation", importance="critical", passages=[ResolvedPassageV2(source_id="rule-1", quote="rule", start_char=0, end_char=4)], confidence="clear", rationale="Clear.")
    baseline = CanonicalBaselineV21(schema_version="2.1", case_fingerprint="a" * 64, requirements=[], contested_requirements=[ContestedRequirementV21(contested_requirement_id="CONT-0001", reviewer_alternative=alternative, auditor_alternative=alternative, unresolved_reason="SOURCE_GAP", rationale="Unresolved.", referee_fragment_fingerprint="c" * 64)], baseline_fingerprint="b" * 64)
    contested = baseline.contested_requirements[0]
    request = build_contested_grade_request_v21(
        baseline, contested, "A", 1, "Operators must file.", {"rule-1": "source context"}, RUBRIC_V21
    )

    assert request.operation == "contested_grade_fragment"
    assert request.payload["baseline_fingerprint"] == baseline.baseline_fingerprint
    assert set(request.payload) == {"anonymous_label", "grader_lane", "baseline_fingerprint", "contested_requirement", "report_text", "report_fingerprint", "source_context", "rubric"}
    assert request.payload["contested_requirement"]["reviewer_alternative"] is not None  # type: ignore[index]
    assert request.payload["contested_requirement"]["auditor_alternative"] is not None  # type: ignore[index]
    assert ordinary_grade_batches(baseline, "A", 1) == ()


def test_ordinary_grade_request_contains_only_its_five_requirement_subset() -> None:
    # Request construction accepts an explicit deterministic inventory rather than a caller-defined list.
    from regulatory_harvest.evaluation.attorney_v2_models import (
        CanonicalRequirementV2,
        ResolvedPassageV2,
    )
    from regulatory_harvest.evaluation.attorney_v21_models import CanonicalBaselineV21

    baseline = CanonicalBaselineV21(
        schema_version="2.1", case_fingerprint="a" * 64,
        requirements=[
            CanonicalRequirementV2(requirement_id=f"REQ-{index:04d}", canonical_order=index - 1, statement=f"Requirement {index}.", kind="obligation", importance="material", passages=[ResolvedPassageV2(source_id="rule-1", quote="rule", start_char=0, end_char=4)], confidence="clear", rationale="Clear.")
            for index in range(1, 7)
        ], baseline_fingerprint="b" * 64,
    )
    batch = ordinary_grade_batches(baseline, "B", 2)[0]

    request = build_ordinary_grade_request_v21(
        baseline, batch, "B", 2, "A report.", {"rule-1": "source context"}, RUBRIC_V21
    )

    assert request.operation == "ordinary_grade_fragment"
    assert [item["requirement_id"] for item in request.payload["requirements"]] == list(batch.requirement_ids)  # type: ignore[index]
    assert len(request.payload["requirements"]) == 5  # type: ignore[arg-type,index]
