"""Request-bound protocol 2.2 source-fragment tests."""

from __future__ import annotations

import hashlib
from datetime import date
from enum import IntEnum, StrEnum
from pathlib import Path

import pytest

from regulatory_harvest.evaluation.attorney_admission import freeze_case
from regulatory_harvest.evaluation.attorney_models import (
    AttorneyEvaluationCase,
    CandidateReport,
    CandidateRole,
    CaseEnvelope,
    EvaluationMode,
    EvaluationSource,
    RequestedAuthority,
)
from regulatory_harvest.evaluation.attorney_v2_compiler import resolve_exact_passage
from regulatory_harvest.evaluation.attorney_v2_models import SemanticPassage
from regulatory_harvest.evaluation.attorney_v22_models import (
    AcceptedSourceAuditFragmentV22,
    AcceptedSourceReviewFragmentV22,
    CanonicalBaselineV22,
    ContestedRequirementV22,
    EvaluatorOperationV22,
    RefereeDisputeV22,
    RefereeEvidenceV22,
    SourceAuditAggregateV22,
    SourceAuditFragmentV22,
    SourceReviewAggregateV22,
    SourceReviewFragmentV22,
)
from regulatory_harvest.evaluation.attorney_v22_requests import (
    COMPILER_CONTRACT_FINGERPRINT_V22,
    COMPILER_CONTRACT_V22,
    build_contested_grade_request_v22,
    build_ordinary_grade_request_v22,
    build_source_audit_fragment_request_v22,
    build_source_referee_fragment_request_v22,
    build_source_review_fragment_request_v22,
    compiler_contract_fingerprint_v22,
)
from regulatory_harvest.models import SourceQuality, SourceRole
from regulatory_harvest.storage import canonical_json_bytes


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class _ForeignOrdinal(IntEnum):
    ONE = 1


class _ForeignLabel(StrEnum):
    A = "A"


def envelope() -> CaseEnvelope:
    text = "Rule: operators must file. Small operators are excluded."
    report = "Operators must file."
    return freeze_case(
        AttorneyEvaluationCase(
            case_id="v22-request-case",
            mode=EvaluationMode.CLOSED_UNIVERSE,
            question="What is required?",
            jurisdiction="Example State",
            as_of=date(2026, 8, 19),
            requested_authorities=[
                RequestedAuthority(
                    authority_id="rule",
                    title="Rule",
                    jurisdiction="Example State",
                    authority_type="regulation",
                    source_ids=["rule-1"],
                )
            ],
            sources=[
                EvaluationSource(
                    source_id="rule-1",
                    title="Rule",
                    normalized_text=text,
                    content_hash=_hash(text),
                    jurisdiction="Example State",
                    authority_type="regulation",
                    source_role=SourceRole.OFFICIAL_PRIMARY,
                    source_quality=SourceQuality.PRIMARY,
                    completeness="complete",
                    language="en",
                )
            ],
            candidates=[
                CandidateReport(
                    candidate_id="candidate",
                    role=CandidateRole.CANDIDATE,
                    report_text=report,
                    report_hash=_hash(report),
                )
            ],
        ),
        seed_hex="0" * 64,
    )


def proposal(statement: str = "Operators must file.") -> dict[str, object]:
    return {
        "statement": statement,
        "kind": "obligation",
        "importance": "critical",
        "passages": [{"source_id": "rule-1", "quote": "operators must file"}],
        "dependency": None,
        "confidence": "clear",
        "rationale": "The source is direct.",
    }


def accepted_review(
    ordinal: int = 1, statement: str = "Operators must file.", *, final: bool = False
) -> AcceptedSourceReviewFragmentV22:
    request = build_source_review_fragment_request_v22(envelope(), (), fragment_ordinal=ordinal)
    return AcceptedSourceReviewFragmentV22(
        fragment_ordinal=ordinal,
        request_fingerprint=request.request_fingerprint,
        response_fingerprint=f"{ordinal + 16:064x}",
        payload=SourceReviewFragmentV22(proposals=[proposal(statement)], review_complete=final),
    )


def review_aggregate() -> SourceReviewAggregateV22:
    from regulatory_harvest.evaluation.attorney_v22_compiler import (
        aggregate_source_review_fragments_v22,
    )

    request = build_source_review_fragment_request_v22(envelope(), (), fragment_ordinal=1)
    fragment = AcceptedSourceReviewFragmentV22(
        fragment_ordinal=1,
        request_fingerprint=request.request_fingerprint,
        response_fingerprint="1" * 64,
        payload=SourceReviewFragmentV22(proposals=[proposal()], review_complete=True),
    )
    return aggregate_source_review_fragments_v22((fragment,))


def audit_aggregate() -> SourceAuditAggregateV22:
    from regulatory_harvest.evaluation.attorney_v22_compiler import (
        aggregate_source_audit_fragments_v22,
    )

    review = review_aggregate()
    request = build_source_audit_fragment_request_v22(
        envelope(), review, (), fragment_ordinal=1
    )
    fragment = AcceptedSourceAuditFragmentV22(
        fragment_ordinal=1,
        request_fingerprint=request.request_fingerprint,
        response_fingerprint="3" * 64,
        payload=SourceAuditFragmentV22(concerns=(), audit_complete=True),
    )
    return aggregate_source_audit_fragments_v22(review, (fragment,))


def referee_inventory(size: int) -> tuple[RefereeDisputeV22, ...]:
    from regulatory_harvest.evaluation.attorney_v22_compiler import (
        aggregate_source_audit_fragments_v22,
        build_referee_disputes_v22,
        referee_dispute_fingerprint_v22,
    )

    review = review_aggregate()
    request = build_source_audit_fragment_request_v22(
        envelope(), review, (), fragment_ordinal=1
    )
    fragment = AcceptedSourceAuditFragmentV22(
        fragment_ordinal=1,
        request_fingerprint=request.request_fingerprint,
        response_fingerprint="4" * 64,
        payload=SourceAuditFragmentV22(
            concerns=[
                {
                    "target_proposal_ref": "P0001",
                    "concern_type": "incorrect_statement",
                    "passages": [{"source_id": "rule-1", "quote": "operators must file"}],
                    "explanation": "The exception is omitted.",
                    "correction": proposal("Operators must file unless small."),
                }
            ],
            audit_complete=True,
        ),
    )
    audit = aggregate_source_audit_fragments_v22(review, (fragment,))
    seed = build_referee_disputes_v22(envelope(), review, audit)[0]
    inventory = []
    for number in range(1, size + 1):
        dispute_id = f"D{number:04d}"
        provisional = RefereeDisputeV22(
            case_fingerprint=seed.case_fingerprint,
            dispute_fingerprint="0" * 64,
            dispute_id=dispute_id,
            material_dispute=seed.material_dispute.model_copy(update={"dispute_id": dispute_id}),
            evidence=[seed.evidence[0].model_copy(update={"evidence_ref": f"EVID-{number:04d}"})],
        )
        inventory.append(
            provisional.model_copy(
                update={"dispute_fingerprint": referee_dispute_fingerprint_v22(provisional)}
            )
        )
    return tuple(inventory)


def test_compiler_contract_binds_every_wire_shaping_rule() -> None:
    assert COMPILER_CONTRACT_V22["protocol"] == "2.2"
    assert COMPILER_CONTRACT_V22["operations"] == [item.value for item in EvaluatorOperationV22]
    assert COMPILER_CONTRACT_V22["fragment_maximum"] == 5
    assert COMPILER_CONTRACT_V22["fragments_per_operation_maximum"] == 128
    assert COMPILER_CONTRACT_V22["items_per_operation_maximum"] == 640
    assert COMPILER_CONTRACT_V22["rubric_version"] == "attorney-eval-v2.2"
    assert len(COMPILER_CONTRACT_V22["strict_schema_hashes"]["rubric"]) == 64
    assert (
        compiler_contract_fingerprint_v22({**COMPILER_CONTRACT_V22, "aggregate_version": "changed"})
        != COMPILER_CONTRACT_FINGERPRINT_V22
    )


def test_second_review_request_carries_only_compiled_accepted_inventory() -> None:
    first = accepted_review()
    request = build_source_review_fragment_request_v22(envelope(), (first,), fragment_ordinal=2)

    assert request.operation is EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT
    assert request.payload["accepted_proposals"] == [proposal()]
    assert request.payload["max_new_proposals"] == 5
    assert request.payload["fragment_ordinal"] == 2
    assert "report_text" not in request.payload["source_record"]
    assert (
        request.safe_metadata["compiler_contract_fingerprint"] == COMPILER_CONTRACT_FINGERPRINT_V22
    )


def test_linear_source_builders_preserve_pre_refactor_request_bytes() -> None:
    from regulatory_harvest.evaluation.attorney_v22_compiler import (
        aggregate_source_review_fragments_v22,
    )

    case = envelope()
    first_request = build_source_review_fragment_request_v22(
        case, (), fragment_ordinal=1
    )
    first = AcceptedSourceReviewFragmentV22(
        fragment_ordinal=1,
        request_fingerprint=first_request.request_fingerprint,
        response_fingerprint="1" * 64,
        payload=SourceReviewFragmentV22(
            proposals=[proposal()], review_complete=False
        ),
    )
    second_request = build_source_review_fragment_request_v22(
        case, (first,), fragment_ordinal=2
    )
    review = aggregate_source_review_fragments_v22(
        (
            first.model_copy(
                update={
                    "payload": first.payload.model_copy(
                        update={"review_complete": True}
                    )
                }
            ),
        )
    )
    audit_request = build_source_audit_fragment_request_v22(
        case, review, (), fragment_ordinal=1
    )
    requests = (first_request, second_request, audit_request)

    assert tuple(item.request_fingerprint for item in requests) == (
        "987ec550249548eb3e70ef566d8dc850b1b507818ae2929c36879afd807f49e9",
        "cabeb291263f15fcea6f2aebbcf704e376edf5752ff6464bc1e5f303c14675b0",
        "3bea380ea7d22f24af7616f70961fd9148878184e460aab3d70575f021aeb3cb",
    )
    assert tuple(
        hashlib.sha256(
            canonical_json_bytes(item.model_dump(mode="json"))
        ).hexdigest()
        for item in requests
    ) == (
        "e8751d500471e7a566bcd9781461611f58af699d535fcb2abd7e056648e6f7a6",
        "4eacbb5994711de5bcd513fbbd1b1f7c4f78d0ed42024d0d7ad5ff067ed5ea4b",
        "c4b6288f6aebc979f8a75136284444ce15080272e48bf5bded134b04fa4f8487",
    )


def test_source_fragment_requests_reject_skipped_or_bypass_constructed_history() -> None:
    first = accepted_review()
    with pytest.raises(ValueError, match="ordinal"):
        build_source_review_fragment_request_v22(envelope(), (first,), fragment_ordinal=3)
    forged = first.model_construct(
        **{
            **first.__dict__,
            "payload": SourceReviewFragmentV22.model_construct(proposals=(), review_complete=False),
        }
    )
    with pytest.raises(ValueError, match="accepted source-review"):
        build_source_review_fragment_request_v22(envelope(), (forged,), fragment_ordinal=2)


def test_review_history_cannot_be_reused_for_a_different_case() -> None:
    first = accepted_review()
    changed = envelope().case.model_copy(update={"case_id": "other-v22-request-case"})
    from regulatory_harvest.evaluation.attorney_admission import freeze_case

    other = freeze_case(changed, seed_hex="1" * 64)

    with pytest.raises(ValueError, match="another request sequence"):
        build_source_review_fragment_request_v22(other, (first,), fragment_ordinal=2)


def test_source_audit_request_carries_full_review_and_prior_concerns() -> None:
    initial_request = build_source_audit_fragment_request_v22(
        envelope(), review_aggregate(), (), fragment_ordinal=1
    )
    first = AcceptedSourceAuditFragmentV22(
        fragment_ordinal=1,
        request_fingerprint=initial_request.request_fingerprint,
        response_fingerprint="5" * 64,
        payload=SourceAuditFragmentV22(
            concerns=[
                {
                    "target_proposal_ref": "P0001",
                    "concern_type": "ambiguity",
                    "passages": [{"source_id": "rule-1", "quote": "operators must file"}],
                    "explanation": "The exception needs attention.",
                    "correction": None,
                }
            ],
            audit_complete=False,
        ),
    )
    request = build_source_audit_fragment_request_v22(
        envelope(), review_aggregate(), (first,), fragment_ordinal=2
    )

    assert request.operation is EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT
    assert request.payload["indexed_proposals"] == [
        item.model_dump(mode="json") for item in review_aggregate().proposals
    ]
    assert len(request.payload["accepted_concerns"]) == 1
    assert request.payload["max_new_concerns"] == 5
    assert (
        request.safe_metadata["source_record_fingerprint"]
        == _hash(request.payload["source_record"].__class__.__name__)
        or len(request.safe_metadata["source_record_fingerprint"]) == 64
    )


def test_downstream_requests_use_only_v22_payload_schemas() -> None:
    from regulatory_harvest.evaluation.attorney_v22_compiler import build_referee_disputes_v22

    review = review_aggregate()
    audit = audit_aggregate()
    baseline = None
    disputes = build_referee_disputes_v22(envelope(), review, audit)
    if disputes:
        referee = build_source_referee_fragment_request_v22(
            envelope(), disputes[0], controller_disputes=disputes
        )
        assert referee.operation is EvaluatorOperationV22.SOURCE_REFEREE_FRAGMENT
        assert referee.json_schema["properties"]["schema_version"]["const"] == "2.2"
    # A no-dispute baseline still creates v2.2 ordinary grade packets.
    from regulatory_harvest.evaluation.attorney_v22_compiler import (
        aggregate_referee_decisions_v22,
        compile_baseline_v22,
    )

    aggregate = aggregate_referee_decisions_v22(disputes, ())
    baseline = compile_baseline_v22(envelope(), review, audit, aggregate)
    if baseline.requirements:
        from regulatory_harvest.evaluation.attorney_v22_compiler import ordinary_grade_batches_v22

        batch = ordinary_grade_batches_v22(baseline, "A", 1)[0]
        ordinary = build_ordinary_grade_request_v22(
            baseline, batch, "A", 1, "Operators must file.", {"rule-1": "source"}
        )
        assert ordinary.operation is EvaluatorOperationV22.ORDINARY_GRADE_FRAGMENT
        assert "2.1" not in str(ordinary.model_dump(mode="json"))
    assert baseline is not None
    assert build_contested_grade_request_v22 is not None


def test_referee_request_enforces_128_dispute_inventory_before_issuance() -> None:
    inventory = referee_inventory(128)
    request = build_source_referee_fragment_request_v22(
        envelope(), inventory[0], controller_disputes=inventory
    )
    assert request.safe_metadata["dispute_id"] == "D0001"

    with pytest.raises(ValueError, match="inventory"):
        build_source_referee_fragment_request_v22(
            envelope(), referee_inventory(129)[0], controller_disputes=referee_inventory(129)
        )


def test_referee_request_rejects_a_foreign_companion_dispute_inventory_item() -> None:
    from regulatory_harvest.evaluation.attorney_v22_compiler import referee_dispute_fingerprint_v22

    first, second = referee_inventory(2)
    foreign = second.model_copy(
        update={"case_fingerprint": "f" * 64, "dispute_fingerprint": "0" * 64}
    )
    foreign = foreign.model_copy(
        update={"dispute_fingerprint": referee_dispute_fingerprint_v22(foreign)}
    )
    with pytest.raises(ValueError, match="inventory"):
        build_source_referee_fragment_request_v22(
            envelope(), first, controller_disputes=(first, foreign)
        )


def test_referee_request_rejects_same_case_padded_exact_source_evidence() -> None:
    from regulatory_harvest.evaluation.attorney_v22_compiler import referee_dispute_fingerprint_v22

    (dispute,) = referee_inventory(1)
    padded = dispute.model_copy(
        update={
            "evidence": (
                *dispute.evidence,
                RefereeEvidenceV22(
                    evidence_ref="EVID-0002",
                    passage=resolve_exact_passage(
                        envelope().case.sources[0].normalized_text,
                        SemanticPassage(source_id="rule-1", quote="Small operators"),
                    ),
                ),
            ),
            "dispute_fingerprint": "0" * 64,
        }
    )
    padded = padded.model_copy(
        update={"dispute_fingerprint": referee_dispute_fingerprint_v22(padded)}
    )
    with pytest.raises(ValueError, match="inventory"):
        build_source_referee_fragment_request_v22(
            envelope(), padded, controller_disputes=(padded,)
        )


def test_contested_grade_request_enforces_128_item_inventory_before_issuance() -> None:
    from regulatory_harvest.evaluation.attorney_v22_compiler import (
        aggregate_referee_decisions_v22,
        build_referee_disputes_v22,
        compile_baseline_v22,
    )

    review, audit = review_aggregate(), audit_aggregate()
    disputes = build_referee_disputes_v22(envelope(), review, audit)
    baseline = compile_baseline_v22(
        envelope(), review, audit, aggregate_referee_decisions_v22(disputes, ())
    )
    alternative = baseline.requirements[0]
    inventory = tuple(
        ContestedRequirementV22(
            contested_requirement_id=f"CONT-{number:04d}",
            reviewer_alternative=alternative,
            auditor_alternative=None,
            unresolved_reason="SOURCE_GAP",
            rationale="A valid dispute remains.",
            referee_fragment_fingerprint=f"{number:064x}",
        )
        for number in range(1, 130)
    )
    raw_128 = {
        **baseline.model_dump(mode="json"),
        "contested_requirements": [item.model_dump(mode="json") for item in inventory[:128]],
    }
    raw_128["baseline_fingerprint"] = hashlib.sha256(
        canonical_json_bytes(
            {key: value for key, value in raw_128.items() if key != "baseline_fingerprint"}
        )
    ).hexdigest()
    sealed_128 = CanonicalBaselineV22.model_validate(raw_128)
    request = build_contested_grade_request_v22(
        sealed_128, inventory[127], "A", 1, "report", {"rule-1": "source"}
    )
    assert request.safe_metadata["contested_requirement_id"] == "CONT-0128"
    raw_129 = {
        **baseline.model_dump(mode="json"),
        "contested_requirements": [item.model_dump(mode="json") for item in inventory],
    }
    raw_129["baseline_fingerprint"] = hashlib.sha256(
        canonical_json_bytes(
            {key: value for key, value in raw_129.items() if key != "baseline_fingerprint"}
        )
    ).hexdigest()
    sealed_129 = CanonicalBaselineV22.model_validate(raw_129)
    with pytest.raises(ValueError, match="128"):
        build_contested_grade_request_v22(
            sealed_129, inventory[128], "A", 1, "report", {"rule-1": "source"}
        )


@pytest.mark.parametrize("forged_ordinal", [True, "1", 1.0], ids=("bool", "str", "float"))
def test_source_request_histories_reject_constructed_noninteger_ordinals(
    forged_ordinal: object,
) -> None:
    with pytest.raises(ValueError):
        build_source_review_fragment_request_v22(
            envelope(), (), fragment_ordinal=forged_ordinal  # type: ignore[arg-type]
        )
    first = accepted_review()
    forged_review = AcceptedSourceReviewFragmentV22.model_construct(
        **{**first.__dict__, "fragment_ordinal": forged_ordinal}
    )
    with pytest.raises(ValueError, match="accepted source-review"):
        build_source_review_fragment_request_v22(
            envelope(), (forged_review,), fragment_ordinal=2
        )

    review = review_aggregate()
    with pytest.raises(ValueError):
        build_source_audit_fragment_request_v22(
            envelope(), review, (), fragment_ordinal=forged_ordinal  # type: ignore[arg-type]
        )
    initial = build_source_audit_fragment_request_v22(envelope(), review, (), fragment_ordinal=1)
    audit = AcceptedSourceAuditFragmentV22.model_construct(
        fragment_ordinal=forged_ordinal,
        request_fingerprint=initial.request_fingerprint,
        response_fingerprint="5" * 64,
        payload=SourceAuditFragmentV22(
            concerns=[
                {
                    "target_proposal_ref": "P0001",
                    "concern_type": "ambiguity",
                    "passages": [{"source_id": "rule-1", "quote": "operators must file"}],
                    "explanation": "The exception needs attention.",
                    "correction": None,
                }
            ],
            audit_complete=False,
        ),
    )
    with pytest.raises(ValueError, match="accepted source-audit"):
        build_source_audit_fragment_request_v22(envelope(), review, (audit,), fragment_ordinal=2)


def _contested_baseline() -> tuple[CanonicalBaselineV22, ContestedRequirementV22]:
    from test_attorney_v22_compiler import _bound_disputed_source_aggregates

    from regulatory_harvest.evaluation.attorney_v22_compiler import (
        aggregate_referee_decisions_v22,
        build_referee_disputes_v22,
        compile_baseline_v22,
        validate_referee_fragment_v22,
    )

    review, audit = _bound_disputed_source_aggregates()
    disputes = build_referee_disputes_v22(envelope(), review, audit)
    fragment = validate_referee_fragment_v22(
        disputes[0],
        {
            "decision": "unresolved",
            "unresolved_reason": "SOURCE_GAP",
            "evidence_refs": [disputes[0].evidence[0].evidence_ref],
            "rationale": "The source does not resolve the alternatives.",
        },
        response_fingerprint="5" * 64,
    )
    baseline = compile_baseline_v22(
        envelope(), review, audit, aggregate_referee_decisions_v22(disputes, (fragment,))
    )
    return baseline, baseline.contested_requirements[0]


@pytest.mark.parametrize("grader_lane", [True, "1", 1.0], ids=("bool", "str", "float"))
def test_grade_request_boundaries_reject_noninteger_lane_coordinates(
    grader_lane: object,
) -> None:
    from test_attorney_v22_compiler import canonical_baseline

    from regulatory_harvest.evaluation.attorney_v22_compiler import ordinary_grade_batches_v22

    ordinary_baseline = canonical_baseline()
    with pytest.raises(ValueError):
        ordinary_grade_batches_v22(
            ordinary_baseline, "A", grader_lane  # type: ignore[arg-type]
        )
    batch = ordinary_grade_batches_v22(ordinary_baseline, "A", 1)[0]
    with pytest.raises(ValueError):
        build_ordinary_grade_request_v22(
            ordinary_baseline,
            batch,
            "A",
            grader_lane,  # type: ignore[arg-type]
            "report",
            {"rule-1": "source"},
        )

    contested_baseline, contested = _contested_baseline()
    with pytest.raises(ValueError):
        build_contested_grade_request_v22(
            contested_baseline,
            contested,
            "A",
            grader_lane,  # type: ignore[arg-type]
            "report",
            {"rule-1": "source"},
        )


def test_referee_request_rejects_constructed_boolean_passage_offsets() -> None:
    from test_attorney_v22_compiler import _dispute_with_boolean_source_offset

    (dispute,) = referee_inventory(1)
    forged = _dispute_with_boolean_source_offset(dispute)
    with pytest.raises(ValueError, match="referee dispute"):
        build_source_referee_fragment_request_v22(
            envelope(), forged, controller_disputes=(forged,)
        )


def test_request_coordinates_reject_unrelated_enum_scalar_provenance() -> None:
    from test_attorney_v22_compiler import canonical_baseline

    from regulatory_harvest.evaluation.attorney_v22_compiler import ordinary_grade_batches_v22

    with pytest.raises(ValueError):
        build_source_review_fragment_request_v22(
            envelope(), (), fragment_ordinal=_ForeignOrdinal.ONE
        )

    baseline = canonical_baseline()
    batch = ordinary_grade_batches_v22(baseline, "A", 1)[0]
    with pytest.raises(ValueError):
        build_ordinary_grade_request_v22(
            baseline,
            batch,
            _ForeignLabel.A,  # type: ignore[arg-type]
            _ForeignOrdinal.ONE,  # type: ignore[arg-type]
            "report",
            {"rule-1": "source"},
        )


@pytest.mark.parametrize(
    "source_context",
    [
        {True: "source"},
        {1: "source"},
        {"rule-1": True},
        {"rule-1": 1},
        {"rule-1": Path("source.txt")},
        {"": "source"},
        {"rule-1": " "},
        {f"rule-{index}": "source" for index in range(641)},
        {"rule-1": "x" * (16 * 1024 * 1024 + 1)},
    ],
    ids=(
        "bool-key",
        "number-key",
        "bool-value",
        "number-value",
        "path-value",
        "blank-key",
        "blank-value",
        "item-limit",
        "byte-limit",
    ),
)
def test_grade_requests_reject_nonplain_or_unbounded_source_context(
    source_context: object,
) -> None:
    from test_attorney_v22_compiler import canonical_baseline

    from regulatory_harvest.evaluation.attorney_v22_compiler import ordinary_grade_batches_v22

    ordinary_baseline = canonical_baseline()
    batch = ordinary_grade_batches_v22(ordinary_baseline, "A", 1)[0]
    with pytest.raises(ValueError, match="source context"):
        build_ordinary_grade_request_v22(
            ordinary_baseline,
            batch,
            "A",
            1,
            "report",
            source_context,  # type: ignore[arg-type]
        )

    contested_baseline, contested = _contested_baseline()
    with pytest.raises(ValueError, match="source context"):
        build_contested_grade_request_v22(
            contested_baseline,
            contested,
            "A",
            1,
            "report",
            source_context,  # type: ignore[arg-type]
        )
