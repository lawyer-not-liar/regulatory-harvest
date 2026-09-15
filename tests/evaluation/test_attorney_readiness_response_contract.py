"""The published safety response format must agree with its real compiler."""

from __future__ import annotations

from collections.abc import Mapping

import pytest
from test_attorney_readiness_drafts import (
    _provenance,
    _safety_draft,
    _verified_grader_lanes,
)
from test_attorney_readiness_inputs import _make_verified_inputs

from regulatory_harvest.evaluation.attorney_readiness_drafts import (
    CompiledReadinessDraftV1,
    NeedsReadinessClarificationV1,
    ReadinessEngineDefectV1,
    compile_readiness_draft_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_inputs import (
    build_verified_readiness_input_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_models import ReadinessEvaluatorRequestV1
from regulatory_harvest.evaluation.attorney_readiness_requests import (
    build_gap_candidate_inventory_v1,
    build_safety_lane_request_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_response_contract import (
    CONSEQUENCES,
    RESOLUTION_ACTIONS,
    RESOLUTION_OUTCOMES,
    SPECIFICITY_TERMS,
)
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest


def test_v1_lexical_rules_retain_the_preexisting_acceptance_vocabulary():
    """Pin the reviewed legacy rules, independently of producer/consumer agreement."""
    descriptor = {
        "consequences": CONSEQUENCES,
        "resolution_actions": RESOLUTION_ACTIONS,
        "resolution_outcomes": RESOLUTION_OUTCOMES,
        "specificity_terms": sorted(SPECIFICITY_TERMS),
    }
    assert sha256_digest(canonical_json_bytes(descriptor)) == (
        "f7291773e76f238ffbf2044cfc41a4e2ef086817d4830abe298aef9be2855251"
    )


@pytest.fixture(scope="module")
def safety_request(tmp_path_factory: pytest.TempPathFactory) -> ReadinessEvaluatorRequestV1:
    artifacts = _make_verified_inputs(tmp_path_factory.mktemp("safety-format-contract"))
    inputs = build_verified_readiness_input_v1(
        baseline_run_dir=artifacts.baseline_run_dir,
        qualification_run_dir=artifacts.qualification_run_dir,
        generation_run_dir=artifacts.generation_run_dir,
        validation_receipt_path=artifacts.validation_receipt_path,
    )
    lanes = _verified_grader_lanes(inputs)
    return build_safety_lane_request_v1(
        inputs, lanes, build_gap_candidate_inventory_v1(inputs, lanes), lane=1
    )


def _rebind(raw: dict) -> ReadinessEvaluatorRequestV1:
    raw.pop("request_fingerprint", None)
    return ReadinessEvaluatorRequestV1.model_validate(
        {**raw, "request_fingerprint": sha256_digest(canonical_json_bytes(raw))}
    )


def test_safety_packet_consumer_can_obey_the_advertised_lexical_rules(safety_request):
    """Catch missing or inaccurate instructions for enforced rationale predicates."""
    contract = safety_request.payload.get("safety_response_contract")
    assert isinstance(contract, Mapping), "Safety packet must communicate its format rules"
    draft = _safety_draft(safety_request)
    assessment = draft["candidate_assessments"][0]
    rationale = contract["rationale"]
    noun = rationale["shortfall_and_unresolved"]["required_any_word"][0]
    consequence = rationale["why_it_matters"]["required_any_phrase"][0]
    action = rationale["resolution_test"]["required_any_action"][0]
    outcome = rationale["resolution_test"]["required_any_outcome"][0]
    evidence_ref = assessment["evidence_refs"][0]
    assessment.update(
        shortfall_description=f"The {noun} omits the exact recipient of the notice.",
        why_unresolved=f"The {noun} does not identify who receives that notice.",
        why_it_matters=f"The {consequence} depends on {evidence_ref} naming the notice recipient.",
        resolution_test=f"{action.capitalize()} the {outcome} identifying the notice recipient.",
    )
    assert isinstance(
        compile_readiness_draft_v1(safety_request, draft, _provenance()),
        CompiledReadinessDraftV1,
    )


@pytest.mark.parametrize("field", ["shortfall_description", "why_unresolved"])
def test_contract_publication_does_not_relax_the_existing_keyword_gate(safety_request, field):
    """Concrete-looking prose still obeys the retained, disclosed lexical check."""
    assert "safety_response_contract" in safety_request.payload
    draft = _safety_draft(safety_request)
    draft["candidate_assessments"][0][field] = (
        "Covered organizations must notify affected customers within twenty four hours."
    )
    result = compile_readiness_draft_v1(safety_request, draft, _provenance())
    assert isinstance(result, NeedsReadinessClarificationV1)
    assert [code.value for code in result.reason_codes] == ["RATIONALE_GENERIC"]


@pytest.mark.parametrize(
    "mutation",
    [
        "null",
        "unknown_version",
        "changed_rule",
        "removed",
        "fingerprint",
        "missing_fingerprint",
        "both_removed",
    ],
)
def test_rebound_request_rejects_unknown_or_inconsistent_response_contract(
    safety_request, mutation
):
    """Validate packet mechanics; persisted-run binding is checked by workflow tests."""
    raw = safety_request.model_dump(mode="json")
    assert "safety_response_contract" in raw["payload"]
    if mutation == "null":
        raw["payload"]["safety_response_contract"] = None
    elif mutation == "unknown_version":
        raw["payload"]["safety_response_contract"]["version"] = "unrecognized"
    elif mutation == "changed_rule":
        raw["payload"]["safety_response_contract"]["rationale"]["shortfall_and_unresolved"][
            "minimum_words"
        ] = 0
    elif mutation == "fingerprint":
        raw["payload"]["safety_response_contract_fingerprint"] = "0" * 64
    elif mutation == "missing_fingerprint":
        raw["payload"].pop("safety_response_contract_fingerprint")
    elif mutation == "both_removed":
        raw["payload"].pop("safety_response_contract")
        raw["payload"].pop("safety_response_contract_fingerprint")
    else:
        raw["payload"].pop("safety_response_contract")
    result = compile_readiness_draft_v1(_rebind(raw), _safety_draft(safety_request), _provenance())
    assert isinstance(result, ReadinessEngineDefectV1)


def test_current_request_does_not_reveal_any_extra_matter_evidence(safety_request):
    """The repair adds generic mechanics, not report-specific examples or past drafts."""
    contract = safety_request.payload.get("safety_response_contract")
    assert isinstance(contract, Mapping)
    serialized = canonical_json_bytes(contract)
    assert safety_request.payload["report_text"].encode() not in serialized
    assert b"scripted_fixture" not in serialized
    assert b"human_review" not in serialized
