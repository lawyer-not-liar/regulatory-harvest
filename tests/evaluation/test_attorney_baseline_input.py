"""Behavior tests for qualification-bound, report-independent baseline identity."""

from __future__ import annotations

import copy
import json
import os
from collections.abc import Callable
from datetime import date
from pathlib import Path

import pytest
from pydantic import ValidationError

from regulatory_harvest.evaluation.attorney_baseline_input import (
    BaselineControlInputV1,
    BaselineInputError,
    baseline_reuse_decision_v1,
    build_baseline_input_v1,
    legal_input_fingerprint_v1,
    load_baseline_control_input_v1,
)
from regulatory_harvest.evaluation.attorney_baseline_models import (
    BaselineInputV1,
    BaselineReuseDecisionV1,
)
from regulatory_harvest.evaluation.attorney_models import (
    AdmissionCheck,
    CaseAdmissionJudgment,
    EvaluationMode,
    EvaluationSource,
    JudgeIsolation,
    JudgeOperation,
    JudgeResponse,
    QualificationCase,
    RequestedAuthority,
)
from regulatory_harvest.evaluation.attorney_qualification import (
    initialize_case_qualification,
    next_qualification_request,
    submit_case_qualification,
)
from regulatory_harvest.models import SourceQuality, SourceRole
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

ROOT = Path(__file__).resolve().parents[2]
HASH = "f" * 64


def _source(source_id: str, text: str, *, authority_type: str) -> EvaluationSource:
    return EvaluationSource(
        source_id=source_id,
        title=f"Fictional {source_id}",
        normalized_text=text,
        content_hash=sha256_digest(text.encode("utf-8")),
        canonical_url=f"https://public.example/{source_id}",
        publisher="Example Legislative Office",
        jurisdiction="Example State",
        authority_type=authority_type,
        source_role=SourceRole.OFFICIAL_PRIMARY,
        source_quality=SourceQuality.PRIMARY,
        completeness="complete",
        language="en",
        version="2026-08-24",
        effective_date="2026-08-24",
        relationship_ids=["fictional-rule"] if source_id == "fictional-status" else [],
    )


def _qualification_case(*, schema_version: str = "1.1") -> QualificationCase:
    sources = [
        _source(
            "fictional-rule",
            "Section 4. A covered operator must file an annual notice.",
            authority_type="regulation",
        ),
        _source(
            "fictional-status",
            "Status notice. Section 4 is effective and unsuperseded on 2026-08-24.",
            authority_type="official-status",
        ),
    ]
    payload: dict[str, object] = {
        "schema_version": schema_version,
        "case_id": "fictional-baseline-input",
        "mode": EvaluationMode.CURRENT_LAW,
        "question": "What notice must a covered operator file?",
        "jurisdiction": "Example State",
        "as_of": date(2026, 8, 24),
        "requested_authorities": [
            RequestedAuthority(
                authority_id="fictional-rule",
                title="Fictional Rule",
                jurisdiction="Example State",
                authority_type="regulation",
                source_ids=["fictional-rule"],
            )
        ],
        "sources": sources,
    }
    if schema_version == "1.1":
        payload.update(
            {
                "build_binding": {"commit": "a" * 40, "archive_sha256": "b" * 64},
                "language_treatments": [
                    {
                        "source_ids": [source.source_id for source in sources],
                        "method": "Original-language review of the English sources.",
                        "rationale": "Both fictional sources are written in English.",
                        "limitations": "No non-English source was present.",
                    }
                ],
            }
        )
    return QualificationCase.model_validate(payload)


def _judgment(
    request_fingerprint: str,
    source_ids: list[str],
    *,
    admitted: bool,
) -> CaseAdmissionJudgment:
    codes = (
        "AUTHORITY_ALIGNMENT",
        "OPERATIVE_TEXT",
        "CURRENTNESS_EVIDENCE",
        "LANGUAGE_RESOLUTION",
        "SOURCE_PARITY",
    )
    return CaseAdmissionJudgment(
        request_fingerprint=request_fingerprint,
        checks=[
            AdmissionCheck(
                code=code,
                satisfied=admitted,
                material=True,
                rationale=(
                    "The retained fictional sources satisfy this material admission check."
                    if admitted
                    else "The retained fictional sources do not satisfy this material check."
                ),
                source_ids=source_ids if admitted else [],
            )
            for code in codes
        ],
    )


def _qualification(run: Path, *, admitted: bool = True, schema_version: str = "1.1") -> None:
    case = _qualification_case(schema_version=schema_version)
    initialize_case_qualification(case, run, nonce_hex="1" * 64)
    request = next_qualification_request(run)
    assert request is not None
    judgment = _judgment(
        request.request_fingerprint,
        [source.source_id for source in case.sources],
        admitted=admitted,
    )
    response = (
        judgment
        if schema_version == "1.0"
        else JudgeResponse(
            operation=JudgeOperation.ADMIT_CASE,
            request_fingerprint=request.request_fingerprint,
            provider_name="fictional-provider",
            model_name="fictional-model",
            judge_isolation=JudgeIsolation.FRESH_CONTEXT,
            response_id="fictional-baseline-input-response",
            usage={"input_tokens": 101, "output_tokens": 202},
            payload=judgment.model_dump(mode="json"),
        )
    )
    submit_case_qualification(run, response)


def _control(
    root: Path,
    *,
    qualification_path: str = "qualification",
    client_facts_path: str | None = None,
) -> Path:
    path = root / "baseline-control.json"
    path.write_bytes(
        canonical_json_bytes(
            {
                "client_facts_path": client_facts_path,
                "qualification_capsule_path": qualification_path,
                "schema_version": "1.0",
            }
        )
    )
    return path


@pytest.fixture
def sealed(tmp_path: Path) -> BaselineInputV1:
    _qualification(tmp_path / "qualification")
    return build_baseline_input_v1(_control(tmp_path))


def _rebind(value: BaselineInputV1, change: Callable[[dict[str, object]], None]) -> BaselineInputV1:
    payload = copy.deepcopy(value.model_dump(mode="python"))
    payload["compiler_contract"] = json.loads(
        canonical_json_bytes(payload["compiler_contract"])
    )
    change(payload)
    payload["legal_input_fingerprint"] = "0" * 64
    candidate = BaselineInputV1.model_validate(payload)
    payload["legal_input_fingerprint"] = legal_input_fingerprint_v1(candidate)
    return BaselineInputV1.model_validate(payload)


def _change_source_byte(value: BaselineInputV1) -> BaselineInputV1:
    def change(payload: dict[str, object]) -> None:
        sources = payload["sources"]
        assert isinstance(sources, tuple)
        source = sources[0]
        assert isinstance(source, dict)
        text = str(source["normalized_text"]) + "\r\n"
        source["normalized_text"] = text
        source["content_hash"] = sha256_digest(text.encode("utf-8"))
        payload["source_record_fingerprint"] = "1" * 64

    return _rebind(value, change)


def _change_source_id(value: BaselineInputV1) -> BaselineInputV1:
    def change(payload: dict[str, object]) -> None:
        sources = payload["sources"]
        authorities = payload["requested_authorities"]
        assert isinstance(sources, tuple) and isinstance(authorities, tuple)
        assert isinstance(sources[1], dict) and isinstance(authorities[0], dict)
        sources[1]["source_id"] = "fictional-status-revised"
        authorities[0]["source_ids"] = ["fictional-rule", "fictional-status-revised"]
        payload["source_record_fingerprint"] = "2" * 64

    return _rebind(value, change)


def _change_text_field(field: str, value: str) -> Callable[[BaselineInputV1], BaselineInputV1]:
    def mutate(baseline: BaselineInputV1) -> BaselineInputV1:
        def change(payload: dict[str, object]) -> None:
            payload[field] = value
            payload["source_record_fingerprint"] = sha256_digest(value.encode("utf-8"))

        return _rebind(baseline, change)

    return mutate


def _change_authority_scope(value: BaselineInputV1) -> BaselineInputV1:
    def change(payload: dict[str, object]) -> None:
        authorities = payload["requested_authorities"]
        assert isinstance(authorities, tuple) and isinstance(authorities[0], dict)
        authorities[0]["title"] = "Fictional Rule and Status Notice"
        payload["source_record_fingerprint"] = "3" * 64

    return _rebind(value, change)


def _change_client_fact(value: str) -> Callable[[BaselineInputV1], BaselineInputV1]:
    def mutate(baseline: BaselineInputV1) -> BaselineInputV1:
        return _rebind(
            baseline,
            lambda payload: payload.update(
                {
                    "client_facts": value,
                    "client_facts_binding": f"sha256:{sha256_digest(value.encode('utf-8'))}",
                }
            ),
        )

    return mutate


def _change_qualification_root(value: BaselineInputV1) -> BaselineInputV1:
    return _rebind(value, lambda payload: payload.update({"qualification_root": "4" * 64}))


def _change_compiler_contract(value: BaselineInputV1) -> BaselineInputV1:
    def change(payload: dict[str, object]) -> None:
        contract = payload["compiler_contract"]
        assert isinstance(contract, dict)
        contract["canonical_ordering_version"] = "controller-canonical-order-v2"
        payload["compiler_contract_fingerprint"] = sha256_digest(canonical_json_bytes(contract))

    return _rebind(value, change)


def _change_rubric_bytes(value: BaselineInputV1) -> BaselineInputV1:
    def change(payload: dict[str, object]) -> None:
        rubric = b'{"version":"attorney-eval-v2.2","weights":"changed"}'
        payload["evaluation_rubric_bytes"] = rubric
        payload["evaluation_rubric_fingerprint"] = sha256_digest(rubric)

    return _rebind(value, change)


def _change_importance_policy(value: BaselineInputV1) -> BaselineInputV1:
    def change(payload: dict[str, object]) -> None:
        policy = b'{"importance_policy_version":"importance-policy-v1","changed":true}'
        payload["importance_policy_bytes"] = policy
        payload["importance_policy_fingerprint"] = sha256_digest(policy)

    return _rebind(value, change)


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        (_change_source_byte, "SOURCE_BYTES_CHANGED"),
        (_change_source_id, "SOURCE_ID_CHANGED"),
        (_change_text_field("question", "What revised notice is required?"), "QUESTION_CHANGED"),
        (_change_text_field("jurisdiction", "Revised Example State"), "JURISDICTION_CHANGED"),
        (_change_text_field("as_of", "2026-08-25"), "AS_OF_CHANGED"),
        (_change_authority_scope, "AUTHORITY_SCOPE_CHANGED"),
        (_change_client_fact("The operator has two facilities."), "CLIENT_FACTS_CHANGED"),
        (_change_client_fact(""), "CLIENT_FACTS_CHANGED"),
        (_change_qualification_root, "QUALIFICATION_CHANGED"),
        (_change_compiler_contract, "COMPILER_CHANGED"),
        (_change_rubric_bytes, "RUBRIC_CHANGED"),
        (_change_importance_policy, "IMPORTANCE_POLICY_CHANGED"),
    ],
)
def test_reuse_refuses_each_legal_input_change(
    sealed: BaselineInputV1,
    mutation: Callable[[BaselineInputV1], BaselineInputV1],
    reason: str,
) -> None:
    decision = baseline_reuse_decision_v1(sealed, mutation(sealed))

    assert decision == BaselineReuseDecisionV1(reusable=False, reason_codes=(reason,))


def test_report_candidate_label_seed_grader_and_generation_have_no_identity_surface(
    sealed: BaselineInputV1,
) -> None:
    before = canonical_json_bytes(sealed)
    first_revision = {
        "candidate_id": "candidate-7",
        "anonymous_label": "A",
        "report_text": "First report revision.",
        "run_seed": "7" * 64,
        "grader": "grader-7",
        "generation": {"model": "generator-7"},
        "baseline_input": sealed,
    }
    second_revision = {
        **first_revision,
        "candidate_id": "candidate-13",
        "anonymous_label": "B",
        "report_text": "Thirteenth report revision with different bytes.",
        "run_seed": "d" * 64,
        "grader": "grader-13",
        "generation": {"model": "generator-13"},
    }

    first_key = legal_input_fingerprint_v1(first_revision["baseline_input"])
    second_key = legal_input_fingerprint_v1(second_revision["baseline_input"])

    assert before == canonical_json_bytes(second_revision["baseline_input"])
    assert first_key == second_key == sealed.legal_input_fingerprint
    for forbidden in first_revision.keys() - {"baseline_input"}:
        with pytest.raises(ValidationError):
            BaselineInputV1.model_validate(
                {**sealed.model_dump(mode="python"), forbidden: first_revision[forbidden]}
            )


def test_source_review_response_revision_reuses_the_already_sealed_baseline(
    sealed: BaselineInputV1,
) -> None:
    cache = {sealed.legal_input_fingerprint: object()}
    sealed_baseline = cache[sealed.legal_input_fingerprint]
    generated = 0

    def lookup(report: str, source_review_response: dict[str, object]) -> object:
        nonlocal generated
        assert report and source_review_response
        key = legal_input_fingerprint_v1(sealed)
        if key not in cache:
            generated += 1
            cache[key] = object()
        return cache[key]

    first = lookup("report revision 7", {"proposal_count": 7})
    second = lookup("report revision 13", {"proposal_count": 13})

    assert first is second is sealed_baseline
    assert generated == 0


def test_control_template_is_exact_controller_only_shape() -> None:
    template = ROOT / "assets" / "attorney-evaluation-baseline-input.template.json"

    assert json.loads(template.read_bytes()) == {
        "client_facts_path": None,
        "qualification_capsule_path": "qualification",
        "schema_version": "1.0",
    }


def test_exact_template_bytes_load_after_qualification_is_present(tmp_path: Path) -> None:
    _qualification(tmp_path / "qualification")
    control = tmp_path / "baseline-control.json"
    control.write_bytes(
        (ROOT / "assets" / "attorney-evaluation-baseline-input.template.json").read_bytes()
    )

    loaded = load_baseline_control_input_v1(control)

    assert loaded.qualification_capsule_path == (tmp_path / "qualification").resolve()
    assert loaded.client_facts_path is None


def test_control_loader_resolves_physical_paths_without_persisting_them(tmp_path: Path) -> None:
    _qualification(tmp_path / "qualification")
    facts_bytes = b"\xef\xbb\xbfKnown fact.\r\n"
    (tmp_path / "facts.txt").write_bytes(facts_bytes)
    control_path = _control(tmp_path, client_facts_path="facts.txt")

    control = load_baseline_control_input_v1(control_path)
    baseline = build_baseline_input_v1(control_path)

    assert control == BaselineControlInputV1(
        schema_version="1.0",
        qualification_capsule_path=(tmp_path / "qualification").resolve(),
        client_facts_path=(tmp_path / "facts.txt").resolve(),
    )
    assert baseline.client_facts == facts_bytes.decode("utf-8")
    assert baseline.client_facts_binding == f"sha256:{sha256_digest(facts_bytes)}"
    persisted = baseline.model_dump(mode="python")
    assert "qualification_capsule_path" not in persisted
    assert "client_facts_path" not in persisted


def test_explicit_null_and_empty_client_facts_have_distinct_identity(tmp_path: Path) -> None:
    _qualification(tmp_path / "qualification")
    null_input = build_baseline_input_v1(_control(tmp_path))
    (tmp_path / "empty.txt").write_bytes(b"")
    empty_control = tmp_path / "empty-control.json"
    empty_control.write_bytes(
        canonical_json_bytes(
            {
                "client_facts_path": "empty.txt",
                "qualification_capsule_path": "qualification",
                "schema_version": "1.0",
            }
        )
    )

    empty_input = build_baseline_input_v1(empty_control)

    assert null_input.client_facts is None
    assert empty_input.client_facts == ""
    assert null_input.legal_input_fingerprint != empty_input.legal_input_fingerprint
    assert baseline_reuse_decision_v1(null_input, empty_input).reason_codes == (
        "CLIENT_FACTS_CHANGED",
    )


def test_build_rejects_non_admitted_qualification(tmp_path: Path) -> None:
    _qualification(tmp_path / "qualification", admitted=False)

    with pytest.raises(BaselineInputError, match="BASELINE_QUALIFICATION_NOT_ADMITTED"):
        build_baseline_input_v1(_control(tmp_path))


def test_build_rejects_unverified_qualification(tmp_path: Path) -> None:
    _qualification(tmp_path / "qualification")
    case_path = tmp_path / "qualification" / "qualification-case.json"
    case_path.write_bytes(case_path.read_bytes() + b" ")

    with pytest.raises(BaselineInputError, match="BASELINE_QUALIFICATION_INVALID"):
        build_baseline_input_v1(_control(tmp_path))


def _rewrite_manifest(run: Path, *, source_record_fingerprint: str | None = None) -> None:
    manifest_path = run / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    if source_record_fingerprint is not None:
        manifest["source_record_fingerprint"] = source_record_fingerprint
    manifest["root_hash"] = sha256_digest(
        canonical_json_bytes({key: value for key, value in manifest.items() if key != "root_hash"})
    )
    manifest_path.write_bytes(canonical_json_bytes(manifest))


def test_build_rejects_schema_1_0_qualification_with_invented_fields(tmp_path: Path) -> None:
    run = tmp_path / "qualification"
    _qualification(run, schema_version="1.0")
    case_path = run / "qualification-case.json"
    case_payload = json.loads(case_path.read_bytes())
    case_payload["language_treatments"] = []
    case_bytes = canonical_json_bytes(case_payload)
    case_path.write_bytes(case_bytes)
    manifest = json.loads((run / "manifest.json").read_bytes())
    for artifact in manifest["artifacts"]:
        if artifact["artifact_path"] == "qualification-case.json":
            artifact["artifact_hash"] = sha256_digest(case_bytes)
    manifest["root_hash"] = sha256_digest(
        canonical_json_bytes({key: value for key, value in manifest.items() if key != "root_hash"})
    )
    (run / "manifest.json").write_bytes(canonical_json_bytes(manifest))

    with pytest.raises(BaselineInputError, match="BASELINE_QUALIFICATION_INVALID"):
        build_baseline_input_v1(_control(tmp_path))


def test_build_rejects_mismatched_qualification_source_record(tmp_path: Path) -> None:
    run = tmp_path / "qualification"
    _qualification(run)
    _rewrite_manifest(run, source_record_fingerprint=HASH)

    with pytest.raises(BaselineInputError, match="BASELINE_QUALIFICATION_INVALID"):
        build_baseline_input_v1(_control(tmp_path))


@pytest.mark.skipif(os.name != "posix", reason="symlink containment is POSIX-specific")
def test_control_rejects_symlink_aliased_qualification_path(tmp_path: Path) -> None:
    _qualification(tmp_path / "qualification")
    (tmp_path / "qualification-link").symlink_to("qualification", target_is_directory=True)

    with pytest.raises(BaselineInputError, match="BASELINE_CONTROL_PATH_UNSAFE"):
        build_baseline_input_v1(_control(tmp_path, qualification_path="qualification-link"))


def test_control_rejects_path_escaping_qualification(tmp_path: Path) -> None:
    _qualification(tmp_path / "qualification")
    control_root = tmp_path / "control"
    control_root.mkdir()

    with pytest.raises(BaselineInputError, match="BASELINE_CONTROL_PATH_UNSAFE"):
        build_baseline_input_v1(_control(control_root, qualification_path="../qualification"))


def test_control_rejects_noncanonical_or_extra_input_before_qualification_replay(
    tmp_path: Path,
) -> None:
    _qualification(tmp_path / "qualification")
    control = tmp_path / "baseline-control.json"
    control.write_text(
        '{"schema_version":"1.0","qualification_capsule_path":"qualification",'
        '"client_facts_path":null,"candidate_id":"forbidden"}\n',
        encoding="utf-8",
    )

    with pytest.raises(BaselineInputError, match="BASELINE_CONTROL_INVALID"):
        load_baseline_control_input_v1(control)
