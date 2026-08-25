from __future__ import annotations

import hashlib
import json
import os
import stat
import warnings
from collections.abc import Callable, Iterator
from datetime import date
from pathlib import Path

import pytest
from pydantic import ValidationError

from regulatory_harvest.evaluation import (
    QualificationBuildBinding,
    QualificationLanguageTreatment,
    attorney_admission,
    attorney_models,
    attorney_qualification,
)
from regulatory_harvest.evaluation.attorney_admission import (
    build_admission_request,
    build_source_record,
)
from regulatory_harvest.evaluation.attorney_artifacts import (
    EvaluationIntegrityError,
    _model_bytes,
)
from regulatory_harvest.evaluation.attorney_models import (
    AdmissionCheck,
    CaseAdmissionJudgment,
    CaseReadiness,
    EvaluationMode,
    EvaluationSource,
    JudgeIsolation,
    JudgeOperation,
    JudgeRequest,
    JudgeResponse,
    QualificationCase,
    QualificationReceipt,
    ReadinessStatus,
    RequestedAuthority,
    model_fingerprint,
)
from regulatory_harvest.evaluation.attorney_qualification import (
    guarded_submit_case_qualification,
    initialize_case_qualification,
    load_verified_qualification_context,
    next_qualification_request,
    preflight_case_qualification,
    resume_case_qualification,
    submit_case_qualification,
    verify_case_qualification,
)
from regulatory_harvest.models import SourceQuality, SourceRole
from regulatory_harvest.storage import canonical_json_bytes

ROOT = Path(__file__).parents[2]

_LEGACY_1_0_CASE_BYTES_SHA256 = (
    "30b478b87948084ea4652572e4fe42020e04bb4fe07b33dc017879f87c903702"
)
_LEGACY_1_0_SOURCE_RECORD_BYTES_SHA256 = (
    "1eb75734d43cd875d72bf30e19a0b6fa7272aa1538f77c55b3139692a5f51e89"
)
_LEGACY_1_0_REQUEST_BYTES_SHA256 = (
    "5ad20087f6b8fbfbf090b638bf9d6e2221b93318718261894d38f28e389fc749"
)
_LEGACY_1_0_REQUEST_FINGERPRINT = (
    "993f1bce630bb333f1ff5bfaaa311fc7b56b5c450572b8d69deec695eab07dad"
)
_LEGACY_1_0_RESPONSE_BYTES_SHA256 = (
    "15704d7c0f2abe0fee60e206f267c2b48f507c4270061921117bba846373c7e1"
)
_LEGACY_1_0_RECEIPT_BYTES_SHA256 = (
    "65c3ce94532a9b34962ab8470cf31eab9f6574735dbfce7f877652c28668fee7"
)
_LEGACY_1_0_ROOT_HASH = (
    "e05d85d2246a001cec1b11b99a84e36b4ad9c0b65fef3f51fae401f5c515236b"
)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def qualification_case(*, currentness_source: bool = True) -> QualificationCase:
    operative_text = (
        "Section 12. A covered workshop shall retain a public compliance record."
    )
    status_text = (
        "Status notice. Section 12 is effective and unsuperseded on 2026-08-15."
    )
    sources = [
        EvaluationSource(
            source_id="fictional-act-operative",
            title="Fictional Workshop Records Act",
            normalized_text=operative_text,
            content_hash=_sha256(operative_text),
            canonical_url="https://public.example/fictional-act/section-12",
            publisher="Example Legislative Office",
            jurisdiction="Example State",
            authority_type="statute",
            source_role=SourceRole.OFFICIAL_PRIMARY,
            source_quality=SourceQuality.PRIMARY,
            completeness="complete",
            language="en",
            version="2026 edition",
            effective_date="2026-01-01",
        )
    ]
    source_ids = ["fictional-act-operative"]
    if currentness_source:
        sources.append(
            EvaluationSource(
                source_id="fictional-act-status",
                title="Fictional Workshop Records Act Status Notice",
                normalized_text=status_text,
                content_hash=_sha256(status_text),
                canonical_url="https://public.example/fictional-act/status",
                publisher="Example Legislative Office",
                jurisdiction="Example State",
                authority_type="official-status",
                source_role=SourceRole.OFFICIAL_PRIMARY,
                source_quality=SourceQuality.PRIMARY,
                completeness="complete",
                language="en",
                version="2026-08-15",
                effective_date="2026-08-15",
                relationship_ids=["fictional-act-operative"],
            )
        )
    return QualificationCase(
        case_id="fictional-workshop-records",
        mode=EvaluationMode.CURRENT_LAW,
        question="What public compliance record must a covered workshop retain?",
        jurisdiction="Example State",
        as_of=date(2026, 8, 15),
        requested_authorities=[
            RequestedAuthority(
                authority_id="fictional-workshop-act",
                title="Fictional Workshop Records Act",
                jurisdiction="Example State",
                authority_type="statute",
                source_ids=source_ids,
            )
        ],
        sources=sources,
    )


def qualification_case_schema_1_1() -> QualificationCase:
    payload = qualification_case().model_dump(mode="json")
    payload.update(
        {
            "schema_version": "1.1",
            "build_binding": {
                "commit": "a" * 40,
                "archive_sha256": "b" * 64,
            },
            "language_treatments": [
                {
                    "source_ids": [source["source_id"] for source in payload["sources"]],
                    "method": "Original-language review of the fictional English sources.",
                    "rationale": "Both fictional sources state their operative text in English.",
                    "limitations": "No non-English text was present in the retained record.",
                }
            ],
        }
    )
    return QualificationCase.model_validate(payload)


def test_legacy_1_0_case_source_record_and_request_bytes_are_frozen() -> None:
    case = qualification_case()
    case_bytes = canonical_json_bytes(case.model_dump(mode="json"))
    source_record = build_source_record(case)
    source_record_bytes = canonical_json_bytes(source_record)
    request = build_admission_request(source_record)
    request_bytes = canonical_json_bytes(request.model_dump(mode="json"))

    assert set(source_record) == {
        "schema_version",
        "mode",
        "question",
        "jurisdiction",
        "as_of",
        "requested_authorities",
        "sources",
    }
    assert "build_binding" not in case.model_dump(mode="json")
    assert "language_treatments" not in case.model_dump(mode="json")
    assert hashlib.sha256(case_bytes).hexdigest() == _LEGACY_1_0_CASE_BYTES_SHA256
    assert (
        hashlib.sha256(source_record_bytes).hexdigest()
        == _LEGACY_1_0_SOURCE_RECORD_BYTES_SHA256
    )
    assert hashlib.sha256(request_bytes).hexdigest() == _LEGACY_1_0_REQUEST_BYTES_SHA256
    assert request.request_fingerprint == _LEGACY_1_0_REQUEST_FINGERPRINT


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("commit", "A" * 40),
        ("commit", "a" * 39),
        ("commit", "g" * 40),
        ("archive_sha256", "B" * 64),
        ("archive_sha256", "b" * 63),
        ("archive_sha256", "g" * 64),
    ],
)
def test_build_binding_rejects_malformed_hashes(field: str, value: str) -> None:
    model = attorney_models.QualificationBuildBinding
    payload = {"commit": "a" * 40, "archive_sha256": "b" * 64}
    payload[field] = value

    with pytest.raises(ValidationError):
        model.model_validate(payload)


def test_build_binding_is_strict_and_canonical() -> None:
    model = attorney_models.QualificationBuildBinding

    binding = model(commit="a" * 40, archive_sha256="b" * 64)

    assert binding.model_dump(mode="json") == {
        "commit": "a" * 40,
        "archive_sha256": "b" * 64,
    }
    with pytest.raises(ValidationError):
        model.model_validate(
            {"commit": "a" * 40, "archive_sha256": "b" * 64, "extra": "forbidden"}
        )


def test_qualification_metadata_models_are_exported_from_evaluation() -> None:
    assert QualificationBuildBinding is attorney_models.QualificationBuildBinding
    assert QualificationLanguageTreatment is attorney_models.QualificationLanguageTreatment


@pytest.mark.parametrize(
    "update",
    [
        {"source_ids": []},
        {"source_ids": ["fictional-act-operative", "fictional-act-operative"]},
        {"method": "   "},
        {"rationale": "\t"},
        {"limitations": "\n"},
    ],
)
def test_language_treatment_rejects_malformed_values(update: dict[str, object]) -> None:
    model = attorney_models.QualificationLanguageTreatment
    payload: dict[str, object] = {
        "source_ids": ["fictional-act-operative"],
        "method": "Original-language review.",
        "rationale": "The fictional source is written in English.",
    }
    payload.update(update)

    with pytest.raises(ValidationError):
        model.model_validate(payload)


@pytest.mark.parametrize(
    "treatments",
    [
        [],
        [
            {
                "source_ids": ["fictional-act-operative"],
                "method": "Original-language review.",
                "rationale": "The fictional source is written in English.",
            }
        ],
        [
            {
                "source_ids": ["fictional-act-operative", "fictional-act-status"],
                "method": "Original-language review.",
                "rationale": "The fictional sources are written in English.",
            },
            {
                "source_ids": ["fictional-act-status"],
                "method": "Second review.",
                "rationale": "A duplicate row must fail.",
            },
        ],
        [
            {
                "source_ids": [
                    "fictional-act-operative",
                    "fictional-act-status",
                    "fictional-act-unknown",
                ],
                "method": "Original-language review.",
                "rationale": "An unknown source must fail.",
            }
        ],
        [
            {
                "source_ids": [["fictional-act-operative"], "fictional-act-status"],
                "method": "Original-language review.",
                "rationale": "An unhashable source identifier must fail closed.",
            }
        ],
    ],
)
def test_schema_1_1_language_treatment_requires_exact_source_coverage(
    treatments: list[dict[str, object]],
) -> None:
    payload = qualification_case().model_dump(mode="json")
    payload.update(
        {
            "schema_version": "1.1",
            "build_binding": {"commit": "a" * 40, "archive_sha256": "b" * 64},
            "language_treatments": treatments,
        }
    )

    with pytest.raises((ValidationError, TypeError, ValueError)):
        QualificationCase.model_validate(payload)


def test_schema_1_1_requires_build_binding_and_language_treatments() -> None:
    valid = qualification_case_schema_1_1().model_dump(mode="json")

    for missing in ("build_binding", "language_treatments"):
        payload = {key: value for key, value in valid.items() if key != missing}
        with pytest.raises(ValidationError):
            QualificationCase.model_validate(payload)


def test_legacy_1_0_rejects_schema_1_1_fields() -> None:
    legacy = qualification_case().model_dump(mode="json")

    with pytest.raises(ValidationError):
        QualificationCase.model_validate(
            {
                **legacy,
                "build_binding": {"commit": "a" * 40, "archive_sha256": "b" * 64},
            }
        )
    with pytest.raises(ValidationError):
        QualificationCase.model_validate(
            {
                **legacy,
                "language_treatments": [],
            }
        )


@pytest.mark.parametrize(
    "bypass",
    [
        lambda case: case.model_copy(update={"build_binding": None}),
        lambda case: case.model_copy(update={"language_treatments": []}),
        lambda case: QualificationCase.model_construct(
            **case.model_dump(mode="python"),
            build_binding=None,
        ),
        lambda case: QualificationCase.model_construct(
            **case.model_dump(mode="python"),
            language_treatments=[],
        ),
    ],
)
def test_legacy_1_0_projection_rejects_explicit_empty_metadata_bypasses(
    bypass: Callable[[QualificationCase], QualificationCase],
) -> None:
    case = bypass(qualification_case())
    before = case.__dict__.copy()

    with pytest.raises((ValidationError, TypeError, ValueError)):
        build_source_record(case)

    assert case.__dict__ == before


@pytest.mark.parametrize(
    "bypass",
    [
        lambda case: case.model_copy(update={"build_binding": None}),
        lambda case: case.model_copy(update={"language_treatments": []}),
        lambda case: QualificationCase.model_construct(
            **case.model_dump(mode="python"),
            build_binding=None,
        ),
        lambda case: QualificationCase.model_construct(
            **case.model_dump(mode="python"),
            language_treatments=[],
        ),
    ],
)
def test_legacy_1_0_initialization_rejects_explicit_empty_metadata_bypasses_without_writes(
    bypass: Callable[[QualificationCase], QualificationCase],
    tmp_path: Path,
) -> None:
    """Initialization must not serialize away explicit forbidden-field presence."""
    case = bypass(qualification_case())
    before = case.__dict__.copy()
    fields_before = set(case.model_fields_set)
    run = tmp_path / "qualification-run"

    with warnings.catch_warnings(record=True) as observed:
        warnings.simplefilter("always")
        with pytest.raises((ValidationError, TypeError, ValueError)):
            initialize_case_qualification(case, run, nonce_hex="1" * 64)

    assert observed == []
    assert case.__dict__ == before
    assert case.model_fields_set == fields_before
    assert not run.exists()


def test_schema_1_1_projection_and_request_bind_source_metadata_without_mutation() -> None:
    case = qualification_case_schema_1_1()
    before = case.model_dump(mode="json")

    source_record = build_source_record(case)
    request = build_admission_request(source_record)

    assert set(source_record) == {
        "schema_version",
        "mode",
        "question",
        "jurisdiction",
        "as_of",
        "requested_authorities",
        "sources",
        "build_binding",
        "language_treatments",
    }
    assert source_record["build_binding"] == before["build_binding"]
    assert source_record["language_treatments"] == before["language_treatments"]
    assert request.payload["build_binding"] == before["build_binding"]
    assert request.payload["language_treatments"] == before["language_treatments"]
    assert json.loads(request.safe_metadata["build_binding"]) == before["build_binding"]
    assert json.loads(request.safe_metadata["language_treatments"]) == before[
        "language_treatments"
    ]
    assert "supplied language treatment and its limitations" in request.system_instructions
    assert case.model_dump(mode="json") == before


def test_schema_1_1_build_admission_request_rejects_wrong_source_record_keys() -> None:
    source_record = build_source_record(qualification_case_schema_1_1())

    for changed in (
        {key: value for key, value in source_record.items() if key != "build_binding"},
        {**source_record, "unexpected": "forbidden"},
    ):
        with pytest.raises(ValueError, match="unexpected shape"):
            build_admission_request(changed)


def test_schema_1_1_stripped_projection_cannot_enable_public_compatibility_bypass() -> None:
    projection = build_source_record(qualification_case_schema_1_1())
    stripped = {
        key: value
        for key, value in projection.items()
        if key not in {"build_binding", "language_treatments"}
    }

    with pytest.raises(TypeError):
        build_admission_request(stripped, _allow_evaluation_schema_1_1=True)


def test_schema_1_1_stripped_projection_cannot_use_attorney_compatibility_path() -> None:
    projection = build_source_record(qualification_case_schema_1_1())
    stripped = {
        key: value
        for key, value in projection.items()
        if key not in {"build_binding", "language_treatments"}
    }
    with pytest.raises(TypeError, match="AttorneyEvaluationCase"):
        attorney_admission._build_attorney_admission_request(stripped)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (
            "build_binding",
            {"commit": "A" * 40, "archive_sha256": "b" * 64},
        ),
        ("language_treatments", []),
        (
            "language_treatments",
            [
                {
                    "source_ids": [["fictional-act-operative"], "fictional-act-status"],
                    "method": "Original-language review.",
                    "rationale": "Malformed source identifiers must fail closed.",
                    "limitations": None,
                }
            ],
        ),
    ],
)
def test_schema_1_1_build_admission_request_rejects_raw_malformed_metadata_without_mutation(
    field: str,
    value: object,
) -> None:
    source_record = build_source_record(qualification_case_schema_1_1())
    source_record[field] = value
    before = json.loads(canonical_json_bytes(source_record))

    with pytest.raises((ValidationError, TypeError, ValueError)):
        build_admission_request(source_record)

    assert source_record == before


def test_schema_1_1_projection_revalidates_model_copy_and_model_construct_bypasses() -> None:
    case = qualification_case_schema_1_1()
    binding_model = attorney_models.QualificationBuildBinding
    treatment_model = attorney_models.QualificationLanguageTreatment
    malformed_binding = binding_model.model_construct(
        commit=["unhashable"], archive_sha256="b" * 64
    )
    malformed_treatment = treatment_model.model_construct(
        source_ids=[["fictional-act-operative"], "fictional-act-status"],
        method="Original-language review.",
        rationale="The malformed identifier must fail closed.",
    )

    bypasses = (
        case.model_copy(update={"build_binding": malformed_binding}),
        case.model_copy(update={"language_treatments": [malformed_treatment]}),
        QualificationCase.model_construct(
            **{
                **case.__dict__,
                "build_binding": {"commit": "not-a-commit", "archive_sha256": "b" * 64},
            }
        ),
    )

    for bypass in bypasses:
        before = bypass.__dict__.copy()
        with warnings.catch_warnings(record=True) as observed:
            warnings.simplefilter("always")
            with pytest.raises((ValidationError, TypeError, ValueError)):
                build_source_record(bypass)
        assert observed == []
        assert bypass.__dict__ == before


def admitted_judgment(request: JudgeRequest) -> CaseAdmissionJudgment:
    request_fingerprint = request.request_fingerprint
    source_ids = [source["source_id"] for source in request.payload["sources"]]
    rationales = {
        "AUTHORITY_ALIGNMENT": "The requested authority aligns with the retained record.",
        "OPERATIVE_TEXT": "The complete responsive operative text is retained.",
        "CURRENTNESS_EVIDENCE": "The status notice supports the declared date.",
        "LANGUAGE_RESOLUTION": "Every material source is available in resolved English.",
        "SOURCE_PARITY": "This frozen record is the common later-candidate evidence universe.",
    }
    return CaseAdmissionJudgment(
        request_fingerprint=request_fingerprint,
        checks=[
            AdmissionCheck(
                code=code,
                satisfied=True,
                material=True,
                rationale=rationale,
                source_ids=source_ids,
            )
            for code, rationale in rationales.items()
        ],
    )


def admitted_response(
    request: JudgeRequest,
    *,
    provider_name: str = "fictional-provider",
    model_name: str = "fictional-model",
    judge_isolation: JudgeIsolation = JudgeIsolation.FRESH_CONTEXT,
) -> JudgeResponse:
    return JudgeResponse(
        operation=JudgeOperation.ADMIT_CASE,
        request_fingerprint=request.request_fingerprint,
        provider_name=provider_name,
        model_name=model_name,
        judge_isolation=judge_isolation,
        response_id="fictional-response-1",
        usage={"input_tokens": 101, "output_tokens": 202},
        payload=admitted_judgment(request).model_dump(mode="json"),
    )


def failed_currentness_judgment(request: JudgeRequest) -> CaseAdmissionJudgment:
    judgment = admitted_judgment(request)
    judgment.checks[2] = AdmissionCheck(
        code="CURRENTNESS_EVIDENCE",
        satisfied=False,
        material=True,
        rationale="No retained status source supports the declared date.",
        source_ids=[],
    )
    return judgment


def _initialize_and_next(case: QualificationCase, run: Path) -> JudgeRequest:
    initialize_case_qualification(case, run, nonce_hex="1" * 64)
    request = next_qualification_request(run)
    assert request is not None
    return request


def _tree_bytes(run: Path) -> dict[str, bytes]:
    return {
        path.relative_to(run).as_posix(): path.read_bytes()
        for path in sorted(run.rglob("*"))
        if path.is_file()
    }


def test_qualification_schema_1_1_response_envelope_lifecycle(tmp_path: Path) -> None:
    request = _initialize_and_next(qualification_case_schema_1_1(), tmp_path)
    response = admitted_response(request)
    judgment = CaseAdmissionJudgment.model_validate(response.payload)

    assert {
        "provider_name",
        "model_name",
        "judge_isolation",
        "payload",
    }.issubset(request.json_schema["properties"])
    assert set(request.json_schema["properties"]["payload"]["properties"]) == {
        "request_fingerprint",
        "checks",
        "issues",
    }

    receipt = submit_case_qualification(tmp_path, response)

    response_bytes = canonical_json_bytes(response.model_dump(mode="json"))
    assert (tmp_path / "admission-response.json").read_bytes() == response_bytes
    assert receipt.judgment_fingerprint == model_fingerprint(judgment)
    manifest = json.loads((tmp_path / "manifest.json").read_bytes())
    response_artifact = next(
        artifact
        for artifact in manifest["artifacts"]
        if artifact["artifact_path"] == "admission-response.json"
    )
    assert response_artifact["artifact_hash"] == hashlib.sha256(response_bytes).hexdigest()
    assert verify_case_qualification(tmp_path).valid is True


@pytest.mark.parametrize(
    "mutation",
    ["provider", "model", "isolation", "commit", "archive", "language_treatment"],
)
def test_qualification_schema_1_1_build_binding_and_response_envelope_change_root(
    mutation: str,
    tmp_path: Path,
) -> None:
    def seal(name: str, changed: bool) -> tuple[str, str]:
        run = tmp_path / name
        case = qualification_case_schema_1_1()
        if changed and mutation == "commit":
            assert case.build_binding is not None
            case.build_binding.commit = "c" * 40
        elif changed and mutation == "archive":
            assert case.build_binding is not None
            case.build_binding.archive_sha256 = "d" * 64
        elif changed and mutation == "language_treatment":
            case.language_treatments[0].method = "Official bilingual fictional text review."
        request = _initialize_and_next(case, run)
        response = admitted_response(
            request,
            provider_name=(
                "alternate-provider"
                if changed and mutation == "provider"
                else "fictional-provider"
            ),
            model_name=(
                "alternate-model"
                if changed and mutation == "model"
                else "fictional-model"
            ),
            judge_isolation=(
                JudgeIsolation.SEQUENTIAL_SAME_CONTEXT
                if changed and mutation == "isolation"
                else JudgeIsolation.FRESH_CONTEXT
            ),
        )
        submit_case_qualification(run, response)
        response_hash = hashlib.sha256(
            (run / "admission-response.json").read_bytes()
        ).hexdigest()
        return resume_case_qualification(run).root_hash, response_hash

    baseline = seal("baseline", False)
    changed = seal("changed", True)

    assert changed[0] != baseline[0]
    assert changed[1] != baseline[1]


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("raw_inner", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("operation", "EVALUATION_RESPONSE_REQUEST_MISMATCH"),
        ("outer_fingerprint", "EVALUATION_RESPONSE_REQUEST_MISMATCH"),
        ("inner_fingerprint", "EVALUATION_RESPONSE_REQUEST_MISMATCH"),
        ("blank_provider", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("blank_model", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("invalid_isolation", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("extra_key", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("unhashable", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
    ],
)
def test_qualification_schema_1_1_response_envelope_refusal_is_write_free(
    mutation: str,
    expected_code: str,
    tmp_path: Path,
) -> None:
    request = _initialize_and_next(qualification_case_schema_1_1(), tmp_path)
    response: object = admitted_response(request).model_dump(mode="python")
    assert isinstance(response, dict)
    if mutation == "raw_inner":
        response = admitted_judgment(request).model_dump(mode="python")
    elif mutation == "operation":
        response["operation"] = "grade_report"
    elif mutation == "outer_fingerprint":
        response["request_fingerprint"] = "0" * 64
    elif mutation == "inner_fingerprint":
        response["payload"]["request_fingerprint"] = "0" * 64
    elif mutation == "blank_provider":
        response["provider_name"] = "   "
    elif mutation == "blank_model":
        response["model_name"] = "\t"
    elif mutation == "invalid_isolation":
        response["judge_isolation"] = "not-isolated"
    elif mutation == "extra_key":
        response["unexpected"] = "forbidden"
    else:
        response["payload"]["checks"][0]["source_ids"] = [["not-hashable"]]
    before = _tree_bytes(tmp_path)

    preflight = preflight_case_qualification(tmp_path, response)
    guarded = guarded_submit_case_qualification(tmp_path, response)

    assert preflight.ok is False
    assert [issue.code for issue in preflight.issues] == [expected_code]
    assert guarded.accepted is False
    assert guarded.preflight == preflight
    assert _tree_bytes(tmp_path) == before


@pytest.mark.parametrize("mutation", ["blank_provider", "unhashable_payload"])
def test_qualification_schema_1_1_response_envelope_model_bypass_is_write_free(
    mutation: str,
    tmp_path: Path,
) -> None:
    request = _initialize_and_next(qualification_case_schema_1_1(), tmp_path)
    response = admitted_response(request)
    if mutation == "blank_provider":
        bypass = response.model_copy(update={"provider_name": "   "})
    else:
        payload = response.payload.copy()
        checks = list(payload["checks"])
        checks[0] = {**checks[0], "source_ids": [["not-hashable"]]}
        payload["checks"] = checks
        bypass = JudgeResponse.model_construct(
            **{**response.__dict__, "payload": payload}
        )
    before = _tree_bytes(tmp_path)

    preflight = preflight_case_qualification(tmp_path, bypass)
    guarded = guarded_submit_case_qualification(tmp_path, bypass)

    assert preflight.ok is False
    assert [issue.code for issue in preflight.issues] == [
        "EVALUATION_RESPONSE_SCHEMA_INVALID"
    ]
    assert guarded.accepted is False
    assert guarded.preflight == preflight
    assert _tree_bytes(tmp_path) == before


@pytest.mark.parametrize("kind", ["raw", "model_construct"])
def test_qualification_schema_1_1_response_envelope_deep_bypass_is_bounded(
    kind: str,
    tmp_path: Path,
) -> None:
    request = _initialize_and_next(qualification_case_schema_1_1(), tmp_path)
    response = admitted_response(request).model_dump(mode="python")
    nested: object = []
    for _ in range(2048):
        nested = [nested]
    response["payload"]["checks"][0]["source_ids"] = nested
    value: object = response
    if kind == "model_construct":
        value = JudgeResponse.model_construct(**response)
    before = _tree_bytes(tmp_path)

    preflight = preflight_case_qualification(tmp_path, value)

    assert preflight.ok is False
    assert [issue.code for issue in preflight.issues] == [
        "EVALUATION_RESPONSE_SCHEMA_INVALID"
    ]
    assert _tree_bytes(tmp_path) == before


@pytest.mark.parametrize("kind", ["raw", "model_construct"])
@pytest.mark.parametrize("nesting", ["tuple", "mixed"])
def test_qualification_schema_1_1_tuple_response_depth_is_bounded_and_write_free(
    kind: str,
    nesting: str,
    tmp_path: Path,
) -> None:
    """Tuple-backed depth must be refused before recursive canonical serialization."""
    request = _initialize_and_next(qualification_case_schema_1_1(), tmp_path)
    response = admitted_response(request).model_dump(mode="python")
    nested: object = ()
    for index in range(2048):
        if nesting == "tuple" or index % 3 == 0:
            nested = (nested,)
        elif index % 3 == 1:
            nested = [nested]
        else:
            nested = {"nested": nested}
    response["payload"]["checks"][0]["source_ids"] = nested
    value: object = response
    if kind == "model_construct":
        value = JudgeResponse.model_construct(**response)
    before = _tree_bytes(tmp_path)

    preflight = preflight_case_qualification(tmp_path, value)
    guarded = guarded_submit_case_qualification(tmp_path, value)

    assert preflight.ok is False
    assert [issue.code for issue in preflight.issues] == [
        "EVALUATION_RESPONSE_SCHEMA_INVALID"
    ]
    assert guarded.accepted is False
    assert guarded.preflight == preflight
    assert guarded.receipt is None
    assert _tree_bytes(tmp_path) == before


def test_qualification_schema_1_1_recursive_iterator_is_write_free(
    tmp_path: Path,
) -> None:
    """Container iteration recursion must remain a stable schema refusal."""

    class RecursiveList(list[object]):
        def __iter__(self) -> Iterator[object]:
            raise RecursionError("synthetic recursive iterator")

    request = _initialize_and_next(qualification_case_schema_1_1(), tmp_path)
    response = admitted_response(request).model_dump(mode="python")
    response["payload"]["checks"][0]["source_ids"] = RecursiveList()
    before = _tree_bytes(tmp_path)

    preflight = preflight_case_qualification(tmp_path, response)
    guarded = guarded_submit_case_qualification(tmp_path, response)

    assert preflight.ok is False
    assert [issue.code for issue in preflight.issues] == [
        "EVALUATION_RESPONSE_SCHEMA_INVALID"
    ]
    assert guarded.accepted is False
    assert guarded.preflight == preflight
    assert guarded.receipt is None
    assert _tree_bytes(tmp_path) == before


def test_qualification_schema_1_1_deep_response_does_not_mask_capsule_integrity(
    tmp_path: Path,
) -> None:
    request = _initialize_and_next(qualification_case_schema_1_1(), tmp_path)
    response = admitted_response(request).model_dump(mode="python")
    nested: object = []
    for _ in range(2048):
        nested = [nested]
    response["payload"]["checks"][0]["source_ids"] = nested
    (tmp_path / "admission-request.json").write_bytes(b"{}")

    with pytest.raises(EvaluationIntegrityError):
        preflight_case_qualification(tmp_path, response)


@pytest.mark.parametrize("cycle_kind", ["list", "dict"])
def test_qualification_schema_1_1_response_envelope_cycle_is_write_free(
    cycle_kind: str,
    tmp_path: Path,
) -> None:
    request = _initialize_and_next(qualification_case_schema_1_1(), tmp_path)
    response = admitted_response(request)
    payload = response.payload.copy()
    checks = list(payload["checks"])
    if cycle_kind == "list":
        cyclic: object = []
        cyclic.append(cyclic)
    else:
        cyclic = {}
        cyclic["self"] = cyclic
    checks[0] = {**checks[0], "source_ids": cyclic}
    payload["checks"] = checks
    bypass = JudgeResponse.model_construct(
        **{**response.__dict__, "payload": payload}
    )
    before = _tree_bytes(tmp_path)

    preflight = preflight_case_qualification(tmp_path, bypass)

    assert preflight.ok is False
    assert [issue.code for issue in preflight.issues] == [
        "EVALUATION_RESPONSE_SCHEMA_INVALID"
    ]
    assert _tree_bytes(tmp_path) == before


@pytest.mark.parametrize("container_kind", ["list", "dict"])
def test_qualification_schema_1_1_tuple_container_cycle_is_write_free(
    container_kind: str,
    tmp_path: Path,
) -> None:
    request = _initialize_and_next(qualification_case_schema_1_1(), tmp_path)
    response = admitted_response(request)
    payload = response.payload.copy()
    checks = list(payload["checks"])
    if container_kind == "list":
        anchor: list[object] | dict[str, object] = []
        cyclic_tuple = (anchor,)
        anchor.append(cyclic_tuple)
    else:
        anchor = {}
        cyclic_tuple = (anchor,)
        anchor["cycle"] = cyclic_tuple
    checks[0] = {**checks[0], "source_ids": cyclic_tuple}
    payload["checks"] = checks
    bypass = JudgeResponse.model_construct(
        **{**response.__dict__, "payload": payload}
    )
    before = _tree_bytes(tmp_path)

    preflight = preflight_case_qualification(tmp_path, bypass)
    guarded = guarded_submit_case_qualification(tmp_path, bypass)

    assert preflight.ok is False
    assert [issue.code for issue in preflight.issues] == [
        "EVALUATION_RESPONSE_SCHEMA_INVALID"
    ]
    assert guarded.accepted is False
    assert guarded.preflight == preflight
    assert _tree_bytes(tmp_path) == before


def test_qualification_response_depth_allows_repeated_acyclic_tuples() -> None:
    """Identity reuse is not a back-edge cycle when the first traversal has exited."""
    shared = ("fictional-act-operative", "fictional-act-status")

    attorney_qualification._assert_response_depth(
        {"first": shared, "second": [shared, {"third": shared}]}
    )


def test_qualification_schema_1_1_repeated_acyclic_values_are_allowed(
    tmp_path: Path,
) -> None:
    request = _initialize_and_next(qualification_case_schema_1_1(), tmp_path)
    response = admitted_response(request)
    shared_source_ids = [
        "fictional-act-operative",
        "fictional-act-status",
    ]
    payload = response.payload.copy()
    payload["checks"] = [
        {**check, "source_ids": shared_source_ids}
        for check in payload["checks"]
    ]
    repeated = JudgeResponse.model_construct(
        **{**response.__dict__, "payload": payload}
    )

    preflight = preflight_case_qualification(tmp_path, repeated)

    assert preflight.ok is True


@pytest.mark.parametrize(
    ("artifact", "path", "value"),
    [
        ("admission-response.json", ("schema_version",), "9.9"),
        ("admission-response.json", ("operation",), "grade_report"),
        ("admission-response.json", ("request_fingerprint",), "0" * 64),
        ("admission-response.json", ("provider_name",), "tampered-provider"),
        ("admission-response.json", ("model_name",), "tampered-model"),
        ("admission-response.json", ("judge_isolation",), "scripted_fixture"),
        ("admission-response.json", ("response_id",), "tampered-response"),
        ("admission-response.json", ("usage", "input_tokens"), 999),
        (
            "admission-response.json",
            ("payload", "request_fingerprint"),
            "0" * 64,
        ),
        (
            "admission-response.json",
            ("payload", "checks", 0, "rationale"),
            "Tampered judgment rationale.",
        ),
        ("qualification-case.json", ("build_binding", "commit"), "c" * 40),
        (
            "qualification-case.json",
            ("build_binding", "archive_sha256"),
            "d" * 64,
        ),
        (
            "qualification-case.json",
            ("language_treatments", 0, "source_ids"),
            ["fictional-act-operative"],
        ),
        (
            "qualification-case.json",
            ("language_treatments", 0, "method"),
            "Tampered treatment.",
        ),
        (
            "qualification-case.json",
            ("language_treatments", 0, "rationale"),
            "Tampered rationale.",
        ),
        (
            "qualification-case.json",
            ("language_treatments", 0, "limitations"),
            "Tampered limitation.",
        ),
    ],
)
def test_qualification_schema_1_1_replay_rejects_envelope_and_build_binding_tamper(
    artifact: str,
    path: tuple[str | int, ...],
    value: object,
    tmp_path: Path,
) -> None:
    request = _initialize_and_next(qualification_case_schema_1_1(), tmp_path)
    submit_case_qualification(tmp_path, admitted_response(request))
    artifact_path = tmp_path / artifact
    payload = json.loads(artifact_path.read_bytes())
    target = payload
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    artifact_path.write_bytes(canonical_json_bytes(payload))

    assert verify_case_qualification(tmp_path).model_dump(mode="json") == {
        "valid": False,
        "root_hash": None,
        "issues": ["QUALIFICATION_INTEGRITY_INVALID"],
    }


def test_qualification_schema_1_1_verify_bounds_rehashed_deep_response(
    tmp_path: Path,
) -> None:
    """Replay must convert recursive response parsing into invalid integrity."""
    request = _initialize_and_next(qualification_case_schema_1_1(), tmp_path)
    submit_case_qualification(tmp_path, admitted_response(request))
    response_path = tmp_path / "admission-response.json"
    response_bytes = b'{"payload":' + b"[" * 1500 + b"0" + b"]" * 1500 + b"}"
    response_path.write_bytes(response_bytes)
    manifest_path = tmp_path / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    for artifact in manifest["artifacts"]:
        if artifact["artifact_path"] == "admission-response.json":
            artifact["artifact_hash"] = hashlib.sha256(response_bytes).hexdigest()
    manifest["root_hash"] = hashlib.sha256(
        canonical_json_bytes(
            {key: value for key, value in manifest.items() if key != "root_hash"}
        )
    ).hexdigest()
    manifest_path.write_bytes(canonical_json_bytes(manifest))

    assert verify_case_qualification(tmp_path).model_dump(mode="json") == {
        "valid": False,
        "root_hash": None,
        "issues": ["QUALIFICATION_INTEGRITY_INVALID"],
    }


def test_qualification_legacy_1_0_response_receipt_and_root_bytes_are_frozen(
    tmp_path: Path,
) -> None:
    request = _initialize_and_next(qualification_case(), tmp_path)
    judgment = admitted_judgment(request)

    receipt = submit_case_qualification(tmp_path, judgment)

    assert (tmp_path / "admission-response.json").read_bytes() == canonical_json_bytes(
        judgment.model_dump(mode="json")
    )
    assert hashlib.sha256(
        (tmp_path / "admission-response.json").read_bytes()
    ).hexdigest() == _LEGACY_1_0_RESPONSE_BYTES_SHA256
    assert hashlib.sha256(
        (tmp_path / "qualification-receipt.json").read_bytes()
    ).hexdigest() == _LEGACY_1_0_RECEIPT_BYTES_SHA256
    assert receipt.receipt_fingerprint == (
        "668cac696933659c012674665838f2a3e8456cfe82bb0f5509c24d1074f1a8b3"
    )
    assert resume_case_qualification(tmp_path).root_hash == _LEGACY_1_0_ROOT_HASH


def test_candidate_free_qualification_seals_admitted_source_record(tmp_path: Path) -> None:
    case = qualification_case(currentness_source=True)
    state = initialize_case_qualification(case, tmp_path, nonce_hex="1" * 64)
    request = next_qualification_request(tmp_path)

    assert state.status == "awaiting-judgment"
    assert request is not None
    assert request.payload["sources"]
    assert "candidates" not in request.payload
    assert "client_facts" not in request.payload
    receipt = submit_case_qualification(tmp_path, admitted_judgment(request))

    assert receipt.readiness.status is ReadinessStatus.ADMITTED
    verification = verify_case_qualification(tmp_path)
    assert verification.valid is True
    assert verification.root_hash == resume_case_qualification(tmp_path).root_hash


def test_unready_qualification_is_terminal_without_generation(tmp_path: Path) -> None:
    request = _initialize_and_next(qualification_case(currentness_source=False), tmp_path)

    receipt = submit_case_qualification(
        tmp_path,
        failed_currentness_judgment(request),
    )

    assert receipt.readiness.status is ReadinessStatus.CASE_INVALID
    assert next_qualification_request(tmp_path) is None
    assert resume_case_qualification(tmp_path).status == "case-invalid"


def test_current_law_qualification_requires_objective_currentness_metadata(
    tmp_path: Path,
) -> None:
    case = qualification_case()
    for source in case.sources:
        source.version = None
        source.effective_date = None
        source.supersession = None
    case.sources[-1].source_role = SourceRole.COMMENTARY_ANALYSIS
    case.sources[-1].version = "2026 commentary edition"
    request = _initialize_and_next(case, tmp_path)

    receipt = submit_case_qualification(tmp_path, admitted_judgment(request))

    assert receipt.readiness.status is ReadinessStatus.CASE_INVALID
    assert receipt.readiness.issue_codes == ["CURRENTNESS_EVIDENCE_INSUFFICIENT"]
    assert resume_case_qualification(tmp_path).status == "case-invalid"
    verification = verify_case_qualification(tmp_path)
    assert verification.valid is True
    assert verification.root_hash == resume_case_qualification(tmp_path).root_hash


def test_qualification_binds_exact_source_bytes(tmp_path: Path) -> None:
    case = qualification_case()
    state = initialize_case_qualification(case, tmp_path, nonce_hex="2" * 64)

    assert (tmp_path / "qualification-case.json").read_bytes() == canonical_json_bytes(
        case.model_dump(mode="json")
    )
    request = next_qualification_request(tmp_path)
    assert request is not None
    assert request.payload["sources"][0]["normalized_text"].endswith("record.")
    assert request.payload["source_record_fingerprint"] == state.source_record_fingerprint


def test_initialization_refuses_a_nonempty_target_without_changing_it(tmp_path: Path) -> None:
    tmp_path.chmod(0o755)
    marker = tmp_path / "owned.txt"
    marker.write_text("owned\n", encoding="utf-8")
    before = tmp_path.stat()
    before_metadata = (
        stat.S_IMODE(before.st_mode),
        before.st_uid,
        before.st_gid,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )

    with pytest.raises(EvaluationIntegrityError, match="must be empty"):
        initialize_case_qualification(
            qualification_case(),
            tmp_path,
            nonce_hex="3" * 64,
        )

    assert _tree_bytes(tmp_path) == {"owned.txt": b"owned\n"}
    after = tmp_path.stat()
    assert (
        stat.S_IMODE(after.st_mode),
        after.st_uid,
        after.st_gid,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ) == before_metadata


def test_qualification_receipt_rejects_inconclusive_terminal_readiness() -> None:
    readiness = CaseReadiness(
        status=ReadinessStatus.INCONCLUSIVE,
        case_fingerprint="1" * 64,
        judgment_fingerprint="2" * 64,
        issue_codes=["JUDGE_UNAVAILABLE"],
        rationale="No terminal source qualification was reached.",
    )
    payload = {
        "schema_version": "1.0",
        "case_fingerprint": "1" * 64,
        "source_record_fingerprint": "3" * 64,
        "request_fingerprint": "4" * 64,
        "judgment_fingerprint": "2" * 64,
        "readiness": readiness.model_dump(mode="json"),
    }
    receipt_fingerprint = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()

    with pytest.raises(ValidationError, match=r"terminal.*ADMITTED.*CASE_INVALID"):
        QualificationReceipt(
            **payload,
            receipt_fingerprint=receipt_fingerprint,
        )


def test_qualification_receipt_model_bypass_fails_at_serialization_boundary() -> None:
    readiness = CaseReadiness(
        status=ReadinessStatus.INCONCLUSIVE,
        case_fingerprint="1" * 64,
        judgment_fingerprint="2" * 64,
        issue_codes=["JUDGE_UNAVAILABLE"],
        rationale="No terminal source qualification was reached.",
    )
    payload = {
        "schema_version": "1.0",
        "case_fingerprint": "1" * 64,
        "source_record_fingerprint": "3" * 64,
        "request_fingerprint": "4" * 64,
        "judgment_fingerprint": "2" * 64,
        "readiness": readiness,
    }
    receipt_fingerprint = hashlib.sha256(
        canonical_json_bytes(
            {
                **payload,
                "readiness": readiness.model_dump(mode="json"),
            }
        )
    ).hexdigest()
    bypass = QualificationReceipt.model_construct(
        **payload,
        receipt_fingerprint=receipt_fingerprint,
    )

    with pytest.raises(EvaluationIntegrityError, match="QualificationReceipt"):
        _model_bytes(bypass, QualificationReceipt)


def test_malformed_judgment_preflight_and_guard_write_zero_bytes(tmp_path: Path) -> None:
    _initialize_and_next(qualification_case(), tmp_path)
    before = _tree_bytes(tmp_path)
    malformed = {"request_fingerprint": "not-a-fingerprint", "checks": []}

    preflight = preflight_case_qualification(tmp_path, malformed)
    guarded = guarded_submit_case_qualification(tmp_path, malformed)

    assert preflight.ok is False
    assert [issue.code for issue in preflight.issues] == [
        "EVALUATION_RESPONSE_SCHEMA_INVALID"
    ]
    assert guarded.accepted is False
    assert guarded.preflight == preflight
    assert guarded.receipt is None
    assert _tree_bytes(tmp_path) == before


def test_first_valid_judgment_seals_and_later_submissions_fail_closed(tmp_path: Path) -> None:
    request = _initialize_and_next(qualification_case(), tmp_path)
    judgment = admitted_judgment(request)
    first = submit_case_qualification(tmp_path, judgment)
    sealed = _tree_bytes(tmp_path)

    with pytest.raises(EvaluationIntegrityError, match="no pending qualification judgment"):
        submit_case_qualification(tmp_path, judgment)

    assert resume_case_qualification(tmp_path).receipt_fingerprint == first.receipt_fingerprint
    assert _tree_bytes(tmp_path) == sealed


def test_guarded_valid_submission_matches_direct_receipt_and_artifact_bytes(
    tmp_path: Path,
) -> None:
    direct_run = tmp_path / "direct"
    guarded_run = tmp_path / "guarded"
    direct_request = _initialize_and_next(qualification_case(), direct_run)
    guarded_request = _initialize_and_next(qualification_case(), guarded_run)

    direct_receipt = submit_case_qualification(
        direct_run,
        admitted_judgment(direct_request),
    )
    guarded = guarded_submit_case_qualification(
        guarded_run,
        admitted_judgment(guarded_request),
    )

    assert guarded.accepted is True
    assert guarded.receipt == direct_receipt
    assert _tree_bytes(guarded_run) == _tree_bytes(direct_run)


@pytest.mark.parametrize(
    "artifact_path",
    [
        "qualification-case.json",
        "admission-request.json",
        "admission-response.json",
        "qualification-receipt.json",
        "manifest.json",
    ],
)
def test_qualification_replay_rejects_tampered_artifact(
    tmp_path: Path,
    artifact_path: str,
) -> None:
    request = _initialize_and_next(qualification_case(), tmp_path)
    submit_case_qualification(tmp_path, admitted_judgment(request))
    path = tmp_path / artifact_path
    value = json.loads(path.read_text(encoding="utf-8"))
    if artifact_path == "qualification-case.json":
        value["question"] = "A tampered question?"
    elif artifact_path == "admission-request.json":
        value["safe_metadata"]["record_scope"] = "tampered"
    elif artifact_path == "admission-response.json":
        value["checks"][0]["rationale"] = "Tampered rationale."
    elif artifact_path == "qualification-receipt.json":
        value["readiness"]["rationale"] = "Tampered readiness."
    else:
        value["status"] = "awaiting-judgment"
    path.write_bytes(canonical_json_bytes(value))

    verification = verify_case_qualification(tmp_path)

    assert verification.valid is False
    assert verification.issues == ("QUALIFICATION_INTEGRITY_INVALID",)
    assert verification.root_hash is None


def test_qualification_replay_rejects_unallowlisted_artifact(tmp_path: Path) -> None:
    _initialize_and_next(qualification_case(), tmp_path)
    (tmp_path / "generation-output.json").write_text("{}", encoding="utf-8")

    assert verify_case_qualification(tmp_path).valid is False


def test_qualification_replay_rejects_unallowlisted_empty_directory(
    tmp_path: Path,
) -> None:
    _initialize_and_next(qualification_case(), tmp_path)
    (tmp_path / "unexpected-empty-directory").mkdir()

    verification = verify_case_qualification(tmp_path)

    assert verification.valid is False
    assert verification.issues == ("QUALIFICATION_INTEGRITY_INVALID",)


@pytest.mark.skipif(os.name != "posix", reason="symlink containment is POSIX-specific")
def test_qualification_replay_rejects_unallowlisted_symlink(tmp_path: Path) -> None:
    _initialize_and_next(qualification_case(), tmp_path)
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (tmp_path / "unexpected-link").symlink_to(outside, target_is_directory=True)

    verification = verify_case_qualification(tmp_path)

    assert verification.valid is False
    assert verification.issues == ("QUALIFICATION_INTEGRITY_INVALID",)


@pytest.mark.skipif(os.name != "posix", reason="symlink containment is POSIX-specific")
def test_qualification_refuses_symlink_target_path(tmp_path: Path) -> None:
    owned = tmp_path / "owned"
    owned.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(owned, target_is_directory=True)

    with pytest.raises(EvaluationIntegrityError, match=r"symlink|non-directory"):
        initialize_case_qualification(
            qualification_case(),
            linked,
            nonce_hex="4" * 64,
        )

    assert _tree_bytes(owned) == {}


def test_verified_qualification_context_returns_one_replay_typed_snapshot(
    tmp_path: Path,
) -> None:
    request = _initialize_and_next(qualification_case_schema_1_1(), tmp_path)
    receipt = submit_case_qualification(tmp_path, admitted_response(request))

    context = load_verified_qualification_context(tmp_path)

    assert context.case == qualification_case_schema_1_1()
    assert context.receipt == receipt
    assert context.manifest.root_hash == resume_case_qualification(tmp_path).root_hash
    assert context.artifact_bytes == {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in sorted(tmp_path.iterdir())
        if path.is_file()
    }


@pytest.mark.skipif(os.name != "posix", reason="root inode replacement is POSIX-specific")
def test_verified_qualification_context_rejects_root_replacement_during_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = tmp_path / "qualification"
    request = _initialize_and_next(qualification_case_schema_1_1(), run)
    submit_case_qualification(run, admitted_response(request))
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    (replacement / "outside.txt").write_bytes(b"outside\n")
    parked = tmp_path / "parked"
    original = attorney_qualification._load_manifest
    swapped = False

    def swap_before_manifest_read(storage: object) -> object:
        nonlocal swapped
        run.rename(parked)
        replacement.rename(run)
        swapped = True
        return original(storage)  # type: ignore[arg-type]

    monkeypatch.setattr(attorney_qualification, "_load_manifest", swap_before_manifest_read)

    with pytest.raises(EvaluationIntegrityError, match=r"identity|changed"):
        load_verified_qualification_context(run)

    assert swapped
    assert (run / "outside.txt").read_bytes() == b"outside\n"


def test_qualification_template_is_candidate_free_and_uses_only_relative_paths() -> None:
    template_path = ROOT / "assets" / "attorney-evaluation-qualification.template.json"
    payload = json.loads(template_path.read_text(encoding="utf-8"))

    assert "candidates" not in payload
    assert "client_facts_path" not in payload
    assert len(payload["sources"]) == 2
    assert {source["qualification_role"] for source in payload["sources"]} == {
        "operative_text",
        "status_currentness",
    }
    for source in payload["sources"]:
        path = Path(source["path"])
        assert not path.is_absolute()
        assert ".." not in path.parts
    serialized = template_path.read_text(encoding="utf-8")
    assert "__REPLACE__" in serialized
    assert "<REPLACE" not in serialized
