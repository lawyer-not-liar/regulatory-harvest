"""Freeze attorney-evaluation cases and fail closed at admission."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import cast

from regulatory_harvest.models.enums import SourceRole
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from .attorney_models import (
    AdmissionCheck,
    AttorneyEvaluationCase,
    BlindAssignment,
    CandidateReport,
    CaseAdmissionJudgment,
    CaseEnvelope,
    CaseReadiness,
    EvaluationIssue,
    EvaluationMode,
    EvaluationSource,
    IssueSeverity,
    JudgeOperation,
    JudgeRequest,
    QualificationBuildBinding,
    QualificationCase,
    QualificationLanguageTreatment,
    ReadinessStatus,
    RequestedAuthority,
    model_fingerprint,
)

_SEED_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_REQUIRED_CHECK_CODES = {
    "AUTHORITY_ALIGNMENT": "AUTHORITY_MISMATCH",
    "OPERATIVE_TEXT": "OPERATIVE_TEXT_MISSING",
    "CURRENTNESS_EVIDENCE": "CURRENTNESS_EVIDENCE_INSUFFICIENT",
    "LANGUAGE_RESOLUTION": "LANGUAGE_UNRESOLVED",
    "SOURCE_PARITY": "SOURCE_PARITY_UNPROVEN",
}
_FATAL_JUDGE_ISSUE_CODES = frozenset(_REQUIRED_CHECK_CODES.values())
_SOURCE_RECORD_KEYS = frozenset(
    {
        "schema_version",
        "mode",
        "question",
        "jurisdiction",
        "as_of",
        "requested_authorities",
        "sources",
    }
)
_QUALIFICATION_SOURCE_METADATA_KEYS = frozenset(
    {"build_binding", "language_treatments"}
)


def freeze_case(case: AttorneyEvaluationCase, *, seed_hex: str) -> CaseEnvelope:
    """Bind a validated case and deterministic blind assignments to a secret seed."""
    _validate_seed(seed_hex)
    case = _strict_case_snapshot(case)
    _validate_source_hashes(case.sources)
    _validate_report_hashes(case.candidates)
    _validate_requested_authorities(case)
    payload = case.model_dump(mode="json")
    seed_fingerprint = sha256_digest(seed_hex.encode("ascii"))
    return CaseEnvelope(
        case=case,
        assignments=_blind_assignments(case.candidates, seed_fingerprint),
        case_fingerprint=sha256_digest(canonical_json_bytes(payload)),
        seed_fingerprint=seed_fingerprint,
    )


def build_source_record(
    case: AttorneyEvaluationCase | QualificationCase,
) -> dict[str, object]:
    """Project only the legal question, authorities, and frozen source record."""
    if isinstance(case, AttorneyEvaluationCase):
        snapshot: AttorneyEvaluationCase | QualificationCase = _strict_case_snapshot(case)
    elif isinstance(case, QualificationCase):
        if case.schema_version == "1.0" and (
            _QUALIFICATION_SOURCE_METADATA_KEYS & case.model_fields_set
        ):
            raise ValueError("schema 1.0 must omit qualification source metadata")
        snapshot = QualificationCase.model_validate(
            case.model_dump(mode="json", warnings=False)
        )
    else:
        raise TypeError("source record requires an attorney evaluation or qualification case")
    source_record: dict[str, object] = {
        "schema_version": snapshot.schema_version,
        "mode": snapshot.mode.value,
        "question": snapshot.question,
        "jurisdiction": snapshot.jurisdiction,
        "as_of": snapshot.as_of.isoformat(),
        "requested_authorities": [
            _admission_authority_payload(authority)
            for authority in snapshot.requested_authorities
        ],
        "sources": [_admission_source_payload(source) for source in snapshot.sources],
    }
    if isinstance(snapshot, QualificationCase) and snapshot.schema_version == "1.1":
        if snapshot.build_binding is None:
            raise ValueError("schema 1.1 qualification case requires build_binding")
        source_record.update(
            {
                "build_binding": snapshot.build_binding.model_dump(mode="json"),
                "language_treatments": [
                    treatment.model_dump(mode="json")
                    for treatment in snapshot.language_treatments
                ],
            }
        )
    return source_record


def build_admission_request(source_record: Mapping[str, object]) -> JudgeRequest:
    """Create the canonical five-dimension request for one frozen source record."""
    source_projection = _canonical_source_record(source_record)
    schema_version = source_projection.get("schema_version")
    if schema_version == "1.0":
        required_keys = _SOURCE_RECORD_KEYS
        qualification_schema_1_1 = False
    elif schema_version == "1.1":
        required_keys = _SOURCE_RECORD_KEYS | _QUALIFICATION_SOURCE_METADATA_KEYS
        qualification_schema_1_1 = True
    else:
        raise ValueError("source record has an unsupported schema version")
    if set(source_projection) != required_keys:
        raise ValueError("source record has an unexpected shape")
    if qualification_schema_1_1:
        _validate_qualification_source_metadata(source_projection)
    return _finish_admission_request(
        source_projection,
        qualification_schema_1_1=qualification_schema_1_1,
    )


def _canonical_source_record(source_record: Mapping[str, object]) -> dict[str, object]:
    """Copy an untrusted source mapping into ordinary canonical JSON values."""
    try:
        source_projection = json.loads(canonical_json_bytes(dict(source_record)))
    except (TypeError, ValueError) as error:
        raise ValueError("source record is not canonical JSON") from error
    if not isinstance(source_projection, dict):
        raise ValueError("source record has an unexpected shape")
    return cast(dict[str, object], source_projection)


def _build_attorney_admission_request(case: AttorneyEvaluationCase) -> JudgeRequest:
    """Preserve the typed attorney-evaluation source projection for schema 1.0/1.1."""
    if not isinstance(case, AttorneyEvaluationCase):
        raise TypeError("attorney compatibility requires an AttorneyEvaluationCase")
    source_projection = _canonical_source_record(build_source_record(case))
    if (
        source_projection.get("schema_version") not in {"1.0", "1.1"}
        or set(source_projection) != _SOURCE_RECORD_KEYS
    ):
        raise ValueError("attorney evaluation source record has an unexpected shape")
    return _finish_admission_request(
        source_projection,
        qualification_schema_1_1=False,
    )


def _finish_admission_request(
    source_projection: dict[str, object],
    *,
    qualification_schema_1_1: bool,
) -> JudgeRequest:
    """Fingerprint one strictly validated admission source projection."""
    source_record_fingerprint = sha256_digest(canonical_json_bytes(source_projection))
    payload = {
        **source_projection,
        "source_record_fingerprint": source_record_fingerprint,
    }
    system_instructions = (
        "Assess whether the supplied legal source record is admissible for evaluation. "
        "Copy this request's request_fingerprint into the judgment. Return each of these "
        "five checks exactly once, with material=true: AUTHORITY_ALIGNMENT (the requested "
        "authorities, jurisdictions, authority types, and retained sources align); "
        "OPERATIVE_TEXT (complete responsive operative text is available); "
        "CURRENTNESS_EVIDENCE (status and version evidence supports the declared as-of "
        "date); LANGUAGE_RESOLUTION (each material source language is resolved); and "
        "SOURCE_PARITY (the common source record is fit to evaluate every candidate). "
        "For each check, set satisfied from only the supplied source record, give a "
        "concrete rationale, and identify supporting source_ids. Put any distinct defect "
        "in issues. Return only the required structured admission judgment."
    )
    if qualification_schema_1_1:
        system_instructions += (
            " For LANGUAGE_RESOLUTION, assess the supplied language treatment and its "
            "limitations."
        )
    json_schema = CaseAdmissionJudgment.model_json_schema()
    safe_metadata = {
        "source_record_fingerprint": source_record_fingerprint,
        "record_scope": "source-only",
    }
    if qualification_schema_1_1:
        safe_metadata.update(
            {
                "build_binding": canonical_json_bytes(
                    source_projection["build_binding"]
                ).decode("utf-8"),
                "language_treatments": canonical_json_bytes(
                    source_projection["language_treatments"]
                ).decode("utf-8"),
            }
        )
    request_payload = {
        "schema_version": "1.0",
        "operation": JudgeOperation.ADMIT_CASE.value,
        "system_instructions": system_instructions,
        "json_schema": json_schema,
        "payload": payload,
        "safe_metadata": safe_metadata,
    }
    return JudgeRequest(
        operation=JudgeOperation.ADMIT_CASE,
        request_fingerprint=sha256_digest(canonical_json_bytes(request_payload)),
        system_instructions=system_instructions,
        json_schema=json_schema,
        payload=payload,
        safe_metadata=safe_metadata,
    )


def build_admission_packet(envelope: CaseEnvelope) -> JudgeRequest:
    """Create a blind, source-record-only request for admission review."""
    envelope = _strict_envelope_snapshot(envelope)
    _validate_envelope_binding(envelope)
    return _build_attorney_admission_request(envelope.case)


def adjudicate_admission(
    envelope: CaseEnvelope, judgment: CaseAdmissionJudgment
) -> CaseReadiness:
    """Combine deterministic prechecks and a bound admission judgment fail closed."""
    envelope = _strict_envelope_snapshot(envelope)
    judgment = _strict_judgment_snapshot(judgment)
    _validate_envelope_binding(envelope)
    request = build_admission_packet(envelope)
    return adjudicate_source_record(
        case_fingerprint=envelope.case_fingerprint,
        source_ids={source.source_id for source in envelope.case.sources},
        deterministic_issues=_deterministic_issues(envelope.case),
        request=request,
        judgment=judgment,
    )


def adjudicate_source_record(
    *,
    case_fingerprint: str,
    source_ids: set[str],
    deterministic_issues: Sequence[EvaluationIssue],
    request: JudgeRequest,
    judgment: CaseAdmissionJudgment,
) -> CaseReadiness:
    """Fail closed over deterministic source checks and one exact bound judgment."""
    judgment = _strict_judgment_snapshot(judgment)
    if judgment.request_fingerprint != request.request_fingerprint:
        raise ValueError("admission judgment does not bind the exact admission packet")

    _validate_material_check_support(judgment.checks, source_ids)
    failed_checks = _failed_material_checks(judgment.checks)
    issue_codes = _unique_codes(
        [issue.code for issue in deterministic_issues]
        + failed_checks
        + _judgment_issue_codes(judgment.issues)
    )
    judgment_fingerprint = sha256_digest(canonical_json_bytes(judgment.model_dump(mode="json")))
    if issue_codes:
        return CaseReadiness(
            status=ReadinessStatus.CASE_INVALID,
            case_fingerprint=case_fingerprint,
            judgment_fingerprint=judgment_fingerprint,
            issue_codes=issue_codes,
            rationale=f"Case admission failed: {', '.join(issue_codes)}.",
        )
    return CaseReadiness(
        status=ReadinessStatus.ADMITTED,
        case_fingerprint=case_fingerprint,
        judgment_fingerprint=judgment_fingerprint,
        rationale="Case passed deterministic and model admission checks.",
    )


def _validate_seed(seed_hex: str) -> None:
    if not _SEED_PATTERN.fullmatch(seed_hex):
        raise ValueError("seed_hex must be exactly 64 lowercase hexadecimal characters")


def _validate_qualification_source_metadata(source_record: dict[str, object]) -> None:
    """Revalidate raw schema-1.1 metadata and its exact source coverage."""
    binding_payload = source_record["build_binding"]
    binding = QualificationBuildBinding.model_validate(binding_payload, strict=True)
    if binding.model_dump(mode="json") != binding_payload:
        raise ValueError("build_binding is not canonical")

    treatment_payloads = source_record["language_treatments"]
    if type(treatment_payloads) is not list:
        raise ValueError("language_treatments must be an array")
    treatments = [
        QualificationLanguageTreatment.model_validate(payload, strict=True)
        for payload in treatment_payloads
    ]
    if [treatment.model_dump(mode="json") for treatment in treatments] != treatment_payloads:
        raise ValueError("language_treatments are not canonical")

    sources = source_record["sources"]
    if type(sources) is not list or any(
        type(source) is not dict or type(source.get("source_id")) is not str
        for source in sources
    ):
        raise ValueError("sources must expose canonical source identifiers")
    source_ids = [source["source_id"] for source in sources]
    treated_source_ids = [
        source_id
        for treatment in treatments
        for source_id in treatment.source_ids
    ]
    if (
        len(source_ids) != len(set(source_ids))
        or len(treated_source_ids) != len(set(treated_source_ids))
        or set(treated_source_ids) != set(source_ids)
    ):
        raise ValueError("language treatments must identify every source exactly once")


def _strict_case_snapshot(case: AttorneyEvaluationCase) -> AttorneyEvaluationCase:
    """Round-trip untrusted mutable state through the strict case contract."""
    return AttorneyEvaluationCase.model_validate(case.model_dump(mode="json"))


def _strict_envelope_snapshot(envelope: CaseEnvelope) -> CaseEnvelope:
    """Round-trip untrusted mutable state through the strict envelope contract."""
    return CaseEnvelope.model_validate(envelope.model_dump(mode="json"))


def _strict_judgment_snapshot(judgment: CaseAdmissionJudgment) -> CaseAdmissionJudgment:
    """Reject post-validation scalar mutation before strict revalidation."""
    if not isinstance(judgment.checks, list) or any(
        not isinstance(check, AdmissionCheck)
        or type(check.satisfied) is not bool
        or type(check.material) is not bool
        for check in judgment.checks
    ):
        raise ValueError(
            "admission judgment checks must retain boolean satisfied and material values"
        )
    return CaseAdmissionJudgment.model_validate(judgment.model_dump(mode="json"))


def _validate_source_hashes(sources: list[EvaluationSource]) -> None:
    source_ids = [source.source_id for source in sources]
    if len(set(source_ids)) != len(source_ids):
        raise ValueError("DUPLICATE_SOURCE_ID")
    for source in sources:
        if source.content_hash != sha256_digest(source.normalized_text.encode("utf-8")):
            raise ValueError(f"SOURCE_CONTENT_HASH_INVALID: {source.source_id}")


def _validate_report_hashes(candidates: list[CandidateReport]) -> None:
    for candidate in candidates:
        if candidate.report_hash != sha256_digest(candidate.report_text.encode("utf-8")):
            raise ValueError(f"CANDIDATE_REPORT_HASH_INVALID: {candidate.candidate_id}")


def _validate_requested_authorities(case: AttorneyEvaluationCase) -> None:
    source_ids = {source.source_id for source in case.sources}
    if not case.requested_authorities or any(
        not authority.source_ids or not set(authority.source_ids).issubset(source_ids)
        for authority in case.requested_authorities
    ):
        raise ValueError("REQUESTED_AUTHORITY_METADATA_MISSING")


def _blind_assignments(
    candidates: list[CandidateReport], seed_fingerprint: str
) -> list[BlindAssignment]:
    ordered = sorted(
        candidates,
        key=lambda candidate: (
            sha256_digest(f"{seed_fingerprint}:{candidate.candidate_id}".encode()),
            candidate.candidate_id,
        ),
    )
    return [
        BlindAssignment(
            anonymous_label="A" if index == 0 else "B",
            candidate_id=candidate.candidate_id,
        )
        for index, candidate in enumerate(ordered)
    ]


def _validate_envelope_binding(envelope: CaseEnvelope) -> None:
    if envelope.case_fingerprint != model_fingerprint(envelope.case):
        raise ValueError("case envelope does not bind its current case data")
    if not _SEED_PATTERN.fullmatch(envelope.seed_fingerprint):
        raise ValueError("case envelope seed_fingerprint is invalid")
    expected_assignments = _blind_assignments(
        envelope.case.candidates, envelope.seed_fingerprint
    )
    if envelope.assignments != expected_assignments:
        raise ValueError("case envelope assignments do not bind its seed_fingerprint")


def _failed_material_checks(checks: list[AdmissionCheck]) -> list[str]:
    checks_by_code = {check.code: check for check in checks}
    if len(checks_by_code) != len(checks):
        raise ValueError("admission judgment contains duplicate checks")
    missing = sorted(set(_REQUIRED_CHECK_CODES) - set(checks_by_code))
    if missing:
        raise ValueError(f"admission judgment is missing required checks: {', '.join(missing)}")
    downgraded = sorted(
        check.code
        for check in checks
        if check.code in _REQUIRED_CHECK_CODES and not check.material
    )
    if downgraded:
        raise ValueError(
            "required admission checks must be material: " + ", ".join(downgraded)
        )
    return [
        _REQUIRED_CHECK_CODES[check.code]
        if check.code in _REQUIRED_CHECK_CODES and not check.satisfied
        else check.code
        for check in checks
        if (check.code in _REQUIRED_CHECK_CODES and not check.satisfied)
        or (check.code not in _REQUIRED_CHECK_CODES and not check.satisfied and check.material)
    ]


def _validate_material_check_support(
    checks: list[AdmissionCheck],
    known_source_ids: set[str],
) -> None:
    if any(
        check.satisfied
        and check.material
        and (
            not check.source_ids
            or not set(check.source_ids).issubset(known_source_ids)
        )
        for check in checks
    ):
        raise ValueError(
            "satisfied material admission checks require supporting source_ids "
            "from the case packet"
        )


def _deterministic_issues(
    case: AttorneyEvaluationCase | QualificationCase,
) -> list[EvaluationIssue]:
    issues: list[EvaluationIssue] = []
    source_ids = [source.source_id for source in case.sources]
    if len(set(source_ids)) != len(source_ids):
        issues.append(_issue("DUPLICATE_SOURCE_ID", "Case sources are not uniquely identified."))

    for source in case.sources:
        if source.content_hash != sha256_digest(source.normalized_text.encode("utf-8")):
            issues.append(
                _issue(
                    "SOURCE_CONTENT_HASH_INVALID",
                    "Retained source text does not match its content hash.",
                    [source.source_id],
                )
            )
        if source.source_role is SourceRole.OFFICIAL_PRIMARY and (
            not source.normalized_text.strip() or source.completeness == "snippet"
        ):
            issues.append(
                _issue(
                    "OPERATIVE_TEXT_MISSING",
                    "Official primary source lacks complete operative text.",
                    [source.source_id],
                )
            )
    if (
        isinstance(case, QualificationCase)
        and case.mode is EvaluationMode.CURRENT_LAW
        and not any(
            source.source_role is not SourceRole.COMMENTARY_ANALYSIS
            and any(
                value is not None
                for value in (source.version, source.effective_date, source.supersession)
            )
            for source in case.sources
        )
    ):
        issues.append(
            _issue(
                "CURRENTNESS_EVIDENCE_INSUFFICIENT",
                "Current-law source record lacks objective currentness metadata.",
                source_ids,
            )
        )
    known_source_ids = set(source_ids)
    for authority in case.requested_authorities:
        if not authority.source_ids or not set(authority.source_ids).issubset(known_source_ids):
            issues.append(
                _issue(
                    "REQUESTED_AUTHORITY_METADATA_MISSING",
                    "Requested authority lacks valid source-record metadata.",
                    [authority.authority_id],
                )
            )
            continue
        for source_id in authority.source_ids:
            source = next(source for source in case.sources if source.source_id == source_id)
            if (
                source.jurisdiction != authority.jurisdiction
                or source.authority_type != authority.authority_type
            ):
                issues.append(
                    _issue(
                        "AUTHORITY_MISMATCH",
                        "Requested authority metadata does not match its retained source.",
                        [authority.authority_id, source_id],
                    )
                )

    if isinstance(case, AttorneyEvaluationCase):
        issues.extend(_source_parity_issues(case))
    return issues


def _source_parity_issues(case: AttorneyEvaluationCase) -> list[EvaluationIssue]:
    expected_hashes = {source.source_id: source.content_hash for source in case.sources}
    if case.schema_version == "1.1":
        expected_client_facts_hash: str | None = (
            None
            if case.client_facts is None
            else sha256_digest(case.client_facts.encode("utf-8"))
        )
        if len(case.candidates) == 1:
            provenance = case.candidates[0].generation_provenance
            if provenance is not None and provenance.get("kind") == "external":
                return []
    else:
        expected_client_facts_hash = sha256_digest((case.client_facts or "").encode("utf-8"))
    issues: list[EvaluationIssue] = []
    for candidate in case.candidates:
        if case.schema_version == "1.1":
            has_parity = _has_exact_capsule_provenance(
                candidate.validation_receipt,
                expected_hashes,
                expected_client_facts_hash,
                case.question,
            )
        else:
            has_parity = _has_exact_parity_commitment(
                candidate.validation_receipt,
                expected_hashes,
                cast(str, expected_client_facts_hash),
            )
        if has_parity:
            continue
        issues.append(
            _issue(
                "SOURCE_PARITY_UNPROVEN",
                "Candidate did not provide an exact source and client-facts provenance commitment.",
                [candidate.candidate_id],
            )
        )
        if candidate.role.value == "comparator":
            issues.append(
                _issue(
                    "COMPARATOR_ACCESS_MISMATCH",
                    "Comparator provenance commitment does not match the case record.",
                    [candidate.candidate_id],
                )
            )
    return issues


def _has_exact_capsule_provenance(
    provenance: dict[str, object] | None,
    expected_hashes: dict[str, str],
    expected_client_facts_hash: str | None,
    expected_question: str,
) -> bool:
    if not isinstance(provenance, Mapping) or set(provenance) != {
        "kind",
        "capsule_root",
        "generation_record",
        "generation_question",
    }:
        return False
    record = provenance["generation_record"]
    return (
        provenance["kind"] == "capsule"
        and isinstance(record, Mapping)
        and record.get("source_hashes") == expected_hashes
        and record.get("client_facts_hash") == expected_client_facts_hash
        and provenance.get("generation_question") == expected_question
    )


def _has_exact_parity_commitment(
    receipt: dict[str, object] | None,
    expected_hashes: dict[str, str],
    expected_client_facts_hash: str,
) -> bool:
    if not isinstance(receipt, Mapping) or set(receipt) != {
        "schema_version",
        "source_hashes",
        "client_facts_hash",
    }:
        return False
    if receipt["schema_version"] != "1.0":
        return False
    source_hashes = receipt["source_hashes"]
    client_facts_hash = receipt["client_facts_hash"]
    if not isinstance(source_hashes, Mapping) or not isinstance(client_facts_hash, str):
        return False
    if not all(
        isinstance(source_id, str) and isinstance(content_hash, str)
        for source_id, content_hash in source_hashes.items()
    ):
        return False
    return (
        dict(source_hashes) == expected_hashes
        and client_facts_hash == expected_client_facts_hash
    )


def _admission_authority_payload(authority: RequestedAuthority) -> dict[str, object]:
    return {
        "authority_id": authority.authority_id,
        "title": authority.title,
        "jurisdiction": authority.jurisdiction,
        "authority_type": authority.authority_type,
        "source_ids": list(authority.source_ids),
    }


def _admission_source_payload(source: EvaluationSource) -> dict[str, object]:
    return {
        "source_id": source.source_id,
        "title": source.title,
        "normalized_text": source.normalized_text,
        "content_hash": source.content_hash,
        "canonical_url": source.canonical_url,
        "publisher": source.publisher,
        "jurisdiction": source.jurisdiction,
        "authority_type": source.authority_type,
        "source_role": source.source_role.value,
        "source_quality": source.source_quality.value,
        "completeness": source.completeness,
        "language": source.language,
        "version": source.version,
        "effective_date": source.effective_date,
        "supersession": source.supersession,
        "relationship_ids": list(source.relationship_ids),
    }


def _judgment_issue_codes(issues: list[EvaluationIssue]) -> list[str]:
    return [
        canonical_code
        for issue in issues
        if (
            (canonical_code := _canonical_issue_code(issue.code)) in _FATAL_JUDGE_ISSUE_CODES
            or issue.severity is IssueSeverity.ERROR
        )
    ]


def _canonical_issue_code(code: str) -> str:
    return code.upper().replace("-", "_")


def _issue(code: str, message: str, related_ids: list[str] | None = None) -> EvaluationIssue:
    return EvaluationIssue(
        code=code,
        severity=IssueSeverity.ERROR,
        message=message,
        related_ids=related_ids or [],
    )


def _unique_codes(codes: list[str]) -> list[str]:
    return list(dict.fromkeys(codes))
