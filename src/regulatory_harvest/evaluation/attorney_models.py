"""Strict, provider-neutral contracts for blind attorney evaluation."""

from __future__ import annotations

import hashlib
import re
from datetime import date
from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator

from regulatory_harvest.models.base import StrictModel
from regulatory_harvest.models.enums import SourceQuality, SourceRole
from regulatory_harvest.storage import canonical_json_bytes

from .attorney_contract import PREFLIGHT_ISSUE_MESSAGES, ResponseContractCode

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_COMMIT_PATTERN = r"^[0-9a-f]{40}$"
EVALUATION_ARTIFACT_SCHEMA_VERSION: Literal["1.3"] = "1.3"
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_WINDOWS_FORBIDDEN_PATH_CHARS = frozenset('<>:"|?*')
_WINDOWS_RESERVED_DEVICE_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "COM2",
        "COM3",
        "COM4",
        "COM5",
        "COM6",
        "COM7",
        "COM8",
        "COM9",
        "COM¹",
        "COM²",
        "COM³",
        "LPT1",
        "LPT2",
        "LPT3",
        "LPT4",
        "LPT5",
        "LPT6",
        "LPT7",
        "LPT8",
        "LPT9",
        "LPT¹",
        "LPT²",
        "LPT³",
    }
)


class EvaluationMode(StrEnum):
    CURRENT_LAW = "current-law"
    CLOSED_UNIVERSE = "closed-universe"


class ReadinessStatus(StrEnum):
    ADMITTED = "ADMITTED"
    CASE_INVALID = "CASE_INVALID"
    INCONCLUSIVE = "INCONCLUSIVE"


class Materiality(StrEnum):
    CRITICAL = "critical"
    MATERIAL = "material"
    SUPPORTING = "supporting"


_MATERIALITY_RANK = {
    Materiality.SUPPORTING: 0,
    Materiality.MATERIAL: 1,
    Materiality.CRITICAL: 2,
}


class CoverageDisposition(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    MISSING = "MISSING"
    OVERSTATED = "OVERSTATED"
    CONTRADICTED = "CONTRADICTED"
    UNSUPPORTED = "UNSUPPORTED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class EntryFindingCode(StrEnum):
    """Closed semantic findings attached to a sealed ledger entry grade."""

    CRITICAL_LEDGER_ENTRY_MISSING = "CRITICAL_LEDGER_ENTRY_MISSING"
    MATERIAL_EXCEPTION_MISSING = "MATERIAL_EXCEPTION_MISSING"
    CONSEQUENCE_TRIGGER_DETACHED = "CONSEQUENCE_TRIGGER_DETACHED"


class NarrativeFindingCode(StrEnum):
    """Closed semantic findings attached to a narrative rubric dimension."""

    KEY_REQUIREMENTS_ACTION_PLAN = "KEY_REQUIREMENTS_ACTION_PLAN"


class LedgerCategory(StrEnum):
    STATUS = "status"
    SCOPE = "scope"
    DEFINITION = "definition"
    REQUIREMENT = "requirement"
    PROHIBITION = "prohibition"
    RIGHT = "right"
    EXCEPTION = "exception"
    DEADLINE = "deadline"
    ENFORCEMENT = "enforcement"
    REMEDY = "remedy"
    PENALTY = "penalty"
    APPEAL = "appeal"
    IMPLEMENTATION = "implementation"


class CandidateRole(StrEnum):
    CANDIDATE = "candidate"
    COMPARATOR = "comparator"


class AbsoluteDisposition(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    CASE_INVALID = "CASE_INVALID"


class ComparativeDisposition(StrEnum):
    REGULATORY_HARVEST_WIN = "REGULATORY_HARVEST_WIN"
    COMPARATOR_WIN = "COMPARATOR_WIN"
    TIE = "TIE"
    NEITHER = "NEITHER"
    INCONCLUSIVE = "INCONCLUSIVE"
    CASE_INVALID = "CASE_INVALID"


class JudgeOperation(StrEnum):
    ADMIT_CASE = "admit_case"
    BUILD_LEDGER = "build_ledger"
    AUDIT_LEDGER = "audit_ledger"
    REPAIR_LEDGER = "repair_ledger"
    GRADE_REPORT = "grade_report"
    REFEREE = "referee"


class JudgeIsolation(StrEnum):
    FRESH_CONTEXT = "fresh_context"
    SEQUENTIAL_SAME_CONTEXT = "sequential_same_context"
    SCRIPTED_FIXTURE = "scripted_fixture"


class IssueSeverity(StrEnum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class EvaluationRunPhase(StrEnum):
    CREATED = "created"
    ADMISSION = "admission"
    LEDGER_BUILD = "ledger-build"
    LEDGER_AUDIT = "ledger-audit"
    LEDGER_REPAIR = "ledger-repair"
    LEDGER_REFEREE = "ledger-referee"
    LEDGER_SEALED = "ledger-sealed"
    GRADE_A = "grade-a"
    GRADE_B = "grade-b"
    REPORT_REFEREE = "report-referee"
    AGGREGATE = "aggregate"
    COMPLETED = "completed"
    INCONCLUSIVE = "inconclusive"
    CASE_INVALID = "case-invalid"


class EvaluationTerminalStatus(StrEnum):
    COMPLETED = "completed"
    INCONCLUSIVE = "inconclusive"
    CASE_INVALID = "case-invalid"


_TERMINAL_PHASE_STATUS = {
    EvaluationRunPhase.COMPLETED: EvaluationTerminalStatus.COMPLETED,
    EvaluationRunPhase.INCONCLUSIVE: EvaluationTerminalStatus.INCONCLUSIVE,
    EvaluationRunPhase.CASE_INVALID: EvaluationTerminalStatus.CASE_INVALID,
}
_POST_LEDGER_PHASES = {
    EvaluationRunPhase.LEDGER_SEALED,
    EvaluationRunPhase.GRADE_A,
    EvaluationRunPhase.GRADE_B,
    EvaluationRunPhase.REPORT_REFEREE,
    EvaluationRunPhase.AGGREGATE,
    EvaluationRunPhase.COMPLETED,
}
_PRE_LEDGER_PHASES = set(EvaluationRunPhase) - _POST_LEDGER_PHASES - set(_TERMINAL_PHASE_STATUS)


def _nonblank(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("value must not be blank")
    return value


def _optional_nonblank(value: str | None) -> str | None:
    return None if value is None else _nonblank(value)


def _exact_content_nonblank(value: str) -> str:
    """Validate human-readable content without changing its byte-equivalent text."""
    if not value.replace("\ufeff", "").strip():
        raise ValueError("value must not be blank")
    return value


def _optional_exact_content_nonblank(value: str | None) -> str | None:
    return None if value is None else _exact_content_nonblank(value)


def _safe_relative_path(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("artifact path must be a string")
    if not value or value != value.strip():
        raise ValueError("artifact path must be nonblank without surrounding whitespace")
    if "\\" in value:
        raise ValueError("artifact path must use forward slashes")
    if value.startswith("/"):
        raise ValueError("artifact path must be relative")
    segments = value.split("/")
    for segment in segments:
        if segment in {"", ".", ".."}:
            raise ValueError("artifact path must not contain empty, '.' or '..' segments")
        if any(ord(character) <= 0x1F or ord(character) == 0x7F for character in segment):
            raise ValueError("artifact path must not contain ASCII control characters")
        if any(character in _WINDOWS_FORBIDDEN_PATH_CHARS for character in segment):
            raise ValueError("artifact path contains a Windows-forbidden character")
        if segment.endswith((" ", ".")):
            raise ValueError("artifact path components must not end in a space or dot")
        device_base = segment.split(".", maxsplit=1)[0].rstrip(" .").upper()
        if device_base in _WINDOWS_RESERVED_DEVICE_NAMES:
            raise ValueError("artifact path contains a reserved Windows device name")
    return value


def _optional_safe_relative_path(value: str | None) -> str | None:
    return None if value is None else _safe_relative_path(value)


def _safe_identifier(value: str) -> str:
    value = _nonblank(value)
    if not _SAFE_IDENTIFIER.fullmatch(value):
        raise ValueError("identifier must contain only letters, digits, '.', '_', ':', or '-'")
    return value


def _optional_safe_identifier(value: str | None) -> str | None:
    return None if value is None else _safe_identifier(value)


def _unique_identifiers(values: list[str]) -> list[str]:
    normalized = [_safe_identifier(value) for value in values]
    if len(set(normalized)) != len(normalized):
        raise ValueError("identifier values must be unique")
    return normalized


def _content_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _strict_hash_mapping(value: object, *, location: str, nonempty: bool) -> None:
    if type(value) is not dict or (nonempty and not value):
        raise ValueError(f"{location} must be a{' nonempty' if nonempty else ''} object")
    if any(
        type(identifier) is not str
        or not _SAFE_IDENTIFIER.fullmatch(identifier)
        or type(digest) is not str
        or re.fullmatch(_HASH_PATTERN, digest) is None
        for identifier, digest in value.items()
    ):
        raise ValueError(f"{location} contains an invalid commitment")


def _validate_generation_record(value: object, *, location: str) -> None:
    required = {
        "candidate_id",
        "capture_fingerprint",
        "client_facts_hash",
        "generation_isolation",
        "generator_artifact_hashes",
        "model_name",
        "nonce_fingerprint",
        "provider_name",
        "report_hash",
        "request_fingerprint",
        "response_fingerprint",
        "response_id",
        "schema_version",
        "source_hashes",
        "usage",
    }
    if type(value) is not dict or set(value) != required:
        raise ValueError(f"{location} has an unexpected shape")
    if value["schema_version"] != "1.0":
        raise ValueError(f"{location} schema version is unsupported")
    candidate_id = value["candidate_id"]
    if type(candidate_id) is not str:
        raise ValueError(f"{location} candidate_id must be a string")
    _safe_identifier(candidate_id)
    for field in (
        "capture_fingerprint",
        "nonce_fingerprint",
        "report_hash",
        "request_fingerprint",
        "response_fingerprint",
    ):
        digest = value[field]
        if type(digest) is not str or re.fullmatch(_HASH_PATTERN, digest) is None:
            raise ValueError(f"{location} {field} is invalid")
    facts_hash = value["client_facts_hash"]
    if facts_hash is not None and (
        type(facts_hash) is not str or re.fullmatch(_HASH_PATTERN, facts_hash) is None
    ):
        raise ValueError(f"{location} client_facts_hash is invalid")
    for field in ("model_name", "provider_name"):
        field_value = value[field]
        if type(field_value) is not str or not field_value.strip():
            raise ValueError(f"{location} {field} is invalid")
    if value["generation_isolation"] not in {
        "fresh_context",
        "sequential_same_context",
        "scripted_fixture",
    }:
        raise ValueError(f"{location} generation_isolation is unsupported")
    response_id = value["response_id"]
    if response_id is not None and (type(response_id) is not str or not response_id.strip()):
        raise ValueError(f"{location} response_id is invalid")
    _strict_hash_mapping(
        value["source_hashes"], location=f"{location} source_hashes", nonempty=True
    )
    _strict_hash_mapping(
        value["generator_artifact_hashes"],
        location=f"{location} generator_artifact_hashes",
        nonempty=True,
    )
    usage = value["usage"]
    if type(usage) is not dict or any(
        type(key) is not str
        or not _SAFE_IDENTIFIER.fullmatch(key)
        or type(amount) is not int
        or amount < 0
        for key, amount in usage.items()
    ):
        raise ValueError(f"{location} usage is invalid")


def _validate_generation_provenance(value: object, *, location: str) -> None:
    if type(value) is not dict or type(value.get("kind")) is not str:
        raise ValueError(f"{location} must distinguish capsule or external provenance")
    if value["kind"] == "external":
        if set(value) != {"kind"}:
            raise ValueError(f"{location} external provenance has an unexpected shape")
        return
    if value["kind"] != "capsule" or set(value) != {
        "kind",
        "capsule_root",
        "generation_record",
        "generation_question",
    }:
        raise ValueError(f"{location} capsule provenance has an unexpected shape")
    capsule_root = value["capsule_root"]
    if type(capsule_root) is not str or re.fullmatch(_HASH_PATTERN, capsule_root) is None:
        raise ValueError(f"{location} capsule_root is invalid")
    generation_question = value["generation_question"]
    if (
        type(generation_question) is not str
        or not generation_question.strip()
        or generation_question != generation_question.strip()
    ):
        raise ValueError(f"{location} generation_question is invalid")
    _validate_generation_record(value["generation_record"], location=f"{location} record")


class RequestedAuthority(StrictModel):
    authority_id: str
    title: str
    jurisdiction: str
    authority_type: str
    source_ids: list[str] = Field(min_length=1)

    _validate_id = field_validator("authority_id")(_safe_identifier)
    _validate_text = field_validator("title", "jurisdiction", "authority_type")(_nonblank)
    _validate_source_ids = field_validator("source_ids")(_unique_identifiers)


class EvaluationSource(StrictModel):
    source_id: str
    title: str
    normalized_text: str
    content_hash: str = Field(pattern=_HASH_PATTERN)
    canonical_url: str | None = None
    publisher: str | None = None
    jurisdiction: str
    authority_type: str
    source_role: SourceRole
    source_quality: SourceQuality
    completeness: Literal["complete", "consolidated", "amending", "partial", "snippet", "unknown"]
    language: str
    version: str | None = None
    effective_date: str | None = None
    supersession: str | None = None
    relationship_ids: list[str] = Field(default_factory=list)

    _validate_id = field_validator("source_id")(_safe_identifier)
    _validate_text = field_validator("title", "jurisdiction", "authority_type", "language")(
        _nonblank
    )
    _validate_normalized_text = field_validator("normalized_text")(_exact_content_nonblank)
    _validate_optional_text = field_validator(
        "canonical_url", "publisher", "version", "effective_date", "supersession"
    )(_optional_nonblank)
    _validate_relationship_ids = field_validator("relationship_ids")(_unique_identifiers)

    @model_validator(mode="after")
    def validate_content_hash(self) -> Self:
        if self.content_hash != _content_hash(self.normalized_text):
            raise ValueError("content_hash must match normalized_text")
        return self


class CandidateReport(StrictModel):
    candidate_id: str
    role: CandidateRole
    report_text: str
    report_hash: str = Field(pattern=_HASH_PATTERN)
    bundle_json: dict[str, object] | None = None
    validation_receipt: dict[str, object] | None = None
    coverage_review: dict[str, object] | None = None

    _validate_id = field_validator("candidate_id")(_safe_identifier)
    _validate_report_text = field_validator("report_text")(_exact_content_nonblank)

    @model_validator(mode="after")
    def validate_report_hash(self) -> Self:
        if self.report_hash != _content_hash(self.report_text):
            raise ValueError("report_hash must match report_text")
        return self

    @property
    def generation_provenance(self) -> dict[str, object] | None:
        """Expose schema-1.1 provenance without changing the legacy wire slot."""
        receipt = self.validation_receipt
        if isinstance(receipt, dict) and receipt.get("kind") in {"capsule", "external"}:
            return receipt
        return None


class AttorneyEvaluationCase(StrictModel):
    schema_version: Literal["1.0", "1.1"] = "1.0"
    case_id: str
    mode: EvaluationMode
    question: str
    jurisdiction: str
    as_of: date
    requested_authorities: list[RequestedAuthority] = Field(min_length=1)
    sources: list[EvaluationSource] = Field(min_length=1)
    candidates: list[CandidateReport] = Field(min_length=1, max_length=2)
    client_facts: str | None = None
    rubric_version: Literal["attorney-eval-v1"] = "attorney-eval-v1"

    _validate_id = field_validator("case_id")(_safe_identifier)
    _validate_text = field_validator("question", "jurisdiction")(_nonblank)
    _validate_client_facts = field_validator("client_facts")(_optional_exact_content_nonblank)

    @model_validator(mode="after")
    def validate_case_integrity(self) -> Self:
        source_ids = [source.source_id for source in self.sources]
        if len(set(source_ids)) != len(source_ids):
            raise ValueError("source_id values must be unique")
        authority_ids = [authority.authority_id for authority in self.requested_authorities]
        if len(set(authority_ids)) != len(authority_ids):
            raise ValueError("authority_id values must be unique")
        requested_source_ids = {
            source_id
            for authority in self.requested_authorities
            for source_id in authority.source_ids
        }
        if not requested_source_ids.issubset(source_ids):
            raise ValueError("requested authority source_ids must identify case sources")
        candidate_ids = [candidate.candidate_id for candidate in self.candidates]
        if len(set(candidate_ids)) != len(candidate_ids):
            raise ValueError("candidate_id values must be unique")
        roles = [candidate.role for candidate in self.candidates]
        if roles.count(CandidateRole.CANDIDATE) != 1:
            raise ValueError("exactly one candidate report is required")
        if roles.count(CandidateRole.COMPARATOR) > 1:
            raise ValueError("at most one comparator report is allowed")
        if self.schema_version == "1.1":
            expected_source_hashes = {
                source.source_id: source.content_hash for source in self.sources
            }
            expected_client_facts_hash = (
                None if self.client_facts is None else _content_hash(self.client_facts)
            )
            for candidate in self.candidates:
                _validate_generation_provenance(
                    candidate.validation_receipt,
                    location=f"candidate {candidate.candidate_id} provenance",
                )
                provenance = candidate.generation_provenance
                if provenance is None or provenance["kind"] == "external":
                    continue
                record = provenance["generation_record"]
                if not isinstance(record, dict):  # guarded above; keeps type narrowing local
                    raise ValueError("capsule generation_record must be an object")
                if record["candidate_id"] != candidate.candidate_id:
                    raise ValueError("capsule candidate_id must match candidate report")
                if record["report_hash"] != candidate.report_hash:
                    raise ValueError("capsule report_hash must match candidate report")
                if record["source_hashes"] != expected_source_hashes:
                    raise ValueError("capsule source_hashes must exactly match case sources")
                if record["client_facts_hash"] != expected_client_facts_hash:
                    raise ValueError("capsule client_facts_hash must match case client facts")
                if provenance["generation_question"] != self.question:
                    raise ValueError("capsule generation_question must match case question")
        return self


class QualificationBuildBinding(StrictModel):
    """Immutable source-build identity sealed into a qualification case."""

    commit: str = Field(pattern=_COMMIT_PATTERN)
    archive_sha256: str = Field(pattern=_HASH_PATTERN)


class QualificationLanguageTreatment(StrictModel):
    """Declared handling for one or more retained source languages."""

    source_ids: list[str] = Field(min_length=1)
    method: str
    rationale: str
    limitations: str | None = None

    _validate_source_ids = field_validator("source_ids")(_unique_identifiers)
    _validate_text = field_validator("method", "rationale")(_nonblank)
    _validate_limitations = field_validator("limitations")(_optional_nonblank)


class QualificationCase(StrictModel):
    """Candidate-free legal source record presented for readiness qualification."""

    schema_version: Literal["1.0", "1.1"] = "1.0"
    case_id: str
    mode: EvaluationMode
    question: str
    jurisdiction: str
    as_of: date
    requested_authorities: list[RequestedAuthority] = Field(min_length=1)
    sources: list[EvaluationSource] = Field(min_length=1)
    build_binding: QualificationBuildBinding | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    language_treatments: list[QualificationLanguageTreatment] = Field(
        default_factory=list,
        exclude_if=lambda value: not value,
    )

    _validate_id = field_validator("case_id")(_safe_identifier)
    _validate_text = field_validator("question", "jurisdiction")(_nonblank)

    @model_validator(mode="after")
    def validate_case_integrity(self) -> Self:
        if self.build_binding is not None:
            QualificationBuildBinding.model_validate(
                self.build_binding.model_dump(mode="python", warnings=False),
                strict=True,
            )
        for treatment in self.language_treatments:
            QualificationLanguageTreatment.model_validate(
                treatment.model_dump(mode="python", warnings=False),
                strict=True,
            )
        source_ids = [source.source_id for source in self.sources]
        if len(set(source_ids)) != len(source_ids):
            raise ValueError("source_id values must be unique")
        authority_ids = [authority.authority_id for authority in self.requested_authorities]
        if len(set(authority_ids)) != len(authority_ids):
            raise ValueError("authority_id values must be unique")
        requested_source_ids = {
            source_id
            for authority in self.requested_authorities
            for source_id in authority.source_ids
        }
        if not requested_source_ids.issubset(source_ids):
            raise ValueError("requested authority source_ids must identify case sources")
        if self.schema_version == "1.0":
            if {"build_binding", "language_treatments"} & self.model_fields_set:
                raise ValueError("schema 1.0 must omit qualification source metadata")
            if self.build_binding is not None or self.language_treatments:
                raise ValueError("schema 1.0 must omit qualification source metadata")
            return self
        if self.build_binding is None:
            raise ValueError("schema 1.1 requires build_binding")
        treated_source_ids = [
            source_id
            for treatment in self.language_treatments
            for source_id in treatment.source_ids
        ]
        if len(treated_source_ids) != len(set(treated_source_ids)):
            raise ValueError("language treatments must identify every source exactly once")
        if set(treated_source_ids) != set(source_ids):
            raise ValueError("language treatments must identify every source exactly once")
        return self


class BlindAssignment(StrictModel):
    anonymous_label: Literal["A", "B"]
    candidate_id: str

    _validate_id = field_validator("candidate_id")(_safe_identifier)


class CaseEnvelope(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    case: AttorneyEvaluationCase
    assignments: list[BlindAssignment]
    case_fingerprint: str = Field(pattern=_HASH_PATTERN)
    seed_fingerprint: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_assignments(self) -> Self:
        if self.case_fingerprint != model_fingerprint(self.case):
            raise ValueError("case_fingerprint must match case")
        labels = [assignment.anonymous_label for assignment in self.assignments]
        candidate_ids = [assignment.candidate_id for assignment in self.assignments]
        expected_ids = {candidate.candidate_id for candidate in self.case.candidates}
        if len(set(labels)) != len(labels):
            raise ValueError("anonymous_label values must be unique")
        if len(set(candidate_ids)) != len(candidate_ids) or set(candidate_ids) != expected_ids:
            raise ValueError("assignments must map every case candidate exactly once")
        return self


class EvaluationIssue(StrictModel):
    code: str
    severity: IssueSeverity
    message: str
    related_ids: list[str] = Field(default_factory=list)

    _validate_code = field_validator("code")(_safe_identifier)
    _validate_message = field_validator("message")(_nonblank)
    _validate_related_ids = field_validator("related_ids")(_unique_identifiers)


class JudgeRequest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    operation: JudgeOperation
    request_fingerprint: str = Field(pattern=_HASH_PATTERN)
    system_instructions: str
    json_schema: dict[str, object]
    payload: dict[str, object]
    safe_metadata: dict[str, str] = Field(default_factory=dict)

    _validate_instructions = field_validator("system_instructions")(_nonblank)


class JudgeResponse(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    operation: JudgeOperation
    request_fingerprint: str = Field(pattern=_HASH_PATTERN)
    provider_name: str
    model_name: str
    judge_isolation: JudgeIsolation
    payload: dict[str, object]
    response_id: str | None = None
    usage: dict[str, int] = Field(default_factory=dict)

    _validate_names = field_validator("provider_name", "model_name")(_nonblank)
    _validate_response_id = field_validator("response_id")(_optional_nonblank)


class EvaluationPreflightIssue(StrictModel):
    code: (
        Literal[
            "EVALUATION_NO_PENDING_REQUEST",
            "EVALUATION_RESPONSE_REQUEST_MISMATCH",
            "EVALUATION_RESPONSE_SCHEMA_INVALID",
        ]
        | ResponseContractCode
    )
    message: str
    related_ids: list[str] = Field(default_factory=list)

    @field_validator("related_ids")
    @classmethod
    def normalize_related_ids(cls, values: list[str]) -> list[str]:
        return sorted({_safe_identifier(value) for value in values})

    @model_validator(mode="after")
    def validate_message(self) -> Self:
        expected = PREFLIGHT_ISSUE_MESSAGES[str(self.code)]
        if self.message != expected:
            raise ValueError("preflight issue message does not match its stable code")
        return self


class EvaluationPreflightResult(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    ok: bool
    operation: JudgeOperation | None
    request_fingerprint: str | None = Field(default=None, pattern=_HASH_PATTERN)
    issues: list[EvaluationPreflightIssue]
    diagnostic_fingerprint: str | None = Field(default=None, pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if self.ok:
            if self.operation is None or self.request_fingerprint is None or self.issues:
                raise ValueError("successful preflight must identify one issue-free request")
        elif not self.issues:
            raise ValueError("failed preflight must contain at least one issue")
        if (self.operation is None) is not (self.request_fingerprint is None):
            raise ValueError("preflight request identity must be complete or absent")
        if self.ok and self.diagnostic_fingerprint is not None:
            raise ValueError("successful preflight must not have a diagnostic fingerprint")
        if (
            not self.ok
            and self.request_fingerprint is not None
            and self.diagnostic_fingerprint is None
        ):
            raise ValueError("failed pending preflight requires a diagnostic fingerprint")
        if (
            not self.ok
            and self.request_fingerprint is None
            and self.diagnostic_fingerprint is not None
        ):
            raise ValueError("terminal preflight must not have a diagnostic fingerprint")
        return self


class AdmissionCheck(StrictModel):
    code: Literal[
        "AUTHORITY_ALIGNMENT",
        "OPERATIVE_TEXT",
        "CURRENTNESS_EVIDENCE",
        "LANGUAGE_RESOLUTION",
        "SOURCE_PARITY",
    ]
    satisfied: bool
    material: bool
    rationale: str
    source_ids: list[str] = Field(default_factory=list)

    _validate_code = field_validator("code")(_safe_identifier)
    _validate_rationale = field_validator("rationale")(_nonblank)
    _validate_source_ids = field_validator("source_ids")(_unique_identifiers)


class CaseAdmissionJudgment(StrictModel):
    request_fingerprint: str = Field(pattern=_HASH_PATTERN)
    checks: list[AdmissionCheck]
    issues: list[EvaluationIssue] = Field(default_factory=list)


class CaseReadiness(StrictModel):
    status: ReadinessStatus
    case_fingerprint: str = Field(pattern=_HASH_PATTERN)
    judgment_fingerprint: str = Field(pattern=_HASH_PATTERN)
    issue_codes: list[str] = Field(default_factory=list)
    rationale: str

    _validate_issue_codes = field_validator("issue_codes")(_unique_identifiers)
    _validate_rationale = field_validator("rationale")(_nonblank)


class QualificationReceipt(StrictModel):
    """Immutable receipt for the sole source-readiness judgment."""

    schema_version: Literal["1.0"] = "1.0"
    case_fingerprint: str = Field(pattern=_HASH_PATTERN)
    source_record_fingerprint: str = Field(pattern=_HASH_PATTERN)
    request_fingerprint: str = Field(pattern=_HASH_PATTERN)
    judgment_fingerprint: str = Field(pattern=_HASH_PATTERN)
    readiness: CaseReadiness
    receipt_fingerprint: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_receipt_binding(self) -> Self:
        if self.readiness.status not in {
            ReadinessStatus.ADMITTED,
            ReadinessStatus.CASE_INVALID,
        }:
            raise ValueError(
                "qualification terminal readiness must be ADMITTED or CASE_INVALID"
            )
        if self.readiness.case_fingerprint != self.case_fingerprint:
            raise ValueError("qualification readiness must bind the qualified case")
        if self.readiness.judgment_fingerprint != self.judgment_fingerprint:
            raise ValueError("qualification readiness must bind the judgment")
        expected = model_fingerprint(self, exclude={"receipt_fingerprint"})
        if self.receipt_fingerprint != expected:
            raise ValueError("receipt_fingerprint must match the qualification receipt")
        return self


class QualificationState(StrictModel):
    """Replay-verified cursor for a source qualification capsule."""

    schema_version: Literal["1.0"] = "1.0"
    case_fingerprint: str = Field(pattern=_HASH_PATTERN)
    source_record_fingerprint: str = Field(pattern=_HASH_PATTERN)
    request_fingerprint: str = Field(pattern=_HASH_PATTERN)
    status: Literal["awaiting-judgment", "qualified", "case-invalid"]
    receipt_fingerprint: str | None = Field(default=None, pattern=_HASH_PATTERN)
    root_hash: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_terminal_receipt(self) -> Self:
        terminal = self.status in {"qualified", "case-invalid"}
        if terminal != (self.receipt_fingerprint is not None):
            raise ValueError("terminal qualification state must bind one receipt")
        return self


class QualificationVerification(StrictModel):
    """Bounded result of replaying a complete qualification capsule."""

    valid: bool
    issues: tuple[str, ...] = ()
    root_hash: str | None = Field(default=None, pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_verification_result(self) -> Self:
        if self.valid:
            if self.issues or self.root_hash is None:
                raise ValueError("valid qualification verification requires only a root hash")
        elif not self.issues or self.root_hash is not None:
            raise ValueError("invalid qualification verification requires bounded issues")
        return self


class QualificationSubmissionResult(StrictModel):
    """No-write guard result for one prospective qualification judgment."""

    schema_version: Literal["1.0"] = "1.0"
    accepted: bool
    preflight: EvaluationPreflightResult
    receipt: QualificationReceipt | None = None

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if self.accepted != self.preflight.ok:
            raise ValueError("qualification acceptance must match preflight")
        if self.accepted != (self.receipt is not None):
            raise ValueError("accepted qualification requires one receipt")
        return self


class LedgerCitation(StrictModel):
    source_id: str
    start_char: int = Field(ge=0)
    end_char: int = Field(gt=0)
    quote: str

    _validate_source_id = field_validator("source_id")(_safe_identifier)
    _validate_quote = field_validator("quote")(_nonblank)

    @model_validator(mode="after")
    def validate_offsets(self) -> Self:
        if self.end_char <= self.start_char:
            raise ValueError("end_char must be greater than start_char")
        return self


class LedgerEntry(StrictModel):
    ledger_id: str
    walk_order: int = Field(ge=0)
    category: LedgerCategory
    materiality: Materiality
    actor: str | None = None
    modality: str
    operative_action: str
    object: str | None = None
    trigger: str | None = None
    threshold: str | None = None
    conditions: list[str] = Field(default_factory=list)
    exceptions: list[str] = Field(default_factory=list)
    timing: str | None = None
    enforcing_authority: str | None = None
    enforcement_route: str | None = None
    consequence: str | None = None
    relationship_ids: list[str] = Field(default_factory=list)
    proposition: str
    materiality_rationale: str
    citations: list[LedgerCitation] = Field(min_length=1)

    _validate_id = field_validator("ledger_id")(_safe_identifier)
    _validate_required_text = field_validator(
        "modality", "operative_action", "proposition", "materiality_rationale"
    )(_nonblank)
    _validate_optional_text = field_validator(
        "actor",
        "object",
        "trigger",
        "threshold",
        "timing",
        "enforcing_authority",
        "enforcement_route",
        "consequence",
    )(_optional_nonblank)
    _validate_relationship_ids = field_validator("relationship_ids")(_unique_identifiers)
    _validate_conditions = field_validator("conditions", "exceptions")(
        lambda values: [_nonblank(value) for value in values]
    )


class LedgerGap(StrictModel):
    gap_id: str
    category: LedgerCategory
    message: str
    source_ids: list[str] = Field(default_factory=list)

    _validate_id = field_validator("gap_id")(_safe_identifier)
    _validate_message = field_validator("message")(_nonblank)
    _validate_source_ids = field_validator("source_ids")(_unique_identifiers)


class LegalLedger(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    case_fingerprint: str = Field(pattern=_HASH_PATTERN)
    entries: list[LedgerEntry]
    gaps: list[LedgerGap] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_unique_ids(self) -> Self:
        ledger_ids = [entry.ledger_id for entry in self.entries]
        gap_ids = [gap.gap_id for gap in self.gaps]
        if len(set(ledger_ids)) != len(ledger_ids):
            raise ValueError("ledger_id values must be unique")
        if len(set(gap_ids)) != len(gap_ids):
            raise ValueError("gap_id values must be unique")
        return self


class LedgerDispute(StrictModel):
    dispute_id: str
    action: Literal["add", "edit", "delete", "split", "merge", "materiality"]
    target_ledger_ids: list[str] = Field(default_factory=list)
    proposed_entries: list[LedgerEntry] = Field(default_factory=list)
    materiality: Materiality
    rationale: str

    _validate_id = field_validator("dispute_id")(_safe_identifier)
    _validate_targets = field_validator("target_ledger_ids")(_unique_identifiers)
    _validate_rationale = field_validator("rationale")(_nonblank)


class LedgerAudit(StrictModel):
    request_fingerprint: str = Field(pattern=_HASH_PATTERN)
    disputes: list[LedgerDispute] = Field(default_factory=list)
    complete: bool


class SealedLedger(StrictModel):
    ledger: LegalLedger
    audit_fingerprint: str = Field(pattern=_HASH_PATTERN)
    ledger_fingerprint: str = Field(pattern=_HASH_PATTERN)


class EntryGrade(StrictModel):
    ledger_id: str
    disposition: CoverageDisposition
    rationale: str
    report_location: str | None = None
    report_passage: str | None
    finding_codes: list[EntryFindingCode] = Field(default_factory=list)

    _validate_id = field_validator("ledger_id")(_safe_identifier)
    _validate_rationale = field_validator("rationale")(_nonblank)
    _validate_location = field_validator("report_location")(_optional_nonblank)
    _validate_passage = field_validator("report_passage")(_optional_nonblank)

    @model_validator(mode="after")
    def validate_report_passage_cardinality(self) -> Self:
        if self.disposition is CoverageDisposition.MISSING:
            if self.report_passage is not None:
                raise ValueError("missing entry grades must omit report_passage")
        elif self.report_passage is None:
            raise ValueError("nonmissing entry grades require report_passage")
        return self


class OutOfLedgerClaim(StrictModel):
    claim_id: str
    claim_text: str
    report_location: str
    disposition: CoverageDisposition
    category: LedgerCategory
    materiality: Materiality
    related_ledger_ids: list[str] = Field(default_factory=list)
    source_record_fingerprint: str = Field(pattern=_HASH_PATTERN)
    evidence_basis: Literal["source_spans", "closed_universe_absence"]
    evidence_spans: list[LedgerCitation]
    rationale: str

    _validate_id = field_validator("claim_id")(_safe_identifier)
    _validate_text = field_validator("claim_text", "report_location", "rationale")(_nonblank)
    _validate_related_ids = field_validator("related_ledger_ids")(_unique_identifiers)

    @model_validator(mode="after")
    def validate_evidence_basis(self) -> Self:
        if (
            self.evidence_basis == "closed_universe_absence"
            and self.disposition is not CoverageDisposition.UNSUPPORTED
        ):
            raise ValueError(
                "closed-universe absence is valid only for the UNSUPPORTED disposition"
            )
        if self.disposition in {
            CoverageDisposition.COMPLETE,
            CoverageDisposition.PARTIAL,
        } and self.evidence_basis != "source_spans":
            raise ValueError("positive-credit dispositions require source_spans evidence basis")
        if self.evidence_basis == "source_spans" and not self.evidence_spans:
            raise ValueError("source_spans evidence basis requires evidence_spans")
        if self.evidence_basis == "closed_universe_absence" and self.evidence_spans:
            raise ValueError("closed-universe absence must not claim positive source spans")
        identities = [
            (span.source_id, span.start_char, span.end_char, span.quote)
            for span in self.evidence_spans
        ]
        if len(identities) != len(set(identities)):
            raise ValueError("evidence_spans must be unique")
        return self


class NarrativeScore(StrictModel):
    dimension: Literal[
        "executive_summary",
        "regulatory_walk",
        "key_requirements",
        "penalties_enforcement",
        "qualification_placement",
        "requirements_workplan_boundary",
        "limitations",
        "scanability",
    ]
    score: int = Field(ge=1, le=4)
    rationale: str
    report_passage: str
    finding_codes: list[NarrativeFindingCode] = Field(default_factory=list)

    _validate_rationale = field_validator("rationale", "report_passage")(_nonblank)


class CandidateGrade(StrictModel):
    schema_version: Literal["1.3"] = EVALUATION_ARTIFACT_SCHEMA_VERSION
    request_fingerprint: str = Field(pattern=_HASH_PATTERN)
    anonymous_label: Literal["A", "B"]
    ledger_fingerprint: str = Field(pattern=_HASH_PATTERN)
    entry_grades: list[EntryGrade]
    out_of_ledger_claims: list[OutOfLedgerClaim] = Field(default_factory=list)
    narrative_scores: list[NarrativeScore]

    @model_validator(mode="after")
    def validate_unique_grade_ids(self) -> Self:
        entry_ids = [grade.ledger_id for grade in self.entry_grades]
        claim_ids = [claim.claim_id for claim in self.out_of_ledger_claims]
        if len(set(entry_ids)) != len(entry_ids):
            raise ValueError("ledger_id values must be unique")
        if len(set(claim_ids)) != len(claim_ids):
            raise ValueError("claim_id values must be unique")
        return self


class GradeAlternative(StrictModel):
    request_fingerprint: str = Field(pattern=_HASH_PATTERN)
    entry_grade: EntryGrade | None = None
    out_of_ledger_claim: OutOfLedgerClaim | None = None
    narrative_score: NarrativeScore | None = None
    absent_claim: bool = False

    @model_validator(mode="after")
    def validate_alternative_cardinality(self) -> Self:
        payload_count = sum(
            value is not None
            for value in (
                self.entry_grade,
                self.out_of_ledger_claim,
                self.narrative_score,
            )
        )
        if self.absent_claim:
            if payload_count:
                raise ValueError("absent_claim cannot include an alternative payload")
        elif payload_count != 1:
            raise ValueError("exactly one alternative payload is required")
        return self


class GradeDispute(StrictModel):
    dispute_id: str
    anonymous_label: Literal["A", "B"]
    ledger_fingerprint: str = Field(pattern=_HASH_PATTERN)
    kind: Literal["entry_grade", "out_of_ledger_claim", "narrative_score"]
    subject_id: str
    materiality: Materiality | None = None
    grader_1: GradeAlternative
    grader_2: GradeAlternative
    rationale: str

    _validate_ids = field_validator("dispute_id", "subject_id")(_safe_identifier)
    _validate_rationale = field_validator("rationale")(_nonblank)

    @model_validator(mode="after")
    def validate_dispute_alternatives(self) -> Self:
        alternatives = (self.grader_1, self.grader_2)
        if self.kind == "entry_grade":
            if self.materiality is None:
                raise ValueError("entry_grade disputes require materiality")
            if any(alternative.entry_grade is None for alternative in alternatives):
                raise ValueError("entry_grade disputes require two entry_grade alternatives")
            if any(
                alternative.entry_grade is not None
                and alternative.entry_grade.ledger_id != self.subject_id
                for alternative in alternatives
            ):
                raise ValueError("entry_grade ledger_id must match subject_id")
        elif self.kind == "out_of_ledger_claim":
            if self.materiality is None:
                raise ValueError("out_of_ledger_claim disputes require materiality")
            if any(
                not alternative.absent_claim and alternative.out_of_ledger_claim is None
                for alternative in alternatives
            ):
                raise ValueError(
                    "out_of_ledger_claim alternatives must carry a claim or explicit absence"
                )
            claims = [
                alternative.out_of_ledger_claim
                for alternative in alternatives
                if alternative.out_of_ledger_claim is not None
            ]
            if not claims:
                raise ValueError("at least one out_of_ledger_claim alternative must be present")
            if any(claim.claim_id != self.subject_id for claim in claims):
                raise ValueError("out_of_ledger_claim claim_id must match subject_id")
            maximum_materiality = max(
                (claim.materiality for claim in claims),
                key=_MATERIALITY_RANK.__getitem__,
            )
            if self.materiality != maximum_materiality:
                raise ValueError(
                    "out_of_ledger_claim materiality must equal maximum present claim materiality"
                )
        else:
            if self.materiality is not None:
                raise ValueError("narrative_score disputes must omit materiality")
            if any(alternative.narrative_score is None for alternative in alternatives):
                raise ValueError(
                    "narrative_score disputes require two narrative_score alternatives"
                )
            if any(
                alternative.narrative_score is not None
                and alternative.narrative_score.dimension != self.subject_id
                for alternative in alternatives
            ):
                raise ValueError("narrative_score dimension must match subject_id")
        return self


class RefereeDecision(StrictModel):
    dispute_id: str
    selected_disposition: CoverageDisposition | None = None
    selected_ledger_resolution: Literal["accept_a", "accept_b", "replace"] | None = None
    replacement_entries: list[LedgerEntry] = Field(default_factory=list)
    selected_grade_resolution: Literal["accept_grader_1", "accept_grader_2", "replace"] | None = (
        None
    )
    grade_dispute_fingerprint: str | None = Field(default=None, pattern=_HASH_PATTERN)
    replacement_grade_alternative: GradeAlternative | None = None
    rationale: str
    source_ids: list[str] = Field(default_factory=list)

    _validate_id = field_validator("dispute_id")(_safe_identifier)
    _validate_rationale = field_validator("rationale")(_nonblank)
    _validate_source_ids = field_validator("source_ids")(_unique_identifiers)

    @model_validator(mode="after")
    def validate_grade_replacement(self) -> Self:
        if self.selected_grade_resolution is not None:
            if self.grade_dispute_fingerprint is None:
                raise ValueError("grade resolution requires dispute fingerprint")
        elif self.grade_dispute_fingerprint is not None:
            raise ValueError("dispute fingerprint requires grade resolution")
        if self.selected_grade_resolution == "replace":
            if self.replacement_grade_alternative is None:
                raise ValueError("replace grade resolution requires a replacement alternative")
        elif self.replacement_grade_alternative is not None:
            raise ValueError("replacement grade alternative requires replace resolution")
        return self


class DeterministicChecks(StrictModel):
    anonymous_label: Literal["A", "B"]
    valid: bool
    critical_codes: list[str] = Field(default_factory=list)
    issues: list[EvaluationIssue] = Field(default_factory=list)

    _validate_critical_codes = field_validator("critical_codes")(_unique_identifiers)


class EvaluationRubric(StrictModel):
    version: Literal["attorney-eval-v1"]
    materiality_weights: dict[Materiality, int]
    critical_recall_floor: float
    weighted_recall_floor: float
    claim_precision_floor: float
    walk_average_floor: float
    walk_dimension_floor: int
    comparison_weights: dict[Literal["recall", "precision", "walk"], float]
    comparison_margin: float


class ReportEvaluation(StrictModel):
    schema_version: Literal["1.3"] = EVALUATION_ARTIFACT_SCHEMA_VERSION
    anonymous_label: Literal["A", "B"]
    absolute_disposition: AbsoluteDisposition
    critical_recall: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    weighted_recall: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    claim_precision: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    walk_average: float = Field(ge=1.0, le=4.0, allow_inf_nan=False)
    walk_minimum: int = Field(ge=1, le=4, strict=True)
    normalized_score: float = Field(ge=0.0, le=100.0, allow_inf_nan=False)
    critical_defect: bool
    issue_codes: list[str] = Field(default_factory=list)
    blocking_codes: list[str] = Field(default_factory=list)
    ledger_fingerprint: str = Field(pattern=_HASH_PATTERN)
    resolved_grade_fingerprint: str = Field(pattern=_HASH_PATTERN)
    deterministic_checks_fingerprint: str = Field(pattern=_HASH_PATTERN)
    rubric_fingerprint: str = Field(pattern=_HASH_PATTERN)
    score_fingerprint: str = Field(pattern=_HASH_PATTERN)

    _validate_codes = field_validator("issue_codes", "blocking_codes")(_unique_identifiers)

    @model_validator(mode="after")
    def validate_score_fingerprint(self) -> Self:
        score_payload = self.model_dump(mode="json", exclude={"score_fingerprint"})
        expected = hashlib.sha256(canonical_json_bytes(score_payload)).hexdigest()
        if self.score_fingerprint != expected:
            raise ValueError("score_fingerprint must match score snapshot")
        return self


class ComparisonEvaluation(StrictModel):
    disposition: ComparativeDisposition
    winner_label: Literal["A", "B"] | None = None
    score_difference: float | None = None
    rationale_codes: list[str] = Field(default_factory=list)

    _validate_codes = field_validator("rationale_codes")(_unique_identifiers)


class RequirementCitationPin(StrictModel):
    source_id: str
    start_char: int = Field(ge=0)
    end_char: int = Field(gt=0)

    _validate_source_id = field_validator("source_id")(_safe_identifier)

    @model_validator(mode="after")
    def validate_offsets(self) -> Self:
        if self.end_char <= self.start_char:
            raise ValueError("end_char must be greater than start_char")
        return self


class RequirementReportFinding(StrictModel):
    anonymous_label: Literal["A", "B"]
    disposition: CoverageDisposition
    report_location: str | None = None
    finding_codes: list[EntryFindingCode] = Field(default_factory=list)
    rationale: str

    _validate_location = field_validator("report_location")(_optional_nonblank)
    _validate_rationale = field_validator("rationale")(_nonblank)


class RequirementMatrixRow(StrictModel):
    ledger_id: str
    walk_order: int = Field(ge=0)
    category: LedgerCategory
    materiality: Materiality
    proposition: str
    citations: list[RequirementCitationPin] = Field(min_length=1)
    report_a: RequirementReportFinding
    report_b: RequirementReportFinding | None = None

    _validate_ledger_id = field_validator("ledger_id")(_safe_identifier)
    _validate_proposition = field_validator("proposition")(_nonblank)

    @model_validator(mode="after")
    def validate_report_labels(self) -> Self:
        if self.report_a.anonymous_label != "A":
            raise ValueError("report_a must use anonymous label A")
        if self.report_b is not None and self.report_b.anonymous_label != "B":
            raise ValueError("report_b must use anonymous label B")
        return self


class RequirementMatrix(StrictModel):
    available: bool
    unavailable_reason: Literal["CASE_INVALID", "INCONCLUSIVE"] | None = None
    rows: list[RequirementMatrixRow]

    @model_validator(mode="after")
    def validate_availability(self) -> Self:
        if self.available:
            if self.unavailable_reason is not None:
                raise ValueError("available matrix must omit unavailable_reason")
            walk_orders = [row.walk_order for row in self.rows]
            ledger_ids = [row.ledger_id for row in self.rows]
            if walk_orders != list(range(len(walk_orders))):
                raise ValueError("available matrix rows must use contiguous zero-based walk order")
            if len(ledger_ids) != len(set(ledger_ids)):
                raise ValueError("available matrix rows must use unique ledger IDs")
        elif self.unavailable_reason is None:
            raise ValueError("unavailable matrix must identify its reason")
        elif self.rows:
            raise ValueError("unavailable matrix must not contain rows")
        return self


class AttorneyEvaluationResult(StrictModel):
    schema_version: Literal["1.3"] = EVALUATION_ARTIFACT_SCHEMA_VERSION
    rubric: EvaluationRubric
    readiness: CaseReadiness
    reports: list[ReportEvaluation]
    requirement_matrix: RequirementMatrix
    comparison: ComparisonEvaluation | None = None
    judge_isolation: Literal["fresh_context", "sequential_same_context"]
    result_fingerprint: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_matrix_availability(self) -> Self:
        if self.reports and not self.requirement_matrix.available:
            raise ValueError("scored reports require an available requirement matrix")
        if not self.reports and self.requirement_matrix.available:
            raise ValueError("an unscored result cannot expose a requirement matrix")
        if self.reports:
            labels = [report.anonymous_label for report in self.reports]
            if labels not in (["A"], ["A", "B"]):
                raise ValueError("scored report labels must be unique fixed order A or A, B")
            if self.readiness.status is not ReadinessStatus.ADMITTED:
                raise ValueError("scored reports require admitted readiness")
            has_report_b = len(labels) == 2
            if any(
                (row.report_b is not None) != has_report_b
                for row in self.requirement_matrix.rows
            ):
                raise ValueError("matrix report_b presence must match scored report B")
        if not self.requirement_matrix.available:
            expected = self.readiness.status.value
            if self.requirement_matrix.unavailable_reason != expected:
                raise ValueError("matrix unavailability must match terminal readiness")
        return self


class JudgeCallRecord(StrictModel):
    call_id: str = Field(strict=True)
    operation: JudgeOperation
    anonymous_label: Literal["A", "B"] | None = None
    attempt: int = Field(ge=1, strict=True)
    prompt_fingerprint: str = Field(pattern=_HASH_PATTERN, strict=True)
    request_fingerprint: str = Field(pattern=_HASH_PATTERN, strict=True)
    response_fingerprint: str | None = Field(
        default=None,
        pattern=_HASH_PATTERN,
        strict=True,
    )
    provider_name: str | None = Field(default=None, strict=True)
    model_name: str | None = Field(default=None, strict=True)
    judge_isolation: JudgeIsolation | None = None
    request_artifact_path: str = Field(strict=True)
    response_artifact_path: str | None = Field(default=None, strict=True)
    diagnostics_artifact_path: str | None = Field(default=None, strict=True)
    state: Literal["pending", "completed", "failed"]
    retry_count: int = Field(ge=0, strict=True)
    terminal_status: Literal["pending", "completed", "failed", "inconclusive", "case_invalid"]

    _validate_call_id = field_validator("call_id")(_safe_identifier)
    _validate_optional_names = field_validator("provider_name", "model_name")(_optional_nonblank)
    _validate_request_path = field_validator("request_artifact_path")(_safe_relative_path)
    _validate_optional_paths = field_validator(
        "response_artifact_path", "diagnostics_artifact_path"
    )(_optional_safe_relative_path)

    @model_validator(mode="after")
    def validate_call_provenance(self) -> Self:
        if self.operation is JudgeOperation.GRADE_REPORT:
            if self.anonymous_label is None:
                raise ValueError("grade_report calls require anonymous_label")
        elif self.anonymous_label is not None and self.operation is not JudgeOperation.REFEREE:
            raise ValueError("anonymous_label is permitted only for grade_report or referee")

        response_provenance = (
            self.response_fingerprint,
            self.provider_name,
            self.model_name,
            self.judge_isolation,
            self.response_artifact_path,
        )
        if self.state == "pending":
            if any(value is not None for value in response_provenance):
                raise ValueError("pending calls must omit response provenance")
            if self.diagnostics_artifact_path is not None:
                raise ValueError("pending calls must omit diagnostics")
            if self.terminal_status != "pending":
                raise ValueError("pending calls require pending terminal_status")
        elif self.state == "completed":
            if any(value is None for value in response_provenance):
                raise ValueError("completed calls require complete response provenance")
            if self.diagnostics_artifact_path is not None:
                raise ValueError("completed calls must omit diagnostics")
            if self.terminal_status != "completed":
                raise ValueError("completed calls require completed terminal_status")
        else:
            if any(value is None for value in response_provenance):
                raise ValueError("failed calls require complete response provenance")
            if self.diagnostics_artifact_path is None:
                raise ValueError("failed calls require diagnostics")
            if self.terminal_status not in {"failed", "inconclusive"}:
                raise ValueError("failed calls require failed or inconclusive terminal_status")
        return self


class ArtifactRecord(StrictModel):
    artifact_path: str = Field(strict=True)
    artifact_hash: str = Field(pattern=_HASH_PATTERN, strict=True)

    _validate_path = field_validator("artifact_path")(_safe_relative_path)


class QualificationCallRecord(StrictModel):
    """The sole pending or completed judgment in a qualification capsule."""

    operation: Literal["admit_case"] = "admit_case"
    request_fingerprint: str = Field(pattern=_HASH_PATTERN, strict=True)
    request_artifact_path: Literal["admission-request.json"] = "admission-request.json"
    judgment_fingerprint: str | None = Field(
        default=None,
        pattern=_HASH_PATTERN,
        strict=True,
    )
    response_artifact_path: Literal["admission-response.json"] | None = None
    state: Literal["pending", "completed"]

    @model_validator(mode="after")
    def validate_call_state(self) -> Self:
        completed = self.state == "completed"
        if completed != (self.judgment_fingerprint is not None):
            raise ValueError("completed qualification call must bind one judgment")
        if completed != (self.response_artifact_path is not None):
            raise ValueError("completed qualification call must bind one response artifact")
        return self


class QualificationManifest(StrictModel):
    """Minimal allowlisted inventory and root for one qualification capsule."""

    schema_version: Literal["1.0"] = "1.0"
    nonce_fingerprint: str = Field(pattern=_HASH_PATTERN, strict=True)
    case_fingerprint: str = Field(pattern=_HASH_PATTERN, strict=True)
    source_record_fingerprint: str = Field(pattern=_HASH_PATTERN, strict=True)
    call: QualificationCallRecord
    artifacts: list[ArtifactRecord]
    status: Literal["awaiting-judgment", "qualified", "case-invalid"]
    receipt_fingerprint: str | None = Field(default=None, pattern=_HASH_PATTERN, strict=True)
    root_hash: str = Field(pattern=_HASH_PATTERN, strict=True)

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        _strictly_revalidate_artifacts(self.artifacts)
        paths = [artifact.artifact_path for artifact in self.artifacts]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ValueError("qualification artifacts must be uniquely path-sorted")
        expected_paths = {
            "admission-request.json",
            "qualification-case.json",
        }
        terminal = self.status in {"qualified", "case-invalid"}
        if terminal:
            expected_paths.update(
                {"admission-response.json", "qualification-receipt.json"}
            )
        if set(paths) != expected_paths:
            raise ValueError("qualification manifest contains an invalid artifact inventory")
        if terminal != (self.call.state == "completed"):
            raise ValueError("qualification call state must match manifest status")
        if terminal != (self.receipt_fingerprint is not None):
            raise ValueError("terminal qualification manifest must bind one receipt")
        payload = self.model_dump(mode="json", exclude={"root_hash"})
        expected_root = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
        if self.root_hash != expected_root:
            raise ValueError("root_hash must match the qualification manifest")
        return self


def _strictly_revalidate_judge_calls(judge_calls: list[JudgeCallRecord]) -> None:
    for call in judge_calls:
        JudgeCallRecord.model_validate(
            call.model_dump(mode="python", warnings=False),
            strict=True,
        )


def _strictly_revalidate_artifacts(artifacts: list[ArtifactRecord]) -> None:
    for artifact in artifacts:
        ArtifactRecord.model_validate(
            artifact.model_dump(mode="python", warnings=False),
            strict=True,
        )


def _validate_judge_call_identities(judge_calls: list[JudgeCallRecord]) -> None:
    attempts: set[tuple[str, int]] = set()
    logical_context: dict[str, tuple[JudgeOperation, Literal["A", "B"] | None]] = {}
    for call in judge_calls:
        attempt_identity = (call.call_id, call.attempt)
        if attempt_identity in attempts:
            raise ValueError("judge call (call_id, attempt) values must be unique")
        attempts.add(attempt_identity)
        context = (call.operation, call.anonymous_label)
        previous = logical_context.setdefault(call.call_id, context)
        if previous != context:
            raise ValueError("attempts sharing call_id must retain operation and label")


def _validate_phase_terminal_status(
    state: EvaluationRunPhase,
    terminal_status: EvaluationTerminalStatus | None,
) -> None:
    expected = _TERMINAL_PHASE_STATUS.get(state)
    if expected is None:
        if terminal_status is not None:
            raise ValueError("nonterminal phase must omit terminal_status")
    elif terminal_status is not expected:
        raise ValueError("terminal phase and terminal_status must match")


class EvaluationManifest(StrictModel):
    schema_version: Literal["1.3"] = EVALUATION_ARTIFACT_SCHEMA_VERSION
    case_fingerprint: str = Field(pattern=_HASH_PATTERN, strict=True)
    case_envelope_hash: str = Field(pattern=_HASH_PATTERN, strict=True)
    rubric_fingerprint: str = Field(pattern=_HASH_PATTERN, strict=True)
    legal_ledger_hash: str | None = Field(
        default=None,
        pattern=_HASH_PATTERN,
        strict=True,
    )
    result_hash: str | None = Field(
        default=None,
        pattern=_HASH_PATTERN,
        strict=True,
    )
    judge_calls: list[JudgeCallRecord] = Field(default_factory=list)
    artifacts: list[ArtifactRecord] = Field(default_factory=list)
    artifact_inventory_fingerprint: str = Field(pattern=_HASH_PATTERN, strict=True)
    state: EvaluationRunPhase
    retry_count: int = Field(ge=0, strict=True)
    terminal_status: EvaluationTerminalStatus | None = None
    manifest_fingerprint: str = Field(pattern=_HASH_PATTERN, strict=True)

    @model_validator(mode="after")
    def validate_manifest_provenance(self) -> Self:
        _strictly_revalidate_judge_calls(self.judge_calls)
        _strictly_revalidate_artifacts(self.artifacts)
        artifact_paths = [artifact.artifact_path for artifact in self.artifacts]
        if artifact_paths != sorted(artifact_paths):
            raise ValueError("artifacts must be sorted by artifact_path")
        if len(set(artifact_paths)) != len(artifact_paths):
            raise ValueError("artifact_path values must be unique")
        if "run-manifest.json" in artifact_paths:
            raise ValueError("run-manifest.json must not record itself")

        artifact_payload = [artifact.model_dump(mode="json") for artifact in self.artifacts]
        expected_inventory = hashlib.sha256(canonical_json_bytes(artifact_payload)).hexdigest()
        if self.artifact_inventory_fingerprint != expected_inventory:
            raise ValueError("artifact_inventory_fingerprint must match artifacts")

        _validate_judge_call_identities(self.judge_calls)
        for call in self.judge_calls:
            for artifact_path in (
                call.request_artifact_path,
                call.response_artifact_path,
                call.diagnostics_artifact_path,
            ):
                if artifact_path is not None and artifact_paths.count(artifact_path) != 1:
                    raise ValueError("every judge call artifact path must exist exactly once")

        completed_grades: dict[Literal["A", "B"], list[JudgeCallRecord]] = {
            "A": [],
            "B": [],
        }
        for call in self.judge_calls:
            if call.operation is JudgeOperation.GRADE_REPORT and call.state == "completed":
                if call.anonymous_label is None:
                    raise ValueError("completed grade_report calls require anonymous_label")
                completed_grades[call.anonymous_label].append(call)
        for calls in completed_grades.values():
            call_ids = [call.call_id for call in calls]
            response_fingerprints = [call.response_fingerprint for call in calls]
            if len(set(call_ids)) != len(call_ids):
                raise ValueError("completed grades for one label require distinct call_id values")
            if len(set(response_fingerprints)) != len(response_fingerprints):
                raise ValueError(
                    "completed grades for one label require distinct response fingerprints"
                )

        _validate_phase_terminal_status(self.state, self.terminal_status)
        if self.state in _TERMINAL_PHASE_STATUS and any(
            call.state == "pending" for call in self.judge_calls
        ):
            raise ValueError("terminal manifests must not retain pending judge calls")
        if self.state in _PRE_LEDGER_PHASES and self.legal_ledger_hash is not None:
            raise ValueError("pre-seal phases must omit legal_ledger_hash")
        if self.state in _POST_LEDGER_PHASES and self.legal_ledger_hash is None:
            raise ValueError("sealed-ledger phases require legal_ledger_hash")
        if self.state is EvaluationRunPhase.CASE_INVALID and self.legal_ledger_hash is not None:
            raise ValueError("case-invalid manifests must omit legal_ledger_hash")
        if self.state not in _TERMINAL_PHASE_STATUS and self.result_hash is not None:
            raise ValueError("nonterminal phases must omit result_hash")
        if self.state is EvaluationRunPhase.COMPLETED and self.result_hash is None:
            raise ValueError("completed manifests require result_hash")

        manifest_payload = self.model_dump(mode="json", exclude={"manifest_fingerprint"})
        expected_manifest = hashlib.sha256(canonical_json_bytes(manifest_payload)).hexdigest()
        if self.manifest_fingerprint != expected_manifest:
            raise ValueError("manifest_fingerprint must match manifest snapshot")
        return self


class EvaluationRunState(StrictModel):
    schema_version: Literal["1.3"] = EVALUATION_ARTIFACT_SCHEMA_VERSION
    case_fingerprint: str = Field(pattern=_HASH_PATTERN, strict=True)
    case_envelope_hash: str = Field(pattern=_HASH_PATTERN, strict=True)
    judge_calls: list[JudgeCallRecord]
    current_operation: JudgeOperation | None = None
    current_call_id: str | None = Field(strict=True)
    attempt: int = Field(ge=0, strict=True)
    state: EvaluationRunPhase
    retry_count: int = Field(ge=0, strict=True)
    terminal_status: EvaluationTerminalStatus | None = None
    manifest_fingerprint: str | None = Field(
        default=None,
        pattern=_HASH_PATTERN,
        strict=True,
    )

    _validate_current_call_id = field_validator("current_call_id")(_optional_safe_identifier)

    @model_validator(mode="after")
    def validate_run_state_structure(self) -> Self:
        _strictly_revalidate_judge_calls(self.judge_calls)
        _validate_judge_call_identities(self.judge_calls)
        _validate_phase_terminal_status(self.state, self.terminal_status)

        if (self.current_operation is None) != (self.current_call_id is None):
            raise ValueError("current_operation and current_call_id must be paired")
        pending_calls = [call for call in self.judge_calls if call.state == "pending"]
        expected_pending_count = 1 if self.current_call_id is not None else 0
        if len(pending_calls) != expected_pending_count:
            raise ValueError("pending judge calls must match the exact current cursor")
        if self.state in _TERMINAL_PHASE_STATUS and (
            self.current_operation is not None or self.current_call_id is not None
        ):
            raise ValueError("terminal states must not retain a current call")
        if self.state is EvaluationRunPhase.CREATED:
            if self.attempt != 0:
                raise ValueError("created state requires attempt zero")
            if self.current_operation is not None or self.current_call_id is not None:
                raise ValueError("created state must not retain a current call")

        if self.current_call_id is not None:
            current_calls = [
                call
                for call in self.judge_calls
                if call.call_id == self.current_call_id and call.attempt == self.attempt
            ]
            if len(current_calls) != 1:
                raise ValueError("current call ID and attempt must resolve exactly once")
            current_call = current_calls[0]
            if current_call.state != "pending":
                raise ValueError("current call must be pending")
            if current_call.operation is not self.current_operation:
                raise ValueError("current call operation must match current_operation")
        return self


class GuardedSubmissionResult(StrictModel):
    """The immutable result of validating and conditionally committing one response."""

    schema_version: Literal["1.0"] = "1.0"
    accepted: bool
    preflight: EvaluationPreflightResult
    state: EvaluationRunState | None = None

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if self.accepted != self.preflight.ok:
            raise ValueError("guarded submission acceptance must match preflight")
        if self.accepted != (self.state is not None):
            raise ValueError("accepted guarded submission requires state")
        return self


def model_fingerprint(value: StrictModel, *, exclude: set[str] | None = None) -> str:
    """Return the SHA-256 digest of canonical model JSON excluding self-hash fields."""
    payload = value.model_dump(mode="json")
    for field_name in exclude or set():
        payload.pop(field_name, None)
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
