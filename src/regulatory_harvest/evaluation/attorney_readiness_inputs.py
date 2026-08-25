"""Read-only, fail-closed admission for delivery-readiness-v1 inputs."""

from __future__ import annotations

import json
import os
import re
import stat
from array import array
from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Literal, Protocol, cast

from pydantic import BaseModel, ValidationError

from regulatory_harvest.analysis import (
    ATOMIC_COVERAGE_CONTRACT_VERSION,
    COVERAGE_CONTRACT_VERSION,
    AnalysisDraft,
    build_analysis,
    build_evidence_inventory,
    build_source_unit_inventory,
    evaluate_atomic_coverage,
    evaluate_coverage_closure,
)
from regulatory_harvest.analysis.report import render_markdown
from regulatory_harvest.combine.stages import note_stage
from regulatory_harvest.models import Gap, ResearchBundle, ResearchRequest, SourceRecord
from regulatory_harvest.storage import (
    calculate_bundle_hash,
    canonical_json_bytes,
    sha256_digest,
)
from regulatory_harvest.validation import validate_bundle

from .attorney_artifacts import EvaluationIntegrityError, open_evaluation_storage
from .attorney_baseline_artifacts import (
    VerifiedBaselineContextV1,
    load_verified_baseline_run,
)
from .attorney_baseline_models import GradeableBaselineProjectionV1
from .attorney_baseline_projection import (
    project_gradeable_baseline_v1,
    verify_gradeable_baseline_projection_v1,
)
from .attorney_generation import (
    GenerationInputError,
    GenerationIntegrityError,
    load_completed_generation_capsule_context,
)
from .attorney_models import (
    CaseAdmissionJudgment,
    EvaluationSource,
    JudgeOperation,
    JudgeResponse,
    QualificationCase,
    QualificationManifest,
    QualificationReceipt,
    model_fingerprint,
)
from .attorney_qualification import (
    VerifiedQualificationContext,
    load_verified_qualification_context,
)
from .attorney_readiness_models import (
    GenerationValidationBindingV1,
    HistoricalV22CrossCheckV1,
    ReadinessInputV1,
    ReadinessRubricV1,
    load_readiness_rubric_v1,
)
from .attorney_v2_models import AbsoluteDispositionV2
from .attorney_v22_artifacts import load_verified_v22_context

_MAX_JSON_BYTES = 16 * 1024 * 1024
_MAX_REPORT_BYTES = 64 * 1024 * 1024
_MAX_QUALIFICATION_PUBLIC_ITEMS = 1024
_MAX_QUALIFICATION_PUBLIC_TEXT_BYTES = 64 * 1024
_MAX_QUALIFICATION_PUBLIC_TOTAL_BYTES = 4 * 1024 * 1024
_MAX_QUALIFICATION_PUBLIC_TEXT_FIELDS = 8192
_MAX_QUALIFICATION_FORBIDDEN_PATTERN_BYTES = 1024 * 1024
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_POSIX_PRIVATE_ROOT_RE = re.compile(
    r"(?<![A-Za-z0-9:/])/(?:Applications|Library|System|Users|Volumes|etc|home|opt|"
    r"private|tmp|usr|var)(?:/|(?=[\s,.;:!?)]|$))"
)
_WINDOWS_ABSOLUTE_PATH_RE = re.compile(r"(?i)(?<![A-Za-z0-9])[A-Z]:[\\/][^\s\x00\"'<>|?*]+")
_WINDOWS_UNC_PATH_RE = re.compile(
    r"(?<![\\A-Za-z0-9])\\\\[^\\/\s\x00\"'<>|?*]+[\\/]"
    r"[^\s\x00\"'<>|?*]+"
)
_FILE_URI_RE = re.compile(r"(?i)(?<![A-Za-z0-9+.-])file:/+[^\s/\x00\"'<>][^\s\x00\"'<>]*")
_DOSSIER_NAME = "agent-dossier.json"
_DOSSIER_FIELDS = {
    "coverage_contract_version",
    "evidence_inventory",
    "gaps",
    "request",
    "schema_version",
    "source_mode",
    "source_unit_inventory",
    "sources",
}
_VALIDATION_RECEIPT_NAME = "validation-receipt.json"
_VALIDATION_RECEIPT_FIELDS = {
    "analysis_draft",
    "audit",
    "blocking_review_count",
    "bundle",
    "coverage_issue_count",
    "coverage_review",
    "coverage_review_hash",
    "evidence_precision_valid",
    "proposition_coverage_valid",
    "provision_recall_valid",
    "report",
    "status",
    "valid",
    "validation_issue_count",
}


class _ValidationReader(Protocol):
    def read_artifact(self, artifact_path: str, *, max_bytes: int) -> bytes: ...

    def assert_root_identity(self) -> None: ...


def _node_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _directory_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _leaf_flags() -> int:
    return os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


class _PosixValidationReader:
    """Small retained descriptor graph for a bounded read-only matter root."""

    def __init__(self, root: Path) -> None:
        if not root.is_absolute():
            raise EvaluationIntegrityError("validation root must be absolute")
        self._anchors: list[
            tuple[int | None, str | None, int, tuple[int, int, int, int, int, int, int]]
        ] = []
        descriptor = os.open("/", _directory_flags())
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                raise EvaluationIntegrityError("filesystem root is not a directory")
            self._anchors.append((None, None, descriptor, _node_identity(metadata)))
            for segment in root.parts[1:]:
                parent = descriptor
                descriptor = os.open(segment, _directory_flags(), dir_fd=parent)
                opened = os.fstat(descriptor)
                named = os.stat(segment, dir_fd=parent, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or stat.S_ISLNK(named.st_mode)
                    or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                ):
                    raise EvaluationIntegrityError(
                        "validation root contains an unsafe directory component"
                    )
                self._anchors.append((parent, segment, descriptor, _node_identity(opened)))
        except BaseException:
            self.close()
            raise

    @property
    def _root_descriptor(self) -> int:
        if not self._anchors:
            raise EvaluationIntegrityError("validation reader is closed")
        return self._anchors[-1][2]

    def assert_root_identity(self) -> None:
        if not self._anchors:
            raise EvaluationIntegrityError("validation reader is closed")
        for parent, name, descriptor, expected in self._anchors:
            opened = os.fstat(descriptor)
            if not stat.S_ISDIR(opened.st_mode) or _node_identity(opened) != expected:
                raise EvaluationIntegrityError("validation root identity changed")
            if parent is None or name is None:
                continue
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if stat.S_ISLNK(named.st_mode) or (named.st_dev, named.st_ino) != (
                opened.st_dev,
                opened.st_ino,
            ):
                raise EvaluationIntegrityError("validation root path identity changed")

    @staticmethod
    def _segments(artifact_path: str) -> tuple[str, ...]:
        if not artifact_path or artifact_path.startswith("/") or "\\" in artifact_path:
            raise EvaluationIntegrityError("validation artifact path is unsafe")
        segments = tuple(artifact_path.split("/"))
        if any(segment in {"", ".", ".."} for segment in segments):
            raise EvaluationIntegrityError("validation artifact path is unsafe")
        return segments

    def read_artifact(self, artifact_path: str, *, max_bytes: int) -> bytes:
        if type(max_bytes) is not int or max_bytes < 0:
            raise EvaluationIntegrityError("validation artifact limit is invalid")
        segments = self._segments(artifact_path)
        self.assert_root_identity()
        parent = self._root_descriptor
        directories: list[tuple[int, str, int, tuple[int, int, int, int, int, int, int]]] = []
        leaf: int | None = None
        try:
            for segment in segments[:-1]:
                child = os.open(segment, _directory_flags(), dir_fd=parent)
                opened = os.fstat(child)
                named = os.stat(segment, dir_fd=parent, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or stat.S_ISLNK(named.st_mode)
                    or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                ):
                    raise EvaluationIntegrityError("validation artifact directory is unsafe")
                directories.append((parent, segment, child, _node_identity(opened)))
                parent = child
            leaf = os.open(segments[-1], _leaf_flags(), dir_fd=parent)
            before = os.fstat(leaf)
            if not stat.S_ISREG(before.st_mode):
                raise EvaluationIntegrityError("validation artifact is not a regular file")
            if before.st_nlink != 1:
                raise EvaluationIntegrityError("validation artifact has multiple hard links")
            if before.st_size > max_bytes:
                raise EvaluationIntegrityError("validation artifact exceeds maximum size")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(leaf, min(1024 * 1024, max_bytes + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise EvaluationIntegrityError("validation artifact exceeds maximum size")
                chunks.append(chunk)
            after = os.fstat(leaf)
            named = os.stat(segments[-1], dir_fd=parent, follow_symlinks=False)
            if (
                _node_identity(before) != _node_identity(after)
                or stat.S_ISLNK(named.st_mode)
                or (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino)
            ):
                raise EvaluationIntegrityError("validation artifact changed while reading")
            for directory_parent, name, descriptor, expected in directories:
                opened = os.fstat(descriptor)
                rebound = os.stat(name, dir_fd=directory_parent, follow_symlinks=False)
                if (
                    _node_identity(opened) != expected
                    or stat.S_ISLNK(rebound.st_mode)
                    or (opened.st_dev, opened.st_ino) != (rebound.st_dev, rebound.st_ino)
                ):
                    raise EvaluationIntegrityError(
                        "validation artifact directory changed while reading"
                    )
            self.assert_root_identity()
            return b"".join(chunks)
        finally:
            if leaf is not None:
                os.close(leaf)
            for _, _, descriptor, _ in reversed(directories):
                os.close(descriptor)

    def close(self) -> None:
        for _, _, descriptor, _ in reversed(self._anchors):
            with suppress(OSError):
                os.close(descriptor)
        self._anchors.clear()


@contextmanager
def _open_validation_reader(root: Path) -> Iterator[_ValidationReader]:
    if os.name != "posix":
        with open_evaluation_storage(root) as storage:
            yield storage
        return
    reader: _PosixValidationReader | None = None
    try:
        reader = _PosixValidationReader(root)
        yield reader
    except EvaluationIntegrityError:
        raise
    except (NotImplementedError, OSError, TypeError) as error:
        raise EvaluationIntegrityError("validation storage read failed") from error
    finally:
        if reader is not None:
            reader.close()


class ReadinessInputError(ValueError):
    """A supplied readiness input failed its verified admission boundary."""


@dataclass(frozen=True)
class QualificationReadinessBindingV1:
    """Path-free exact qualification identities inherited from the baseline."""

    qualification_root: str
    qualification_receipt_fingerprint: str
    qualification_readiness: Literal["ADMITTED"]


@dataclass(frozen=True)
class QualificationRequestedAuthorityV1:
    """Path-free authority scope copied from the verified qualification case."""

    authority_id: str
    title: str
    jurisdiction: str
    authority_type: str
    source_ids: tuple[str, ...]


@dataclass(frozen=True)
class QualificationAdmissionCheckV1:
    """One exact supported admission check from the replayed judgment."""

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
    source_ids: tuple[str, ...]


@dataclass(frozen=True)
class QualificationAdmissionIssueV1:
    """One exact issue from the replayed qualification judgment."""

    code: str
    severity: Literal["error", "warning", "info"]
    message: str
    related_ids: tuple[str, ...]


@dataclass(frozen=True)
class QualificationReceiptReadinessV1:
    """Exact receipt readiness evidence, without inventing a new finding."""

    status: Literal["ADMITTED"]
    issue_codes: tuple[str, ...]
    rationale: str


@dataclass(frozen=True)
class QualificationLanguageSourceV1:
    """Minimal source identity needed to bind a language treatment."""

    source_id: str
    content_hash: str
    language: str


@dataclass(frozen=True)
class QualificationLanguageTreatmentV1:
    """Exact declared treatment and its source bindings."""

    sources: tuple[QualificationLanguageSourceV1, ...]
    method: str
    rationale: str
    limitation_status: Literal["DECLARED", "NOT_DECLARED"]
    limitation_text: str | None


@dataclass(frozen=True)
class QualificationLimitsV1:
    """Detached, immutable qualification evidence for readiness safety review."""

    case_schema_version: Literal["1.1"]
    admission_status: Literal["qualified"]
    qualification_readiness: Literal["ADMITTED"]
    qualification_root: str
    qualification_receipt_fingerprint: str
    case_fingerprint: str
    source_record_fingerprint: str
    request_fingerprint: str
    judgment_fingerprint: str
    requested_authorities: tuple[QualificationRequestedAuthorityV1, ...]
    admission_checks: tuple[QualificationAdmissionCheckV1, ...]
    admission_issues: tuple[QualificationAdmissionIssueV1, ...]
    receipt_readiness: QualificationReceiptReadinessV1
    language_treatments: tuple[QualificationLanguageTreatmentV1, ...]


class _BoundedPayloadMatcher:
    """Compact linear-time matcher for bounded complete byte payloads."""

    def __init__(self, patterns: tuple[bytes, ...]) -> None:
        self._first_child = array("i", [-1])
        self._next_sibling = array("i", [-1])
        self._failure = array("i", [0])
        self._labels = bytearray(1)
        self._terminal = bytearray(1)
        for pattern in patterns:
            node = 0
            for label in pattern:
                child = self._child(node, label)
                if child == -1:
                    child = self._append_child(node, label)
                node = child
            self._terminal[node] = 1
        self._build_failures()

    def _child(self, node: int, label: int) -> int:
        child = self._first_child[node]
        while child != -1:
            if self._labels[child] == label:
                return child
            child = self._next_sibling[child]
        return -1

    def _append_child(self, parent: int, label: int) -> int:
        child = len(self._labels)
        self._labels.append(label)
        self._first_child.append(-1)
        self._next_sibling.append(self._first_child[parent])
        self._failure.append(0)
        self._terminal.append(0)
        self._first_child[parent] = child
        return child

    def _children(self, node: int) -> Iterator[int]:
        child = self._first_child[node]
        while child != -1:
            yield child
            child = self._next_sibling[child]

    def _build_failures(self) -> None:
        pending: deque[int] = deque(self._children(0))
        while pending:
            node = pending.popleft()
            for child in self._children(node):
                pending.append(child)
                label = self._labels[child]
                fallback = self._failure[node]
                target = self._child(fallback, label)
                while fallback and target == -1:
                    fallback = self._failure[fallback]
                    target = self._child(fallback, label)
                self._failure[child] = 0 if target == -1 else target
                if self._terminal[self._failure[child]]:
                    self._terminal[child] = 1

    def contains_pattern(self, value: bytes) -> bool:
        node = 0
        for label in value:
            child = self._child(node, label)
            while node and child == -1:
                node = self._failure[node]
                child = self._child(node, label)
            node = 0 if child == -1 else child
            if self._terminal[node]:
                return True
        return False


def _contains_private_absolute_path(value: str) -> bool:
    return any(
        pattern.search(value) is not None
        for pattern in (
            _POSIX_PRIVATE_ROOT_RE,
            _WINDOWS_ABSOLUTE_PATH_RE,
            _WINDOWS_UNC_PATH_RE,
            _FILE_URI_RE,
        )
    )


def _validate_qualification_public_projection(
    limits: QualificationLimitsV1,
    *,
    forbidden_payloads: tuple[bytes, ...],
) -> QualificationLimitsV1:
    """Reject unsafe public text without rewriting accepted qualification evidence."""
    code = "READINESS_QUALIFICATION_INVALID"
    try:
        if type(limits) is not QualificationLimitsV1 or type(forbidden_payloads) is not tuple:
            raise TypeError("qualification public projection has an invalid type")
        if len(forbidden_payloads) > _MAX_QUALIFICATION_PUBLIC_ITEMS + 1 or any(
            type(payload) is not bytes for payload in forbidden_payloads
        ):
            raise TypeError("qualification forbidden payload inventory is invalid")
        patterns = tuple(
            sorted(
                {
                    payload
                    for payload in forbidden_payloads
                    if payload and len(payload) <= _MAX_QUALIFICATION_PUBLIC_TEXT_BYTES
                }
            )
        )
        if sum(map(len, patterns)) > _MAX_QUALIFICATION_FORBIDDEN_PATTERN_BYTES:
            raise ValueError("qualification forbidden payload inventory is excessive")
        payload_matcher = _BoundedPayloadMatcher(patterns)
        if (
            type(limits.case_schema_version) is not str
            or limits.case_schema_version != "1.1"
            or type(limits.admission_status) is not str
            or limits.admission_status != "qualified"
            or type(limits.qualification_readiness) is not str
            or limits.qualification_readiness != "ADMITTED"
        ):
            raise ValueError("qualification public state is invalid")
        for fingerprint in (
            limits.qualification_root,
            limits.qualification_receipt_fingerprint,
            limits.case_fingerprint,
            limits.source_record_fingerprint,
            limits.request_fingerprint,
            limits.judgment_fingerprint,
        ):
            _hash(fingerprint, code=code)

        text_field_count = 0
        total_text_bytes = 0

        def bounded_native_text(value: object) -> tuple[str, bytes]:
            nonlocal text_field_count, total_text_bytes
            if type(value) is not str or not value or value.isspace():
                raise TypeError("qualification text must be a native nonblank string")
            if len(value) > _MAX_QUALIFICATION_PUBLIC_TEXT_BYTES:
                raise ValueError("qualification text is excessive")
            try:
                encoded = value.encode("utf-8")
            except UnicodeEncodeError as error:
                raise ValueError("qualification text is not UTF-8") from error
            text_field_count += 1
            total_text_bytes += len(encoded)
            if (
                len(encoded) > _MAX_QUALIFICATION_PUBLIC_TEXT_BYTES
                or text_field_count > _MAX_QUALIFICATION_PUBLIC_TEXT_FIELDS
                or total_text_bytes > _MAX_QUALIFICATION_PUBLIC_TOTAL_BYTES
            ):
                raise ValueError("qualification text exceeds public resource limits")
            return value, encoded

        def public_text(value: object) -> str:
            checked, encoded = bounded_native_text(value)
            if payload_matcher.contains_pattern(encoded) or _contains_private_absolute_path(
                checked
            ):
                raise ValueError("qualification public text is unsafe")
            return checked

        def native_text(value: object) -> str:
            checked, _ = bounded_native_text(value)
            return checked

        authorities = limits.requested_authorities
        checks = limits.admission_checks
        issues = limits.admission_issues
        treatments = limits.language_treatments
        if (
            type(authorities) is not tuple
            or len(authorities) > _MAX_QUALIFICATION_PUBLIC_ITEMS
            or type(checks) is not tuple
            or len(checks) != len(_ADMISSION_CHECK_CODES)
            or type(issues) is not tuple
            or len(issues) > _MAX_QUALIFICATION_PUBLIC_ITEMS
            or type(treatments) is not tuple
            or len(treatments) > _MAX_QUALIFICATION_PUBLIC_ITEMS
        ):
            raise TypeError("qualification public inventory is invalid")

        for authority in authorities:
            if type(authority) is not QualificationRequestedAuthorityV1:
                raise TypeError("qualification authority projection is invalid")
            native_text(authority.authority_id)
            public_text(authority.title)
            public_text(authority.jurisdiction)
            public_text(authority.authority_type)
            if (
                type(authority.source_ids) is not tuple
                or len(authority.source_ids) > _MAX_QUALIFICATION_PUBLIC_ITEMS
            ):
                raise TypeError("qualification authority source inventory is invalid")
            for source_id in authority.source_ids:
                native_text(source_id)

        observed_check_codes: set[str] = set()
        for check in checks:
            if type(check) is not QualificationAdmissionCheckV1:
                raise TypeError("qualification check projection is invalid")
            code_value = native_text(check.code)
            observed_check_codes.add(code_value)
            if type(check.satisfied) is not bool or type(check.material) is not bool:
                raise TypeError("qualification check flags are invalid")
            public_text(check.rationale)
            if (
                type(check.source_ids) is not tuple
                or len(check.source_ids) > _MAX_QUALIFICATION_PUBLIC_ITEMS
            ):
                raise TypeError("qualification check source inventory is invalid")
            for source_id in check.source_ids:
                native_text(source_id)
        if observed_check_codes != _ADMISSION_CHECK_CODES:
            raise ValueError("qualification check inventory is invalid")

        for issue in issues:
            if type(issue) is not QualificationAdmissionIssueV1:
                raise TypeError("qualification issue projection is invalid")
            native_text(issue.code)
            if type(issue.severity) is not str or issue.severity not in {
                "error",
                "warning",
                "info",
            }:
                raise TypeError("qualification issue severity is invalid")
            public_text(issue.message)
            if (
                type(issue.related_ids) is not tuple
                or len(issue.related_ids) > _MAX_QUALIFICATION_PUBLIC_ITEMS
            ):
                raise TypeError("qualification issue relation inventory is invalid")
            for related_id in issue.related_ids:
                native_text(related_id)

        readiness = limits.receipt_readiness
        if (
            type(readiness) is not QualificationReceiptReadinessV1
            or type(readiness.status) is not str
            or readiness.status != "ADMITTED"
            or type(readiness.issue_codes) is not tuple
            or len(readiness.issue_codes) > _MAX_QUALIFICATION_PUBLIC_ITEMS
        ):
            raise TypeError("qualification receipt readiness projection is invalid")
        for issue_code in readiness.issue_codes:
            native_text(issue_code)
        public_text(readiness.rationale)

        treatment_source_count = 0
        for treatment in treatments:
            if type(treatment) is not QualificationLanguageTreatmentV1:
                raise TypeError("qualification language treatment projection is invalid")
            if (
                type(treatment.sources) is not tuple
                or len(treatment.sources) > _MAX_QUALIFICATION_PUBLIC_ITEMS
            ):
                raise TypeError("qualification language source inventory is invalid")
            treatment_source_count += len(treatment.sources)
            if treatment_source_count > _MAX_QUALIFICATION_PUBLIC_ITEMS:
                raise ValueError("qualification language source inventory is excessive")
            for source in treatment.sources:
                if type(source) is not QualificationLanguageSourceV1:
                    raise TypeError("qualification language source projection is invalid")
                native_text(source.source_id)
                _hash(source.content_hash, code=code)
                public_text(source.language)
            public_text(treatment.method)
            public_text(treatment.rationale)
            if type(treatment.limitation_status) is not str:
                raise TypeError("qualification limitation status is invalid")
            if treatment.limitation_status == "DECLARED":
                public_text(treatment.limitation_text)
            elif (
                treatment.limitation_status != "NOT_DECLARED"
                or treatment.limitation_text is not None
            ):
                raise ValueError("qualification limitation declaration is invalid")
        return limits
    except ReadinessInputError:
        raise
    except (
        AttributeError,
        RecursionError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as error:
        raise _fail(code, error) from error


@dataclass(frozen=True)
class GenerationCapsuleBindingV1:
    """Path-free generation provenance without duplicated report/source bytes."""

    capsule_root: str
    capture_fingerprint: str
    request_fingerprint: str
    response_fingerprint: str
    report_hash: str
    source_hashes: tuple[tuple[str, str], ...]
    client_facts_hash: str | None
    generator_artifact_hashes: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class VerifiedReadinessInputsV1:
    """Verified in-memory handoff; no fresh grader authority exists yet."""

    readiness_input: ReadinessInputV1
    baseline_context: VerifiedBaselineContextV1
    gradeable_baseline: GradeableBaselineProjectionV1
    report_text: str
    report_hash: str
    source_record: tuple[EvaluationSource, ...]
    qualification_binding: QualificationReadinessBindingV1
    qualification_limits: QualificationLimitsV1
    generation_binding: GenerationCapsuleBindingV1
    generation_validation: GenerationValidationBindingV1
    readiness_rubric: ReadinessRubricV1
    readiness_rubric_bytes: bytes
    strict_equivalent_scoring_contract_bytes: bytes
    historical_v22: HistoricalV22CrossCheckV1 | None


def _fail(code: str, error: BaseException | None = None) -> ReadinessInputError:
    result = ReadinessInputError(code)
    if error is not None:
        result.__cause__ = error
    return result


def _hash(value: object, *, code: str) -> str:
    if type(value) is not str or _HASH_RE.fullmatch(value) is None:
        raise _fail(code)
    return value


def _native_count(value: object, *, code: str) -> int:
    if type(value) is not int or value < 0:
        raise _fail(code)
    return value


def _duplicate_rejecting_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _canonical_file_object(data: bytes, *, code: str) -> dict[str, object]:
    if len(data) > _MAX_JSON_BYTES:
        raise _fail(code)
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_duplicate_rejecting_object,
        )
        if type(value) is not dict or canonical_json_bytes(value) + b"\n" != data:
            raise ValueError("noncanonical JSON file")
        return cast(dict[str, object], value)
    except (
        RecursionError,
        TypeError,
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        raise _fail(code, error) from error


def _canonical_document_object(data: bytes, *, code: str) -> dict[str, object]:
    if len(data) > _MAX_JSON_BYTES:
        raise _fail(code)
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_duplicate_rejecting_object,
        )
        if type(value) is not dict or canonical_json_bytes(value) != data:
            raise ValueError("noncanonical JSON document")
        return cast(dict[str, object], value)
    except (
        RecursionError,
        TypeError,
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        raise _fail(code, error) from error


def _absolute_rooted_artifact(
    value: object,
    *,
    root: Path,
    code: str,
) -> str:
    if type(value) is not str or not value:
        raise _fail(code)
    candidate = Path(value)
    if not candidate.is_absolute():
        raise _fail(code)
    try:
        relative = candidate.relative_to(root)
    except ValueError as error:
        raise _fail(code, error) from error
    relative_text = relative.as_posix()
    if not relative_text or relative_text in {".", ".."}:
        raise _fail(code)
    return relative_text


def _load_verified_baseline(
    baseline_run_dir: Path,
) -> tuple[VerifiedBaselineContextV1, GradeableBaselineProjectionV1]:
    code = "READINESS_BASELINE_INVALID"
    try:
        context = load_verified_baseline_run(baseline_run_dir)
        manifest = context.manifest
        baseline_input = context.baseline_input
        baseline = context.baseline
        if (
            context.verification.valid is not True
            or manifest.root_hash == "0" * 64
            or baseline_input.qualification_readiness != "ADMITTED"
            or baseline_input.qualification_root == "0" * 64
            or baseline_input.qualification_receipt_fingerprint == "0" * 64
            or manifest.legal_input_fingerprint != baseline_input.legal_input_fingerprint
            or manifest.baseline_fingerprint != baseline.baseline_fingerprint
            or baseline.legal_input_fingerprint != baseline_input.legal_input_fingerprint
        ):
            raise ValueError("baseline binding mismatch")
        projection = project_gradeable_baseline_v1(context)
        verified = verify_gradeable_baseline_projection_v1(context, projection)
        if type(verified) is not GradeableBaselineProjectionV1:
            raise TypeError("projection verifier returned an unexpected type")
        return context, verified
    except (
        AttributeError,
        EvaluationIntegrityError,
        OSError,
        RecursionError,
        TypeError,
        ValidationError,
        ValueError,
    ) as error:
        raise _fail(code, error) from error


_ADMISSION_CHECK_CODES = {
    "AUTHORITY_ALIGNMENT",
    "OPERATIVE_TEXT",
    "CURRENTNESS_EVIDENCE",
    "LANGUAGE_RESOLUTION",
    "SOURCE_PARITY",
}


def _same_model_sequence(left: object, right: object) -> bool:
    try:
        return canonical_json_bytes(_wire(left)) == canonical_json_bytes(_wire(right))
    except (AttributeError, RecursionError, TypeError, ValueError):
        return False


def _load_qualification_limits(
    qualification_run_dir: Path,
    projection: GradeableBaselineProjectionV1,
) -> QualificationLimitsV1:
    code = "READINESS_QUALIFICATION_INVALID"
    try:
        context = load_verified_qualification_context(qualification_run_dir)
        if type(context) is not VerifiedQualificationContext:
            raise TypeError("qualification loader returned an unexpected type")
        manifest = QualificationManifest.model_validate(
            context.manifest.model_dump(mode="python", warnings="error"),
            strict=True,
        )
        receipt = QualificationReceipt.model_validate(
            context.receipt.model_dump(mode="python", warnings="error"),
            strict=True,
        )
        baseline = projection.baseline_input
        case = QualificationCase.model_validate(
            context.case.model_dump(mode="python", warnings="error"),
            strict=True,
        )
        case_bytes = context.artifact_bytes.get("qualification-case.json")
        response_bytes = context.artifact_bytes.get("admission-response.json")
        receipt_bytes = context.artifact_bytes.get("qualification-receipt.json")
        manifest_bytes = context.artifact_bytes.get("manifest.json")
        if (
            type(case_bytes) is not bytes
            or type(response_bytes) is not bytes
            or type(receipt_bytes) is not bytes
            or type(manifest_bytes) is not bytes
        ):
            raise TypeError("qualification artifacts are incomplete")
        if (
            canonical_json_bytes(case.model_dump(mode="json", warnings="error")) != case_bytes
            or canonical_json_bytes(receipt.model_dump(mode="json", warnings="error"))
            != receipt_bytes
            or canonical_json_bytes(manifest.model_dump(mode="json", warnings="error"))
            != manifest_bytes
            or model_fingerprint(case) != manifest.case_fingerprint
        ):
            raise ValueError("qualification case is not exact")
        if (
            case.schema_version != "1.1"
            or manifest.status != "qualified"
            or receipt.readiness.status.value != "ADMITTED"
            or baseline.qualification_readiness != "ADMITTED"
            or manifest.root_hash != baseline.qualification_root
            or manifest.receipt_fingerprint != receipt.receipt_fingerprint
            or receipt.receipt_fingerprint != baseline.qualification_receipt_fingerprint
            or manifest.case_fingerprint != receipt.case_fingerprint
            or manifest.source_record_fingerprint != receipt.source_record_fingerprint
            or receipt.source_record_fingerprint != baseline.source_record_fingerprint
            or receipt.readiness.case_fingerprint != receipt.case_fingerprint
            or receipt.readiness.judgment_fingerprint != receipt.judgment_fingerprint
            or case.question != baseline.question
            or case.jurisdiction != baseline.jurisdiction
            or case.as_of.isoformat() != baseline.as_of
            or not _same_model_sequence(
                case.requested_authorities,
                baseline.requested_authorities,
            )
            or not _same_model_sequence(case.sources, baseline.sources)
        ):
            raise ValueError("qualification does not bind the verified baseline")

        response_raw = _canonical_document_object(response_bytes, code=code)
        response = JudgeResponse.model_validate(response_raw)
        if canonical_json_bytes(response.model_dump(mode="json", warnings="error")) != (
            response_bytes
        ):
            raise ValueError("qualification response is not exact")
        judgment = CaseAdmissionJudgment.model_validate(response.payload)
        if canonical_json_bytes(
            judgment.model_dump(mode="json", warnings="error")
        ) != canonical_json_bytes(response.payload):
            raise ValueError("qualification judgment is not exact")
        checks = tuple(judgment.checks)
        check_codes = [check.code for check in checks]
        source_ids = {source.source_id for source in case.sources}
        if (
            response.operation is not JudgeOperation.ADMIT_CASE
            or response.request_fingerprint != receipt.request_fingerprint
            or judgment.request_fingerprint != receipt.request_fingerprint
            or model_fingerprint(judgment) != receipt.judgment_fingerprint
            or manifest.call.request_fingerprint != receipt.request_fingerprint
            or manifest.call.judgment_fingerprint != receipt.judgment_fingerprint
            or len(check_codes) != len(_ADMISSION_CHECK_CODES)
            or set(check_codes) != _ADMISSION_CHECK_CODES
            or any(
                type(check.satisfied) is not bool
                or type(check.material) is not bool
                or not set(check.source_ids).issubset(source_ids)
                for check in checks
            )
        ):
            raise ValueError("qualification admission evidence is invalid")

        sources_by_id = {source.source_id: source for source in case.sources}
        observed_treatment_ids: list[str] = []
        treatments: list[QualificationLanguageTreatmentV1] = []
        for treatment in case.language_treatments:
            observed_treatment_ids.extend(treatment.source_ids)
            treatment_sources = tuple(
                QualificationLanguageSourceV1(
                    source_id=sources_by_id[source_id].source_id,
                    content_hash=sources_by_id[source_id].content_hash,
                    language=sources_by_id[source_id].language,
                )
                for source_id in treatment.source_ids
            )
            limitations = treatment.limitations
            treatments.append(
                QualificationLanguageTreatmentV1(
                    sources=treatment_sources,
                    method=treatment.method,
                    rationale=treatment.rationale,
                    limitation_status=("NOT_DECLARED" if limitations is None else "DECLARED"),
                    limitation_text=limitations,
                )
            )
        expected_source_ids = [source.source_id for source in case.sources]
        if len(observed_treatment_ids) != len(set(observed_treatment_ids)) or set(
            observed_treatment_ids
        ) != set(expected_source_ids):
            raise ValueError("qualification language treatment coverage is invalid")

        return QualificationLimitsV1(
            case_schema_version="1.1",
            admission_status="qualified",
            qualification_readiness="ADMITTED",
            qualification_root=manifest.root_hash,
            qualification_receipt_fingerprint=receipt.receipt_fingerprint,
            case_fingerprint=receipt.case_fingerprint,
            source_record_fingerprint=receipt.source_record_fingerprint,
            request_fingerprint=receipt.request_fingerprint,
            judgment_fingerprint=receipt.judgment_fingerprint,
            requested_authorities=tuple(
                QualificationRequestedAuthorityV1(
                    authority_id=authority.authority_id,
                    title=authority.title,
                    jurisdiction=authority.jurisdiction,
                    authority_type=authority.authority_type,
                    source_ids=tuple(authority.source_ids),
                )
                for authority in case.requested_authorities
            ),
            admission_checks=tuple(
                QualificationAdmissionCheckV1(
                    code=check.code,
                    satisfied=check.satisfied,
                    material=check.material,
                    rationale=check.rationale,
                    source_ids=tuple(check.source_ids),
                )
                for check in checks
            ),
            admission_issues=tuple(
                QualificationAdmissionIssueV1(
                    code=issue.code,
                    severity=issue.severity.value,
                    message=issue.message,
                    related_ids=tuple(issue.related_ids),
                )
                for issue in judgment.issues
            ),
            receipt_readiness=QualificationReceiptReadinessV1(
                status="ADMITTED",
                issue_codes=tuple(receipt.readiness.issue_codes),
                rationale=receipt.readiness.rationale,
            ),
            language_treatments=tuple(treatments),
        )
    except ReadinessInputError:
        raise
    except (
        AttributeError,
        EvaluationIntegrityError,
        KeyError,
        OSError,
        RecursionError,
        TypeError,
        ValidationError,
        ValueError,
    ) as error:
        raise _fail(code, error) from error


def _expected_generation_sources(
    projection: GradeableBaselineProjectionV1,
) -> tuple[tuple[str, str, str], ...]:
    return tuple(
        (source.source_id, source.content_hash, source.normalized_text)
        for source in projection.baseline_input.sources
    )


def _load_verified_generation(
    generation_run_dir: Path,
    projection: GradeableBaselineProjectionV1,
) -> tuple[str, bytes, GenerationCapsuleBindingV1]:
    code = "READINESS_GENERATION_INVALID"
    try:
        provenance, report_bytes, request = load_completed_generation_capsule_context(
            generation_run_dir
        )
        if type(provenance) is not dict or type(request) is not dict:
            raise TypeError("generation context has an unexpected shape")
        record = provenance.get("generation_record")
        if type(record) is not dict:
            raise TypeError("generation record has an unexpected shape")
        capsule_root = _hash(provenance.get("capsule_root"), code=code)
        report_hash = sha256_digest(report_bytes)
        if _hash(record.get("report_hash"), code=code) != report_hash:
            raise ValueError("generation report hash mismatch")
        try:
            report_text = report_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("generation report is not UTF-8") from error
        if not report_text.strip():
            raise ValueError("generation report is blank")
        baseline_input = projection.baseline_input
        if (
            request.get("question") != baseline_input.question
            or request.get("client_facts") != baseline_input.client_facts
        ):
            raise ValueError("generation legal input mismatch")
        raw_sources = request.get("sources")
        if type(raw_sources) is not list:
            raise TypeError("generation sources have an unexpected shape")
        observed_sources: list[tuple[str, str, str]] = []
        for raw in raw_sources:
            if type(raw) is not dict:
                raise TypeError("generation source has an unexpected shape")
            observed_sources.append(
                (
                    cast(str, raw.get("source_id")),
                    _hash(raw.get("content_hash"), code=code),
                    cast(str, raw.get("text")),
                )
            )
        if tuple(observed_sources) != _expected_generation_sources(projection):
            raise ValueError("generation source record mismatch")
        source_hashes = record.get("source_hashes")
        generator_hashes = record.get("generator_artifact_hashes")
        if type(source_hashes) is not dict or type(generator_hashes) is not dict:
            raise TypeError("generation hash inventories have an unexpected shape")
        expected_source_hashes = {
            source_id: content_hash for source_id, content_hash, _ in observed_sources
        }
        if source_hashes != expected_source_hashes:
            raise ValueError("generation source hash inventory mismatch")
        client_facts_hash = record.get("client_facts_hash")
        expected_facts_hash = (
            None
            if baseline_input.client_facts is None
            else sha256_digest(baseline_input.client_facts.encode("utf-8"))
        )
        if client_facts_hash != expected_facts_hash:
            raise ValueError("generation client facts mismatch")
        binding = GenerationCapsuleBindingV1(
            capsule_root=capsule_root,
            capture_fingerprint=_hash(record.get("capture_fingerprint"), code=code),
            request_fingerprint=_hash(record.get("request_fingerprint"), code=code),
            response_fingerprint=_hash(record.get("response_fingerprint"), code=code),
            report_hash=report_hash,
            source_hashes=tuple(
                sorted(
                    (
                        key,
                        _hash(value, code=code),
                    )
                    for key, value in source_hashes.items()
                    if type(key) is str
                )
            ),
            client_facts_hash=(
                None if client_facts_hash is None else _hash(client_facts_hash, code=code)
            ),
            generator_artifact_hashes=tuple(
                sorted(
                    (
                        key,
                        _hash(value, code=code),
                    )
                    for key, value in generator_hashes.items()
                    if type(key) is str
                )
            ),
        )
        if len(binding.source_hashes) != len(source_hashes) or len(
            binding.generator_artifact_hashes
        ) != len(generator_hashes):
            raise TypeError("generation hash inventory keys are invalid")
        return report_text, report_bytes, binding
    except (
        AttributeError,
        GenerationInputError,
        GenerationIntegrityError,
        OSError,
        RecursionError,
        TypeError,
        UnicodeDecodeError,
        ValidationError,
        ValueError,
    ) as error:
        raise _fail(code, error) from error


def _coverage_issue_count(value: dict[str, object]) -> int:
    issues = value.get("issues")
    if type(issues) is list:
        return len(issues)
    lead_recall = value.get("lead_recall")
    proposition = value.get("proposition_coverage")
    if type(lead_recall) is dict and type(proposition) is dict:
        lead_issues = lead_recall.get("issues")
        proposition_issues = proposition.get("issues")
        if type(lead_issues) is list and type(proposition_issues) is list:
            return len(lead_issues) + len(proposition_issues)
    raise ValueError("coverage review issue inventory is invalid")


def _verified_coverage_inputs(
    *,
    draft_data: bytes,
    dossier_data: bytes,
    code: str,
) -> tuple[
    str,
    AnalysisDraft,
    dict[str, object],
    dict[str, object],
    ResearchRequest,
    tuple[SourceRecord, ...],
]:
    draft_raw = _canonical_file_object(draft_data, code=code)
    draft = AnalysisDraft.model_validate(draft_raw)
    if canonical_json_bytes(draft.model_dump(mode="json")) + b"\n" != draft_data:
        raise _fail(code)

    dossier = _canonical_file_object(dossier_data, code=code)
    if set(dossier) != _DOSSIER_FIELDS or dossier.get("schema_version") != "1.0":
        raise _fail(code)
    contract_version = dossier.get("coverage_contract_version")
    if contract_version not in {
        COVERAGE_CONTRACT_VERSION,
        ATOMIC_COVERAGE_CONTRACT_VERSION,
    }:
        raise _fail(code)
    raw_sources = dossier.get("sources")
    raw_gaps = dossier.get("gaps")
    if type(raw_sources) is not list or type(raw_gaps) is not list:
        raise _fail(code)
    request = ResearchRequest.model_validate(dossier.get("request"))
    sources = tuple(SourceRecord.model_validate(item) for item in raw_sources)
    gaps = tuple(Gap.model_validate(item) for item in raw_gaps)
    evidence_inventory = build_evidence_inventory(
        [source.model_dump(mode="json") for source in sources]
    )
    source_unit_inventory = build_source_unit_inventory(
        [source.model_dump(mode="json") for source in sources]
    )
    expected_dossier = {
        "schema_version": "1.0",
        "coverage_contract_version": contract_version,
        "source_mode": request.source_mode,
        "request": request.model_dump(mode="json"),
        "sources": [source.model_dump(mode="json") for source in sources],
        "gaps": [gap.model_dump(mode="json") for gap in gaps],
        "evidence_inventory": evidence_inventory,
        "source_unit_inventory": source_unit_inventory,
    }
    if (
        dossier.get("source_mode") != request.source_mode
        or dossier.get("evidence_inventory") != evidence_inventory
        or dossier.get("source_unit_inventory") != source_unit_inventory
        or canonical_json_bytes(expected_dossier) + b"\n" != dossier_data
    ):
        raise _fail(code)
    return (
        contract_version,
        draft,
        evidence_inventory,
        source_unit_inventory,
        request,
        sources,
    )


def _verify_coverage_review(
    data: bytes,
    *,
    draft_data: bytes,
    dossier_data: bytes,
    bundle: ResearchBundle,
    receipt_hash: object,
    receipt_issue_count: int,
    code: str,
) -> None:
    coverage = _canonical_file_object(data, code=code)
    contract, draft, evidence_inventory, source_unit_inventory, request, sources = (
        _verified_coverage_inputs(
            draft_data=draft_data,
            dossier_data=dossier_data,
            code=code,
        )
    )
    built = build_analysis(draft, list(sources))
    replayed = note_stage(
        bundle.model_copy(
            deep=True,
            update={
                "issues": built.issues,
                "findings": built.findings,
                "citations": built.citations,
                "gaps": built.gaps,
                "review_items": built.review_items,
                "brief": built.brief,
                "validation": None,
                "bundle_hash": None,
            },
        )
    ).bundle
    if (
        bundle.request != request
        or tuple(bundle.sources) != sources
        or bundle.issues != replayed.issues
        or bundle.findings != replayed.findings
        or bundle.citations != replayed.citations
        or bundle.gaps != replayed.gaps
        or bundle.review_items != replayed.review_items
        or bundle.brief != replayed.brief
    ):
        raise _fail(code)
    if contract == ATOMIC_COVERAGE_CONTRACT_VERSION:
        expected = evaluate_atomic_coverage(
            source_unit_inventory,
            evidence_inventory,
            draft,
            sources,
        )
    else:
        coverage_draft = draft
        if draft.coverage_contract_version != COVERAGE_CONTRACT_VERSION:
            coverage_draft = draft.model_copy(update={"coverage_contract_version": None})
        expected = evaluate_coverage_closure(
            evidence_inventory,
            source_unit_inventory,
            coverage_draft,
            sources,
        )
    expected_bytes = canonical_json_bytes(expected) + b"\n"
    declared_hash = _hash(coverage.get("coverage_review_hash"), code=code)
    if (
        data != expected_bytes
        or declared_hash != _hash(receipt_hash, code=code)
        or coverage.get("valid") is not True
        or _coverage_issue_count(coverage) != receipt_issue_count
    ):
        raise _fail(code)


def _verify_bundle_bytes(
    data: bytes,
    *,
    code: str,
    expected_blocking_review_count: int,
    expected_validation_issue_count: int,
    report_bytes: bytes,
) -> ResearchBundle:
    raw = _canonical_document_object(data, code=code)
    bundle = ResearchBundle.model_validate(raw)
    if canonical_json_bytes(bundle.model_dump(mode="json")) != data:
        raise _fail(code)
    declared_hash = _hash(bundle.bundle_hash, code=code)
    if declared_hash != calculate_bundle_hash(bundle):
        raise _fail(code)
    validation = validate_bundle(bundle, require_bundle_hash=True)
    blocking_codes = {
        "PROPOSED_QUOTE_AMBIGUOUS",
        "PROPOSED_QUOTE_NOT_FOUND",
        "PROPOSED_SOURCE_MISSING",
    }
    blocking_review_count = sum(item.code in blocking_codes for item in bundle.review_items)
    if (
        validation.valid is not True
        or len(validation.issues) != expected_validation_issue_count
        or blocking_review_count != expected_blocking_review_count
        or render_markdown(bundle).encode("utf-8") != report_bytes
    ):
        raise _fail(code)
    return bundle


def _load_generation_validation(
    validation_receipt_path: Path,
    *,
    generation_report_bytes: bytes,
) -> GenerationValidationBindingV1:
    code = "READINESS_VALIDATION_RECEIPT_INVALID"
    try:
        absolute = Path(os.path.abspath(validation_receipt_path.expanduser()))
        if absolute.name != _VALIDATION_RECEIPT_NAME:
            raise ValueError("validation receipt name is not canonical")
        root = absolute.parent
        with _open_validation_reader(root) as storage:
            receipt_bytes = storage.read_artifact(
                absolute.name,
                max_bytes=_MAX_JSON_BYTES,
            )
            receipt = _canonical_file_object(receipt_bytes, code=code)
            if set(receipt) != _VALIDATION_RECEIPT_FIELDS:
                raise ValueError("validation receipt shape is invalid")
            paths = {
                field: _absolute_rooted_artifact(receipt[field], root=root, code=code)
                for field in ("analysis_draft", "audit", "bundle", "coverage_review", "report")
            }
            if len(set(paths.values())) != len(paths):
                raise ValueError("validation receipt paths must be unique")
            report_bytes = storage.read_artifact(
                paths["report"],
                max_bytes=_MAX_REPORT_BYTES,
            )
            bundle_bytes = storage.read_artifact(
                paths["bundle"],
                max_bytes=_MAX_JSON_BYTES,
            )
            coverage_bytes = storage.read_artifact(
                paths["coverage_review"],
                max_bytes=_MAX_JSON_BYTES,
            )
            draft_bytes = storage.read_artifact(
                paths["analysis_draft"],
                max_bytes=_MAX_JSON_BYTES,
            )
            dossier_bytes = storage.read_artifact(
                _DOSSIER_NAME,
                max_bytes=_MAX_JSON_BYTES,
            )
            storage.assert_root_identity()
        blocking_count = _native_count(receipt["blocking_review_count"], code=code)
        coverage_issue_count = _native_count(receipt["coverage_issue_count"], code=code)
        validation_issue_count = _native_count(receipt["validation_issue_count"], code=code)
        if (
            receipt["status"] != "completed"
            or receipt["valid"] is not True
            or receipt["evidence_precision_valid"] is not True
            or receipt["proposition_coverage_valid"] is not True
            or receipt["provision_recall_valid"] is not True
            or blocking_count != 0
            or report_bytes != generation_report_bytes
        ):
            raise ValueError("generation validation is not deterministically complete")
        bundle = _verify_bundle_bytes(
            bundle_bytes,
            code=code,
            expected_blocking_review_count=blocking_count,
            expected_validation_issue_count=validation_issue_count,
            report_bytes=report_bytes,
        )
        _verify_coverage_review(
            coverage_bytes,
            draft_data=draft_bytes,
            dossier_data=dossier_bytes,
            bundle=bundle,
            receipt_hash=receipt["coverage_review_hash"],
            receipt_issue_count=coverage_issue_count,
            code=code,
        )
        return GenerationValidationBindingV1(
            receipt_hash=sha256_digest(receipt_bytes),
            report_hash=sha256_digest(report_bytes),
            bundle_hash=sha256_digest(bundle_bytes),
            coverage_review_hash=sha256_digest(coverage_bytes),
            status="completed",
            evidence_precision_valid=True,
            proposition_coverage_valid=True,
            provision_recall_valid=True,
        )
    except ReadinessInputError:
        raise
    except (
        AttributeError,
        EvaluationIntegrityError,
        OSError,
        RecursionError,
        TypeError,
        ValidationError,
        ValueError,
    ) as error:
        raise _fail(code, error) from error


def _wire(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", warnings="error")
    if isinstance(value, Enum):
        return value.value
    if type(value) is dict:
        return {cast(str, key): _wire(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_wire(item) for item in value]
    if value is None or type(value) in {str, bool, int, float}:
        return value
    if hasattr(value, "__dict__"):
        return {key: _wire(item) for key, item in vars(value).items()}
    raise TypeError("historical semantic value has an unsupported shape")


def _field(value: object, name: str) -> object:
    return getattr(value, name)


def _requirement_projection(value: object, *, stable: bool) -> dict[str, object]:
    return {
        "requirement_id": _field(value, "requirement_id"),
        "canonical_order": _field(value, "canonical_order"),
        "statement": _field(value, "statement"),
        "kind": _wire(_field(value, "kind")),
        "importance": _wire(_field(value, "importance")),
        "importance_basis": _wire(_field(value, "importance_basis")),
        "importance_rationale": _field(value, "importance_rationale"),
        "passages": _wire(_field(value, "passages")),
        "dependency": _wire(_field(value, "dependency")),
        "confidence": _field(value, "confidence"),
        "rationale": _field(
            value,
            "substantive_rationale" if stable else "rationale",
        ),
    }


def _contest_projection(value: object, *, stable: bool) -> dict[str, object]:
    reviewer = _field(value, "reviewer_alternative")
    auditor = _field(value, "auditor_alternative")
    return {
        "contested_requirement_id": _field(value, "contested_requirement_id"),
        "reviewer_alternative": (
            None if reviewer is None else _requirement_projection(reviewer, stable=stable)
        ),
        "auditor_alternative": (
            None if auditor is None else _requirement_projection(auditor, stable=stable)
        ),
        "unresolved_reason": _wire(_field(value, "unresolved_reason")),
        "importance": _wire(_field(value, "importance")),
        "importance_basis": _wire(_field(value, "importance_basis")),
        "importance_rationale": _field(value, "importance_rationale"),
        "rationale": _field(
            value,
            "substantive_rationale" if stable else "rationale",
        ),
        "referee_fragment_fingerprint": _field(
            value,
            "referee_fragment_fingerprint",
        ),
    }


def _semantic_baseline_projection(value: object, *, stable: bool) -> bytes | None:
    try:
        raw = {
            "requirements": [
                _requirement_projection(item, stable=stable)
                for item in cast(tuple[object, ...], _field(value, "requirements"))
            ],
            "relationships": _wire(_field(value, "relationships")),
            "contested_requirements": [
                _contest_projection(item, stable=stable)
                for item in cast(
                    tuple[object, ...],
                    _field(value, "contested_requirements"),
                )
            ],
        }
        return canonical_json_bytes(raw)
    except (AttributeError, RecursionError, TypeError, ValueError):
        return None


def _historical_legal_input_comparable(
    context: object,
    baseline_context: VerifiedBaselineContextV1,
) -> bool:
    try:
        loader = _field(context, "load_case_envelope")
        if not callable(loader):
            return False
        case = _field(loader(), "case")
        stable = baseline_context.baseline_input
        historical_as_of = _field(case, "as_of")
        if hasattr(historical_as_of, "isoformat"):
            historical_as_of = historical_as_of.isoformat()
        rubric_bytes = canonical_json_bytes(_wire(_field(context, "rubric")))
        return (
            _field(case, "question") == stable.question
            and _field(case, "jurisdiction") == stable.jurisdiction
            and historical_as_of == stable.as_of
            and canonical_json_bytes(_wire(_field(case, "sources")))
            == canonical_json_bytes(_wire(stable.sources))
            and canonical_json_bytes(_wire(_field(case, "requested_authorities")))
            == canonical_json_bytes(_wire(stable.requested_authorities))
            and _field(case, "client_facts") == stable.client_facts
            and rubric_bytes == stable.evaluation_rubric_bytes
        )
    except (AttributeError, RecursionError, TypeError, ValueError):
        return False


def _enum_text(value: object) -> str:
    raw = value.value if isinstance(value, Enum) else value
    if type(raw) is not str:
        raise TypeError("historical enum is invalid")
    return raw


def _load_historical_v22(
    run_dir: Path,
    label: Literal["A", "B"],
    *,
    baseline_context: VerifiedBaselineContextV1,
    current_report_hash: str,
) -> HistoricalV22CrossCheckV1:
    code = "READINESS_HISTORICAL_INVALID"
    try:
        context = load_verified_v22_context(run_dir)
        result = context.result
        baseline = context.baseline
        if result is None or baseline is None:
            raise ValueError("historical run has no substantive result")
        terminal = _enum_text(result.terminal_status)
        if terminal not in {"COMPLETED", "INCONCLUSIVE"}:
            raise ValueError("historical run is not terminal substantive evidence")
        selected = [item for item in result.reports if item.anonymous_label == label]
        if len(selected) != 1:
            raise ValueError("historical report label is unavailable")
        report = selected[0]
        aggregates = tuple(report.reconciliation.grader_aggregates)
        if len(aggregates) != 2:
            raise ValueError("historical report lacks two grader aggregates")
        aggregate_fingerprints = tuple(
            _hash(item.aggregate_fingerprint, code=code) for item in aggregates
        )
        historical_report_hash = _hash(aggregates[0].report_fingerprint, code=code)
        if aggregates[1].report_fingerprint != historical_report_hash:
            raise ValueError("historical grader report bindings differ")
        report_index = tuple(item.anonymous_label for item in result.reports).index(label)
        start = report_index * 2
        if tuple(context.manifest.grader_aggregate_fingerprints[start : start + 2]) != (
            aggregate_fingerprints
        ):
            raise ValueError("historical manifest grader binding mismatch")
        sensitivity_fingerprint = _hash(
            report.sensitivity.sensitivity_fingerprint,
            code=code,
        )
        if context.manifest.sensitivity_fingerprints[report_index] != sensitivity_fingerprint:
            raise ValueError("historical sensitivity binding mismatch")
        baseline_fingerprint = _hash(baseline.baseline_fingerprint, code=code)
        if context.manifest.baseline_fingerprint != baseline_fingerprint:
            raise ValueError("historical manifest baseline binding mismatch")
        strict_disposition = AbsoluteDispositionV2(
            _enum_text(report.sensitivity.absolute_disposition)
        )
        reason_codes = tuple(report.sensitivity.reason_codes)
        stable_semantics = _semantic_baseline_projection(
            baseline_context.baseline,
            stable=True,
        )
        historical_semantics = _semantic_baseline_projection(baseline, stable=False)
        baseline_comparable = (
            _historical_legal_input_comparable(context, baseline_context)
            and stable_semantics is not None
            and stable_semantics == historical_semantics
        )
        return HistoricalV22CrossCheckV1(
            report_hash=historical_report_hash,
            strict_disposition=strict_disposition,
            result_fingerprint=_hash(result.result_fingerprint, code=code),
            manifest_fingerprint=_hash(
                context.manifest.manifest_fingerprint,
                code=code,
            ),
            baseline_fingerprint=baseline_fingerprint,
            grader_aggregate_fingerprints=aggregate_fingerprints,
            reason_codes=reason_codes,
            baseline_comparable=baseline_comparable,
            report_comparable=historical_report_hash == current_report_hash,
        )
    except (
        AttributeError,
        EvaluationIntegrityError,
        IndexError,
        OSError,
        RecursionError,
        TypeError,
        ValidationError,
        ValueError,
    ) as error:
        raise _fail(code, error) from error


def _load_rubric_and_bytes() -> tuple[ReadinessRubricV1, bytes]:
    code = "READINESS_RUBRIC_INVALID"
    try:
        rubric = load_readiness_rubric_v1()
        data = Path(__file__).with_name("readiness-rubric-v1.json").read_bytes()
        if canonical_json_bytes(rubric.model_dump(mode="json")) != data:
            raise ValueError("readiness rubric bytes changed")
        return rubric, data
    except (OSError, TypeError, ValidationError, ValueError) as error:
        raise _fail(code, error) from error


def build_verified_readiness_input_v1(
    *,
    baseline_run_dir: Path,
    qualification_run_dir: Path,
    generation_run_dir: Path,
    validation_receipt_path: Path,
    historical_v22_run_dir: Path | None = None,
    historical_anonymous_label: Literal["A", "B"] | None = None,
) -> VerifiedReadinessInputsV1:
    """Verify and bind all readiness inputs without creating or modifying a run."""
    baseline_context, projection = _load_verified_baseline(baseline_run_dir)
    qualification_limits = _load_qualification_limits(
        qualification_run_dir,
        projection,
    )

    history_supplied = historical_v22_run_dir is not None
    label_supplied = historical_anonymous_label is not None
    if history_supplied != label_supplied:
        raise _fail("READINESS_HISTORICAL_ARGUMENTS_INVALID")
    if label_supplied and historical_anonymous_label not in {"A", "B"}:
        raise _fail("READINESS_HISTORICAL_ARGUMENTS_INVALID")

    report_text, report_bytes, generation_binding = _load_verified_generation(
        generation_run_dir,
        projection,
    )
    qualification_limits = _validate_qualification_public_projection(
        qualification_limits,
        forbidden_payloads=(
            *(
                source.normalized_text.encode("utf-8")
                for source in projection.baseline_input.sources
            ),
            report_bytes,
        ),
    )
    report_hash = sha256_digest(report_bytes)
    generation_validation = _load_generation_validation(
        validation_receipt_path,
        generation_report_bytes=report_bytes,
    )
    if generation_validation.report_hash != report_hash:
        raise _fail("READINESS_VALIDATION_RECEIPT_INVALID")

    historical: HistoricalV22CrossCheckV1 | None = None
    if historical_v22_run_dir is not None and historical_anonymous_label is not None:
        historical = _load_historical_v22(
            historical_v22_run_dir,
            historical_anonymous_label,
            baseline_context=baseline_context,
            current_report_hash=report_hash,
        )

    rubric, rubric_bytes = _load_rubric_and_bytes()
    scoring_bytes = projection.baseline_input.evaluation_rubric_bytes
    if sha256_digest(scoring_bytes) != projection.binding.evaluation_rubric_fingerprint:
        raise _fail("READINESS_RUBRIC_INVALID")
    qualification_binding = QualificationReadinessBindingV1(
        qualification_root=qualification_limits.qualification_root,
        qualification_receipt_fingerprint=(qualification_limits.qualification_receipt_fingerprint),
        qualification_readiness="ADMITTED",
    )
    readiness_input = ReadinessInputV1(
        protocol_version="delivery-readiness-v1",
        gradeable_baseline=projection,
        grade_target_fingerprint=projection.binding.grade_target_fingerprint,
        report_text=report_text,
        report_hash=report_hash,
        generation_capsule_root=generation_binding.capsule_root,
        generation_validation=generation_validation,
        readiness_rubric_fingerprint=sha256_digest(rubric_bytes),
        strict_equivalent_scoring_contract_fingerprint=sha256_digest(scoring_bytes),
        historical_v22_cross_check=historical,
    )
    return VerifiedReadinessInputsV1(
        readiness_input=readiness_input,
        baseline_context=baseline_context,
        gradeable_baseline=projection,
        report_text=report_text,
        report_hash=report_hash,
        source_record=projection.baseline_input.sources,
        qualification_binding=qualification_binding,
        qualification_limits=qualification_limits,
        generation_binding=generation_binding,
        generation_validation=readiness_input.generation_validation,
        readiness_rubric=rubric,
        readiness_rubric_bytes=rubric_bytes,
        strict_equivalent_scoring_contract_bytes=scoring_bytes,
        historical_v22=historical,
    )


__all__ = [
    "GenerationCapsuleBindingV1",
    "QualificationAdmissionCheckV1",
    "QualificationAdmissionIssueV1",
    "QualificationLanguageSourceV1",
    "QualificationLanguageTreatmentV1",
    "QualificationLimitsV1",
    "QualificationReadinessBindingV1",
    "QualificationReceiptReadinessV1",
    "QualificationRequestedAuthorityV1",
    "ReadinessInputError",
    "VerifiedReadinessInputsV1",
    "build_verified_readiness_input_v1",
]
