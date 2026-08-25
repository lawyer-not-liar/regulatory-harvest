"""Read-only, fail-closed admission for delivery-readiness-v1 inputs."""

from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Literal, Protocol, cast

from pydantic import BaseModel, ValidationError

from regulatory_harvest.analysis.report import render_markdown
from regulatory_harvest.models import ResearchBundle
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
from .attorney_models import EvaluationSource
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
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
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


def _verify_coverage_review(
    data: bytes,
    *,
    receipt_hash: object,
    receipt_issue_count: int,
    code: str,
) -> None:
    coverage = _canonical_file_object(data, code=code)
    declared_hash = _hash(coverage.get("coverage_review_hash"), code=code)
    unsigned = dict(coverage)
    unsigned.pop("coverage_review_hash")
    if (
        declared_hash != sha256_digest(canonical_json_bytes(unsigned))
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
) -> None:
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
        _verify_bundle_bytes(
            bundle_bytes,
            code=code,
            expected_blocking_review_count=blocking_count,
            expected_validation_issue_count=validation_issue_count,
            report_bytes=report_bytes,
        )
        _verify_coverage_review(
            coverage_bytes,
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
        "rationale": _field(
            value,
            "substantive_rationale" if stable else "rationale",
        ),
        "referee_fragment_fingerprint": _field(
            value,
            "referee_fragment_fingerprint",
        ),
    }


def _semantic_baseline_projection(value: object, *, stable: bool) -> bytes:
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
        baseline_comparable = _semantic_baseline_projection(
            baseline_context.baseline,
            stable=True,
        ) == _semantic_baseline_projection(baseline, stable=False)
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
    generation_run_dir: Path,
    validation_receipt_path: Path,
    historical_v22_run_dir: Path | None = None,
    historical_anonymous_label: Literal["A", "B"] | None = None,
) -> VerifiedReadinessInputsV1:
    """Verify and bind all readiness inputs without creating or modifying a run."""
    history_supplied = historical_v22_run_dir is not None
    label_supplied = historical_anonymous_label is not None
    if history_supplied != label_supplied:
        raise _fail("READINESS_HISTORICAL_ARGUMENTS_INVALID")
    if label_supplied and historical_anonymous_label not in {"A", "B"}:
        raise _fail("READINESS_HISTORICAL_ARGUMENTS_INVALID")

    baseline_context, projection = _load_verified_baseline(baseline_run_dir)
    report_text, report_bytes, generation_binding = _load_verified_generation(
        generation_run_dir,
        projection,
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
        qualification_root=projection.baseline_input.qualification_root,
        qualification_receipt_fingerprint=(
            projection.baseline_input.qualification_receipt_fingerprint
        ),
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
        generation_binding=generation_binding,
        generation_validation=readiness_input.generation_validation,
        readiness_rubric=rubric,
        readiness_rubric_bytes=rubric_bytes,
        strict_equivalent_scoring_contract_bytes=scoring_bytes,
        historical_v22=historical,
    )


__all__ = [
    "GenerationCapsuleBindingV1",
    "QualificationReadinessBindingV1",
    "ReadinessInputError",
    "VerifiedReadinessInputsV1",
    "build_verified_readiness_input_v1",
]
