"""Immutable local artifacts for provider-neutral attorney evaluations."""

from __future__ import annotations

import ctypes
import errno
import html
import json
import math
import ntpath
import os
import re
import stat
import tempfile
import unicodedata
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import date, datetime
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, ClassVar, Literal, TypeVar, cast

from pydantic import BaseModel, ValidationError

from regulatory_harvest.models.enums import IssueLevel
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from .attorney_admission import adjudicate_admission, build_admission_packet
from .attorney_grading import (
    GradeResolution,
    ResolvedGrade,
    _finding_code_contract,
    material_disputes,
    resolve_grades,
    strict_resolved_grade_snapshot,
)
from .attorney_ledger import (
    _AUDIT_RATIONALE_ACTION_BOILERPLATE_TERMS,
    _AUDIT_RATIONALE_DEFECT_OR_CORRECTION_SIGNALS,
    _AUDIT_RATIONALE_EVALUATOR_METADATA_TERMS,
    _AUDIT_RATIONALE_LEGAL_LOCATORS,
    _AUDIT_RATIONALE_LEGAL_OR_RECORD_ANCHORS,
    _AUDIT_RATIONALE_MINIMUM_SOURCE_TERMS,
    _AUDIT_RATIONALE_MINIMUM_WORDS,
    _AUDIT_RATIONALE_STOPWORDS,
    _ledger_invariant_contract_v1_0,
    ledger_disputes,
    ledger_findings,
    ledger_invariant_contract,
    seal_ledger,
)
from .attorney_models import (
    EVALUATION_ARTIFACT_SCHEMA_VERSION,
    ArtifactRecord,
    AttorneyEvaluationResult,
    CandidateGrade,
    CandidateReport,
    CandidateRole,
    CaseAdmissionJudgment,
    CaseEnvelope,
    CaseReadiness,
    ComparativeDisposition,
    DeterministicChecks,
    EntryGrade,
    EvaluationIssue,
    EvaluationManifest,
    EvaluationRubric,
    EvaluationRunPhase,
    GradeAlternative,
    GradeDispute,
    IssueSeverity,
    JudgeCallRecord,
    JudgeIsolation,
    JudgeOperation,
    JudgeRequest,
    JudgeResponse,
    LedgerAudit,
    LedgerDispute,
    LegalLedger,
    Materiality,
    ReadinessStatus,
    RefereeDecision,
    ReportEvaluation,
    RequirementCitationPin,
    RequirementMatrix,
    RequirementMatrixRow,
    RequirementReportFinding,
    SealedLedger,
    model_fingerprint,
)
from .attorney_scoring import (
    RUBRIC_V1,
    SCORE_INPUT_SCHEMA_VERSION,
    ReportScoreInputs,
    compare_reports,
    score_report,
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)
_MANIFEST_PATH = "run-manifest.json"
_CASE_ENVELOPE_PATH = "case-envelope.json"
_RUBRIC_PATH = "evaluation-rubric.json"
_LEDGER_PATH = "legal-ledger.json"
_RESULT_PATH = "evaluation-result.json"
_REPORT_PATH = "evaluation-report.md"
_READINESS_PATH = "case-readiness.json"
_TERMINAL_READINESS_PATH = "terminal-readiness.json"
_PROPOSED_LEDGER_PATH = "legal-ledger.proposed.json"
_LEDGER_AUDIT_PATH = "legal-ledger-audit.json"
_REPAIRED_LEDGER_PATH = "legal-ledger.repaired.json"
_REMAINING_AUDIT_PATH = "legal-ledger.remaining-audit.json"
_LEDGER_REFEREE_PATH = "ledger-referee.json"
_REPORT_DISPUTES_PATH = "report-disputes.json"
_REPORT_WIDE_NARRATIVE_DIMENSIONS = frozenset(
    {
        "regulatory_walk",
        "qualification_placement",
        "requirements_workplan_boundary",
        "scanability",
    }
)
_MARKDOWN_H2_PATTERN = re.compile(r"^ {0,3}##(?:[ \t]+|$)")
_MARKDOWN_FENCE_OPEN_PATTERN = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")


def _audit_action_contract() -> dict[str, object]:
    """Return the deterministic initial-finding and remaining-transaction contract."""
    return {
        "initial_audit_findings": {
            "action_payloads": {
                "add": {
                    "ledger_id_rule": "new_relative_to_proposed_ledger",
                    "proposed_entries": "zero_or_more",
                    "target_ledger_ids": "none",
                },
                "delete": {
                    "proposed_entries": "none",
                    "target_ledger_ids": "one_or_more",
                },
                "edit": {
                    "ledger_id_rule": "preserve_target_if_proposed",
                    "proposed_entries": "zero_or_one",
                    "target_ledger_ids": "exactly_one",
                },
                "materiality": {
                    "proposed_entries": "none",
                    "target_ledger_ids": "exactly_one",
                },
                "merge": {
                    "proposed_entries": "zero_or_exactly_one",
                    "target_ledger_ids": "two_or_more",
                },
                "split": {
                    "proposed_entries": "zero_or_two_or_more",
                    "target_ledger_ids": "exactly_one",
                },
            },
            "actions": ["add", "edit", "delete", "split", "merge", "materiality"],
            "grounding": {
                "add_with_proposed_entries": "proposed_entries_are_repair_subject",
                "candidate_reports_permitted": False,
                "non_add": "every_target_id_must_exist_in_proposed_ledger",
                "proposed_entries": {
                    "context": ["proposed_ledger", "finding_proposed_entries"],
                    "issue_reporting": "finding_id_and_issue_codes",
                    "standalone_contiguous_transaction_required": False,
                    "validation": "existing_exact_source_entry_validation",
                },
                "proposal_free_add": {
                    "accepted_if": [
                        "known_source_id_and_all_asserted_locators_match_source",
                        "known_source_id_and_no_locators_and_two_source_terms",
                    ],
                    "exact_known_source_id_required": True,
                    "legal_locator_terms": list(_AUDIT_RATIONALE_LEGAL_LOCATORS),
                    "locator_identifier_forms": [
                        "contains_digit",
                        "single_letter",
                        "roman_numeral",
                    ],
                    "locator_match": {
                        "all_asserted_locators_must_match": True,
                        "case_sensitive": False,
                        "exact_type_and_identifier_required": True,
                        "fields": ["title", "normalized_text"],
                        "source_term_fallback_when_any_locator_asserted": False,
                    },
                    "source_term_match": {
                        "action_boilerplate_terms": list(
                            _AUDIT_RATIONALE_ACTION_BOILERPLATE_TERMS
                        ),
                        "alphabetic_character_required": True,
                        "defect_or_correction_signals_excluded": True,
                        "evaluator_metadata_terms": list(
                            _AUDIT_RATIONALE_EVALUATOR_METADATA_TERMS
                        ),
                        "fields": ["title", "normalized_text"],
                        "legal_locator_terms_excluded": True,
                        "minimum_distinct_terms": _AUDIT_RATIONALE_MINIMUM_SOURCE_TERMS,
                        "source_id_tokens_excluded": True,
                        "stopwords": list(_AUDIT_RATIONALE_STOPWORDS),
                    },
                },
            },
            "rationale": {
                "defect_or_correction_signals": list(
                    _AUDIT_RATIONALE_DEFECT_OR_CORRECTION_SIGNALS
                ),
                "generic_filler_rejected": True,
                "legal_or_record_anchors": list(_AUDIT_RATIONALE_LEGAL_OR_RECORD_ANCHORS),
                "minimum_words": _AUDIT_RATIONALE_MINIMUM_WORDS,
            },
            "required_fields": ["dispute_id", "action", "materiality", "rationale"],
            "transaction_payload_required": False,
        },
        "remaining_audit_transactions": {
            "action_payloads": {
                "add": {"proposed_entries": "one_or_more", "target_ledger_ids": "none"},
                "delete": {"proposed_entries": "none", "target_ledger_ids": "one_or_more"},
                "edit": {
                    "ledger_id_rule": "preserve_target",
                    "proposed_entries": "exactly_one",
                    "target_ledger_ids": "exactly_one",
                },
                "materiality": {
                    "proposed_entries": "none",
                    "target_ledger_ids": "exactly_one",
                },
                "merge": {
                    "proposed_entries": "exactly_one",
                    "target_ledger_ids": "two_or_more",
                },
                "split": {
                    "proposed_entries": "two_or_more",
                    "target_ledger_ids": "exactly_one",
                },
            },
            "transaction_payload_required": True,
        },
    }


class EvaluationIntegrityError(ValueError):
    """Raised when an evaluation run cannot be trusted or safely mutated."""


def _ledger_referee_payload(
    envelope: CaseEnvelope,
    repaired_ledger: LegalLedger,
    dispute: LedgerDispute,
) -> dict[str, object]:
    target_ids = set(dispute.target_ledger_ids)
    relevant = [
        entry for entry in repaired_ledger.entries if entry.ledger_id in target_ids
    ]
    sources = {source.source_id: source for source in envelope.case.sources}
    source_spans: list[dict[str, object]] = []
    seen_spans: set[tuple[str, int, int]] = set()
    for entry in [*relevant, *dispute.proposed_entries]:
        for citation in entry.citations:
            key = (citation.source_id, citation.start_char, citation.end_char)
            if key in seen_spans:
                continue
            seen_spans.add(key)
            text = sources[citation.source_id].normalized_text
            source_spans.append(
                {
                    "source_id": citation.source_id,
                    "start_char": citation.start_char,
                    "end_char": citation.end_char,
                    "quote": text[citation.start_char : citation.end_char],
                }
            )
    return {
        "dispute": dispute.model_dump(mode="json"),
        "relevant_entries": [entry.model_dump(mode="json") for entry in relevant],
        "resolution_contract": {
            "accept_a": "keep the repaired ledger unchanged for this dispute",
            "accept_b": "apply the supplied audit dispute to the repaired ledger",
        },
        "source_record": build_admission_packet(envelope).payload,
        "source_spans": source_spans,
    }


def _validate_grade_evidence(
    envelope: CaseEnvelope,
    grade: CandidateGrade,
) -> None:
    """Bind a grade's exact passages and source evidence to its assigned record."""
    candidate_id = next(
        assignment.candidate_id
        for assignment in envelope.assignments
        if assignment.anonymous_label == grade.anonymous_label
    )
    candidate = next(
        item for item in envelope.case.candidates if item.candidate_id == candidate_id
    )
    source_record = build_admission_packet(envelope).payload
    for entry_grade in grade.entry_grades:
        if (
            entry_grade.report_passage is not None
            and entry_grade.report_passage not in candidate.report_text
        ):
            raise EvaluationIntegrityError(
                "entry-grade report passage is not an exact anonymous-report passage"
            )
    for score in grade.narrative_scores:
        if score.report_passage not in candidate.report_text:
            raise EvaluationIntegrityError(
                "narrative report passage is not an exact anonymous-report passage"
            )
    sources = {source.source_id: source for source in envelope.case.sources}
    expected_record_fingerprint = cast(str, source_record["source_record_fingerprint"])
    for claim in grade.out_of_ledger_claims:
        if claim.claim_text not in candidate.report_text:
            raise EvaluationIntegrityError(
                "out-of-ledger claim text is not an exact anonymous-report passage"
            )
        if claim.source_record_fingerprint != expected_record_fingerprint:
            raise EvaluationIntegrityError(
                "out-of-ledger evidence does not bind the common source record"
            )
        for span in claim.evidence_spans:
            source = sources.get(span.source_id)
            if source is None:
                raise EvaluationIntegrityError(
                    "out-of-ledger evidence identifies an unknown source"
                )
            if (
                span.end_char > len(source.normalized_text)
                or source.normalized_text[span.start_char : span.end_char] != span.quote
            ):
                raise EvaluationIntegrityError(
                    "out-of-ledger evidence is not an exact common-source span"
                )


def _markdown_h2_section_spans(report_text: str) -> list[tuple[int, int]]:
    """Locate exact ATX H2 sections while ignoring headings inside code fences."""
    heading_starts: list[int] = []
    offset = 0
    fence_marker: str | None = None
    fence_minimum = 0
    for line in report_text.splitlines(keepends=True):
        content = line.rstrip("\r\n")
        if fence_marker is not None:
            closing = re.fullmatch(
                rf" {{0,3}}{re.escape(fence_marker)}{{{fence_minimum},}}[ \t]*",
                content,
            )
            if closing is not None:
                fence_marker = None
                fence_minimum = 0
            offset += len(line)
            continue
        opening = _MARKDOWN_FENCE_OPEN_PATTERN.fullmatch(content)
        if opening is not None and not (
            opening.group(1).startswith("`") and "`" in opening.group(2)
        ):
            fence_marker = opening.group(1)[0]
            fence_minimum = len(opening.group(1))
        elif _MARKDOWN_H2_PATTERN.match(content) is not None:
            heading_starts.append(offset)
        offset += len(line)
    return [
        (start, heading_starts[index + 1] if index + 1 < len(heading_starts) else len(report_text))
        for index, start in enumerate(heading_starts)
    ]


def _unique_enclosing_h2_section(
    report_text: str,
    passage: str,
) -> tuple[int, int] | None:
    """Resolve every exact passage occurrence to one unambiguous H2 section."""
    sections = _markdown_h2_section_spans(report_text)
    resolved: set[tuple[int, int]] = set()
    search_from = 0
    found = False
    while True:
        passage_start = report_text.find(passage, search_from)
        if passage_start < 0:
            break
        found = True
        passage_end = passage_start + len(passage)
        containing = [
            section
            for section in sections
            if section[0] <= passage_start and passage_end <= section[1]
        ]
        if len(containing) != 1:
            return None
        resolved.add(containing[0])
        if len(resolved) > 1:
            return None
        search_from = passage_start + 1
    if not found or len(resolved) != 1:
        return None
    return next(iter(resolved))


def _anonymous_report_text(envelope: CaseEnvelope, dispute: GradeDispute) -> str:
    candidate_id = next(
        assignment.candidate_id
        for assignment in envelope.assignments
        if assignment.anonymous_label == dispute.anonymous_label
    )
    return next(
        candidate.report_text
        for candidate in envelope.case.candidates
        if candidate.candidate_id == candidate_id
    )


def _narrative_referee_passages(
    envelope: CaseEnvelope,
    dispute: GradeDispute,
) -> list[str]:
    """Expand narrative evidence without changing exact grader alternatives."""
    report_text = _anonymous_report_text(envelope, dispute)
    if dispute.subject_id in _REPORT_WIDE_NARRATIVE_DIMENSIONS:
        return [report_text]
    section_spans: set[tuple[int, int]] = set()
    for alternative in (dispute.grader_1, dispute.grader_2):
        score = alternative.narrative_score
        if score is None:
            return [report_text]
        section = _unique_enclosing_h2_section(report_text, score.report_passage)
        if section is None:
            return [report_text]
        section_spans.add(section)
    return [report_text[start:end] for start, end in sorted(section_spans)]


def _report_referee_instructions(dispute: GradeDispute) -> str:
    """Return the exact replayable instructions for one report dispute."""
    instructions = (
        "Resolve only this blinded material grade dispute using its exact anonymous "
        "passages, relevant ledger or rubric context, and exact source evidence. Copy "
        "the exact dispute_id and grade_dispute_fingerprint. Select "
        "exactly one of accept_grader_1, accept_grader_2, or replace. Use replace only "
        "with one complete replacement_grade_alternative matching the dispute kind and "
        "subject. This is a grade dispute. Do not set selected_disposition, "
        "selected_ledger_resolution, replacement_entries, or source_ids. Give a "
        "concrete rationale. Treat a bounded closed-record limitation as a limitation, "
        "not an affirmative out-of-ledger claim, unless it also asserts the proposition "
        "is absent from governing law. Do not infer candidate identity or inspect any "
        "other score."
    )
    if dispute.kind == "narrative_score":
        instructions += (
            " For this narrative dispute, anonymous_passages contains the complete "
            "enclosing H2 section for each exact grader passage, or the complete anonymous "
            "report when the rubric dimension requires report-wide context or section "
            "resolution fails safe. The original exact grader passages remain in the two "
            "alternatives. Judge the named rubric dimension from the expanded anonymous "
            "context, not only the grader-selected fragments."
        )
    return instructions


def _report_referee_payload(
    envelope: CaseEnvelope,
    sealed_ledger: SealedLedger,
    dispute: GradeDispute,
) -> dict[str, object]:
    """Build one label-free, fresh-context packet for a material grade dispute."""
    def alternative_payload(alternative: GradeAlternative) -> dict[str, object]:
        return {
            "entry_grade": (
                None
                if alternative.entry_grade is None
                else alternative.entry_grade.model_dump(mode="json")
            ),
            "out_of_ledger_claim": (
                None
                if alternative.out_of_ledger_claim is None
                else alternative.out_of_ledger_claim.model_dump(mode="json")
            ),
            "narrative_score": (
                None
                if alternative.narrative_score is None
                else alternative.narrative_score.model_dump(mode="json")
            ),
            "absent_claim": alternative.absent_claim,
        }

    alternatives = (dispute.grader_1, dispute.grader_2)
    passages: list[str] = []
    evidence_spans: list[dict[str, object]] = []
    related_ledger_ids: set[str] = set()
    for alternative in alternatives:
        if alternative.entry_grade is not None:
            passage = alternative.entry_grade.report_passage
            if passage is not None and passage not in passages:
                passages.append(passage)
            related_ledger_ids.add(alternative.entry_grade.ledger_id)
        elif alternative.out_of_ledger_claim is not None:
            claim = alternative.out_of_ledger_claim
            if claim.claim_text not in passages:
                passages.append(claim.claim_text)
            related_ledger_ids.update(claim.related_ledger_ids)
            for span in claim.evidence_spans:
                payload = span.model_dump(mode="json")
                if payload not in evidence_spans:
                    evidence_spans.append(payload)
        elif alternative.narrative_score is not None:
            passage = alternative.narrative_score.report_passage
            if passage not in passages:
                passages.append(passage)

    entries = [
        entry
        for entry in sealed_ledger.ledger.entries
        if entry.ledger_id in related_ledger_ids
    ]
    for entry in entries:
        for citation in entry.citations:
            payload = citation.model_dump(mode="json")
            if payload not in evidence_spans:
                evidence_spans.append(payload)
    dispute_payload = {
        "dispute_id": dispute.dispute_id,
        "kind": dispute.kind,
        "subject_id": dispute.subject_id,
        "materiality": (
            None if dispute.materiality is None else dispute.materiality.value
        ),
        "grader_1": alternative_payload(dispute.grader_1),
        "grader_2": alternative_payload(dispute.grader_2),
        "rationale": dispute.rationale,
    }
    if dispute.kind == "narrative_score":
        passages = _narrative_referee_passages(envelope, dispute)
    return {
        "dispute": dispute_payload,
        "anonymous_passages": passages,
        "relevant_context": {
            "kind": dispute.kind,
            "ledger_entries": [entry.model_dump(mode="json") for entry in entries],
            "rubric_dimension": (
                dispute.subject_id if dispute.kind == "narrative_score" else None
            ),
        },
        "source_record": build_admission_packet(envelope).payload,
        "source_spans": evidence_spans,
        "alternative_meanings": {
            "accept_grader_1": "select exactly the grader_1 alternative",
            "accept_grader_2": "select exactly the grader_2 alternative",
            "replace": (
                "supply one complete replacement_grade_alternative matching the dispute "
                "kind and subject"
            ),
        },
    }


@dataclass(frozen=True)
class EvaluationVerification:
    """Result of a complete immutable-run verification."""

    valid: bool
    issues: tuple[str, ...]
    root_hash: str | None


@dataclass(frozen=True)
class _NodeIdentity:
    device: int
    inode: int
    mode: int
    link_count: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True)
class _PosixAnchor:
    name: str | None
    descriptor: int
    identity: _NodeIdentity


class _RunStorage:
    """One retained, race-resistant filesystem view of an evaluation run."""

    root_path: Path
    failure_stage: str

    def read_artifact(self, artifact_path: str) -> bytes:
        raise NotImplementedError

    def read_optional_artifact(self, artifact_path: str) -> bytes | None:
        raise NotImplementedError

    def atomic_write(
        self,
        artifact_path: str,
        data: bytes,
        *,
        mutable: bool,
    ) -> None:
        raise NotImplementedError

    def scan_inventory(self) -> dict[str, _NodeIdentity]:
        raise NotImplementedError

    def scan_files(self) -> set[str]:
        return {path for path in self.scan_inventory() if not path.endswith("/")}

    def assert_root_identity(self) -> None:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError


def _node_identity(metadata: os.stat_result) -> _NodeIdentity:
    return _NodeIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        link_count=metadata.st_nlink,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _new_posix_anchor(name: str | None, descriptor: int) -> _PosixAnchor:
    try:
        return _PosixAnchor(name, descriptor, _node_identity(os.fstat(descriptor)))
    except BaseException:
        os.close(descriptor)
        raise


def _same_filesystem_object(left: os.stat_result | _NodeIdentity, right: _NodeIdentity) -> bool:
    left_device = left.st_dev if isinstance(left, os.stat_result) else left.device
    left_inode = left.st_ino if isinstance(left, os.stat_result) else left.inode
    return (left_device, left_inode) == (right.device, right.inode)


def _lexical_absolute_path(path: Path) -> Path:
    try:
        return Path(os.path.abspath(path.expanduser()))
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise EvaluationIntegrityError("run path cannot be normalized safely") from error


def _require_posix_capabilities() -> None:
    if os.name != "posix":
        raise EvaluationIntegrityError("POSIX storage is unavailable on this platform")
    missing_flags = [name for name in ("O_DIRECTORY", "O_NOFOLLOW") if not hasattr(os, name)]
    missing_functions: list[str] = []
    if os.scandir not in os.supports_fd:
        missing_functions.append("scandir(fd)")
    if missing_flags or missing_functions:
        detail = ", ".join([*missing_flags, *missing_functions])
        raise EvaluationIntegrityError(
            f"secure POSIX storage capabilities are unavailable: {detail}"
        )


def _posix_directory_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _posix_file_flags() -> int:
    return os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _open_posix_directory(parent_descriptor: int | None, name: str) -> int:
    try:
        descriptor = os.open(
            name,
            _posix_directory_flags(),
            dir_fd=parent_descriptor,
        )
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise EvaluationIntegrityError(
                f"run path contains a symlink or non-directory component: {name}"
            ) from error
        raise
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise EvaluationIntegrityError(f"run path component is not a directory: {name}")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise OSError("artifact write made no progress")
        offset += written


def _read_all(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _validate_regular_metadata(metadata: os.stat_result, artifact_path: str) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise EvaluationIntegrityError(f"artifact is not a regular file: {artifact_path}")
    if metadata.st_nlink != 1:
        raise EvaluationIntegrityError(f"artifact has multiple hard links: {artifact_path}")


def _probe_posix_capabilities(directory_descriptor: int) -> None:
    """Exercise required primitives before the requested run is created."""
    os.fsync(directory_descriptor)
    with tempfile.TemporaryDirectory(prefix="regulatory-harvest-storage-probe-") as probe_root:
        root_descriptor = _open_posix_directory(None, probe_root)
        child_descriptor: int | None = None
        try:
            os.mkdir("child", mode=0o700, dir_fd=root_descriptor)
            child_descriptor = _open_posix_directory(root_descriptor, "child")
            descriptor = os.open(
                "before",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=child_descriptor,
            )
            try:
                _write_all(descriptor, b"probe")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            with os.scandir(child_descriptor) as entries:
                if {entry.name for entry in entries} != {"before"}:
                    raise EvaluationIntegrityError("descriptor inventory probe failed")
            os.replace(
                "before",
                "after",
                src_dir_fd=child_descriptor,
                dst_dir_fd=child_descriptor,
            )
            metadata = os.stat("after", dir_fd=child_descriptor, follow_symlinks=False)
            _validate_regular_metadata(metadata, "storage capability probe")
            os.unlink("after", dir_fd=child_descriptor)
            os.fsync(child_descriptor)
            os.fsync(root_descriptor)
        except (NotImplementedError, OSError, TypeError) as error:
            raise EvaluationIntegrityError(
                "secure POSIX storage capability probe failed"
            ) from error
        finally:
            if child_descriptor is not None:
                os.close(child_descriptor)
            with suppress(OSError):
                os.rmdir("child", dir_fd=root_descriptor)
            os.close(root_descriptor)


class _PosixRunStorage(_RunStorage):
    def __init__(self, root_path: Path, anchors: list[_PosixAnchor]) -> None:
        self.root_path = root_path
        self.failure_stage = "operation"
        self._anchors = anchors
        self._root_descriptor = anchors[-1].descriptor
        self._closed = False

    @classmethod
    def open(cls, run_dir: Path, *, initialize: bool) -> _PosixRunStorage:
        _require_posix_capabilities()
        root_path = _lexical_absolute_path(run_dir)
        anchors: list[_PosixAnchor] = []
        try:
            descriptor = _open_posix_directory(None, root_path.anchor)
            anchors.append(_new_posix_anchor(None, descriptor))
            parts = list(root_path.parts[1:])
            missing_at: int | None = None
            for index, segment in enumerate(parts):
                try:
                    descriptor = _open_posix_directory(descriptor, segment)
                except FileNotFoundError:
                    missing_at = index
                    break
                anchors.append(_new_posix_anchor(segment, descriptor))

            if missing_at is not None and not initialize:
                raise EvaluationIntegrityError("run directory does not exist")

            if initialize:
                if missing_at is None:
                    with os.scandir(anchors[-1].descriptor) as entries:
                        if next(entries, None) is not None:
                            raise EvaluationIntegrityError("run directory must be empty")
                _probe_posix_capabilities(anchors[-1].descriptor)
                for segment in parts[missing_at:] if missing_at is not None else ():
                    parent_descriptor = anchors[-1].descriptor
                    with suppress(FileExistsError):
                        os.mkdir(segment, mode=0o700, dir_fd=parent_descriptor)
                    descriptor = _open_posix_directory(parent_descriptor, segment)
                    anchors.append(_new_posix_anchor(segment, descriptor))
                    os.fchmod(descriptor, 0o700)
                    os.fsync(parent_descriptor)
                os.fchmod(anchors[-1].descriptor, 0o700)
                if missing_at is not None:
                    with os.scandir(anchors[-1].descriptor) as entries:
                        if next(entries, None) is not None:
                            raise EvaluationIntegrityError("run directory must be empty")
            elif missing_at is not None:
                raise EvaluationIntegrityError("run directory does not exist")

            storage = cls(root_path, anchors)
            storage.assert_root_identity()
            return storage
        except BaseException:
            for anchor in reversed(anchors):
                with suppress(OSError):
                    os.close(anchor.descriptor)
            raise

    def _ensure_open(self) -> None:
        if self._closed:
            raise EvaluationIntegrityError("run storage is closed")

    def assert_root_identity(self) -> None:
        self._ensure_open()
        for index, anchor in enumerate(self._anchors):
            opened = os.fstat(anchor.descriptor)
            if not stat.S_ISDIR(opened.st_mode) or not _same_filesystem_object(
                opened, anchor.identity
            ):
                raise EvaluationIntegrityError("run directory identity changed")
            if index == 0:
                continue
            parent = self._anchors[index - 1]
            assert anchor.name is not None
            metadata = os.stat(
                anchor.name,
                dir_fd=parent.descriptor,
                follow_symlinks=False,
            )
            if not stat.S_ISDIR(metadata.st_mode) or not _same_filesystem_object(
                metadata, anchor.identity
            ):
                raise EvaluationIntegrityError("run directory path identity changed")

    @contextmanager
    def _artifact_parent(
        self,
        artifact_path: str,
        *,
        create: bool,
    ) -> Iterator[tuple[int, str]]:
        relative = _validate_relative_path(artifact_path)
        descriptors: list[int] = []
        current = self._root_descriptor
        try:
            for segment in relative.parts[:-1]:
                created = False
                try:
                    descriptor = _open_posix_directory(current, segment)
                except FileNotFoundError:
                    if not create:
                        raise
                    with suppress(FileExistsError):
                        os.mkdir(segment, mode=0o700, dir_fd=current)
                    descriptor = _open_posix_directory(current, segment)
                    created = True
                descriptors.append(descriptor)
                if created:
                    os.fchmod(descriptor, 0o700)
                    os.fsync(current)
                current = descriptor
            yield current, relative.name
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    def _read_leaf(self, parent_descriptor: int, name: str, artifact_path: str) -> bytes:
        try:
            descriptor = os.open(
                name,
                _posix_file_flags(),
                dir_fd=parent_descriptor,
            )
        except OSError as error:
            if error.errno == errno.ELOOP:
                raise EvaluationIntegrityError(
                    f"artifact path contains a symlink: {artifact_path}"
                ) from error
            raise
        try:
            before = os.fstat(descriptor)
            _validate_regular_metadata(before, artifact_path)
            data = _read_all(descriptor)
            after = os.fstat(descriptor)
            named = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            if _node_identity(before) != _node_identity(after) or (
                before.st_dev,
                before.st_ino,
            ) != (named.st_dev, named.st_ino):
                raise EvaluationIntegrityError(f"artifact changed while reading: {artifact_path}")
            return data
        finally:
            os.close(descriptor)

    def read_artifact(self, artifact_path: str) -> bytes:
        self.failure_stage = f"artifact read ({artifact_path})"
        self.assert_root_identity()
        try:
            with self._artifact_parent(artifact_path, create=False) as (parent, name):
                data = self._read_leaf(parent, name, artifact_path)
        except FileNotFoundError as error:
            raise EvaluationIntegrityError(f"artifact is missing: {artifact_path}") from error
        self.assert_root_identity()
        return data

    def read_optional_artifact(self, artifact_path: str) -> bytes | None:
        self.failure_stage = f"optional artifact read ({artifact_path})"
        self.assert_root_identity()
        try:
            with self._artifact_parent(artifact_path, create=False) as (parent, name):
                data = self._read_leaf(parent, name, artifact_path)
        except FileNotFoundError:
            data = None
        self.assert_root_identity()
        return data

    def atomic_write(
        self,
        artifact_path: str,
        data: bytes,
        *,
        mutable: bool,
    ) -> None:
        self.failure_stage = f"artifact write ({artifact_path})"
        self.assert_root_identity()
        with self._artifact_parent(artifact_path, create=True) as (parent, name):
            try:
                existing = self._read_leaf(parent, name, artifact_path)
            except FileNotFoundError:
                existing = None
            self.assert_root_identity()
            if existing is not None:
                if existing == data:
                    return
                if not mutable:
                    raise EvaluationIntegrityError(f"immutable artifact differs: {artifact_path}")

            temporary_name = f".{name}.{uuid.uuid4().hex}.tmp"
            descriptor: int | None = None
            try:
                descriptor = os.open(
                    temporary_name,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | os.O_NOFOLLOW
                    | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=parent,
                )
                os.fchmod(descriptor, 0o600)
                _write_all(descriptor, data)
                os.fsync(descriptor)
                self.assert_root_identity()
                os.replace(
                    temporary_name,
                    name,
                    src_dir_fd=parent,
                    dst_dir_fd=parent,
                )
                os.fsync(parent)
                self.assert_root_identity()
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                with suppress(FileNotFoundError):
                    os.unlink(temporary_name, dir_fd=parent)

    def _scan_directory(
        self,
        descriptor: int,
        prefix: PurePosixPath,
    ) -> dict[str, _NodeIdentity]:
        inventory: dict[str, _NodeIdentity] = {}
        with os.scandir(descriptor) as entries:
            names = sorted(entry.name for entry in entries)
        for name in names:
            relative = prefix / name
            relative_text = relative.as_posix()
            _validate_relative_path(relative_text)
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise EvaluationIntegrityError(f"run inventory contains a symlink: {relative_text}")
            if stat.S_ISDIR(metadata.st_mode):
                child = _open_posix_directory(descriptor, name)
                try:
                    opened_directory = os.fstat(child)
                    if (opened_directory.st_dev, opened_directory.st_ino) != (
                        metadata.st_dev,
                        metadata.st_ino,
                    ):
                        raise EvaluationIntegrityError("run inventory directory changed")
                    inventory[f"{relative_text}/"] = _node_identity(opened_directory)
                    inventory.update(self._scan_directory(child, relative))
                finally:
                    os.close(child)
                continue
            _validate_regular_metadata(metadata, relative_text)
            try:
                child = os.open(name, _posix_file_flags(), dir_fd=descriptor)
            except OSError as error:
                if error.errno == errno.ELOOP:
                    raise EvaluationIntegrityError(
                        f"run inventory contains a symlink: {relative_text}"
                    ) from error
                raise
            try:
                opened = os.fstat(child)
                _validate_regular_metadata(opened, relative_text)
                if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                    raise EvaluationIntegrityError("run inventory artifact changed")
            finally:
                os.close(child)
            inventory[relative_text] = _node_identity(opened)
        return inventory

    def scan_inventory(self) -> dict[str, _NodeIdentity]:
        self.failure_stage = "inventory scan"
        self.assert_root_identity()
        inventory = self._scan_directory(self._root_descriptor, PurePosixPath())
        self.assert_root_identity()
        return inventory

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for anchor in reversed(self._anchors):
            with suppress(OSError):
                os.close(anchor.descriptor)


_WIN_DELETE = 0x00010000
_WIN_SYNCHRONIZE = 0x00100000
_WIN_FILE_READ_DATA = 0x00000001
_WIN_FILE_WRITE_DATA = 0x00000002
_WIN_FILE_LIST_DIRECTORY = 0x00000001
_WIN_FILE_TRAVERSE = 0x00000020
_WIN_FILE_READ_ATTRIBUTES = 0x00000080
_WIN_FILE_SHARE_READ = 0x00000001
_WIN_FILE_SHARE_WRITE = 0x00000002
_WIN_FILE_SHARE_DELETE = 0x00000004
_WIN_OPEN_EXISTING = 3
_WIN_FILE_OPEN = 1
_WIN_FILE_CREATE = 2
_WIN_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_WIN_FILE_ATTRIBUTE_NORMAL = 0x00000080
_WIN_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_WIN_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_WIN_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_WIN_FILE_DIRECTORY_FILE = 0x00000001
_WIN_FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
_WIN_FILE_NON_DIRECTORY_FILE = 0x00000040
_WIN_FILE_OPEN_FOR_BACKUP_INTENT = 0x00004000
_WIN_FILE_OPEN_REPARSE_POINT = 0x00200000
_WIN_FILE_TYPE_DISK = 1
_WIN_OBJ_CASE_INSENSITIVE = 0x00000040

_WIN_STATUS_PENDING = 0x00000103
_WIN_STATUS_NO_MORE_FILES = 0x80000006
_WIN_STATUS_NO_SUCH_FILE = 0xC000000F
_WIN_STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
_WIN_STATUS_OBJECT_NAME_COLLISION = 0xC0000035
_WIN_STATUS_OBJECT_PATH_NOT_FOUND = 0xC000003A

_WinDword = ctypes.c_uint32
_WinBool = ctypes.c_int32
_WinHandle = ctypes.c_void_p


@dataclass(frozen=True)
class _WinNodeInfo:
    attributes: int
    reparse_tag: int
    volume_serial: int
    file_index: int
    link_count: int
    size: int
    write_time: int
    file_type: int


class _Win32API:
    def probe(self) -> None:
        raise NotImplementedError

    def open_root(
        self,
        path: str,
        desired_access: int,
        share_mode: int,
        flags: int,
    ) -> int:
        raise NotImplementedError

    def open_relative(
        self,
        parent_handle: int,
        name: str,
        desired_access: int,
        share_mode: int,
        create_disposition: int,
        create_options: int,
        file_attributes: int,
    ) -> int:
        raise NotImplementedError

    def file_info(self, handle: int) -> _WinNodeInfo:
        raise NotImplementedError

    def query_names(self, directory_handle: int) -> list[str]:
        raise NotImplementedError

    def read_file(self, handle: int) -> bytes:
        raise NotImplementedError

    def write_file(self, handle: int, data: bytes) -> None:
        raise NotImplementedError

    def flush_file(self, handle: int) -> None:
        raise NotImplementedError

    def rename_file(
        self,
        handle: int,
        *,
        root_directory: int,
        new_name: str,
        replace: bool,
    ) -> None:
        raise NotImplementedError

    def delete_handle(self, handle: int) -> None:
        raise NotImplementedError

    def close_handle(self, handle: int) -> None:
        raise NotImplementedError


class _WinFileTime(ctypes.Structure):
    _fields_ = [
        ("low", ctypes.c_uint32),
        ("high", ctypes.c_uint32),
    ]


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("attributes", ctypes.c_uint32),
        ("creation_time", _WinFileTime),
        ("last_access_time", _WinFileTime),
        ("last_write_time", _WinFileTime),
        ("volume_serial", ctypes.c_uint32),
        ("size_high", ctypes.c_uint32),
        ("size_low", ctypes.c_uint32),
        ("link_count", ctypes.c_uint32),
        ("file_index_high", ctypes.c_uint32),
        ("file_index_low", ctypes.c_uint32),
    ]


class _FileRenameInformation(ctypes.Structure):
    _fields_ = [
        ("replace_if_exists", ctypes.c_ubyte),
        ("root_directory", ctypes.c_void_p),
        ("file_name_length", ctypes.c_uint32),
        ("file_name", ctypes.c_uint16 * 1),
    ]


class _UnicodeString(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_uint16),
        ("maximum_length", ctypes.c_uint16),
        ("buffer", ctypes.c_void_p),
    ]


class _ObjectAttributes(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_uint32),
        ("root_directory", ctypes.c_void_p),
        ("object_name", ctypes.POINTER(_UnicodeString)),
        ("attributes", ctypes.c_uint32),
        ("security_descriptor", ctypes.c_void_p),
        ("security_quality_of_service", ctypes.c_void_p),
    ]


class _IOStatusValue(ctypes.Union):
    _fields_: ClassVar[list[tuple[str, Any]]] = [
        ("status", ctypes.c_int32),
        ("pointer", ctypes.c_void_p),
    ]


class _IOStatusBlock(ctypes.Structure):
    _anonymous_ = ("value",)
    _fields_ = [
        ("value", _IOStatusValue),
        ("information", ctypes.c_size_t),
    ]


class _FileNamesInformation(ctypes.Structure):
    _fields_ = [
        ("next_entry_offset", ctypes.c_uint32),
        ("file_index", ctypes.c_uint32),
        ("file_name_length", ctypes.c_uint32),
        ("file_name", ctypes.c_uint16 * 1),
    ]


class _FileAttributeTagInformation(ctypes.Structure):
    _fields_ = [
        ("attributes", ctypes.c_uint32),
        ("reparse_tag", ctypes.c_uint32),
    ]


class _FileDispositionInformation(ctypes.Structure):
    _fields_ = [("delete_file", ctypes.c_ubyte)]


_WIN_FILE_RENAME_INFO_CLASS = 3
_WIN_FILE_DISPOSITION_INFO_CLASS = 4
_WIN_FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
_WIN_FILE_NAMES_INFORMATION_CLASS = 12
_WIN_ERROR_FILE_NOT_FOUND = 2
_WIN_ERROR_PATH_NOT_FOUND = 3
_WIN_ERROR_FILE_EXISTS = 80
_WIN_ERROR_ALREADY_EXISTS = 183


def _ntstatus_code(status: int) -> int:
    return int(ctypes.c_uint32(status).value)


def _nt_success(status: int) -> bool:
    return int(ctypes.c_int32(status).value) >= 0


def _windows_child_name(name: str) -> str:
    try:
        encoded = name.encode("utf-16-le")
    except UnicodeError as error:
        raise EvaluationIntegrityError("unsafe Windows filesystem name") from error
    if (
        not name
        or name in {".", ".."}
        or "\x00" in name
        or "/" in name
        or "\\" in name
        or ":" in name
        or len(encoded) > 0xFFFE
    ):
        raise EvaluationIntegrityError("unsafe Windows filesystem name")
    return name


def _split_windows_absolute_path(
    raw_path: str,
    *,
    require_child: bool,
) -> tuple[str, str, list[str]]:
    if "\x00" in raw_path:
        raise EvaluationIntegrityError("run path cannot be normalized safely")
    normalized_separators = raw_path.replace("/", "\\")
    if normalized_separators.startswith("\\\\"):
        raise EvaluationIntegrityError("Windows UNC and device namespaces are unsupported")
    drive, tail = ntpath.splitdrive(normalized_separators)
    if len(drive) != 2 or not drive[0].isalpha() or drive[1] != ":" or not tail.startswith("\\"):
        raise EvaluationIntegrityError("Windows run path must be drive-absolute")
    stripped_tail = tail.lstrip("\\")
    normalized = ntpath.normpath(f"{drive}\\{stripped_tail}")
    normalized_drive, normalized_tail = ntpath.splitdrive(normalized)
    if normalized_drive.casefold() != drive.casefold():
        raise EvaluationIntegrityError("Windows run path changed drive during normalization")
    parts = [part for part in normalized_tail.split("\\") if part]
    for part in parts:
        _windows_child_name(part)
    if require_child and not parts:
        raise EvaluationIntegrityError("Windows run path cannot be a filesystem root")
    filesystem_root = f"{drive[0].upper()}:\\"
    normalized = ntpath.join(filesystem_root, *parts)
    return filesystem_root, normalized, parts


class _CtypesWin32API(_Win32API):
    """Native boundary whose only dependent opens are relative to handles."""

    def __init__(self) -> None:
        loader = getattr(ctypes, "WinDLL", None)
        if loader is None:
            raise EvaluationIntegrityError("Win32 APIs are unavailable on this platform")
        self._kernel32: Any = loader("kernel32", use_last_error=True)
        self._ntdll: Any = loader("ntdll")
        self._create_file_w: Any = self._kernel32.CreateFileW
        self._get_file_information: Any = self._kernel32.GetFileInformationByHandle
        self._get_file_information_ex: Any = self._kernel32.GetFileInformationByHandleEx
        self._get_file_type: Any = self._kernel32.GetFileType
        self._get_temp_path_w: Any = self._kernel32.GetTempPathW
        self._read_file: Any = self._kernel32.ReadFile
        self._write_file: Any = self._kernel32.WriteFile
        self._flush_file_buffers: Any = self._kernel32.FlushFileBuffers
        self._set_file_information: Any = self._kernel32.SetFileInformationByHandle
        self._close_handle: Any = self._kernel32.CloseHandle
        self._nt_create_file: Any = self._ntdll.NtCreateFile
        self._nt_query_directory_file: Any = self._ntdll.NtQueryDirectoryFile
        self._rtl_nt_status_to_dos_error: Any = self._ntdll.RtlNtStatusToDosError
        self._configure_signatures()

    def _configure_signatures(self) -> None:
        handle = _WinHandle
        dword = _WinDword
        boolean = _WinBool
        self._create_file_w.argtypes = [
            ctypes.c_wchar_p,
            dword,
            dword,
            ctypes.c_void_p,
            dword,
            dword,
            handle,
        ]
        self._create_file_w.restype = handle
        self._get_file_information.argtypes = [
            handle,
            ctypes.POINTER(_ByHandleFileInformation),
        ]
        self._get_file_information.restype = boolean
        self._get_file_information_ex.argtypes = [
            handle,
            ctypes.c_int,
            ctypes.c_void_p,
            dword,
        ]
        self._get_file_information_ex.restype = boolean
        self._get_file_type.argtypes = [handle]
        self._get_file_type.restype = dword
        self._get_temp_path_w.argtypes = [dword, ctypes.c_wchar_p]
        self._get_temp_path_w.restype = dword
        self._read_file.argtypes = [
            handle,
            ctypes.c_void_p,
            dword,
            ctypes.POINTER(dword),
            ctypes.c_void_p,
        ]
        self._read_file.restype = boolean
        self._write_file.argtypes = [
            handle,
            ctypes.c_void_p,
            dword,
            ctypes.POINTER(dword),
            ctypes.c_void_p,
        ]
        self._write_file.restype = boolean
        self._flush_file_buffers.argtypes = [handle]
        self._flush_file_buffers.restype = boolean
        self._set_file_information.argtypes = [
            handle,
            ctypes.c_int,
            ctypes.c_void_p,
            dword,
        ]
        self._set_file_information.restype = boolean
        self._close_handle.argtypes = [handle]
        self._close_handle.restype = boolean

        self._nt_create_file.argtypes = [
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_uint32,
            ctypes.POINTER(_ObjectAttributes),
            ctypes.POINTER(_IOStatusBlock),
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        self._nt_create_file.restype = ctypes.c_int32
        self._nt_query_directory_file.argtypes = [
            handle,
            handle,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(_IOStatusBlock),
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_int,
            ctypes.c_ubyte,
            ctypes.POINTER(_UnicodeString),
            ctypes.c_ubyte,
        ]
        self._nt_query_directory_file.restype = ctypes.c_int32
        self._rtl_nt_status_to_dos_error.argtypes = [ctypes.c_int32]
        self._rtl_nt_status_to_dos_error.restype = ctypes.c_uint32

    @staticmethod
    def _win_error(error_code: int, path: str) -> OSError:
        format_error = getattr(ctypes, "FormatError", None)
        message = (
            str(format_error(error_code)).strip()
            if format_error is not None
            else f"Win32 error {error_code}"
        )
        if error_code in {_WIN_ERROR_FILE_NOT_FOUND, _WIN_ERROR_PATH_NOT_FOUND}:
            return FileNotFoundError(error_code, message, path)
        if error_code in {_WIN_ERROR_FILE_EXISTS, _WIN_ERROR_ALREADY_EXISTS}:
            return FileExistsError(error_code, message, path)
        return OSError(error_code, message, path)

    @classmethod
    def _last_error(cls, path: str) -> OSError:
        get_last_error = getattr(ctypes, "get_last_error", None)
        error_code = int(get_last_error()) if get_last_error is not None else 0
        return cls._win_error(error_code, path)

    def _nt_error(self, status: int, path: str) -> OSError:
        code = _ntstatus_code(status)
        if code in {
            _WIN_STATUS_NO_SUCH_FILE,
            _WIN_STATUS_OBJECT_NAME_NOT_FOUND,
            _WIN_STATUS_OBJECT_PATH_NOT_FOUND,
        }:
            return FileNotFoundError(code, "native object was not found", path)
        if code == _WIN_STATUS_OBJECT_NAME_COLLISION:
            return FileExistsError(code, "native object already exists", path)
        dos_error = int(self._rtl_nt_status_to_dos_error(ctypes.c_int32(status)))
        return self._win_error(dos_error, path)

    @staticmethod
    def _as_handle(handle: int) -> _WinHandle:
        return _WinHandle(handle)

    @staticmethod
    def _unicode_string(name: str) -> tuple[Any, _UnicodeString]:
        encoded = _windows_child_name(name).encode("utf-16-le")
        buffer = ctypes.create_string_buffer(encoded + b"\x00\x00")
        value = _UnicodeString(
            length=len(encoded),
            maximum_length=len(encoded) + 2,
            buffer=ctypes.addressof(buffer),
        )
        return buffer, value

    def open_root(
        self,
        path: str,
        desired_access: int,
        share_mode: int,
        flags: int,
    ) -> int:
        filesystem_root, normalized, parts = _split_windows_absolute_path(
            path,
            require_child=False,
        )
        if parts or normalized.casefold() != filesystem_root.casefold():
            raise EvaluationIntegrityError("absolute Win32 opens are restricted to drive roots")
        raw_handle = self._create_file_w(
            filesystem_root,
            desired_access,
            share_mode,
            None,
            _WIN_OPEN_EXISTING,
            flags,
            None,
        )
        handle_value = cast(int | None, raw_handle)
        invalid_handle = ctypes.c_void_p(-1).value
        if handle_value is None or handle_value == invalid_handle:
            raise self._last_error(path)
        return int(handle_value)

    def open_relative(
        self,
        parent_handle: int,
        name: str,
        desired_access: int,
        share_mode: int,
        create_disposition: int,
        create_options: int,
        file_attributes: int,
    ) -> int:
        _name_buffer, unicode_name = self._unicode_string(name)
        attributes = _ObjectAttributes(
            length=ctypes.sizeof(_ObjectAttributes),
            root_directory=parent_handle,
            object_name=ctypes.pointer(unicode_name),
            attributes=_WIN_OBJ_CASE_INSENSITIVE,
            security_descriptor=None,
            security_quality_of_service=None,
        )
        io_status = _IOStatusBlock()
        raw_handle = ctypes.c_void_p()
        status = int(
            self._nt_create_file(
                ctypes.byref(raw_handle),
                desired_access,
                ctypes.byref(attributes),
                ctypes.byref(io_status),
                None,
                file_attributes,
                share_mode,
                create_disposition,
                create_options,
                None,
                0,
            )
        )
        if _ntstatus_code(status) == _WIN_STATUS_PENDING:
            raise EvaluationIntegrityError("synchronous NtCreateFile returned pending status")
        if not _nt_success(status) or raw_handle.value is None:
            raise self._nt_error(status, name)
        return int(raw_handle.value)

    def file_info(self, handle: int) -> _WinNodeInfo:
        information = _ByHandleFileInformation()
        tag_information = _FileAttributeTagInformation()
        raw_handle = self._as_handle(handle)
        if not self._get_file_information(raw_handle, ctypes.byref(information)):
            raise self._last_error("open handle")
        if not self._get_file_information_ex(
            raw_handle,
            _WIN_FILE_ATTRIBUTE_TAG_INFO_CLASS,
            ctypes.byref(tag_information),
            ctypes.sizeof(tag_information),
        ):
            raise self._last_error("open handle")
        file_type = int(self._get_file_type(raw_handle))
        return _WinNodeInfo(
            attributes=int(tag_information.attributes),
            reparse_tag=int(tag_information.reparse_tag),
            volume_serial=int(information.volume_serial),
            file_index=(int(information.file_index_high) << 32) | int(information.file_index_low),
            link_count=int(information.link_count),
            size=(int(information.size_high) << 32) | int(information.size_low),
            write_time=(int(information.last_write_time.high) << 32)
            | int(information.last_write_time.low),
            file_type=file_type,
        )

    def query_names(self, directory_handle: int) -> list[str]:
        names: list[str] = []
        restart = 1
        while True:
            buffer = ctypes.create_string_buffer(64 * 1024)
            io_status = _IOStatusBlock()
            status = int(
                self._nt_query_directory_file(
                    self._as_handle(directory_handle),
                    None,
                    None,
                    None,
                    ctypes.byref(io_status),
                    buffer,
                    len(buffer),
                    _WIN_FILE_NAMES_INFORMATION_CLASS,
                    0,
                    None,
                    restart,
                )
            )
            restart = 0
            code = _ntstatus_code(status)
            if code == _WIN_STATUS_NO_MORE_FILES:
                return sorted(names, key=str.casefold)
            if code == _WIN_STATUS_PENDING:
                raise EvaluationIntegrityError(
                    "synchronous NtQueryDirectoryFile returned pending status"
                )
            if not _nt_success(status):
                raise self._nt_error(status, "directory handle")
            used = int(io_status.information)
            if used <= 0 or used > len(buffer):
                raise EvaluationIntegrityError(
                    "native directory enumeration made no valid progress"
                )
            offset = 0
            while True:
                header_end = offset + _FileNamesInformation.file_name.offset
                if header_end > used:
                    raise EvaluationIntegrityError("native directory entry is truncated")
                entry = _FileNamesInformation.from_buffer(buffer, offset)
                name_length = int(entry.file_name_length)
                name_end = header_end + name_length
                if name_length % 2 or name_end > used:
                    raise EvaluationIntegrityError("native directory name is malformed")
                encoded = bytes(buffer.raw[header_end:name_end])
                try:
                    name = encoded.decode("utf-16-le", errors="strict")
                except UnicodeError as error:
                    raise EvaluationIntegrityError("native directory name is malformed") from error
                if name not in {".", ".."}:
                    names.append(_windows_child_name(name))
                next_offset = int(entry.next_entry_offset)
                if next_offset == 0:
                    break
                if next_offset % 4 or next_offset < _FileNamesInformation.file_name.offset:
                    raise EvaluationIntegrityError("native directory offset is malformed")
                offset += next_offset
                if offset >= used:
                    raise EvaluationIntegrityError("native directory offset is out of range")

    def read_file(self, handle: int) -> bytes:
        chunks: list[bytes] = []
        while True:
            buffer = ctypes.create_string_buffer(1024 * 1024)
            read_count = _WinDword()
            if not self._read_file(
                self._as_handle(handle),
                buffer,
                len(buffer),
                ctypes.byref(read_count),
                None,
            ):
                raise self._last_error("open handle")
            if read_count.value == 0:
                return b"".join(chunks)
            chunks.append(buffer.raw[: read_count.value])

    def write_file(self, handle: int, data: bytes) -> None:
        offset = 0
        while offset < len(data):
            chunk = data[offset : offset + 1024 * 1024]
            buffer = ctypes.create_string_buffer(chunk, len(chunk))
            written = _WinDword()
            if not self._write_file(
                self._as_handle(handle),
                buffer,
                len(chunk),
                ctypes.byref(written),
                None,
            ):
                raise self._last_error("open handle")
            if written.value == 0:
                raise OSError("Win32 artifact write made no progress")
            offset += int(written.value)

    def flush_file(self, handle: int) -> None:
        if not self._flush_file_buffers(self._as_handle(handle)):
            raise self._last_error("open handle")

    def rename_file(
        self,
        handle: int,
        *,
        root_directory: int,
        new_name: str,
        replace: bool,
    ) -> None:
        encoded_name = _windows_child_name(new_name).encode("utf-16-le")
        buffer_size = max(
            ctypes.sizeof(_FileRenameInformation),
            _FileRenameInformation.file_name.offset + len(encoded_name),
        )
        buffer = ctypes.create_string_buffer(buffer_size)
        information = _FileRenameInformation.from_buffer(buffer)
        information.replace_if_exists = int(replace)
        information.root_directory = self._as_handle(root_directory)
        information.file_name_length = len(encoded_name)
        ctypes.memmove(
            ctypes.addressof(buffer) + _FileRenameInformation.file_name.offset,
            encoded_name,
            len(encoded_name),
        )
        if not self._set_file_information(
            self._as_handle(handle),
            _WIN_FILE_RENAME_INFO_CLASS,
            buffer,
            buffer_size,
        ):
            raise self._last_error(new_name)

    def delete_handle(self, handle: int) -> None:
        information = _FileDispositionInformation(delete_file=1)
        if not self._set_file_information(
            self._as_handle(handle),
            _WIN_FILE_DISPOSITION_INFO_CLASS,
            ctypes.byref(information),
            ctypes.sizeof(information),
        ):
            raise self._last_error("open handle")

    def _temporary_directory_path(self) -> str:
        buffer = ctypes.create_unicode_buffer(32_768)
        length = int(self._get_temp_path_w(len(buffer), buffer))
        if length == 0:
            raise self._last_error("Windows temporary directory")
        if length >= len(buffer):
            raise EvaluationIntegrityError("Windows temporary directory path is too long")
        return str(buffer.value)

    def close_handle(self, handle: int) -> None:
        if not self._close_handle(self._as_handle(handle)):
            raise self._last_error("open handle")

    def probe(self) -> None:
        filesystem_root, _, temp_parts = _split_windows_absolute_path(
            self._temporary_directory_path(),
            require_child=False,
        )
        anchors: list[int] = []
        probe_handle: int | None = None
        child_handle: int | None = None
        file_handle: int | None = None
        read_handle: int | None = None
        file_delete_requested = False
        child_delete_requested = False
        probe_delete_requested = False
        primary_error: BaseException | None = None
        cleanup_errors: list[tuple[str, BaseException]] = []
        try:
            root_handle = self.open_root(
                filesystem_root,
                _windows_directory_access(),
                _windows_directory_share(),
                _windows_root_flags(),
            )
            anchors.append(root_handle)
            _validate_windows_directory(self.file_info(root_handle), filesystem_root)
            current = root_handle
            current_path = filesystem_root
            for segment in temp_parts:
                current = _open_windows_child_checked(
                    self,
                    current,
                    current_path,
                    segment,
                    _windows_directory_access(),
                    _windows_directory_share(),
                    _WIN_FILE_OPEN,
                    _windows_directory_options(),
                    0,
                )
                anchors.append(current)
                current_path = ntpath.join(current_path, segment)
                _validate_windows_directory(self.file_info(current), segment)

            probe_name = f"regulatory-harvest-storage-probe-{uuid.uuid4().hex}"
            probe_handle = _open_windows_child_checked(
                self,
                current,
                current_path,
                probe_name,
                _windows_directory_access() | _WIN_DELETE,
                _windows_directory_share(),
                _WIN_FILE_CREATE,
                _windows_directory_create_options(),
                _WIN_FILE_ATTRIBUTE_DIRECTORY,
            )
            probe_path = ntpath.join(current_path, probe_name)
            probe_identity = _windows_directory_identity(self, probe_handle, probe_path)
            child_handle = _open_windows_child_checked(
                self,
                probe_handle,
                probe_path,
                "child",
                _windows_directory_access() | _WIN_DELETE,
                _windows_directory_share(),
                _WIN_FILE_CREATE,
                _windows_directory_create_options(),
                _WIN_FILE_ATTRIBUTE_DIRECTORY,
            )
            child_path = ntpath.join(probe_path, "child")
            child_identity = _windows_directory_identity(self, child_handle, child_path)
            file_handle = _open_windows_child_checked(
                self,
                child_handle,
                child_path,
                "before",
                _windows_writable_file_access(),
                _WIN_FILE_SHARE_READ,
                _WIN_FILE_CREATE,
                _windows_file_options(),
                _WIN_FILE_ATTRIBUTE_NORMAL,
            )
            self.write_file(file_handle, b"probe")
            self.flush_file(file_handle)
            _validate_windows_regular(self.file_info(file_handle), "before")
            _assert_windows_directory_identity(self, child_handle, child_path, child_identity)
            if _query_windows_names_checked(self, child_handle, child_path) != ["before"]:
                raise EvaluationIntegrityError("native directory inventory probe failed")
            _rename_windows_file_checked(
                self,
                file_handle,
                root_directory=child_handle,
                root_path=child_path,
                new_name="after",
                replace=False,
            )
            read_handle = _open_windows_child_checked(
                self,
                child_handle,
                child_path,
                "after",
                _windows_readable_file_access(),
                _WIN_FILE_SHARE_READ | _WIN_FILE_SHARE_WRITE | _WIN_FILE_SHARE_DELETE,
                _WIN_FILE_OPEN,
                _windows_file_options(),
                0,
            )
            try:
                _validate_windows_regular(self.file_info(read_handle), "after")
                if self.read_file(read_handle) != b"probe":
                    raise EvaluationIntegrityError("native relative read probe failed")
            finally:
                self.close_handle(read_handle)
                read_handle = None
            self.delete_handle(file_handle)
            file_delete_requested = True
            self.close_handle(file_handle)
            file_handle = None
            if _query_windows_names_checked(self, child_handle, child_path):
                raise EvaluationIntegrityError("native handle disposition probe failed")
            _assert_windows_directory_identity(self, child_handle, child_path, child_identity)
            self.delete_handle(child_handle)
            child_delete_requested = True
            self.close_handle(child_handle)
            child_handle = None
            _assert_windows_directory_identity(self, probe_handle, probe_path, probe_identity)
            self.delete_handle(probe_handle)
            probe_delete_requested = True
            self.close_handle(probe_handle)
            probe_handle = None
        except BaseException as error:
            primary_error = error
        finally:
            pending_file_delete_error: BaseException | None = None
            if file_handle is not None and not file_delete_requested:
                try:
                    self.delete_handle(file_handle)
                    file_delete_requested = True
                except BaseException as error:
                    pending_file_delete_error = error

            if read_handle is not None:
                try:
                    self.close_handle(read_handle)
                    read_handle = None
                except BaseException as error:
                    cleanup_errors.append(("close probe read handle", error))

            if file_handle is not None:
                if not file_delete_requested:
                    try:
                        self.delete_handle(file_handle)
                        file_delete_requested = True
                        pending_file_delete_error = None
                    except BaseException as error:
                        if pending_file_delete_error is not None:
                            cleanup_errors.append(
                                ("initial delete probe file", pending_file_delete_error)
                            )
                        cleanup_errors.append(("delete probe file", error))
                try:
                    self.close_handle(file_handle)
                    file_handle = None
                except BaseException as error:
                    cleanup_errors.append(("close probe file", error))

            if child_handle is not None:
                if not child_delete_requested:
                    try:
                        self.delete_handle(child_handle)
                        child_delete_requested = True
                    except BaseException as error:
                        cleanup_errors.append(("delete probe child directory", error))
                try:
                    self.close_handle(child_handle)
                    child_handle = None
                except BaseException as error:
                    cleanup_errors.append(("close probe child directory", error))

            if probe_handle is not None:
                if not probe_delete_requested:
                    try:
                        self.delete_handle(probe_handle)
                        probe_delete_requested = True
                    except BaseException as error:
                        cleanup_errors.append(("delete probe directory", error))
                try:
                    self.close_handle(probe_handle)
                    probe_handle = None
                except BaseException as error:
                    cleanup_errors.append(("close probe directory", error))
            for handle in reversed(anchors):
                try:
                    self.close_handle(handle)
                except BaseException as error:
                    cleanup_errors.append(("close probe anchor", error))

        _raise_windows_operation_cleanup_errors(
            primary_error,
            cleanup_errors,
            operation="native capability probe",
        )


@dataclass(frozen=True)
class _WindowsAnchor:
    name: str | None
    display_path: str
    parent_handle: int | None
    handle: int
    identity: _NodeIdentity


def _windows_node_identity(info: _WinNodeInfo) -> _NodeIdentity:
    mode = stat.S_IFDIR if info.attributes & _WIN_FILE_ATTRIBUTE_DIRECTORY else stat.S_IFREG
    return _NodeIdentity(
        device=info.volume_serial,
        inode=info.file_index,
        mode=mode,
        link_count=info.link_count,
        size=info.size,
        modified_ns=info.write_time,
        changed_ns=info.write_time,
    )


def _raise_windows_operation_cleanup_errors(
    primary_error: BaseException | None,
    cleanup_errors: list[tuple[str, BaseException]],
    *,
    operation: str,
) -> None:
    if cleanup_errors:
        evidence = "; ".join(
            f"{stage}: {type(error).__name__}: {error}" for stage, error in cleanup_errors
        )
        if primary_error is not None:
            raise EvaluationIntegrityError(
                f"{operation} failed; cleanup also failed: {evidence}"
            ) from primary_error
        raise EvaluationIntegrityError(
            f"{operation} cleanup failed: {evidence}"
        ) from cleanup_errors[0][1]
    if primary_error is not None:
        raise primary_error


def _validate_windows_directory(info: _WinNodeInfo, path: str) -> None:
    if info.attributes & _WIN_FILE_ATTRIBUTE_REPARSE_POINT or info.reparse_tag:
        raise EvaluationIntegrityError(f"run path contains a reparse point: {path}")
    if info.file_type != _WIN_FILE_TYPE_DISK or not (
        info.attributes & _WIN_FILE_ATTRIBUTE_DIRECTORY
    ):
        raise EvaluationIntegrityError(f"run path component is not a directory: {path}")
    if info.link_count != 1:
        raise EvaluationIntegrityError(f"run path component has multiple hard links: {path}")


def _validate_windows_regular(info: _WinNodeInfo, artifact_path: str) -> None:
    if info.attributes & _WIN_FILE_ATTRIBUTE_REPARSE_POINT or info.reparse_tag:
        raise EvaluationIntegrityError(f"artifact path contains a reparse point: {artifact_path}")
    if info.file_type != _WIN_FILE_TYPE_DISK or (info.attributes & _WIN_FILE_ATTRIBUTE_DIRECTORY):
        raise EvaluationIntegrityError(f"artifact is not a regular file: {artifact_path}")
    if info.link_count != 1:
        raise EvaluationIntegrityError(f"artifact has multiple hard links: {artifact_path}")


def _windows_directory_access() -> int:
    return (
        _WIN_FILE_LIST_DIRECTORY | _WIN_FILE_TRAVERSE | _WIN_FILE_READ_ATTRIBUTES | _WIN_SYNCHRONIZE
    )


def _windows_directory_share() -> int:
    return _WIN_FILE_SHARE_READ | _WIN_FILE_SHARE_WRITE


def _windows_directory_identity(
    api: _Win32API,
    handle: int,
    display_path: str,
) -> _NodeIdentity:
    info = api.file_info(handle)
    _validate_windows_directory(info, display_path)
    return _windows_node_identity(info)


def _assert_windows_directory_identity(
    api: _Win32API,
    handle: int,
    display_path: str,
    expected: _NodeIdentity,
) -> None:
    current = _windows_directory_identity(api, handle, display_path)
    if not _same_filesystem_object(current, expected):
        raise EvaluationIntegrityError(f"directory identity changed: {display_path}")


def _open_windows_child_checked(
    api: _Win32API,
    parent_handle: int,
    parent_path: str,
    name: str,
    desired_access: int,
    share_mode: int,
    create_disposition: int,
    create_options: int,
    file_attributes: int,
) -> int:
    parent_identity = _windows_directory_identity(api, parent_handle, parent_path)
    try:
        handle = api.open_relative(
            parent_handle,
            name,
            desired_access,
            share_mode,
            create_disposition,
            create_options,
            file_attributes,
        )
    except BaseException as error:
        try:
            _assert_windows_directory_identity(
                api,
                parent_handle,
                parent_path,
                parent_identity,
            )
        except BaseException as identity_error:
            raise identity_error from error
        raise
    try:
        _assert_windows_directory_identity(
            api,
            parent_handle,
            parent_path,
            parent_identity,
        )
    except BaseException as validation_error:
        cleanup_errors: list[tuple[str, BaseException]] = []
        if create_disposition == _WIN_FILE_CREATE and desired_access & _WIN_DELETE:
            try:
                api.delete_handle(handle)
            except BaseException as error:
                cleanup_errors.append(("delete new child", error))
        try:
            api.close_handle(handle)
        except BaseException as error:
            cleanup_errors.append(("close new child", error))
        _raise_windows_operation_cleanup_errors(
            validation_error,
            cleanup_errors,
            operation="Windows child validation",
        )
        raise
    return handle


def _query_windows_names_checked(
    api: _Win32API,
    directory_handle: int,
    display_path: str,
) -> list[str]:
    identity = _windows_directory_identity(api, directory_handle, display_path)
    try:
        names = api.query_names(directory_handle)
    except BaseException as error:
        try:
            _assert_windows_directory_identity(api, directory_handle, display_path, identity)
        except BaseException as identity_error:
            raise identity_error from error
        raise
    _assert_windows_directory_identity(api, directory_handle, display_path, identity)
    return names


def _rename_windows_file_checked(
    api: _Win32API,
    handle: int,
    *,
    root_directory: int,
    root_path: str,
    new_name: str,
    replace: bool,
) -> None:
    identity = _windows_directory_identity(api, root_directory, root_path)
    try:
        api.rename_file(
            handle,
            root_directory=root_directory,
            new_name=new_name,
            replace=replace,
        )
    except BaseException as error:
        try:
            _assert_windows_directory_identity(api, root_directory, root_path, identity)
        except BaseException as identity_error:
            raise identity_error from error
        raise
    _assert_windows_directory_identity(api, root_directory, root_path, identity)


def _windows_readable_file_access() -> int:
    return _WIN_FILE_READ_DATA | _WIN_FILE_READ_ATTRIBUTES | _WIN_SYNCHRONIZE


def _windows_writable_file_access() -> int:
    return (
        _WIN_FILE_READ_DATA
        | _WIN_FILE_WRITE_DATA
        | _WIN_FILE_READ_ATTRIBUTES
        | _WIN_DELETE
        | _WIN_SYNCHRONIZE
    )


def _windows_root_flags() -> int:
    return _WIN_FILE_FLAG_BACKUP_SEMANTICS | _WIN_FILE_FLAG_OPEN_REPARSE_POINT


def _windows_directory_options() -> int:
    return (
        _WIN_FILE_SYNCHRONOUS_IO_NONALERT
        | _WIN_FILE_OPEN_FOR_BACKUP_INTENT
        | _WIN_FILE_OPEN_REPARSE_POINT
    )


def _windows_directory_create_options() -> int:
    return (
        _WIN_FILE_DIRECTORY_FILE
        | _WIN_FILE_SYNCHRONOUS_IO_NONALERT
        | _WIN_FILE_OPEN_FOR_BACKUP_INTENT
    )


def _windows_file_options() -> int:
    return (
        _WIN_FILE_NON_DIRECTORY_FILE
        | _WIN_FILE_SYNCHRONOUS_IO_NONALERT
        | _WIN_FILE_OPEN_REPARSE_POINT
    )


def _windows_node_options() -> int:
    return (
        _WIN_FILE_SYNCHRONOUS_IO_NONALERT
        | _WIN_FILE_OPEN_FOR_BACKUP_INTENT
        | _WIN_FILE_OPEN_REPARSE_POINT
    )


def _open_windows_directory(
    api: _Win32API,
    parent_handle: int,
    name: str,
    display_path: str,
    *,
    create: bool,
) -> _WindowsAnchor:
    disposition = _WIN_FILE_CREATE if create else _WIN_FILE_OPEN
    options = _windows_directory_create_options() if create else _windows_directory_options()
    parent_path = ntpath.dirname(display_path)
    try:
        handle = _open_windows_child_checked(
            api,
            parent_handle,
            parent_path,
            name,
            _windows_directory_access(),
            _windows_directory_share(),
            disposition,
            options,
            _WIN_FILE_ATTRIBUTE_DIRECTORY if create else 0,
        )
    except FileExistsError:
        if not create:
            raise
        handle = _open_windows_child_checked(
            api,
            parent_handle,
            parent_path,
            name,
            _windows_directory_access(),
            _windows_directory_share(),
            _WIN_FILE_OPEN,
            _windows_directory_options(),
            0,
        )
    try:
        info = api.file_info(handle)
        _validate_windows_directory(info, display_path)
        return _WindowsAnchor(
            name=name,
            display_path=display_path,
            parent_handle=parent_handle,
            handle=handle,
            identity=_windows_node_identity(info),
        )
    except BaseException:
        api.close_handle(handle)
        raise


class _WindowsRunStorage(_RunStorage):
    def __init__(
        self,
        root_path: Path,
        root_text: str,
        anchors: list[_WindowsAnchor],
        api: _Win32API,
    ) -> None:
        self.root_path = root_path
        self.failure_stage = "operation"
        self._root_text = root_text
        self._anchors = anchors
        self._root_handle = anchors[-1].handle
        self._api = api
        self._closed = False

    @classmethod
    def open(
        cls,
        run_dir: Path,
        *,
        initialize: bool,
        api: _Win32API,
    ) -> _WindowsRunStorage:
        try:
            raw_path = os.fspath(run_dir.expanduser())
        except (OSError, RuntimeError, TypeError, ValueError) as error:
            raise EvaluationIntegrityError("run path cannot be normalized safely") from error
        filesystem_root, root_text, parts = _split_windows_absolute_path(
            raw_path,
            require_child=True,
        )
        anchors: list[_WindowsAnchor] = []
        current_path = filesystem_root
        try:
            handle = api.open_root(
                filesystem_root,
                _windows_directory_access(),
                _windows_directory_share(),
                _windows_root_flags(),
            )
            try:
                info = api.file_info(handle)
                _validate_windows_directory(info, filesystem_root)
            except BaseException:
                api.close_handle(handle)
                raise
            anchors.append(
                _WindowsAnchor(
                    name=None,
                    display_path=filesystem_root,
                    parent_handle=None,
                    handle=handle,
                    identity=_windows_node_identity(info),
                )
            )
            missing_at: int | None = None
            for index, segment in enumerate(parts):
                current_path = ntpath.join(current_path, segment)
                try:
                    anchor = _open_windows_directory(
                        api,
                        anchors[-1].handle,
                        segment,
                        current_path,
                        create=False,
                    )
                except FileNotFoundError:
                    missing_at = index
                    break
                anchors.append(anchor)

            if missing_at is not None and not initialize:
                raise EvaluationIntegrityError("run directory does not exist")
            if initialize:
                try:
                    api.probe()
                except (NotImplementedError, OSError, TypeError) as error:
                    raise EvaluationIntegrityError(
                        "secure Windows storage capability probe failed"
                    ) from error
                for segment in parts[missing_at:] if missing_at is not None else ():
                    current_path = ntpath.join(anchors[-1].display_path, segment)
                    anchors.append(
                        _open_windows_directory(
                            api,
                            anchors[-1].handle,
                            segment,
                            current_path,
                            create=True,
                        )
                    )
                if _query_windows_names_checked(
                    api,
                    anchors[-1].handle,
                    anchors[-1].display_path,
                ):
                    raise EvaluationIntegrityError("run directory must be empty")
            elif missing_at is not None:
                raise EvaluationIntegrityError("run directory does not exist")

            storage = cls(Path(root_text), root_text, anchors, api)
            storage.assert_root_identity()
            return storage
        except BaseException:
            for anchor in reversed(anchors):
                with suppress(Exception):
                    api.close_handle(anchor.handle)
            raise

    def _ensure_open(self) -> None:
        if self._closed:
            raise EvaluationIntegrityError("run storage is closed")

    def assert_root_identity(self) -> None:
        self._ensure_open()
        for anchor in self._anchors:
            info = self._api.file_info(anchor.handle)
            _validate_windows_directory(info, anchor.display_path)
            opened_identity = _windows_node_identity(info)
            if not _same_filesystem_object(opened_identity, anchor.identity):
                raise EvaluationIntegrityError("run directory identity changed")
            if anchor.parent_handle is None:
                continue
            assert anchor.name is not None
            reopened = _open_windows_child_checked(
                self._api,
                anchor.parent_handle,
                ntpath.dirname(anchor.display_path),
                anchor.name,
                _windows_directory_access(),
                _windows_directory_share(),
                _WIN_FILE_OPEN,
                _windows_directory_options(),
                0,
            )
            try:
                info = self._api.file_info(reopened)
                _validate_windows_directory(info, anchor.display_path)
                if not _same_filesystem_object(_windows_node_identity(info), anchor.identity):
                    raise EvaluationIntegrityError("run directory path identity changed")
            finally:
                self._api.close_handle(reopened)

    def _assert_relative_bindings(self, bindings: tuple[_WindowsAnchor, ...]) -> None:
        for binding in bindings:
            info = self._api.file_info(binding.handle)
            _validate_windows_directory(info, binding.display_path)
            if not _same_filesystem_object(_windows_node_identity(info), binding.identity):
                raise EvaluationIntegrityError("artifact parent identity changed")
            assert binding.name is not None and binding.parent_handle is not None
            reopened = _open_windows_child_checked(
                self._api,
                binding.parent_handle,
                ntpath.dirname(binding.display_path),
                binding.name,
                _windows_directory_access(),
                _windows_directory_share(),
                _WIN_FILE_OPEN,
                _windows_directory_options(),
                0,
            )
            try:
                reopened_info = self._api.file_info(reopened)
                _validate_windows_directory(reopened_info, binding.display_path)
                if not _same_filesystem_object(
                    _windows_node_identity(reopened_info), binding.identity
                ):
                    raise EvaluationIntegrityError("artifact parent path identity changed")
            finally:
                self._api.close_handle(reopened)

    @contextmanager
    def _artifact_parent(
        self,
        artifact_path: str,
        *,
        create: bool,
    ) -> Iterator[tuple[int, str, tuple[_WindowsAnchor, ...]]]:
        relative = _validate_relative_path(artifact_path)
        bindings: list[_WindowsAnchor] = []
        current_handle = self._root_handle
        current_path = self._root_text
        try:
            for segment in relative.parts[:-1]:
                current_path = ntpath.join(current_path, segment)
                try:
                    binding = _open_windows_directory(
                        self._api,
                        current_handle,
                        segment,
                        current_path,
                        create=False,
                    )
                except FileNotFoundError:
                    if not create:
                        raise
                    binding = _open_windows_directory(
                        self._api,
                        current_handle,
                        segment,
                        current_path,
                        create=True,
                    )
                bindings.append(binding)
                current_handle = binding.handle
            self._assert_relative_bindings(tuple(bindings))
            yield current_handle, relative.name, tuple(bindings)
        finally:
            for binding in reversed(bindings):
                self._api.close_handle(binding.handle)

    def _read_leaf(self, parent_handle: int, name: str, artifact_path: str) -> bytes:
        parent_path = ntpath.dirname(
            ntpath.join(self._root_text, *PurePosixPath(artifact_path).parts)
        )
        handle = _open_windows_child_checked(
            self._api,
            parent_handle,
            parent_path,
            name,
            _windows_readable_file_access(),
            _WIN_FILE_SHARE_READ,
            _WIN_FILE_OPEN,
            _windows_file_options(),
            0,
        )
        try:
            before = self._api.file_info(handle)
            _validate_windows_regular(before, artifact_path)
            data = self._api.read_file(handle)
            after = self._api.file_info(handle)
            if _windows_node_identity(before) != _windows_node_identity(after):
                raise EvaluationIntegrityError(f"artifact changed while reading: {artifact_path}")
            reopened = _open_windows_child_checked(
                self._api,
                parent_handle,
                parent_path,
                name,
                _windows_readable_file_access(),
                _WIN_FILE_SHARE_READ,
                _WIN_FILE_OPEN,
                _windows_file_options(),
                0,
            )
            try:
                named = self._api.file_info(reopened)
                _validate_windows_regular(named, artifact_path)
                if not _same_filesystem_object(
                    _windows_node_identity(named), _windows_node_identity(after)
                ):
                    raise EvaluationIntegrityError(
                        f"artifact path identity changed while reading: {artifact_path}"
                    )
            finally:
                self._api.close_handle(reopened)
            return data
        finally:
            self._api.close_handle(handle)

    def read_artifact(self, artifact_path: str) -> bytes:
        self.failure_stage = f"artifact read ({artifact_path})"
        self.assert_root_identity()
        try:
            with self._artifact_parent(artifact_path, create=False) as (
                parent,
                name,
                bindings,
            ):
                data = self._read_leaf(parent, name, artifact_path)
                self._assert_relative_bindings(bindings)
        except FileNotFoundError as error:
            raise EvaluationIntegrityError(f"artifact is missing: {artifact_path}") from error
        self.assert_root_identity()
        return data

    def read_optional_artifact(self, artifact_path: str) -> bytes | None:
        self.failure_stage = f"optional artifact read ({artifact_path})"
        self.assert_root_identity()
        try:
            with self._artifact_parent(artifact_path, create=False) as (
                parent,
                name,
                bindings,
            ):
                data = self._read_leaf(parent, name, artifact_path)
                self._assert_relative_bindings(bindings)
        except FileNotFoundError:
            data = None
        self.assert_root_identity()
        return data

    def atomic_write(
        self,
        artifact_path: str,
        data: bytes,
        *,
        mutable: bool,
    ) -> None:
        self.failure_stage = f"artifact write ({artifact_path})"
        self.assert_root_identity()
        with self._artifact_parent(artifact_path, create=True) as (
            parent_handle,
            name,
            bindings,
        ):
            try:
                existing = self._read_leaf(parent_handle, name, artifact_path)
            except FileNotFoundError:
                existing = None
            self._assert_relative_bindings(bindings)
            self.assert_root_identity()
            if existing is not None:
                if existing == data:
                    self._assert_relative_bindings(bindings)
                    self.assert_root_identity()
                    return
                if not mutable:
                    raise EvaluationIntegrityError(f"immutable artifact differs: {artifact_path}")

            temporary_name = f".rh-{uuid.uuid4().hex}.tmp"
            handle: int | None = None
            renamed = False
            primary_error: BaseException | None = None
            cleanup_errors: list[tuple[str, BaseException]] = []
            try:
                parent_path = ntpath.dirname(
                    ntpath.join(self._root_text, *PurePosixPath(artifact_path).parts)
                )
                handle = _open_windows_child_checked(
                    self._api,
                    parent_handle,
                    parent_path,
                    temporary_name,
                    _windows_writable_file_access(),
                    0,
                    _WIN_FILE_CREATE,
                    _windows_file_options(),
                    _WIN_FILE_ATTRIBUTE_NORMAL,
                )
                _validate_windows_regular(self._api.file_info(handle), artifact_path)
                self._api.write_file(handle, data)
                self._api.flush_file(handle)
                _validate_windows_regular(self._api.file_info(handle), artifact_path)
                self._assert_relative_bindings(bindings)
                self.assert_root_identity()
                _rename_windows_file_checked(
                    self._api,
                    handle,
                    root_directory=parent_handle,
                    root_path=parent_path,
                    new_name=name,
                    replace=mutable and existing is not None,
                )
                renamed = True
                renamed_info = self._api.file_info(handle)
                _validate_windows_regular(renamed_info, artifact_path)
                self._assert_relative_bindings(bindings)
                self.assert_root_identity()
            except BaseException as error:
                primary_error = error
            finally:
                if handle is not None:
                    if not renamed:
                        try:
                            self._api.delete_handle(handle)
                        except BaseException as error:
                            cleanup_errors.append(("dispose temporary artifact", error))
                    try:
                        self._api.close_handle(handle)
                    except BaseException as error:
                        cleanup_stage = (
                            "close renamed artifact" if renamed else "close temporary artifact"
                        )
                        cleanup_errors.append((cleanup_stage, error))
            _raise_windows_operation_cleanup_errors(
                primary_error,
                cleanup_errors,
                operation=f"Windows artifact write ({artifact_path})",
            )

    def scan_inventory(self) -> dict[str, _NodeIdentity]:
        self.failure_stage = "inventory scan"
        self.assert_root_identity()
        inventory = self._scan_directory(self._root_handle, PurePosixPath())
        self.assert_root_identity()
        return inventory

    def _scan_directory(
        self,
        directory_handle: int,
        prefix: PurePosixPath,
    ) -> dict[str, _NodeIdentity]:
        inventory: dict[str, _NodeIdentity] = {}
        directory_path = ntpath.join(self._root_text, *prefix.parts)
        initial_names = sorted(
            _query_windows_names_checked(self._api, directory_handle, directory_path),
            key=str.casefold,
        )
        if len({name.casefold() for name in initial_names}) != len(initial_names):
            raise EvaluationIntegrityError("run inventory contains ambiguous Windows names")
        for name in initial_names:
            _windows_child_name(name)
            relative = prefix / name
            relative_text = relative.as_posix()
            _validate_relative_path(relative_text)
            try:
                child_handle = _open_windows_child_checked(
                    self._api,
                    directory_handle,
                    directory_path,
                    name,
                    _windows_directory_access(),
                    _windows_directory_share(),
                    _WIN_FILE_OPEN,
                    _windows_node_options(),
                    0,
                )
            except FileNotFoundError as error:
                raise EvaluationIntegrityError(
                    f"run inventory changed while scanning: {relative_text}"
                ) from error
            try:
                info = self._api.file_info(child_handle)
                if info.attributes & _WIN_FILE_ATTRIBUTE_REPARSE_POINT or info.reparse_tag:
                    raise EvaluationIntegrityError(
                        f"run inventory contains a reparse point: {relative_text}"
                    )
                identity = _windows_node_identity(info)
                if info.attributes & _WIN_FILE_ATTRIBUTE_DIRECTORY:
                    _validate_windows_directory(info, relative_text)
                    inventory[f"{relative_text}/"] = identity
                    inventory.update(self._scan_directory(child_handle, relative))
                else:
                    _validate_windows_regular(info, relative_text)
                    inventory[relative_text] = identity
                if _windows_node_identity(self._api.file_info(child_handle)) != identity:
                    raise EvaluationIntegrityError(
                        f"run inventory changed while scanning: {relative_text}"
                    )
                reopened = _open_windows_child_checked(
                    self._api,
                    directory_handle,
                    directory_path,
                    name,
                    _windows_directory_access(),
                    _windows_directory_share(),
                    _WIN_FILE_OPEN,
                    _windows_node_options(),
                    0,
                )
                try:
                    named_info = self._api.file_info(reopened)
                    if info.attributes & _WIN_FILE_ATTRIBUTE_DIRECTORY:
                        _validate_windows_directory(named_info, relative_text)
                    else:
                        _validate_windows_regular(named_info, relative_text)
                    if not _same_filesystem_object(_windows_node_identity(named_info), identity):
                        raise EvaluationIntegrityError(
                            f"run inventory path identity changed: {relative_text}"
                        )
                finally:
                    self._api.close_handle(reopened)
            finally:
                self._api.close_handle(child_handle)
        final_names = sorted(
            _query_windows_names_checked(self._api, directory_handle, directory_path),
            key=str.casefold,
        )
        if final_names != initial_names:
            raise EvaluationIntegrityError("run inventory changed while scanning")
        return inventory

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for anchor in reversed(self._anchors):
            with suppress(Exception):
                self._api.close_handle(anchor.handle)


def _storage_platform() -> str:
    return os.name


def _new_win32_api() -> _Win32API:
    return _CtypesWin32API()


@contextmanager
def _open_run_storage(run_dir: Path, *, initialize: bool = False) -> Iterator[_RunStorage]:
    storage: _RunStorage | None = None
    try:
        platform = _storage_platform()
        if platform == "posix":
            storage = _PosixRunStorage.open(run_dir, initialize=initialize)
        elif platform == "nt":
            storage = _WindowsRunStorage.open(
                run_dir,
                initialize=initialize,
                api=_new_win32_api(),
            )
        else:
            raise EvaluationIntegrityError(
                f"secure evaluation storage is unavailable on platform: {platform}"
            )
        yield storage
    except EvaluationIntegrityError:
        raise
    except (NotImplementedError, OSError, TypeError) as error:
        stage = "open" if storage is None else storage.failure_stage
        raise EvaluationIntegrityError(f"evaluation storage {stage} failed") from error
    finally:
        if storage is not None:
            storage.close()


def _ensure_python_json_source(value: object, *, location: str = "value") -> None:
    """Reject values that JSON-mode serialization could silently launder."""
    if value is None or type(value) in {str, bool, int}:
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise EvaluationIntegrityError(f"{location} contains a non-finite number")
        return
    if isinstance(value, (Enum, date, datetime)):
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _ensure_python_json_source(item, location=f"{location}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if type(key) is not str and not isinstance(key, Enum):
                raise EvaluationIntegrityError(f"{location} has a non-string key")
            _ensure_python_json_source(item, location=f"{location}.{key}")
        return
    raise EvaluationIntegrityError(
        f"{location} is not an ordinary JSON-compatible value: {type(value).__name__}"
    )


def _ensure_ordinary_json(value: object, *, location: str = "value") -> None:
    if value is None or type(value) in {str, bool, int}:
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise EvaluationIntegrityError(f"{location} contains a non-finite number")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _ensure_ordinary_json(item, location=f"{location}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if type(key) is not str:
                raise EvaluationIntegrityError(f"{location} has a non-string key")
            _ensure_ordinary_json(item, location=f"{location}.{key}")
        return
    raise EvaluationIntegrityError(f"{location} is not ordinary JSON: {type(value).__name__}")


def _strict_model_payload(
    value: _ModelT,
    model_type: type[_ModelT],
) -> tuple[_ModelT, dict[str, object]]:
    """Revalidate an entire model before its JSON bytes can be hashed or written."""
    if not isinstance(value, model_type):
        raise EvaluationIntegrityError(f"expected {model_type.__name__}")
    try:
        python_payload = value.model_dump(mode="python", warnings="error")
        _ensure_python_json_source(python_payload, location=model_type.__name__)
        strict_snapshot = model_type.model_validate(python_payload, strict=True)
        json_payload = strict_snapshot.model_dump(mode="json", warnings="error")
        _ensure_ordinary_json(json_payload, location=model_type.__name__)
        ordinary_snapshot = model_type.model_validate(json_payload)
        final_payload = ordinary_snapshot.model_dump(mode="json", warnings="error")
        _ensure_ordinary_json(final_payload, location=model_type.__name__)
    except (TypeError, ValidationError, ValueError) as error:
        raise EvaluationIntegrityError(
            f"malformed {model_type.__name__} persistence snapshot"
        ) from error
    return ordinary_snapshot, cast(dict[str, object], final_payload)


def _model_bytes(value: _ModelT, model_type: type[_ModelT]) -> tuple[_ModelT, bytes]:
    snapshot, payload = _strict_model_payload(value, model_type)
    return snapshot, canonical_json_bytes(payload)


def _ordinary_json_bytes(value: object) -> bytes:
    _ensure_ordinary_json(value)
    return canonical_json_bytes(value)


def _parse_json_bytes(data: bytes, *, location: str) -> object:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvaluationIntegrityError(f"{location} is malformed JSON") from error
    _ensure_ordinary_json(value, location=location)
    if canonical_json_bytes(value) != data:
        raise EvaluationIntegrityError(f"{location} bytes are not canonical JSON")
    return value


def _schema_unsupported(location: str) -> EvaluationIntegrityError:
    return EvaluationIntegrityError(
        f"EVALUATION_ARTIFACT_SCHEMA_UNSUPPORTED: {location}"
    )


def _require_artifact_schema(value: object, *, location: str) -> None:
    if not isinstance(value, dict):
        return
    schema = value.get("schema_version")
    if schema is not None and schema != EVALUATION_ARTIFACT_SCHEMA_VERSION:
        raise _schema_unsupported(location)


def _require_candidate_grade_schema(value: object, *, location: str) -> None:
    _require_artifact_schema(value, location=location)


def _require_resolved_grade_schemas(value: object, *, location: str) -> None:
    _require_artifact_schema(value, location=location)
    if not isinstance(value, dict):
        return
    for key in ("grade", "original_grader_1", "original_grader_2"):
        if key in value:
            _require_candidate_grade_schema(value[key], location=location)


def _require_score_input_schemas(value: object, *, location: str) -> None:
    if (
        isinstance(value, dict)
        and value.get("schema_version") != SCORE_INPUT_SCHEMA_VERSION
    ):
        raise EvaluationIntegrityError(
            f"EVALUATION_SCORE_INPUT_SCHEMA_UNSUPPORTED: {location}"
        )
    if isinstance(value, dict) and "resolved_grade" in value:
        _require_resolved_grade_schemas(value["resolved_grade"], location=location)


def _require_result_schemas(value: object, *, location: str) -> None:
    _require_artifact_schema(value, location=location)
    if not isinstance(value, dict):
        return
    reports = value.get("reports")
    if isinstance(reports, list):
        for report in reports:
            _require_artifact_schema(report, location=location)


def _load_model_bytes(
    data: bytes,
    model_type: type[_ModelT],
    *,
    location: str,
) -> _ModelT:
    payload = _parse_json_bytes(data, location=location)
    if model_type is AttorneyEvaluationResult:
        _require_result_schemas(payload, location=location)
    elif model_type in {CandidateGrade, ReportEvaluation}:
        _require_artifact_schema(payload, location=location)
    try:
        value = model_type.model_validate(payload)
    except (ValidationError, ValueError, TypeError) as error:
        raise EvaluationIntegrityError(
            f"{location} is not a valid {model_type.__name__}"
        ) from error
    snapshot, snapshot_bytes = _model_bytes(value, model_type)
    if snapshot_bytes != data:
        raise EvaluationIntegrityError(f"{location} changed during strict validation")
    return snapshot


def _validate_relative_path(artifact_path: str) -> PurePosixPath:
    try:
        ArtifactRecord(
            artifact_path=artifact_path,
            artifact_hash="0" * 64,
        )
    except (ValidationError, ValueError, TypeError) as error:
        raise EvaluationIntegrityError("unsafe artifact path") from error
    return PurePosixPath(artifact_path)


def _atomic_write(
    run_dir: Path | _RunStorage,
    artifact_path: str,
    data: bytes,
    *,
    mutable: bool = False,
) -> None:
    if isinstance(run_dir, _RunStorage):
        run_dir.atomic_write(artifact_path, data, mutable=mutable)
        return
    with _open_run_storage(run_dir) as storage:
        storage.atomic_write(artifact_path, data, mutable=mutable)


def _read_artifact(run_dir: Path | _RunStorage, artifact_path: str) -> bytes:
    if isinstance(run_dir, _RunStorage):
        return run_dir.read_artifact(artifact_path)
    with _open_run_storage(run_dir) as storage:
        return storage.read_artifact(artifact_path)


def _artifact_record(artifact_path: str, data: bytes) -> ArtifactRecord:
    # The bytes must already have crossed a model or ordinary-JSON validation boundary.
    payload = {
        "artifact_path": artifact_path,
        "artifact_hash": sha256_digest(data),
    }
    try:
        return ArtifactRecord.model_validate(payload)
    except (ValidationError, ValueError, TypeError) as error:
        raise EvaluationIntegrityError("invalid artifact record") from error


def _manifest_bytes(manifest: EvaluationManifest) -> tuple[EvaluationManifest, bytes]:
    return _model_bytes(manifest, EvaluationManifest)


def _load_manifest(run_dir: Path | _RunStorage) -> EvaluationManifest:
    data = _read_artifact(run_dir, _MANIFEST_PATH)
    payload = _parse_json_bytes(data, location=_MANIFEST_PATH)
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != EVALUATION_ARTIFACT_SCHEMA_VERSION
    ):
        raise EvaluationIntegrityError("EVALUATION_ARTIFACT_SCHEMA_UNSUPPORTED: run-manifest.json")
    return _load_model_bytes(data, EvaluationManifest, location=_MANIFEST_PATH)


def _write_manifest(run_dir: Path | _RunStorage, manifest: EvaluationManifest) -> None:
    if not isinstance(run_dir, _RunStorage):
        with _open_run_storage(run_dir) as storage:
            _write_manifest(storage, manifest)
        return
    snapshot, data = _manifest_bytes(manifest)
    mutable = True
    existing_bytes = run_dir.read_optional_artifact(_MANIFEST_PATH)
    if existing_bytes is not None:
        existing = _load_model_bytes(
            existing_bytes,
            EvaluationManifest,
            location=_MANIFEST_PATH,
        )
        if existing.terminal_status is not None:
            mutable = False
    _atomic_write(run_dir, _MANIFEST_PATH, data, mutable=mutable)
    # Keep the fully revalidated snapshot alive through the write boundary.
    if snapshot.manifest_fingerprint != manifest.manifest_fingerprint:
        raise EvaluationIntegrityError("manifest changed during persistence")


def _serialize_grade_resolution(value: GradeResolution) -> dict[str, object]:
    return {
        "kind": value.kind,
        "subject_id": value.subject_id,
        "grader_1": _strict_model_payload(value.grader_1, GradeAlternative)[1],
        "grader_2": _strict_model_payload(value.grader_2, GradeAlternative)[1],
        "selected": _strict_model_payload(value.selected, GradeAlternative)[1],
        "dispute": (
            None if value.dispute is None else _strict_model_payload(value.dispute, GradeDispute)[1]
        ),
        "referee": (
            None
            if value.referee is None
            else _strict_model_payload(value.referee, RefereeDecision)[1]
        ),
    }


def _serialize_resolved_grade(
    sealed_ledger: SealedLedger,
    resolved: ResolvedGrade,
) -> dict[str, object]:
    snapshot = strict_resolved_grade_snapshot(sealed_ledger, resolved)
    payload: dict[str, object] = {
        "schema_version": EVALUATION_ARTIFACT_SCHEMA_VERSION,
        "grade": _strict_model_payload(snapshot.grade, CandidateGrade)[1],
        "audit": [_serialize_grade_resolution(resolution) for resolution in snapshot.audit],
        "resolution_fingerprint": snapshot.resolution_fingerprint,
        "original_grader_1": _strict_model_payload(snapshot.original_grader_1, CandidateGrade)[1],
        "original_grader_2": _strict_model_payload(snapshot.original_grader_2, CandidateGrade)[1],
        "referee_decisions": [
            _strict_model_payload(decision, RefereeDecision)[1]
            for decision in snapshot.referee_decisions
        ],
    }
    _ensure_ordinary_json(payload, location="ResolvedGrade")
    return payload


def _derive_requirement_matrix(
    sealed_ledger: SealedLedger,
    resolved_by_label: dict[Literal["A", "B"], ResolvedGrade],
) -> RequirementMatrix:
    sealed = _strict_model_payload(sealed_ledger, SealedLedger)[0]
    if set(resolved_by_label) not in ({"A"}, {"A", "B"}):
        raise EvaluationIntegrityError("requirement matrix has invalid report labels")
    grades: dict[Literal["A", "B"], dict[str, EntryGrade]] = {}
    for label, resolved in resolved_by_label.items():
        snapshot = strict_resolved_grade_snapshot(sealed, resolved)
        if snapshot.anonymous_label != label:
            raise EvaluationIntegrityError("requirement matrix report label mismatch")
        grades[label] = {grade.ledger_id: grade for grade in snapshot.entry_grades}

    def report_finding(
        label: Literal["A", "B"], ledger_id: str
    ) -> RequirementReportFinding:
        try:
            grade = grades[label][ledger_id]
        except KeyError as error:
            raise EvaluationIntegrityError(
                "requirement matrix is missing a resolved ledger grade"
            ) from error
        return RequirementReportFinding(
            anonymous_label=label,
            disposition=grade.disposition,
            report_location=grade.report_location,
            finding_codes=list(grade.finding_codes),
            rationale=grade.rationale,
        )

    rows = [
        RequirementMatrixRow(
            ledger_id=entry.ledger_id,
            walk_order=entry.walk_order,
            category=entry.category,
            materiality=entry.materiality,
            proposition=entry.proposition,
            citations=[
                RequirementCitationPin(
                    source_id=citation.source_id,
                    start_char=citation.start_char,
                    end_char=citation.end_char,
                )
                for citation in entry.citations
            ],
            report_a=report_finding("A", entry.ledger_id),
            report_b=(
                report_finding("B", entry.ledger_id) if "B" in resolved_by_label else None
            ),
        )
        for entry in sorted(
            sealed.ledger.entries,
            key=lambda item: (item.walk_order, item.ledger_id),
        )
    ]
    return _strict_model_payload(
        RequirementMatrix(available=True, unavailable_reason=None, rows=rows),
        RequirementMatrix,
    )[0]


def _dict_value(value: object, *, location: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(type(key) is str for key in value):
        raise EvaluationIntegrityError(f"{location} must be an object")
    return cast(dict[str, object], value)


def _list_value(value: object, *, location: str) -> list[object]:
    if not isinstance(value, list):
        raise EvaluationIntegrityError(f"{location} must be an array")
    return cast(list[object], value)


def _model_from_payload(
    payload: object,
    model_type: type[_ModelT],
    *,
    location: str,
) -> _ModelT:
    try:
        value = model_type.model_validate_json(
            _ordinary_json_bytes(payload),
            strict=True,
        )
    except (ValidationError, ValueError, TypeError) as error:
        raise EvaluationIntegrityError(f"{location} is malformed") from error
    return _strict_model_payload(value, model_type)[0]


def _deserialize_grade_resolution(payload: object) -> GradeResolution:
    value = _dict_value(payload, location="grade resolution")
    expected = {"kind", "subject_id", "grader_1", "grader_2", "selected", "dispute", "referee"}
    if set(value) != expected:
        raise EvaluationIntegrityError("grade resolution has an unexpected shape")
    kind = value["kind"]
    subject_id = value["subject_id"]
    if kind not in {"entry_grade", "out_of_ledger_claim", "narrative_score"}:
        raise EvaluationIntegrityError("grade resolution kind is invalid")
    if type(subject_id) is not str or not subject_id:
        raise EvaluationIntegrityError("grade resolution subject is invalid")
    dispute = value["dispute"]
    referee = value["referee"]
    return GradeResolution(
        kind=kind,
        subject_id=subject_id,
        grader_1=_model_from_payload(
            value["grader_1"], GradeAlternative, location="grader_1 alternative"
        ),
        grader_2=_model_from_payload(
            value["grader_2"], GradeAlternative, location="grader_2 alternative"
        ),
        selected=_model_from_payload(
            value["selected"], GradeAlternative, location="selected alternative"
        ),
        dispute=(
            None
            if dispute is None
            else _model_from_payload(dispute, GradeDispute, location="grade dispute")
        ),
        referee=(
            None
            if referee is None
            else _model_from_payload(referee, RefereeDecision, location="grade referee")
        ),
    )


def _deserialize_resolved_grade(
    payload: object,
    sealed_ledger: SealedLedger,
    *,
    location: str = "resolved grade",
) -> ResolvedGrade:
    _require_resolved_grade_schemas(payload, location=location)
    value = _dict_value(payload, location="resolved grade")
    expected = {
        "schema_version",
        "grade",
        "audit",
        "resolution_fingerprint",
        "original_grader_1",
        "original_grader_2",
        "referee_decisions",
    }
    if set(value) != expected:
        raise EvaluationIntegrityError("resolved grade has an unexpected shape")
    fingerprint = value["resolution_fingerprint"]
    if type(fingerprint) is not str:
        raise EvaluationIntegrityError("resolved grade fingerprint must be a string")
    resolved = ResolvedGrade(
        grade=_model_from_payload(value["grade"], CandidateGrade, location="resolved grade"),
        audit=tuple(
            _deserialize_grade_resolution(item)
            for item in _list_value(value["audit"], location="resolved audit")
        ),
        resolution_fingerprint=fingerprint,
        original_grader_1=_model_from_payload(
            value["original_grader_1"], CandidateGrade, location="original grader 1"
        ),
        original_grader_2=_model_from_payload(
            value["original_grader_2"], CandidateGrade, location="original grader 2"
        ),
        referee_decisions=tuple(
            _model_from_payload(item, RefereeDecision, location="referee decision")
            for item in _list_value(value["referee_decisions"], location="referee decisions")
        ),
    )
    return strict_resolved_grade_snapshot(sealed_ledger, resolved)


def _score_inputs_payload(
    sealed_ledger: SealedLedger,
    resolved_grade: ResolvedGrade,
    deterministic_checks: DeterministicChecks,
    rubric: EvaluationRubric,
    source_record: object,
) -> dict[str, object]:
    sealed = _strict_model_payload(sealed_ledger, SealedLedger)[0]
    checks, checks_payload = _strict_model_payload(deterministic_checks, DeterministicChecks)
    rubric_snapshot, rubric_payload = _strict_model_payload(rubric, EvaluationRubric)
    resolved_payload = _serialize_resolved_grade(sealed, resolved_grade)
    source_record_payload = json.loads(
        _ordinary_json_bytes(source_record).decode("utf-8")
    )
    payload: dict[str, object] = {
        "schema_version": SCORE_INPUT_SCHEMA_VERSION,
        "anonymous_label": checks.anonymous_label,
        "sealed_ledger": _strict_model_payload(sealed, SealedLedger)[1],
        "resolved_grade": resolved_payload,
        "deterministic_checks": checks_payload,
        "rubric": rubric_payload,
        "source_record": source_record_payload,
    }
    _ensure_ordinary_json(payload, location="ReportScoreInputs")
    if rubric_snapshot.model_dump(mode="json") != RUBRIC_V1.model_dump(mode="json"):
        raise EvaluationIntegrityError("score inputs must use the canonical rubric")
    return payload


def _score_inputs_from_payload(
    payload: object,
    *,
    location: str = "score inputs",
) -> ReportScoreInputs:
    _require_score_input_schemas(payload, location=location)
    value = _dict_value(payload, location="score inputs")
    if set(value) != {
        "schema_version",
        "anonymous_label",
        "sealed_ledger",
        "resolved_grade",
        "deterministic_checks",
        "rubric",
        "source_record",
    }:
        raise EvaluationIntegrityError("score inputs have an unexpected shape")
    sealed = _model_from_payload(
        value["sealed_ledger"], SealedLedger, location="score input sealed ledger"
    )
    checks = _model_from_payload(
        value["deterministic_checks"],
        DeterministicChecks,
        location="score input deterministic checks",
    )
    rubric = _model_from_payload(value["rubric"], EvaluationRubric, location="score input rubric")
    if rubric.model_dump(mode="json") != RUBRIC_V1.model_dump(mode="json"):
        raise EvaluationIntegrityError("score inputs do not retain the canonical rubric")
    if value["anonymous_label"] != checks.anonymous_label:
        raise EvaluationIntegrityError("score input anonymous label mismatch")
    resolved = _deserialize_resolved_grade(
        value["resolved_grade"], sealed, location=location
    )
    source_record = _ordinary_json_bytes(value["source_record"])
    return ReportScoreInputs(sealed, resolved, checks, source_record)


def _scan_run_files(run_dir: Path | _RunStorage) -> set[str]:
    if isinstance(run_dir, _RunStorage):
        return run_dir.scan_files()
    with _open_run_storage(run_dir) as storage:
        return storage.scan_files()


def _scan_run_inventory(
    run_dir: Path | _RunStorage,
) -> dict[str, _NodeIdentity]:
    if isinstance(run_dir, _RunStorage):
        return run_dir.scan_inventory()
    with _open_run_storage(run_dir) as storage:
        return storage.scan_inventory()


def _expected_request_fingerprint(request: JudgeRequest) -> str:
    payload = request.model_dump(mode="json", exclude={"request_fingerprint"})
    _ensure_ordinary_json(payload, location="JudgeRequest fingerprint")
    return sha256_digest(canonical_json_bytes(payload))


def _prompt_fingerprint(request: JudgeRequest) -> str:
    payload = {
        "system_instructions": request.system_instructions,
        "json_schema": request.json_schema,
    }
    _ensure_ordinary_json(payload, location="judge prompt")
    return sha256_digest(canonical_json_bytes(payload))


def _result_fingerprint(result: AttorneyEvaluationResult) -> str:
    payload = result.model_dump(mode="json", exclude={"result_fingerprint"})
    _ensure_ordinary_json(payload, location="evaluation result")
    return sha256_digest(canonical_json_bytes(payload))


def _derive_deterministic_checks(
    candidate: CandidateReport,
    label: str,
) -> DeterministicChecks:
    if label not in {"A", "B"}:
        raise EvaluationIntegrityError("deterministic-check label is invalid")
    issues: list[EvaluationIssue] = []
    if candidate.bundle_json is None:
        issues.append(
            EvaluationIssue(
                code="NATIVE_BUNDLE_CONTROLS_UNAVAILABLE",
                severity=IssueSeverity.WARNING,
                message=(
                    "No native Regulatory Harvest bundle controls were supplied; "
                    "the report remains subject to source-ledger grading."
                ),
            )
        )
    else:
        # Native-bundle validation belongs to the optional research stack.  Keep
        # it off the evaluation module's import path for report-only runs.
        from regulatory_harvest.models.bundle import ResearchBundle
        from regulatory_harvest.validation.bundle import validate_bundle

        try:
            bundle = ResearchBundle.model_validate(candidate.bundle_json)
        except (TypeError, ValidationError, ValueError):
            issues.append(
                EvaluationIssue(
                    code="NATIVE_BUNDLE_MALFORMED",
                    severity=IssueSeverity.ERROR,
                    message=(
                        "The supplied native Regulatory Harvest bundle does not "
                        "satisfy the public bundle contract."
                    ),
                )
            )
        else:
            validation = validate_bundle(bundle, require_bundle_hash=True)
            severity = {
                IssueLevel.ERROR: IssueSeverity.ERROR,
                IssueLevel.WARNING: IssueSeverity.WARNING,
                IssueLevel.INFO: IssueSeverity.INFO,
            }
            issues.extend(
                EvaluationIssue(
                    code=issue.code,
                    severity=severity[issue.level],
                    message=f"Native bundle validation finding: {issue.code}.",
                )
                for issue in validation.issues
            )
    critical_codes = list(
        dict.fromkeys(issue.code for issue in issues if issue.severity is IssueSeverity.ERROR)
    )
    checks = DeterministicChecks(
        anonymous_label=cast(Literal["A", "B"], label),
        valid=not critical_codes,
        critical_codes=critical_codes,
        issues=issues,
    )
    return _strict_model_payload(checks, DeterministicChecks)[0]


def _derive_source_spans(
    envelope: CaseEnvelope,
    sealed_ledger: SealedLedger,
) -> list[dict[str, object]]:
    sources = {source.source_id: source for source in envelope.case.sources}
    spans: list[dict[str, object]] = []
    seen: set[tuple[str, int, int]] = set()
    for entry in sealed_ledger.ledger.entries:
        for citation in entry.citations:
            key = (citation.source_id, citation.start_char, citation.end_char)
            if key in seen:
                continue
            seen.add(key)
            source = sources[citation.source_id]
            spans.append(
                {
                    "source_id": citation.source_id,
                    "start_char": citation.start_char,
                    "end_char": citation.end_char,
                    "quote": source.normalized_text[citation.start_char : citation.end_char],
                }
            )
    return spans


def _logical_call_groups(
    manifest: EvaluationManifest,
) -> list[list[JudgeCallRecord]]:
    groups: list[list[JudgeCallRecord]] = []
    for call in manifest.judge_calls:
        if not groups or groups[-1][0].call_id != call.call_id:
            groups.append([call])
        else:
            groups[-1].append(call)
    for index, group in enumerate(groups):
        if len(group) not in {1, 2}:
            raise EvaluationIntegrityError("judge transition has too many attempts")
        if [call.attempt for call in group] != list(range(1, len(group) + 1)):
            raise EvaluationIntegrityError("judge transition attempts are not contiguous")
        if len(group) == 2 and group[0].state != "failed":
            raise EvaluationIntegrityError("judge retry lacks its failed first attempt")
        if any(call.retry_count != call.attempt - 1 for call in group):
            raise EvaluationIntegrityError("judge transition call retry metadata is inconsistent")
        if len(group) == 2 and group[0].terminal_status != "failed":
            raise EvaluationIntegrityError("judge transition first failure is not retryable")
        if len(group) == 2:
            first_request = _read_retry_identity(group[0])
            second_request = _read_retry_identity(group[1])
            if first_request != second_request:
                raise EvaluationIntegrityError(
                    "judge retry transition changed the exact request packet"
                )
        if index < len(groups) - 1 and group[-1].state != "completed":
            raise EvaluationIntegrityError(
                "judge transition advanced before its prior call completed"
            )
    retry_count = sum(len(group) - 1 for group in groups)
    if manifest.retry_count != retry_count:
        raise EvaluationIntegrityError("judge transition retry count mismatch")
    return groups


def _read_retry_identity(call: JudgeCallRecord) -> tuple[object, ...]:
    return (
        call.call_id,
        call.operation,
        call.anonymous_label,
        call.prompt_fingerprint,
        call.request_fingerprint,
    )


def _expected_report_disputes(
    run_dir: _RunStorage,
    envelope: CaseEnvelope,
) -> list[GradeDispute]:
    sealed = _load_model_bytes(
        _read_artifact(run_dir, _LEDGER_PATH),
        SealedLedger,
        location=_LEDGER_PATH,
    )
    disputes: list[GradeDispute] = []
    for assignment in envelope.assignments:
        label = assignment.anonymous_label
        first = _load_model_bytes(
            _read_artifact(run_dir, f"grader-1-report-{label}.json"),
            CandidateGrade,
            location=f"grader-1-report-{label}.json",
        )
        second = _load_model_bytes(
            _read_artifact(run_dir, f"grader-2-report-{label}.json"),
            CandidateGrade,
            location=f"grader-2-report-{label}.json",
        )
        _validate_grade_evidence(envelope, first)
        _validate_grade_evidence(envelope, second)
        disputes.extend(material_disputes(sealed, first, second))
    return disputes


def _validate_report_referee_decision(
    run_dir: _RunStorage,
    envelope: CaseEnvelope,
    dispute: GradeDispute,
    decision: RefereeDecision,
) -> None:
    label = dispute.anonymous_label
    sealed = _load_model_bytes(
        _read_artifact(run_dir, _LEDGER_PATH),
        SealedLedger,
        location=_LEDGER_PATH,
    )
    first = _load_model_bytes(
        _read_artifact(run_dir, f"grader-1-report-{label}.json"),
        CandidateGrade,
        location=f"grader-1-report-{label}.json",
    )
    second = _load_model_bytes(
        _read_artifact(run_dir, f"grader-2-report-{label}.json"),
        CandidateGrade,
        location=f"grader-2-report-{label}.json",
    )
    expected_disputes = material_disputes(sealed, first, second)
    if dispute not in expected_disputes:
        raise EvaluationIntegrityError(
            "report referee decision does not identify an exact grade dispute"
        )
    decisions = [
        (
            decision
            if item.dispute_id == dispute.dispute_id
            else RefereeDecision(
                dispute_id=item.dispute_id,
                selected_grade_resolution="accept_grader_1",
                grade_dispute_fingerprint=model_fingerprint(item),
                rationale="Deterministic validation placeholder decision.",
            )
        )
        for item in expected_disputes
    ]
    resolved = resolve_grades(sealed, first, second, decisions)
    _validate_grade_evidence(envelope, resolved.grade)


def _verify_transition_sequence(
    run_dir: _RunStorage,
    manifest: EvaluationManifest,
    envelope: CaseEnvelope,
) -> None:
    groups = _logical_call_groups(manifest)
    if not groups or groups[0][0].call_id != "admission":
        raise EvaluationIntegrityError("judge transition must begin with admission")

    group_index = 0

    def consume(
        call_id: str,
        operation: JudgeOperation,
        label: str | None = None,
    ) -> bool:
        nonlocal group_index
        if group_index >= len(groups):
            return False
        group = groups[group_index]
        first = group[0]
        if first.call_id != call_id:
            return False
        if first.operation is not operation or first.anonymous_label != label:
            raise EvaluationIntegrityError("judge transition operation/label mismatch")
        group_index += 1
        return True

    def finish_partial(
        group: list[JudgeCallRecord],
        phase: EvaluationRunPhase,
    ) -> None:
        if group_index != len(groups):
            raise EvaluationIntegrityError(
                "judge transition advanced beyond an incomplete operation"
            )
        last_call = group[-1]
        pending = [call for call in manifest.judge_calls if call.state == "pending"]
        if last_call.state == "pending":
            if (
                manifest.terminal_status is not None
                or manifest.state is not phase
                or pending != [last_call]
            ):
                raise EvaluationIntegrityError(
                    "pending judge transition conflicts with manifest phase"
                )
            return
        if (
            last_call.state == "failed"
            and last_call.attempt == 2
            and manifest.state is EvaluationRunPhase.INCONCLUSIVE
            and manifest.terminal_status is not None
            and not pending
        ):
            return
        raise EvaluationIntegrityError(
            "incomplete judge transition lacks pending or terminal failure evidence"
        )

    if not consume("admission", JudgeOperation.ADMIT_CASE):
        raise EvaluationIntegrityError("judge transition admission is malformed")
    if manifest.state is EvaluationRunPhase.CASE_INVALID:
        if group_index != len(groups) or groups[0][-1].state != "completed":
            raise EvaluationIntegrityError(
                "case-invalid transition must stop after completed admission"
            )
        return

    admission = groups[0][-1]
    if admission.state != "completed":
        finish_partial(groups[0], EvaluationRunPhase.ADMISSION)
        return

    if not consume("ledger-build", JudgeOperation.BUILD_LEDGER):
        raise EvaluationIntegrityError("judge transition skipped ledger build")
    build_group = groups[group_index - 1]
    if build_group[-1].state != "completed":
        finish_partial(build_group, EvaluationRunPhase.LEDGER_BUILD)
        return

    if not consume("ledger-audit", JudgeOperation.AUDIT_LEDGER):
        raise EvaluationIntegrityError("judge transition skipped ledger audit")
    audit_group = groups[group_index - 1]
    if audit_group[-1].state != "completed":
        finish_partial(audit_group, EvaluationRunPhase.LEDGER_AUDIT)
        return

    audit = _load_model_bytes(
        _read_artifact(run_dir, _LEDGER_AUDIT_PATH),
        LedgerAudit,
        location=_LEDGER_AUDIT_PATH,
    )
    proposed = _load_model_bytes(
        _read_artifact(run_dir, _PROPOSED_LEDGER_PATH),
        LegalLedger,
        location=_PROPOSED_LEDGER_PATH,
    )
    audit_has_disputes = bool(ledger_findings(envelope, proposed, audit))
    if audit_has_disputes:
        if not consume("ledger-repair", JudgeOperation.REPAIR_LEDGER):
            raise EvaluationIntegrityError("judge transition skipped required ledger repair")
        repair_group = groups[group_index - 1]
        if repair_group[-1].state != "completed":
            finish_partial(repair_group, EvaluationRunPhase.LEDGER_REPAIR)
            return
        remaining = _load_model_bytes(
            _read_artifact(run_dir, _REMAINING_AUDIT_PATH),
            LedgerAudit,
            location=_REMAINING_AUDIT_PATH,
        )
        material = [
            dispute
            for dispute in ledger_disputes(remaining)
            if dispute.materiality in {Materiality.MATERIAL, Materiality.CRITICAL}
        ]
        if len(material) > 1:
            if (
                group_index != len(groups)
                or manifest.state is not EvaluationRunPhase.INCONCLUSIVE
                or manifest.terminal_status is None
            ):
                raise EvaluationIntegrityError(
                    "judge transition did not stop at unresolved ledger disputes"
                )
            return
        if material:
            if not consume("ledger-referee", JudgeOperation.REFEREE):
                raise EvaluationIntegrityError("judge transition skipped required ledger referee")
            referee_group = groups[group_index - 1]
            if referee_group[-1].state != "completed":
                finish_partial(referee_group, EvaluationRunPhase.LEDGER_REFEREE)
                return
        elif group_index < len(groups) and groups[group_index][0].call_id == "ledger-referee":
            raise EvaluationIntegrityError(
                "judge transition added a ledger referee without a material dispute"
            )
    elif group_index < len(groups) and groups[group_index][0].call_id in {
        "ledger-repair",
        "ledger-referee",
    }:
        raise EvaluationIntegrityError("judge transition added repair after a clean ledger audit")

    labels = [assignment.anonymous_label for assignment in envelope.assignments]
    for label in labels:
        for number in (1, 2):
            expected_id = f"grade-{label}-{number}"
            if not consume(expected_id, JudgeOperation.GRADE_REPORT, label):
                raise EvaluationIntegrityError(
                    "judge transition lacks two grades per anonymous report"
                )
            grade_group = groups[group_index - 1]
            if grade_group[-1].state != "completed":
                phase = EvaluationRunPhase.GRADE_A if label == "A" else EvaluationRunPhase.GRADE_B
                finish_partial(grade_group, phase)
                return

    recorded_disputes = _load_report_disputes(run_dir)
    replayed_disputes = _expected_report_disputes(run_dir, envelope)
    if recorded_disputes != replayed_disputes:
        raise EvaluationIntegrityError(
            "report dispute artifact differs from exact blind-grade replay"
        )
    for index, dispute in enumerate(replayed_disputes):
        call_id = f"report-referee-{index + 1}"
        if not consume(call_id, JudgeOperation.REFEREE, dispute.anonymous_label):
            raise EvaluationIntegrityError(
                "judge transition skipped a required report dispute referee"
            )
        referee_group = groups[group_index - 1]
        if referee_group[-1].state != "completed":
            finish_partial(referee_group, EvaluationRunPhase.REPORT_REFEREE)
            return

    if group_index != len(groups):
        raise EvaluationIntegrityError("judge transition contains an out-of-order call")
    if (
        manifest.state is not EvaluationRunPhase.COMPLETED
        or manifest.terminal_status is None
        or any(call.state == "pending" for call in manifest.judge_calls)
    ):
        raise EvaluationIntegrityError(
            "completed judge transition conflicts with terminal manifest state"
        )


def _all_keys(value: object) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, list):
        for item in value:
            keys.update(_all_keys(item))
    elif isinstance(value, dict):
        for key, item in value.items():
            if type(key) is str:
                keys.add(key)
            keys.update(_all_keys(item))
    return keys


def _ledger_contract_mode(
    request: JudgeRequest,
) -> Literal["pre-contract", "1.0", "1.1"] | None:
    """Return the recognized invariant-contract mode for one ledger request."""
    if request.operation not in {
        JudgeOperation.BUILD_LEDGER,
        JudgeOperation.AUDIT_LEDGER,
        JudgeOperation.REPAIR_LEDGER,
    }:
        return None
    if "ledger_invariant_contract" not in request.system_instructions:
        return "pre-contract"
    contract = request.payload.get("ledger_invariant_contract")
    if contract == _ledger_invariant_contract_v1_0():
        return "1.0"
    if contract == ledger_invariant_contract():
        return "1.1"
    raise EvaluationIntegrityError("ledger request invariant contract is not recognized")


def _verify_ledger_contract_mode_consistency(requests: list[JudgeRequest]) -> None:
    """Require every ledger request in one replay run to use one recognized mode."""
    modes = {
        mode
        for request in requests
        if (mode := _ledger_contract_mode(request)) is not None
    }
    if len(modes) > 1:
        raise EvaluationIntegrityError("ledger request invariant-contract modes differ")


def _verify_request_noninterference(
    run_dir: _RunStorage,
    request: JudgeRequest,
    call: JudgeCallRecord,
    envelope: CaseEnvelope,
    manifest: EvaluationManifest,
) -> None:
    source_only = request.operation in {
        JudgeOperation.ADMIT_CASE,
        JudgeOperation.BUILD_LEDGER,
        JudgeOperation.AUDIT_LEDGER,
        JudgeOperation.REPAIR_LEDGER,
    } or (request.operation is JudgeOperation.REFEREE and call.anonymous_label is None)
    keys = _all_keys(request.model_dump(mode="json"))
    forbidden_keys = {"candidate_id", "assignments", "answer_key"}
    if source_only and forbidden_keys & keys:
        raise EvaluationIntegrityError(
            "source-only request contains candidate or answer-key evidence"
        )

    admission = build_admission_packet(envelope)
    source_record = admission.payload
    source_metadata = {
        "record_scope": "source-only",
        "source_record_fingerprint": admission.safe_metadata["source_record_fingerprint"],
    }
    invariant_contracts = (
        _ledger_invariant_contract_v1_0(),
        ledger_invariant_contract(),
    )
    requires_invariant_contract = "ledger_invariant_contract" in request.system_instructions
    if request.operation is JudgeOperation.ADMIT_CASE and request != admission:
        raise EvaluationIntegrityError(
            "admission request differs from the exact source-only packet"
        )
    if request.operation is JudgeOperation.BUILD_LEDGER:
        expected_payload: dict[str, object] = {"source_record": source_record}
        expected_payloads = (
            [
                {
                    **expected_payload,
                    "ledger_invariant_contract": invariant_contract,
                }
                for invariant_contract in invariant_contracts
            ]
            if requires_invariant_contract
            else [expected_payload]
        )
        if request.payload not in expected_payloads or request.safe_metadata != source_metadata:
            raise EvaluationIntegrityError(
                "ledger-build request differs from the exact source-only packet"
            )
    if request.operation is JudgeOperation.AUDIT_LEDGER:
        proposed = _load_model_bytes(
            _read_artifact(run_dir, _PROPOSED_LEDGER_PATH),
            LegalLedger,
            location=_PROPOSED_LEDGER_PATH,
        )
        expected_payload = {
            "source_record": source_record,
            "proposed_ledger": proposed.model_dump(mode="json"),
            "audit_action_contract": _audit_action_contract(),
        }
        expected_payloads = (
            [
                {
                    **expected_payload,
                    "ledger_invariant_contract": invariant_contract,
                }
                for invariant_contract in invariant_contracts
            ]
            if requires_invariant_contract
            else [expected_payload]
        )
        if request.payload not in expected_payloads or request.safe_metadata != source_metadata:
            raise EvaluationIntegrityError(
                "ledger-audit request differs from exact source-only evidence"
            )
    if request.operation is JudgeOperation.REPAIR_LEDGER:
        proposed = _load_model_bytes(
            _read_artifact(run_dir, _PROPOSED_LEDGER_PATH),
            LegalLedger,
            location=_PROPOSED_LEDGER_PATH,
        )
        audit = _load_model_bytes(
            _read_artifact(run_dir, _LEDGER_AUDIT_PATH),
            LedgerAudit,
            location=_LEDGER_AUDIT_PATH,
        )
        expected_payload = {
            "source_record": source_record,
            "proposed_ledger": proposed.model_dump(mode="json"),
            "audit": audit.model_dump(mode="json"),
            "audit_action_contract": _audit_action_contract(),
        }
        expected_payloads = (
            [
                {
                    **expected_payload,
                    "ledger_invariant_contract": invariant_contract,
                }
                for invariant_contract in invariant_contracts
            ]
            if requires_invariant_contract
            else [expected_payload]
        )
        if request.payload not in expected_payloads or request.safe_metadata != source_metadata:
            raise EvaluationIntegrityError(
                "ledger-repair request differs from exact source-only evidence"
            )
    if request.operation is JudgeOperation.REFEREE and call.anonymous_label is None:
        remaining = _load_model_bytes(
            _read_artifact(run_dir, _REMAINING_AUDIT_PATH),
            LedgerAudit,
            location=_REMAINING_AUDIT_PATH,
        )
        material = [
            dispute
            for dispute in ledger_disputes(remaining)
            if dispute.materiality in {Materiality.MATERIAL, Materiality.CRITICAL}
        ]
        if len(material) != 1:
            raise EvaluationIntegrityError("ledger referee lacks exactly one material dispute")
        repaired = _load_model_bytes(
            _read_artifact(run_dir, _REPAIRED_LEDGER_PATH),
            LegalLedger,
            location=_REPAIRED_LEDGER_PATH,
        )
        if request.payload != _ledger_referee_payload(envelope, repaired, material[0]):
            raise EvaluationIntegrityError(
                "ledger-referee request differs from its one material dispute"
            )
        if request.safe_metadata != {
            "record_scope": "source-only-dispute",
            "referee_scope": "ledger",
        }:
            raise EvaluationIntegrityError(
                "ledger-referee request metadata exceeds its allowed scope"
            )

    if request.operation is JudgeOperation.GRADE_REPORT:
        if set(request.payload) != {
            "anonymous_report",
            "sealed_ledger",
            "source_record",
            "source_spans",
            "deterministic_checks",
            "rubric",
            "finding_code_contract",
        }:
            raise EvaluationIntegrityError("grade request has an unexpected packet shape")
        if forbidden_keys & keys:
            raise EvaluationIntegrityError("grade request reveals candidate identity")
        label = call.anonymous_label
        if label not in {"A", "B"}:
            raise EvaluationIntegrityError("grade request lacks an anonymous label")
        candidate_id = next(
            assignment.candidate_id
            for assignment in envelope.assignments
            if assignment.anonymous_label == label
        )
        candidate = next(
            item for item in envelope.case.candidates if item.candidate_id == candidate_id
        )
        expected_report = {
            "anonymous_label": label,
            "report_hash": candidate.report_hash,
            "report_text": candidate.report_text,
        }
        if request.payload["anonymous_report"] != expected_report:
            raise EvaluationIntegrityError(
                "grade request does not contain exactly one assigned anonymous report"
            )
        sealed = _load_model_bytes(
            _read_artifact(run_dir, _LEDGER_PATH),
            SealedLedger,
            location=_LEDGER_PATH,
        )
        if request.payload["sealed_ledger"] != sealed.model_dump(mode="json"):
            raise EvaluationIntegrityError("grade request sealed-ledger snapshot mismatch")
        if request.payload["source_record"] != source_record:
            raise EvaluationIntegrityError("grade request common-source snapshot mismatch")
        checks_path = f"deterministic-checks-{label}.json"
        checks = _load_model_bytes(
            _read_artifact(run_dir, checks_path),
            DeterministicChecks,
            location=checks_path,
        )
        if request.payload["deterministic_checks"] != checks.model_dump(mode="json"):
            raise EvaluationIntegrityError("grade request deterministic-check snapshot mismatch")
        rubric = _load_model_bytes(
            _read_artifact(run_dir, _RUBRIC_PATH),
            EvaluationRubric,
            location=_RUBRIC_PATH,
        )
        if request.payload["rubric"] != rubric.model_dump(mode="json"):
            raise EvaluationIntegrityError("grade request rubric snapshot mismatch")
        if request.payload["finding_code_contract"] != _finding_code_contract():
            raise EvaluationIntegrityError("grade request finding-code contract mismatch")
        if request.payload["source_spans"] != _derive_source_spans(envelope, sealed):
            raise EvaluationIntegrityError("grade request source-span snapshot mismatch")
        if request.safe_metadata != {
            "record_scope": "one-anonymous-report",
            "anonymous_label": label,
            "legal_ledger_hash": cast(str, manifest.legal_ledger_hash),
            "legal_ledger_fingerprint": sealed.ledger_fingerprint,
        }:
            raise EvaluationIntegrityError("grade request metadata snapshot mismatch")

    if request.operation is JudgeOperation.REFEREE and call.anonymous_label is not None:
        try:
            index = int(call.call_id.rsplit("-", maxsplit=1)[1]) - 1
        except (IndexError, ValueError) as error:
            raise EvaluationIntegrityError("report-referee call ID is malformed") from error
        disputes = _expected_report_disputes(run_dir, envelope)
        if index < 0 or index >= len(disputes):
            raise EvaluationIntegrityError(
                "report referee does not identify a recorded report dispute"
            )
        dispute = disputes[index]
        sealed = _load_model_bytes(
            _read_artifact(run_dir, _LEDGER_PATH),
            SealedLedger,
            location=_LEDGER_PATH,
        )
        if (
            request.system_instructions != _report_referee_instructions(dispute)
            or request.json_schema != RefereeDecision.model_json_schema()
        ):
            raise EvaluationIntegrityError(
                "report referee request instructions or schema differ from replay"
            )
        if request.payload != _report_referee_payload(envelope, sealed, dispute):
            raise EvaluationIntegrityError(
                "report referee request differs from its exact dispute-scoped packet"
            )
        if request.safe_metadata != {
            "record_scope": "one-material-dispute",
            "referee_scope": "report",
            "grade_dispute_fingerprint": model_fingerprint(dispute),
            "legal_ledger_hash": cast(str, manifest.legal_ledger_hash),
        }:
            raise EvaluationIntegrityError(
                "report referee metadata differs from its recorded dispute"
            )


def _load_report_disputes(run_dir: _RunStorage) -> list[GradeDispute]:
    payload = _dict_value(
        _parse_json_bytes(
            _read_artifact(run_dir, _REPORT_DISPUTES_PATH),
            location=_REPORT_DISPUTES_PATH,
        ),
        location=_REPORT_DISPUTES_PATH,
    )
    _require_artifact_schema(payload, location=_REPORT_DISPUTES_PATH)
    if set(payload) != {"schema_version", "disputes"}:
        raise EvaluationIntegrityError("report disputes artifact has unexpected shape")
    return [
        _model_from_payload(item, GradeDispute, location="report dispute")
        for item in _list_value(payload["disputes"], location="report disputes")
    ]


def _referee_artifact_path(index: int, dispute: GradeDispute) -> str:
    return (
        f"referee-report-{dispute.anonymous_label}-{index + 1}-"
        f"{model_fingerprint(dispute)[:12]}.json"
    )


def _completed_response_artifact(
    run_dir: _RunStorage,
    call: JudgeCallRecord,
    response: JudgeResponse,
    envelope: CaseEnvelope,
) -> None:
    """Bind every accepted response to the exact semantic artifact it produced."""
    if call.operation is JudgeOperation.ADMIT_CASE:
        judgment = _model_from_payload(
            response.payload,
            CaseAdmissionJudgment,
            location="admission response payload",
        )
        expected_readiness = adjudicate_admission(envelope, judgment)
        readiness = _load_model_bytes(
            _read_artifact(run_dir, _READINESS_PATH),
            CaseReadiness,
            location=_READINESS_PATH,
        )
        if readiness != expected_readiness:
            raise EvaluationIntegrityError(
                "admission evidence differs from exact response adjudication"
            )
        return

    if call.operation is JudgeOperation.BUILD_LEDGER:
        ledger_artifact = _load_model_bytes(
            _read_artifact(run_dir, _PROPOSED_LEDGER_PATH),
            LegalLedger,
            location=_PROPOSED_LEDGER_PATH,
        )
        expected_ledger = _model_from_payload(
            response.payload, LegalLedger, location="ledger response payload"
        )
        if ledger_artifact != expected_ledger:
            raise EvaluationIntegrityError("ledger evidence differs from exact response payload")
        return

    if call.operation is JudgeOperation.AUDIT_LEDGER:
        proposed = _load_model_bytes(
            _read_artifact(run_dir, _PROPOSED_LEDGER_PATH),
            LegalLedger,
            location=_PROPOSED_LEDGER_PATH,
        )
        audit_artifact = _load_model_bytes(
            _read_artifact(run_dir, _LEDGER_AUDIT_PATH),
            LedgerAudit,
            location=_LEDGER_AUDIT_PATH,
        )
        expected_audit = _model_from_payload(
            response.payload, LedgerAudit, location="ledger audit response payload"
        )
        if expected_audit.request_fingerprint != call.request_fingerprint:
            raise EvaluationIntegrityError(
                "ledger-audit evidence request fingerprint mismatch"
            )
        ledger_findings(envelope, proposed, expected_audit)
        if audit_artifact != expected_audit:
            raise EvaluationIntegrityError(
                "ledger-audit evidence differs from exact response payload"
            )
        return

    if call.operation is JudgeOperation.REPAIR_LEDGER:
        if set(response.payload) != {"repaired_ledger", "remaining_audit"}:
            raise EvaluationIntegrityError("ledger-repair response has an unexpected shape")
        expected_repaired = _model_from_payload(
            response.payload["repaired_ledger"],
            LegalLedger,
            location="repaired-ledger response payload",
        )
        expected_remaining = _model_from_payload(
            response.payload["remaining_audit"],
            LedgerAudit,
            location="remaining-audit response payload",
        )
        if expected_remaining.request_fingerprint != call.request_fingerprint:
            raise EvaluationIntegrityError(
                "remaining-audit evidence request fingerprint mismatch"
            )
        ledger_disputes(expected_remaining)
        repaired = _load_model_bytes(
            _read_artifact(run_dir, _REPAIRED_LEDGER_PATH),
            LegalLedger,
            location=_REPAIRED_LEDGER_PATH,
        )
        remaining = _load_model_bytes(
            _read_artifact(run_dir, _REMAINING_AUDIT_PATH),
            LedgerAudit,
            location=_REMAINING_AUDIT_PATH,
        )
        if repaired != expected_repaired or remaining != expected_remaining:
            raise EvaluationIntegrityError(
                "ledger-repair evidence differs from exact response payload"
            )
        return

    if call.operation is JudgeOperation.GRADE_REPORT:
        parts = call.call_id.split("-")
        if len(parts) != 3 or parts[1] not in {"A", "B"} or parts[2] not in {"1", "2"}:
            raise EvaluationIntegrityError("completed grade call ID is malformed")
        grade_path = f"grader-{parts[2]}-report-{parts[1]}.json"
        grade = _load_model_bytes(
            _read_artifact(run_dir, grade_path),
            CandidateGrade,
            location=grade_path,
        )
        expected_grade = _model_from_payload(
            response.payload,
            CandidateGrade,
            location="grade response payload",
        )
        if grade != expected_grade:
            raise EvaluationIntegrityError(
                "grade evidence artifact differs from exact response payload"
            )
        _validate_grade_evidence(envelope, grade)
        if grade.request_fingerprint != call.request_fingerprint:
            raise EvaluationIntegrityError("grade evidence request fingerprint mismatch")
        return

    if call.operation is JudgeOperation.REFEREE and call.anonymous_label is None:
        decision = _load_model_bytes(
            _read_artifact(run_dir, _LEDGER_REFEREE_PATH),
            RefereeDecision,
            location=_LEDGER_REFEREE_PATH,
        )
        expected_decision = _model_from_payload(
            response.payload,
            RefereeDecision,
            location="ledger-referee response payload",
        )
        if decision != expected_decision:
            raise EvaluationIntegrityError(
                "ledger-referee evidence differs from exact response payload"
            )
        return

    if call.operation is JudgeOperation.REFEREE:
        try:
            index = int(call.call_id.rsplit("-", maxsplit=1)[1]) - 1
        except (IndexError, ValueError) as error:
            raise EvaluationIntegrityError("report-referee call ID is malformed") from error
        disputes = _load_report_disputes(run_dir)
        if index < 0 or index >= len(disputes):
            raise EvaluationIntegrityError(
                "report-referee call exceeds the recorded dispute inventory"
            )
        decision_path = _referee_artifact_path(index, disputes[index])
        decision = _load_model_bytes(
            _read_artifact(run_dir, decision_path),
            RefereeDecision,
            location=decision_path,
        )
        _validate_report_referee_decision(
            run_dir,
            envelope,
            disputes[index],
            decision,
        )
        expected_decision = _model_from_payload(
            response.payload,
            RefereeDecision,
            location="report-referee response payload",
        )
        if decision != expected_decision:
            raise EvaluationIntegrityError(
                "report-referee evidence differs from exact response payload"
            )


def _verify_call_artifacts(
    run_dir: _RunStorage,
    manifest: EvaluationManifest,
    envelope: CaseEnvelope,
) -> None:
    ledger_requests: list[JudgeRequest] = []
    for call in manifest.judge_calls:
        expected_request_path = f"judge-requests/{call.call_id}-attempt-{call.attempt}.json"
        if call.request_artifact_path != expected_request_path:
            raise EvaluationIntegrityError("judge request artifact path is not canonical")
        expected_response_path = (
            None
            if call.state == "pending"
            else f"judge-responses/{call.call_id}-attempt-{call.attempt}.json"
        )
        if call.response_artifact_path != expected_response_path:
            raise EvaluationIntegrityError("judge response artifact path is not canonical")
        expected_diagnostics_path = (
            f"judge-diagnostics/{call.call_id}-attempt-{call.attempt}.json"
            if call.state == "failed"
            else None
        )
        if call.diagnostics_artifact_path != expected_diagnostics_path:
            raise EvaluationIntegrityError("judge diagnostics artifact path is not canonical")
        request_bytes = _read_artifact(run_dir, call.request_artifact_path)
        request = _load_model_bytes(
            request_bytes, JudgeRequest, location=call.request_artifact_path
        )
        if request.operation is not call.operation:
            raise EvaluationIntegrityError("judge request operation mismatch")
        if request.request_fingerprint != call.request_fingerprint:
            raise EvaluationIntegrityError("judge request fingerprint mismatch")
        if _expected_request_fingerprint(request) != call.request_fingerprint:
            raise EvaluationIntegrityError("judge request self-fingerprint mismatch")
        if _prompt_fingerprint(request) != call.prompt_fingerprint:
            raise EvaluationIntegrityError("judge prompt fingerprint mismatch")
        _verify_request_noninterference(run_dir, request, call, envelope, manifest)
        ledger_requests.append(request)
        if call.operation is JudgeOperation.GRADE_REPORT:
            if request.safe_metadata.get("anonymous_label") != call.anonymous_label:
                raise EvaluationIntegrityError("grade request anonymous label mismatch")
            if request.safe_metadata.get("legal_ledger_hash") != manifest.legal_ledger_hash:
                raise EvaluationIntegrityError("grade request sealed-ledger hash mismatch")

        if call.response_artifact_path is None:
            continue
        response_bytes = _read_artifact(run_dir, call.response_artifact_path)
        response = _load_model_bytes(
            response_bytes, JudgeResponse, location=call.response_artifact_path
        )
        if (
            call.operation is JudgeOperation.GRADE_REPORT
            and call.state == "completed"
        ):
            _require_candidate_grade_schema(
                response.payload,
                location=call.response_artifact_path,
            )
        if sha256_digest(response_bytes) != call.response_fingerprint:
            raise EvaluationIntegrityError("judge response fingerprint mismatch")
        if response.provider_name != call.provider_name or response.model_name != call.model_name:
            raise EvaluationIntegrityError("judge response provider/model provenance mismatch")
        if response.judge_isolation is not call.judge_isolation:
            raise EvaluationIntegrityError("judge response isolation provenance mismatch")
        if call.state == "completed" and (
            response.operation is not call.operation
            or response.request_fingerprint != call.request_fingerprint
        ):
            raise EvaluationIntegrityError("completed response/request/operation mismatch")
        if call.state == "completed":
            _completed_response_artifact(run_dir, call, response, envelope)
        if call.state == "failed" and call.diagnostics_artifact_path is None:
            raise EvaluationIntegrityError("failed response is missing diagnostics")
        if call.diagnostics_artifact_path is not None:
            _parse_json_bytes(
                _read_artifact(run_dir, call.diagnostics_artifact_path),
                location=call.diagnostics_artifact_path,
            )
    _verify_ledger_contract_mode_consistency(ledger_requests)


def _verify_bound_artifacts(
    run_dir: _RunStorage,
    manifest: EvaluationManifest,
) -> tuple[CaseEnvelope, AttorneyEvaluationResult | None]:
    envelope_bytes = _read_artifact(run_dir, _CASE_ENVELOPE_PATH)
    if sha256_digest(envelope_bytes) != manifest.case_envelope_hash:
        raise EvaluationIntegrityError("case-envelope artifact hash mismatch")
    envelope = _load_model_bytes(envelope_bytes, CaseEnvelope, location=_CASE_ENVELOPE_PATH)
    if envelope.case_fingerprint != manifest.case_fingerprint:
        raise EvaluationIntegrityError("case fingerprint mismatch")

    rubric = _load_model_bytes(
        _read_artifact(run_dir, _RUBRIC_PATH),
        EvaluationRubric,
        location=_RUBRIC_PATH,
    )
    if model_fingerprint(rubric) != manifest.rubric_fingerprint:
        raise EvaluationIntegrityError("rubric fingerprint mismatch")
    if rubric.model_dump(mode="json") != RUBRIC_V1.model_dump(mode="json"):
        raise EvaluationIntegrityError("run rubric is not canonical")

    if manifest.legal_ledger_hash is not None:
        ledger_bytes = _read_artifact(run_dir, _LEDGER_PATH)
        if sha256_digest(ledger_bytes) != manifest.legal_ledger_hash:
            raise EvaluationIntegrityError("legal-ledger artifact hash mismatch")
        _load_model_bytes(ledger_bytes, SealedLedger, location=_LEDGER_PATH)

    result: AttorneyEvaluationResult | None = None
    if manifest.result_hash is not None:
        result_bytes = _read_artifact(run_dir, _RESULT_PATH)
        if sha256_digest(result_bytes) != manifest.result_hash:
            raise EvaluationIntegrityError("evaluation-result artifact hash mismatch")
        result = _load_model_bytes(result_bytes, AttorneyEvaluationResult, location=_RESULT_PATH)
        if _result_fingerprint(result) != result.result_fingerprint:
            raise EvaluationIntegrityError("evaluation result self-fingerprint mismatch")
    return envelope, result


def _verify_derived_artifacts(
    run_dir: _RunStorage,
    manifest: EvaluationManifest,
    envelope: CaseEnvelope,
) -> None:
    if manifest.legal_ledger_hash is None:
        return
    stored = _load_model_bytes(
        _read_artifact(run_dir, _LEDGER_PATH),
        SealedLedger,
        location=_LEDGER_PATH,
    )
    completed_ids = {call.call_id for call in manifest.judge_calls if call.state == "completed"}
    if "ledger-repair" in completed_ids:
        ledger = _load_model_bytes(
            _read_artifact(run_dir, _REPAIRED_LEDGER_PATH),
            LegalLedger,
            location=_REPAIRED_LEDGER_PATH,
        )
        audit = _load_model_bytes(
            _read_artifact(run_dir, _REMAINING_AUDIT_PATH),
            LedgerAudit,
            location=_REMAINING_AUDIT_PATH,
        )
        referee = (
            _load_model_bytes(
                _read_artifact(run_dir, _LEDGER_REFEREE_PATH),
                RefereeDecision,
                location=_LEDGER_REFEREE_PATH,
            )
            if "ledger-referee" in completed_ids
            else None
        )
    else:
        ledger = _load_model_bytes(
            _read_artifact(run_dir, _PROPOSED_LEDGER_PATH),
            LegalLedger,
            location=_PROPOSED_LEDGER_PATH,
        )
        audit = _load_model_bytes(
            _read_artifact(run_dir, _LEDGER_AUDIT_PATH),
            LedgerAudit,
            location=_LEDGER_AUDIT_PATH,
        )
        referee = None
    try:
        replayed = seal_ledger(envelope, ledger, audit, referee)
    except (TypeError, ValidationError, ValueError) as error:
        raise EvaluationIntegrityError(
            "sealed-ledger replay could not reproduce a valid ledger"
        ) from error
    if replayed != stored:
        raise EvaluationIntegrityError("sealed-ledger replay differs from immutable evidence")

    candidates = {candidate.candidate_id: candidate for candidate in envelope.case.candidates}
    for assignment in envelope.assignments:
        path = f"deterministic-checks-{assignment.anonymous_label}.json"
        checks = _load_model_bytes(
            _read_artifact(run_dir, path),
            DeterministicChecks,
            location=path,
        )
        expected = _derive_deterministic_checks(
            candidates[assignment.candidate_id], assignment.anonymous_label
        )
        if checks != expected:
            raise EvaluationIntegrityError(
                "deterministic-check replay differs from immutable evidence"
            )


def _protocol_inventory(
    run_dir: _RunStorage,
    manifest: EvaluationManifest,
    envelope: CaseEnvelope,
) -> set[str]:
    expected = {_CASE_ENVELOPE_PATH, _RUBRIC_PATH}
    for call in manifest.judge_calls:
        expected.add(call.request_artifact_path)
        if call.response_artifact_path is not None:
            expected.add(call.response_artifact_path)
        if call.diagnostics_artifact_path is not None:
            expected.add(call.diagnostics_artifact_path)

    completed = [call for call in manifest.judge_calls if call.state == "completed"]
    completed_ids = {call.call_id for call in completed}
    admission_completed = "admission" in completed_ids
    if admission_completed or manifest.state is EvaluationRunPhase.INCONCLUSIVE:
        expected.add(_READINESS_PATH)
    if manifest.state is EvaluationRunPhase.INCONCLUSIVE and admission_completed:
        expected.add(_TERMINAL_READINESS_PATH)
    if "ledger-build" in completed_ids:
        expected.add(_PROPOSED_LEDGER_PATH)
    if "ledger-audit" in completed_ids:
        expected.add(_LEDGER_AUDIT_PATH)
    if "ledger-repair" in completed_ids:
        expected.update({_REPAIRED_LEDGER_PATH, _REMAINING_AUDIT_PATH})
    if "ledger-referee" in completed_ids:
        expected.add(_LEDGER_REFEREE_PATH)

    labels = [assignment.anonymous_label for assignment in envelope.assignments]
    if manifest.legal_ledger_hash is not None:
        expected.add(_LEDGER_PATH)
        expected.update(f"deterministic-checks-{label}.json" for label in labels)
    for label in labels:
        for number in (1, 2):
            if f"grade-{label}-{number}" in completed_ids:
                expected.add(f"grader-{number}-report-{label}.json")

    all_grades_completed = all(
        f"grade-{label}-{number}" in completed_ids for label in labels for number in (1, 2)
    )
    if all_grades_completed:
        expected.add(_REPORT_DISPUTES_PATH)
        disputes = _load_report_disputes(run_dir)
        for index, dispute in enumerate(disputes):
            if f"report-referee-{index + 1}" in completed_ids:
                expected.add(_referee_artifact_path(index, dispute))

    if manifest.state is EvaluationRunPhase.COMPLETED:
        for label in labels:
            expected.update(
                {
                    f"resolved-grade-{label}.json",
                    f"report-score-inputs-{label}.json",
                    f"report-evaluation-{label}.json",
                }
            )
    if manifest.terminal_status is not None:
        expected.update({_RESULT_PATH, _REPORT_PATH})
    return expected


def _verify_protocol_inventory(
    run_dir: _RunStorage,
    manifest: EvaluationManifest,
    envelope: CaseEnvelope,
) -> None:
    declared = {artifact.artifact_path for artifact in manifest.artifacts}
    expected = _protocol_inventory(run_dir, manifest, envelope)
    if declared != expected:
        missing = sorted(expected - declared)
        added = sorted(declared - expected)
        raise EvaluationIntegrityError(
            f"protocol inventory mismatch; missing={missing}; added={added}"
        )


def _load_readiness_artifact(run_dir: _RunStorage, path: str) -> CaseReadiness:
    return _load_model_bytes(_read_artifact(run_dir, path), CaseReadiness, location=path)


def _verify_terminal_result(
    run_dir: _RunStorage,
    manifest: EvaluationManifest,
    envelope: CaseEnvelope,
    result: AttorneyEvaluationResult | None,
) -> None:
    if manifest.terminal_status is None:
        if result is not None or manifest.result_hash is not None:
            raise EvaluationIntegrityError(
                "nonterminal run unexpectedly retains an evaluation result"
            )
        return
    if result is None or manifest.result_hash is None:
        raise EvaluationIntegrityError("terminal run is missing its evaluation result")
    if result.rubric.model_dump(mode="json") != RUBRIC_V1.model_dump(mode="json"):
        raise EvaluationIntegrityError("terminal result does not use the canonical rubric")
    if result.readiness.case_fingerprint != envelope.case_fingerprint:
        raise EvaluationIntegrityError("terminal readiness case fingerprint mismatch")
    expected_isolation = (
        "sequential_same_context"
        if any(
            call.state != "pending"
            and call.judge_isolation is JudgeIsolation.SEQUENTIAL_SAME_CONTEXT
            for call in manifest.judge_calls
        )
        else "fresh_context"
    )
    if result.judge_isolation != expected_isolation:
        raise EvaluationIntegrityError(
            "terminal aggregate judge isolation differs from manifest provenance"
        )

    admission = _load_readiness_artifact(run_dir, _READINESS_PATH)
    if manifest.state is EvaluationRunPhase.COMPLETED:
        expected_status = ReadinessStatus.ADMITTED
        expected_disposition: ComparativeDisposition | None = None
        authoritative_readiness = admission
    elif manifest.state is EvaluationRunPhase.CASE_INVALID:
        expected_status = ReadinessStatus.CASE_INVALID
        expected_disposition = ComparativeDisposition.CASE_INVALID
        authoritative_readiness = admission
    elif manifest.state is EvaluationRunPhase.INCONCLUSIVE:
        expected_status = ReadinessStatus.INCONCLUSIVE
        expected_disposition = ComparativeDisposition.INCONCLUSIVE
        admission_completed = any(
            call.call_id == "admission" and call.state == "completed"
            for call in manifest.judge_calls
        )
        if admission_completed:
            if admission.status is not ReadinessStatus.ADMITTED:
                raise EvaluationIntegrityError(
                    "post-admission terminal run changed admitted case readiness"
                )
            authoritative_readiness = _load_readiness_artifact(run_dir, _TERMINAL_READINESS_PATH)
        else:
            authoritative_readiness = admission
    else:
        raise EvaluationIntegrityError("terminal result has an unsupported phase")

    if result.readiness != authoritative_readiness:
        raise EvaluationIntegrityError(
            "terminal result readiness differs from its immutable evidence"
        )
    if result.readiness.status is not expected_status:
        raise EvaluationIntegrityError("terminal result readiness status mismatch")

    if manifest.state is not EvaluationRunPhase.COMPLETED:
        if result.reports:
            raise EvaluationIntegrityError(
                "invalid or inconclusive result must not retain report scores"
            )
        if len(envelope.case.candidates) == 1:
            if result.comparison is not None:
                raise EvaluationIntegrityError(
                    "one-candidate terminal result must be absolute only"
                )
        else:
            if expected_disposition is None:
                raise EvaluationIntegrityError("terminal comparison disposition is unavailable")
            expected_comparison: dict[str, object] = {
                "disposition": expected_disposition.value,
                "winner_label": None,
                "score_difference": None,
                "rationale_codes": [],
            }
            if (
                result.comparison is None
                or result.comparison.model_dump(mode="json") != expected_comparison
            ):
                if result.comparison is not None and result.comparison.winner_label is not None:
                    raise EvaluationIntegrityError(
                        "invalid or inconclusive result cannot retain a winner"
                    )
                raise EvaluationIntegrityError("terminal comparison disposition is not fail-closed")

    expected_report = render_evaluation_report(result).encode("utf-8")
    if _read_artifact(run_dir, _REPORT_PATH) != expected_report:
        raise EvaluationIntegrityError("evaluation Markdown does not match the fixed renderer")


def _verify_score_replay(
    run_dir: _RunStorage,
    manifest: EvaluationManifest,
    envelope: CaseEnvelope,
    result: AttorneyEvaluationResult | None,
) -> None:
    if manifest.state.value != "completed":
        return
    if result is None:
        raise EvaluationIntegrityError("completed run is missing its evaluation result")
    labels: list[Literal["A", "B"]] = [
        assignment.anonymous_label for assignment in envelope.assignments
    ]
    inputs_by_label: dict[str, ReportScoreInputs] = {}
    reports_by_label: dict[str, ReportEvaluation] = {}
    resolved_by_label: dict[Literal["A", "B"], ResolvedGrade] = {}
    expected_source_record = canonical_json_bytes(
        build_admission_packet(envelope).payload
    )
    for label in labels:
        inputs_path = f"report-score-inputs-{label}.json"
        inputs = _score_inputs_from_payload(
            _parse_json_bytes(_read_artifact(run_dir, inputs_path), location=inputs_path),
            location=inputs_path,
        )
        if inputs.deterministic_checks.anonymous_label != label:
            raise EvaluationIntegrityError("score-input artifact label mismatch")
        if inputs.source_record != expected_source_record:
            raise EvaluationIntegrityError(
                "score-input source record differs from immutable case evidence"
            )
        sealed = _load_model_bytes(
            _read_artifact(run_dir, _LEDGER_PATH),
            SealedLedger,
            location=_LEDGER_PATH,
        )
        if inputs.sealed_ledger != sealed:
            raise EvaluationIntegrityError(
                "score-input sealed ledger differs from immutable evidence"
            )
        checks_path = f"deterministic-checks-{label}.json"
        checks = _load_model_bytes(
            _read_artifact(run_dir, checks_path),
            DeterministicChecks,
            location=checks_path,
        )
        if inputs.deterministic_checks != checks:
            raise EvaluationIntegrityError(
                "score-input deterministic checks differ from immutable evidence"
            )
        original_first = _load_model_bytes(
            _read_artifact(run_dir, f"grader-1-report-{label}.json"),
            CandidateGrade,
            location=f"grader-1-report-{label}.json",
        )
        original_second = _load_model_bytes(
            _read_artifact(run_dir, f"grader-2-report-{label}.json"),
            CandidateGrade,
            location=f"grader-2-report-{label}.json",
        )
        if (
            inputs.resolved_grade.original_grader_1 != original_first
            or inputs.resolved_grade.original_grader_2 != original_second
        ):
            raise EvaluationIntegrityError("score inputs do not retain the exact grade evidence")
        resolved_path = f"resolved-grade-{label}.json"
        resolved = _deserialize_resolved_grade(
            _parse_json_bytes(_read_artifact(run_dir, resolved_path), location=resolved_path),
            sealed,
            location=resolved_path,
        )
        if inputs.resolved_grade != resolved:
            raise EvaluationIntegrityError("score inputs differ from the resolved-grade evidence")
        report_path = f"report-evaluation-{label}.json"
        report = _load_model_bytes(
            _read_artifact(run_dir, report_path),
            ReportEvaluation,
            location=report_path,
        )
        replayed = score_report(
            inputs.sealed_ledger,
            inputs.resolved_grade,
            inputs.deterministic_checks,
            RUBRIC_V1,
            source_record=inputs.source_record,
        )
        if replayed != report:
            raise EvaluationIntegrityError("report score does not match exact replay inputs")
        inputs_by_label[label] = inputs
        reports_by_label[label] = report
        resolved_by_label[label] = resolved

    ordered_reports = [reports_by_label[label] for label in labels]
    if result.reports != ordered_reports:
        raise EvaluationIntegrityError("result reports do not match replayed score artifacts")
    replayed_matrix = _derive_requirement_matrix(sealed, resolved_by_label)
    if result.requirement_matrix != replayed_matrix:
        raise EvaluationIntegrityError(
            "requirement matrix does not match exact ledger and grade replay"
        )
    if len(labels) == 1:
        if result.comparison is not None:
            raise EvaluationIntegrityError("one-candidate result must be absolute only")
        return
    assignments = {item.candidate_id: item.anonymous_label for item in envelope.assignments}
    candidate_id = next(
        candidate.candidate_id
        for candidate in envelope.case.candidates
        if candidate.role is CandidateRole.CANDIDATE
    )
    comparator_id = next(
        candidate.candidate_id
        for candidate in envelope.case.candidates
        if candidate.role is CandidateRole.COMPARATOR
    )
    candidate_label = assignments[candidate_id]
    comparator_label = assignments[comparator_id]
    replayed_comparison = compare_reports(
        reports_by_label[candidate_label],
        reports_by_label[comparator_label],
        RUBRIC_V1,
        candidate_inputs=inputs_by_label[candidate_label],
        comparator_inputs=inputs_by_label[comparator_label],
    )
    if result.comparison != replayed_comparison:
        raise EvaluationIntegrityError("comparison does not match exact score replay")


def _verify_evaluation_run_or_raise(
    run_dir: Path | _RunStorage,
) -> tuple[EvaluationManifest, CaseEnvelope, AttorneyEvaluationResult | None]:
    if not isinstance(run_dir, _RunStorage):
        with _open_run_storage(run_dir) as storage:
            return _verify_evaluation_run_or_raise(storage)
    initial_inventory = _scan_run_inventory(run_dir)
    actual_paths = {path for path in initial_inventory if not path.endswith("/")}
    if _MANIFEST_PATH not in actual_paths:
        raise EvaluationIntegrityError("run manifest is missing from inventory")
    manifest = _load_manifest(run_dir)
    expected_paths = {artifact.artifact_path for artifact in manifest.artifacts}
    expected_with_manifest = expected_paths | {_MANIFEST_PATH}
    if actual_paths != expected_with_manifest:
        missing = sorted(expected_with_manifest - actual_paths)
        added = sorted(actual_paths - expected_with_manifest)
        raise EvaluationIntegrityError(
            f"artifact inventory mismatch; missing={missing}; added={added}"
        )
    artifacts_by_path = {artifact.artifact_path: artifact for artifact in manifest.artifacts}
    for artifact_path, record in artifacts_by_path.items():
        data = _read_artifact(run_dir, artifact_path)
        if sha256_digest(data) != record.artifact_hash:
            raise EvaluationIntegrityError(f"artifact hash mismatch: {artifact_path}")
        if artifact_path.endswith(".json"):
            _parse_json_bytes(data, location=artifact_path)
    envelope, result = _verify_bound_artifacts(run_dir, manifest)
    _verify_transition_sequence(run_dir, manifest, envelope)
    _verify_protocol_inventory(run_dir, manifest, envelope)
    _verify_call_artifacts(run_dir, manifest, envelope)
    _verify_derived_artifacts(run_dir, manifest, envelope)
    _verify_terminal_result(run_dir, manifest, envelope, result)
    _verify_score_replay(run_dir, manifest, envelope, result)
    final_inventory = _scan_run_inventory(run_dir)
    if final_inventory != initial_inventory:
        raise EvaluationIntegrityError("run inventory changed during verification")
    return manifest, envelope, result


def verify_evaluation_run(run_dir: Path) -> EvaluationVerification:
    """Verify the exact inventory, artifact bytes, provenance, and replay root."""
    try:
        with _open_run_storage(run_dir) as storage:
            manifest, _, _ = _verify_evaluation_run_or_raise(storage)
            storage.assert_root_identity()
    except (
        EvaluationIntegrityError,
        OSError,
        TypeError,
        ValidationError,
        ValueError,
    ) as error:
        return EvaluationVerification(False, (str(error),), None)
    return EvaluationVerification(True, (), manifest.manifest_fingerprint)


def load_verified_evaluation_run(
    run_dir: Path,
) -> tuple[EvaluationManifest, AttorneyEvaluationResult]:
    """Return one manifest/result snapshot after one complete read-only verification pass."""
    with _open_run_storage(run_dir) as storage:
        manifest, _, result = _verify_evaluation_run_or_raise(storage)
        if result is None:
            raise EvaluationIntegrityError("terminal evaluation has no result artifact")
        storage.assert_root_identity()
        return manifest, result


def _markdown_table_value(value: str) -> str:
    escaped: list[str] = []
    for character in value:
        codepoint = ord(character)
        if character == "\\":
            escaped.append("\\\\")
        elif character == "|":
            escaped.append("\\|")
        elif character == "\r":
            escaped.append("\\r")
        elif character == "\n":
            escaped.append("\\n")
        elif unicodedata.category(character) == "Cc":
            if codepoint <= 0xFF:
                escaped.append(f"\\x{codepoint:02x}")
            elif codepoint <= 0xFFFF:
                escaped.append(f"\\u{codepoint:04x}")
            else:
                escaped.append(f"\\U{codepoint:08x}")
        else:
            escaped.append(character)
    return html.escape("".join(escaped), quote=False)


def _matrix_finding_cells(finding: RequirementReportFinding | None) -> list[str]:
    if finding is None:
        return ["Not supplied"] * 4
    location = finding.report_location if finding.report_location is not None else "Not stated"
    finding_codes = ", ".join(code.value for code in finding.finding_codes) or "None"
    return [
        _markdown_table_value(finding.disposition.value),
        _markdown_table_value(location),
        _markdown_table_value(finding_codes),
        _markdown_table_value(finding.rationale),
    ]


def render_evaluation_report(result: AttorneyEvaluationResult) -> str:
    """Render a fixed-order, identity-blind attorney-evaluation summary."""
    snapshot, _ = _strict_model_payload(result, AttorneyEvaluationResult)
    if _result_fingerprint(snapshot) != snapshot.result_fingerprint:
        raise EvaluationIntegrityError("evaluation result self-fingerprint mismatch")

    report_lines = ["# Automated Attorney Evaluation", "", "## Disposition", ""]
    if snapshot.reports:
        report_lines.extend(
            f"- Anonymous report {report.anonymous_label}: {report.absolute_disposition.value}"
            for report in snapshot.reports
        )
    else:
        report_lines.append(f"- Evaluation: {snapshot.readiness.status.value}")

    report_lines.extend(
        [
            "",
            "## Case Readiness",
            "",
            f"- Status: {snapshot.readiness.status.value}",
            f"- Rationale: {snapshot.readiness.rationale}",
            "",
            "## Critical Defects",
            "",
        ]
    )
    critical = [
        (report.anonymous_label, code)
        for report in snapshot.reports
        for code in report.blocking_codes
        if report.critical_defect
    ]
    report_lines.extend(
        [f"- Report {label}: {code}" for label, code in critical] or ["- None recorded."]
    )

    report_lines.extend(
        [
            "",
            "## Requirement-by-Requirement Matrix",
            "",
        ]
    )
    matrix = snapshot.requirement_matrix
    if not matrix.available:
        report_lines.append(f"- Unavailable: {matrix.unavailable_reason}.")
    elif not matrix.rows:
        report_lines.append("- No sealed ledger entries.")
    else:
        report_lines.extend(
            [
                "| Walk | Ledger ID | Category | Materiality | Legal proposition | "
                "Source pins | A disposition | A location | A findings | A rationale | "
                "B disposition | B location | B findings | B rationale |",
                "| ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | "
                "--- | --- | --- | --- |",
            ]
        )
        for row in matrix.rows:
            citations = "<br>".join(
                f"{_markdown_table_value(pin.source_id)}@{pin.start_char}:{pin.end_char}"
                for pin in row.citations
            )
            cells = [
                str(row.walk_order),
                _markdown_table_value(row.ledger_id),
                _markdown_table_value(row.category.value),
                _markdown_table_value(row.materiality.value),
                _markdown_table_value(row.proposition),
                citations,
                *_matrix_finding_cells(row.report_a),
                *_matrix_finding_cells(row.report_b),
            ]
            report_lines.append(f"| {' | '.join(cells)} |")

    report_lines.extend(
        [
            "",
            "## Score Summary",
            "",
            "| Report | Critical recall | Weighted recall | Claim precision |",
            "| --- | ---: | ---: | ---: |",
        ]
    )
    report_lines.extend(
        f"| {report.anonymous_label} | {report.critical_recall:.3f} | "
        f"{report.weighted_recall:.3f} | {report.claim_precision:.3f} |"
        for report in snapshot.reports
    )
    if not snapshot.reports:
        report_lines.append("| — | — | — | — |")

    unsupported = [
        (report.anonymous_label, code)
        for report in snapshot.reports
        for code in report.blocking_codes
        if code.startswith(("UNSUPPORTED_", "OVERSTATED_", "CONTRADICTED_"))
    ]
    report_lines.extend(
        ["", "## Unsupported or Overstated Claims", ""]
        + ([f"- Report {label}: {code}" for label, code in unsupported] or ["- None recorded."])
    )

    report_lines.extend(
        [
            "",
            "## Regulatory Walk",
            "",
            "| Report | Average | Minimum |",
            "| --- | ---: | ---: |",
        ]
    )
    report_lines.extend(
        f"| {report.anonymous_label} | {report.walk_average:.3f} | {report.walk_minimum} |"
        for report in snapshot.reports
    )
    if not snapshot.reports:
        report_lines.append("| — | — | — |")

    report_lines.extend(["", "## Comparative Result", ""])
    if snapshot.comparison is None:
        report_lines.append("- Absolute evaluation only; no comparator was supplied.")
    else:
        report_lines.append(f"- Disposition: {snapshot.comparison.disposition.value}")
        if snapshot.comparison.winner_label is not None:
            report_lines.append(f"- Winning anonymous report: {snapshot.comparison.winner_label}")

    report_lines.extend(
        [
            "",
            "## Evaluation Limits and Provenance",
            "",
            "- Results are AI generated and may contain errors.",
            "- An attorney must validate the output before delivering legal advice.",
            "- Detailed blind grades, deterministic checks, score inputs, and judge-call "
            "provenance remain in the immutable run artifacts.",
            f"- Aggregate judge isolation: {snapshot.judge_isolation}.",
            "",
        ]
    )
    return "\n".join(report_lines)
