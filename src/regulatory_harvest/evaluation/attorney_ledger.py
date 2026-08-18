"""Validate, repair, and seal source-only attorney-evaluation legal ledgers."""

from __future__ import annotations

import hashlib
import json
import re
from typing import cast

from pydantic import ValidationError

from regulatory_harvest.models.enums import SourceRole
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from .attorney_admission import build_admission_packet
from .attorney_contract import ResponseContractCode, ResponseContractError
from .attorney_models import (
    CaseEnvelope,
    EvaluationIssue,
    EvaluationSource,
    IssueSeverity,
    LedgerAudit,
    LedgerCategory,
    LedgerCitation,
    LedgerDispute,
    LedgerEntry,
    LegalLedger,
    Materiality,
    RefereeDecision,
    SealedLedger,
    model_fingerprint,
)


class LedgerInconclusiveError(ResponseContractError):
    """Raised when the source-only ledger cannot safely be sealed."""


_OPERATIVE_CATEGORIES = frozenset(
    {
        LedgerCategory.REQUIREMENT,
        LedgerCategory.PROHIBITION,
        LedgerCategory.RIGHT,
        LedgerCategory.DEADLINE,
        LedgerCategory.ENFORCEMENT,
        LedgerCategory.REMEDY,
        LedgerCategory.PENALTY,
    }
)
_ACTOR_OBJECT_CATEGORIES = frozenset(
    {
        LedgerCategory.REQUIREMENT,
        LedgerCategory.PROHIBITION,
        LedgerCategory.RIGHT,
    }
)
_TRIGGER_LINK_CATEGORIES = frozenset({LedgerCategory.ENFORCEMENT, LedgerCategory.PENALTY})
_GENERIC_MATERIALITY_RATIONALES = frozenset(
    {"important", "material", "critical", "significant", "high priority"}
)
_AUDIT_RATIONALE_MINIMUM_WORDS = 6
_AUDIT_RATIONALE_LEGAL_OR_RECORD_ANCHORS = (
    "authority",
    "citation",
    "condition",
    "consequence",
    "deadline",
    "duty",
    "exception",
    "ledger",
    "materiality",
    "penalty",
    "proposition",
    "record",
    "regulation",
    "requirement",
    "right",
    "source",
    "statute",
    "text",
    "timing",
    "trigger",
)
_AUDIT_RATIONALE_DEFECT_OR_CORRECTION_SIGNALS = (
    "add",
    "combine",
    "combined",
    "combines",
    "conflict",
    "correction",
    "delete",
    "duplicate",
    "edit",
    "fails",
    "incorrect",
    "incomplete",
    "lacks",
    "merge",
    "missing",
    "needs",
    "omitted",
    "overaggregated",
    "overstates",
    "repair",
    "requires",
    "separate",
    "split",
    "understates",
    "unsupported",
    "wrong",
)
_AUDIT_RATIONALE_STOPWORDS = (
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "because",
    "been",
    "being",
    "by",
    "for",
    "from",
    "has",
    "have",
    "in",
    "into",
    "is",
    "it",
    "its",
    "of",
    "on",
    "or",
    "that",
    "the",
    "their",
    "this",
    "to",
    "was",
    "were",
    "with",
)
_AUDIT_RATIONALE_EVALUATOR_METADATA_TERMS = (
    "audit",
    "case",
    "correction",
    "corrections",
    "critical",
    "entries",
    "entry",
    "evaluator",
    "finding",
    "findings",
    "fingerprint",
    "high",
    "immaterial",
    "importance",
    "important",
    "ledger",
    "low",
    "major",
    "material",
    "materiality",
    "materially",
    "metadata",
    "minor",
    "payload",
    "priority",
    "proposal",
    "proposed",
    "record",
    "request",
    "response",
    "schema",
    "significant",
    "source",
    "supporting",
    "target",
    "targets",
)
_AUDIT_RATIONALE_ACTION_BOILERPLATE_TERMS = (
    "add",
    "added",
    "adding",
    "adds",
    "change",
    "changed",
    "changes",
    "changing",
    "concrete",
    "contains",
    "distinct",
    "identified",
    "indeed",
    "need",
    "needed",
    "needing",
    "needs",
    "omit",
    "omission",
    "omissions",
    "omits",
    "omitted",
    "omitting",
    "repair",
    "repaired",
    "repairing",
    "repairs",
    "require",
    "required",
    "requires",
    "requiring",
    "still",
    "very",
)
_AUDIT_RATIONALE_LEGAL_LOCATORS = (
    "article",
    "chapter",
    "paragraph",
    "rule",
    "schedule",
    "section",
)
_AUDIT_RATIONALE_MINIMUM_SOURCE_TERMS = 2
_AUDIT_RATIONALE_LOCATOR_PATTERN = re.compile(
    r"\b("
    + "|".join(_AUDIT_RATIONALE_LEGAL_LOCATORS)
    + r")\s+([a-z]*\d+[a-z]*(?:[.-][a-z0-9]+)*(?:\([a-z0-9.-]+\))*|"
    + r"[a-z]|[ivxlcdm]+)(?![a-z0-9(])",
    re.IGNORECASE,
)
_FINGERPRINT_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_LEDGER_INVARIANT_CONTRACT_V1_0_BYTES = b"""{
    "schema_version": "1.0",
    "binding": {"case_fingerprint": "source_record.source_record_fingerprint"},
    "identity": {
        "ledger_ids": "unique",
        "gap_ids": "unique",
        "entry_gap_ids": "disjoint",
        "walk_order": "unique_contiguous_zero_based"
    },
    "relationships": {
        "targets": "known_ledger_ids",
        "self_reference": "forbidden",
        "trigger_link_categories": ["enforcement", "penalty"],
        "trigger_target_categories": ["requirement", "prohibition"]
    },
    "citations": {
        "source_ids": "known_retained_sources",
        "slices": "unique_exact_half_open",
        "quote": "exact_source_text",
        "operative_categories_require_exact_support": true,
        "operative_categories_forbid_commentary_only_support": true
    },
    "required_fields": {
        "requirement_prohibition_right": ["actor", "object"],
        "deadline": ["timing"],
        "exception": ["conditions_or_exceptions"],
        "enforcement": ["enforcing_authority", "enforcement_route", "trigger_link"],
        "penalty": ["consequence", "trigger_link"],
        "remedy": ["consequence"]
    },
    "materiality_rationale": {
        "minimum_word_tokens": 5,
        "generic_only": "forbidden"
    },
    "repair_closure": {
        "resolve_every_initial_finding": true,
        "remaining_audit_request_fingerprint": "exact_repair_request_fingerprint",
        "complete_true_requires_full_recheck": true,
        "remaining_disputes": "transaction_ready_only"
    }
}"""


def _ledger_invariant_contract_v1_0() -> dict[str, object]:
    """Return a fresh copy of immutable schema-1.0 compatibility data."""
    return cast(dict[str, object], json.loads(_LEDGER_INVARIANT_CONTRACT_V1_0_BYTES))


def ledger_invariant_contract() -> dict[str, object]:
    """Return the mixed deterministic/attested ledger-role contract."""
    return {
        "schema_version": "1.1",
        "binding": {
            "case_fingerprint": "source_record.source_record_fingerprint",
        },
        "identity": {
            "ledger_ids": "unique",
            "gap_ids": "unique",
            "entry_gap_ids": "disjoint",
            "walk_order": "unique_contiguous_zero_based",
        },
        "relationships": {
            "targets": "known_ledger_ids",
            "self_reference": "forbidden",
            "trigger_link_categories": ["enforcement", "penalty"],
            "trigger_target_categories": ["requirement", "prohibition"],
        },
        "citations": {
            "source_ids": "known_retained_sources",
            "slices": "unique_exact_half_open",
            "quote": "exact_source_text",
            "operative_categories_require_exact_support": True,
            "operative_categories_forbid_commentary_only_support": True,
        },
        "required_fields": {
            "requirement_prohibition_right": ["actor", "object"],
            "deadline": ["timing"],
            "exception": ["conditions_or_exceptions"],
            "enforcement": [
                "enforcing_authority",
                "enforcement_route",
                "trigger_link",
            ],
            "penalty": ["consequence", "trigger_link"],
            "remedy": ["consequence"],
        },
        "materiality_rationale": {
            "minimum_word_tokens": 5,
            "forbidden_exact_normalized_values": [
                "critical",
                "high priority",
                "important",
                "material",
                "significant",
            ],
        },
        "repair_closure": {
            "resolve_every_initial_finding": "evaluator_attestation",
            "remaining_audit_request_fingerprint": "deterministically_enforced",
            "complete_true_requires_full_recheck": "evaluator_attestation",
            "remaining_disputes": "deterministically_enforced_transaction_ready_only",
        },
    }


def validate_ledger(envelope: CaseEnvelope, ledger: LegalLedger) -> list[EvaluationIssue]:
    """Return deterministic source-record defects for one legal ledger.

    The function intentionally returns issues for content defects.  Malformed
    post-validation model state is still rejected rather than coerced.
    """
    raw_walk_issue = _raw_walk_order_issue(ledger)
    envelope = _strict_envelope_snapshot(envelope)
    _validate_envelope_binding(envelope)
    if raw_walk_issue:
        return [
            _issue(
                "LEDGER_WALK_ORDER_INVALID",
                "Ledger entries must be in unique, contiguous zero-based walk order.",
            )
        ]
    ledger = _strict_ledger_snapshot(ledger)
    source_record_fingerprint = _source_record_fingerprint(envelope)

    issues: list[EvaluationIssue] = []
    sources_by_id = {source.source_id: source for source in envelope.case.sources}
    source_ids = set(sources_by_id)
    ledger_ids = [entry.ledger_id for entry in ledger.entries]
    ledger_id_set = set(ledger_ids)

    if ledger.case_fingerprint != source_record_fingerprint:
        issues.append(
            _issue(
                "LEDGER_CASE_MISMATCH",
                "Ledger does not bind the exact admitted source record.",
            )
        )
    if len(ledger_id_set) != len(ledger_ids):
        issues.append(_issue("LEDGER_DUPLICATE_ID", "Ledger entries must have unique identifiers."))

    gap_ids = [gap.gap_id for gap in ledger.gaps]
    if set(ledger_ids) & set(gap_ids):
        issues.append(
            _issue(
                "LEDGER_IDENTIFIER_COLLISION",
                "Ledger entry and gap identifiers must not overlap.",
            )
        )

    for source in envelope.case.sources:
        unknown_source_relationships = set(source.relationship_ids) - source_ids
        if unknown_source_relationships:
            issues.append(
                _issue(
                    "SOURCE_RELATIONSHIP_UNKNOWN",
                    "Source relationship identifiers must identify retained sources.",
                    [source.source_id, *sorted(unknown_source_relationships)],
                )
            )

    for gap in ledger.gaps:
        unknown_gap_sources = set(gap.source_ids) - source_ids
        if unknown_gap_sources:
            issues.append(
                _issue(
                    "LEDGER_GAP_SOURCE_UNKNOWN",
                    "Ledger gap source identifiers must identify retained sources.",
                    [gap.gap_id, *sorted(unknown_gap_sources)],
                )
            )

    entries_by_id = {entry.ledger_id: entry for entry in ledger.entries}
    for entry in ledger.entries:
        issues.extend(_entry_issues(entry, sources_by_id, entries_by_id))

    return _unique_issues(issues)


def ledger_findings(
    envelope: CaseEnvelope,
    proposed_ledger: LegalLedger,
    audit: LedgerAudit,
) -> list[LedgerDispute]:
    """Return complete initial-audit findings without requiring repair transactions."""
    try:
        envelope = _strict_envelope_snapshot(envelope)
        proposed_ledger = _strict_ledger_snapshot(proposed_ledger)
        _validate_envelope_binding(envelope)
    except (TypeError, ValidationError, ValueError) as error:
        raise LedgerInconclusiveError(f"malformed ledger finding context: {error}") from error
    ledger_issues = validate_ledger(envelope, proposed_ledger)
    if ledger_issues:
        raise LedgerInconclusiveError(
            "invalid proposed ledger context: " + _issues_message(ledger_issues)
        )
    findings = _complete_audit_items(audit)
    for finding in findings:
        _validate_finding_shape(finding)
        if not _concrete_audit_rationale(finding.rationale):
            raise LedgerInconclusiveError(
                f"ledger finding {finding.dispute_id} requires a concrete rationale",
                code=ResponseContractCode.AUDIT_RATIONALE_INSUFFICIENT,
                related_ids=[finding.dispute_id],
            )
        proposed_ids = [entry.ledger_id for entry in finding.proposed_entries]
        if len(set(proposed_ids)) != len(proposed_ids):
            raise LedgerInconclusiveError(
                "ledger finding contains duplicate proposed ledger IDs",
                code=ResponseContractCode.PROPOSED_ENTRY_INVALID,
                related_ids=[finding.dispute_id],
            )
        _validate_finding_grounding(envelope, proposed_ledger, finding)
    return findings


def ledger_disputes(audit: LedgerAudit) -> list[LedgerDispute]:
    """Return transaction-strict disputes from a complete remaining audit."""
    disputes = _complete_audit_items(audit)
    for dispute in disputes:
        _validate_dispute_shape(dispute)
    return disputes


def _complete_audit_items(audit: LedgerAudit) -> list[LedgerDispute]:
    """Return a strict snapshot after completeness and identifier checks."""
    try:
        audit = _strict_audit_snapshot(audit)
    except (TypeError, ValidationError, ValueError) as error:
        raise LedgerInconclusiveError(f"malformed ledger audit: {error}") from error
    if audit.complete is not True:
        raise LedgerInconclusiveError(
            "audit is incomplete", code=ResponseContractCode.AUDIT_INCOMPLETE
        )
    dispute_ids = [dispute.dispute_id for dispute in audit.disputes]
    if len(set(dispute_ids)) != len(dispute_ids):
        raise LedgerInconclusiveError("duplicate ledger dispute ID")
    return [
        LedgerDispute.model_validate(dispute.model_dump(mode="python"), strict=True)
        for dispute in audit.disputes
    ]


def seal_ledger(
    envelope: CaseEnvelope,
    ledger: LegalLedger,
    audit: LedgerAudit,
    referee: RefereeDecision | None,
) -> SealedLedger:
    """Apply a complete audit and produce a source-only sealed ledger.

    Material and critical disputes require an explicit referee choice; supporting
    corrections are deterministic audit repairs.  All inputs are revalidated at
    this public boundary because Pydantic model instances are mutable.
    """
    try:
        envelope = _strict_envelope_snapshot(envelope)
        ledger = _strict_ledger_snapshot(ledger)
        audit = _strict_audit_snapshot(audit)
        referee = _strict_referee_snapshot(referee)
        _validate_envelope_binding(envelope)
    except (TypeError, ValidationError, ValueError) as error:
        raise LedgerInconclusiveError(f"malformed ledger sealing input: {error}") from error

    initial_issues = validate_ledger(envelope, ledger)
    if initial_issues:
        raise LedgerInconclusiveError(_issues_message(initial_issues))
    disputes = ledger_disputes(audit)
    disputes_by_id = {dispute.dispute_id: dispute for dispute in disputes}
    _validate_referee(referee, disputes_by_id, envelope)

    unresolved = [
        dispute
        for dispute in disputes
        if dispute.materiality in {Materiality.MATERIAL, Materiality.CRITICAL}
        and (referee is None or referee.dispute_id != dispute.dispute_id)
    ]
    if unresolved:
        highest = next(
            (dispute for dispute in unresolved if dispute.materiality is Materiality.CRITICAL),
            unresolved[0],
        )
        raise LedgerInconclusiveError(
            f"{highest.materiality.value} ledger dispute requires referee resolution: "
            f"{highest.dispute_id}"
        )

    final_entries = [
        LedgerEntry.model_validate(entry.model_dump(mode="python"), strict=True)
        for entry in ledger.entries
    ]
    source_record_fingerprint = _source_record_fingerprint(envelope)
    final_gaps = [gap.model_copy(deep=True) for gap in ledger.gaps]
    for dispute in disputes:
        _preflight_dispute(final_entries, dispute, referee)
        resolution = _resolution_for(dispute, referee)
        final_entries = _apply_dispute(final_entries, dispute, resolution, referee)
        intermediate = LegalLedger(
            case_fingerprint=source_record_fingerprint,
            entries=final_entries,
            gaps=final_gaps,
        )
        intermediate_issues = validate_ledger(envelope, intermediate)
        if intermediate_issues:
            raise LedgerInconclusiveError(
                f"ledger dispute {dispute.dispute_id} produced invalid intermediate ledger: "
                f"{_issues_message(intermediate_issues)}"
            )

    final_ledger = LegalLedger(
        case_fingerprint=source_record_fingerprint,
        entries=final_entries,
        gaps=final_gaps,
    )
    final_issues = validate_ledger(envelope, final_ledger)
    if final_issues:
        raise LedgerInconclusiveError(_issues_message(final_issues))

    audit_fingerprint = sha256_digest(
        canonical_json_bytes(
            {
                "source_record_fingerprint": source_record_fingerprint,
                "audit": audit.model_dump(mode="json"),
            }
        )
    )
    ledger_fingerprint = sha256_digest(
        canonical_json_bytes(
            {
                "source_record_fingerprint": source_record_fingerprint,
                "audit_fingerprint": audit_fingerprint,
                "ledger": final_ledger.model_dump(mode="json"),
                "referee": None if referee is None else referee.model_dump(mode="json"),
            }
        )
    )
    return SealedLedger(
        ledger=final_ledger,
        audit_fingerprint=audit_fingerprint,
        ledger_fingerprint=ledger_fingerprint,
    )


def _entry_issues(
    entry: LedgerEntry,
    sources_by_id: dict[str, EvaluationSource],
    entries_by_id: dict[str, LedgerEntry],
) -> list[EvaluationIssue]:
    issues: list[EvaluationIssue] = []
    ledger_ids = set(entries_by_id)
    relationship_ids = set(entry.relationship_ids)
    unknown_relationships = relationship_ids - ledger_ids
    if unknown_relationships:
        issues.append(
            _issue(
                "LEDGER_RELATIONSHIP_UNKNOWN",
                "Ledger relationship identifiers must identify ledger entries.",
                [entry.ledger_id, *sorted(unknown_relationships)],
            )
        )
    if entry.ledger_id in relationship_ids:
        issues.append(
            _issue(
                "LEDGER_RELATIONSHIP_SELF",
                "A ledger entry cannot be its own relationship target.",
                [entry.ledger_id],
            )
        )

    exact_citations = 0
    seen_citations: set[tuple[str, int, int, str]] = set()
    commentary_citations = 0
    for citation in entry.citations:
        source = sources_by_id.get(citation.source_id)
        citation_key = (citation.source_id, citation.start_char, citation.end_char, citation.quote)
        if citation_key in seen_citations:
            issues.append(
                _issue(
                    "LEDGER_CITATION_DUPLICATE",
                    "Ledger entry citations must not repeat the same source slice.",
                    [entry.ledger_id, citation.source_id],
                )
            )
        seen_citations.add(citation_key)
        if source is None:
            issues.append(
                _issue(
                    "LEDGER_CITATION_SOURCE_UNKNOWN",
                    "Ledger citations must identify retained sources.",
                    [entry.ledger_id, citation.source_id],
                )
            )
            continue
        if not _quote_matches(source, citation):
            issues.append(
                _issue(
                    "LEDGER_QUOTE_MISMATCH",
                    "Ledger citation quote and half-open offsets must match source text exactly.",
                    [entry.ledger_id, citation.source_id],
                )
            )
            continue
        exact_citations += 1
        if source.source_role is SourceRole.COMMENTARY_ANALYSIS:
            commentary_citations += 1

    if entry.category in _OPERATIVE_CATEGORIES and exact_citations == 0 and not issues:
        issues.append(
            _issue(
                "LEDGER_OPERATIVE_CITATION_MISSING",
                "Operative ledger entries require at least one exact source citation.",
                [entry.ledger_id],
            )
        )
    if (
        entry.category in _OPERATIVE_CATEGORIES
        and exact_citations > 0
        and commentary_citations == exact_citations
    ):
        issues.append(
            _issue(
                "LEDGER_COMMENTARY_ONLY_SUPPORT",
                "Operative ledger entries cannot rely only on commentary analysis.",
                [entry.ledger_id],
            )
        )

    if entry.category in _ACTOR_OBJECT_CATEGORIES:
        if entry.actor is None:
            issues.append(
                _issue(
                    "LEDGER_ACTOR_MISSING",
                    "Operative duty entries must identify the regulated actor.",
                    [entry.ledger_id],
                )
            )
        if entry.object is None:
            issues.append(
                _issue(
                    "LEDGER_OBJECT_MISSING",
                    "Operative duty entries must identify their regulated object.",
                    [entry.ledger_id],
                )
            )
    if entry.category is LedgerCategory.DEADLINE and entry.timing is None:
        issues.append(
            _issue(
                "LEDGER_DEADLINE_TIMING_MISSING",
                "Deadline entries must identify a timing requirement.",
                [entry.ledger_id],
            )
        )
    if entry.category is LedgerCategory.EXCEPTION and not (entry.conditions or entry.exceptions):
        issues.append(
            _issue(
                "LEDGER_EXCEPTION_CONDITIONS_MISSING",
                "Exception entries must identify the exception conditions.",
                [entry.ledger_id],
            )
        )
    if entry.category is LedgerCategory.ENFORCEMENT:
        if entry.enforcing_authority is None:
            issues.append(
                _issue(
                    "LEDGER_ENFORCING_AUTHORITY_MISSING",
                    "Enforcement entries must identify an enforcing authority.",
                    [entry.ledger_id],
                )
            )
        if entry.enforcement_route is None:
            issues.append(
                _issue(
                    "LEDGER_ENFORCEMENT_ROUTE_MISSING",
                    "Enforcement entries must identify an enforcement route.",
                    [entry.ledger_id],
                )
            )
    if (
        entry.category in {LedgerCategory.PENALTY, LedgerCategory.REMEDY}
        and entry.consequence is None
    ):
        issues.append(
            _issue(
                f"LEDGER_{entry.category.value.upper()}_CONSEQUENCE_MISSING",
                f"{entry.category.value.capitalize()} entries must identify a consequence.",
                [entry.ledger_id],
            )
        )
    if entry.category in _TRIGGER_LINK_CATEGORIES and not entry.relationship_ids:
        issues.append(
            _issue(
                "LEDGER_TRIGGER_LINK_MISSING",
                "Enforcement and penalty entries must identify a triggering entry relationship.",
                [entry.ledger_id],
            )
        )
    if (
        entry.category in _TRIGGER_LINK_CATEGORIES
        and entry.relationship_ids
        and not any(
            entries_by_id[relationship_id].category
            in {LedgerCategory.REQUIREMENT, LedgerCategory.PROHIBITION}
            for relationship_id in entry.relationship_ids
            if relationship_id in entries_by_id
        )
    ):
        issues.append(
            _issue(
                "LEDGER_TRIGGER_RELATIONSHIP_INVALID",
                "Enforcement and penalty entries must relate to a requirement or prohibition.",
                [entry.ledger_id],
            )
        )
    if not _concrete_rationale(entry.materiality_rationale):
        issues.append(
            _issue(
                "LEDGER_MATERIALITY_RATIONALE_INSUFFICIENT",
                "Materiality rationale must state a concrete legal or practical consequence.",
                [entry.ledger_id],
            )
        )
    return issues


def _quote_matches(source: EvaluationSource, span: LedgerCitation) -> bool:
    return (
        0 <= span.start_char < span.end_char <= len(source.normalized_text)
        and source.normalized_text[span.start_char : span.end_char] == span.quote
    )


def _concrete_rationale(rationale: str) -> bool:
    normalized = " ".join(rationale.lower().split())
    return (
        normalized not in _GENERIC_MATERIALITY_RATIONALES
        and len(re.findall(r"[a-z0-9]+", normalized)) >= 5
    )


def _concrete_audit_rationale(rationale: str) -> bool:
    """Apply the deterministic lexical contract for initial-audit rationales."""
    normalized = " ".join(rationale.lower().split())
    tokens = re.findall(r"[a-z0-9]+", normalized)
    return (
        normalized not in _GENERIC_MATERIALITY_RATIONALES
        and len(tokens) >= _AUDIT_RATIONALE_MINIMUM_WORDS
        and any(token in _AUDIT_RATIONALE_LEGAL_OR_RECORD_ANCHORS for token in tokens)
        and any(
            token in _AUDIT_RATIONALE_DEFECT_OR_CORRECTION_SIGNALS for token in tokens
        )
    )


def _validate_finding_grounding(
    envelope: CaseEnvelope,
    proposed_ledger: LegalLedger,
    finding: LedgerDispute,
) -> None:
    _validate_finding_proposed_entries(envelope, proposed_ledger, finding)
    if finding.action != "add":
        unknown_targets = set(finding.target_ledger_ids) - {
            entry.ledger_id for entry in proposed_ledger.entries
        }
        if unknown_targets:
            raise LedgerInconclusiveError(
                f"{finding.action} initial ledger finding has an unknown target",
                code=ResponseContractCode.AUDIT_TARGET_UNKNOWN,
                related_ids=sorted(unknown_targets),
            )
        return
    if finding.proposed_entries:
        existing_ids = {entry.ledger_id for entry in proposed_ledger.entries}
        proposed_ids = {entry.ledger_id for entry in finding.proposed_entries}
        if existing_ids & proposed_ids:
            raise LedgerInconclusiveError(
                "add initial ledger finding must use new ledger IDs",
                code=ResponseContractCode.PROPOSED_ENTRY_INVALID,
                related_ids=sorted(existing_ids & proposed_ids),
            )
        return
    if not _proposal_free_add_is_source_grounded(envelope, finding.rationale):
        raise LedgerInconclusiveError(
            "proposal-free add initial ledger finding requires a source-grounded rationale",
            code=ResponseContractCode.SOURCE_BINDING_INVALID,
            related_ids=[finding.dispute_id],
        )


def _validate_finding_proposed_entries(
    envelope: CaseEnvelope,
    proposed_ledger: LegalLedger,
    finding: LedgerDispute,
) -> None:
    if not finding.proposed_entries:
        return
    sources_by_id = {source.source_id: source for source in envelope.case.sources}
    entries_by_id = {entry.ledger_id: entry for entry in proposed_ledger.entries}
    entries_by_id.update(
        {entry.ledger_id: entry for entry in finding.proposed_entries}
    )
    issues = _unique_issues(
        [
            issue
            for entry in finding.proposed_entries
            for issue in _entry_issues(entry, sources_by_id, entries_by_id)
        ]
    )
    if issues:
        issue_codes = ",".join(sorted({issue.code for issue in issues}))
        source_issue_codes = {
            "LEDGER_CITATION_SOURCE_UNKNOWN",
            "LEDGER_QUOTE_MISMATCH",
            "LEDGER_OPERATIVE_CITATION_MISSING",
        }
        raise LedgerInconclusiveError(
            f"ledger finding {finding.dispute_id} has invalid proposed entries: {issue_codes}",
            code=(
                ResponseContractCode.SOURCE_BINDING_INVALID
                if any(issue.code in source_issue_codes for issue in issues)
                else ResponseContractCode.PROPOSED_ENTRY_INVALID
            ),
            related_ids=[finding.dispute_id],
        )


def _proposal_free_add_is_source_grounded(
    envelope: CaseEnvelope, rationale: str
) -> bool:
    for source in envelope.case.sources:
        source_pattern = re.compile(
            rf"(?<![A-Za-z0-9_-]){re.escape(source.source_id)}(?![A-Za-z0-9_-])"
        )
        if not source_pattern.search(rationale):
            continue
        rationale_locators = _audit_legal_locators(rationale)
        source_text = f"{source.title} {source.normalized_text}"
        if rationale_locators:
            return rationale_locators <= _audit_legal_locators(source_text)
        rationale_terms = _audit_significant_terms(rationale) - set(
            re.findall(r"[a-z0-9]+", source.source_id.lower())
        )
        source_terms = _audit_significant_terms(
            f"{source.title} {source.normalized_text}"
        )
        if len(rationale_terms & source_terms) >= _AUDIT_RATIONALE_MINIMUM_SOURCE_TERMS:
            return True
    return False


def _audit_legal_locators(value: str) -> set[tuple[str, str]]:
    return {
        (match.group(1).casefold(), match.group(2).casefold())
        for match in _AUDIT_RATIONALE_LOCATOR_PATTERN.finditer(value)
    }


def _audit_significant_terms(value: str) -> set[str]:
    excluded = {
        *_AUDIT_RATIONALE_STOPWORDS,
        *_AUDIT_RATIONALE_EVALUATOR_METADATA_TERMS,
        *_AUDIT_RATIONALE_ACTION_BOILERPLATE_TERMS,
        *_AUDIT_RATIONALE_DEFECT_OR_CORRECTION_SIGNALS,
        *_AUDIT_RATIONALE_LEGAL_LOCATORS,
    }
    return {
        token
        for token in re.findall(r"[a-z0-9]+", value.lower())
        if token not in excluded and any(character.isalpha() for character in token)
    }


def _validate_finding_shape(finding: LedgerDispute) -> None:
    """Require supplied initial payloads to be consistent without requiring a repair."""
    targets = finding.target_ledger_ids
    proposed = finding.proposed_entries
    if finding.action == "add" and targets:
        raise LedgerInconclusiveError(
            "add initial ledger finding must have no targets",
            code=ResponseContractCode.AUDIT_ACTION_INVALID,
            related_ids=[finding.dispute_id],
        )
    if finding.action == "edit" and len(targets) != 1:
        raise LedgerInconclusiveError(
            "edit initial ledger finding must have one target",
            code=ResponseContractCode.AUDIT_ACTION_INVALID,
            related_ids=[finding.dispute_id],
        )
    if finding.action == "edit" and len(proposed) > 1:
        raise LedgerInconclusiveError(
            "edit initial ledger finding must have at most one entry",
            code=ResponseContractCode.AUDIT_ACTION_INVALID,
            related_ids=[finding.dispute_id],
        )
    if (
        finding.action == "edit"
        and proposed
        and proposed[0].ledger_id != targets[0]
    ):
        raise LedgerInconclusiveError(
            "edit initial ledger finding must preserve its ledger ID",
            code=ResponseContractCode.AUDIT_ACTION_INVALID,
            related_ids=[finding.dispute_id],
        )
    if finding.action == "delete" and (not targets or proposed):
        raise LedgerInconclusiveError(
            "delete initial ledger finding must have targets and no entries",
            code=ResponseContractCode.AUDIT_ACTION_INVALID,
            related_ids=[finding.dispute_id],
        )
    if finding.action == "split" and (len(targets) != 1 or len(proposed) == 1):
        raise LedgerInconclusiveError(
            "split initial ledger finding must have one target and zero or multiple entries",
            code=ResponseContractCode.AUDIT_ACTION_INVALID,
            related_ids=[finding.dispute_id],
        )
    if finding.action == "merge" and (len(targets) < 2 or len(proposed) > 1):
        raise LedgerInconclusiveError(
            "merge initial ledger finding must have multiple targets and at most one entry",
            code=ResponseContractCode.AUDIT_ACTION_INVALID,
            related_ids=[finding.dispute_id],
        )
    if finding.action == "materiality" and (len(targets) != 1 or proposed):
        raise LedgerInconclusiveError(
            "materiality initial ledger finding must have one target and no entries",
            code=ResponseContractCode.AUDIT_ACTION_INVALID,
            related_ids=[finding.dispute_id],
        )


def _validate_dispute_shape(dispute: LedgerDispute) -> None:
    targets = dispute.target_ledger_ids
    proposed = dispute.proposed_entries
    if dispute.action == "add" and (targets or not proposed):
        raise LedgerInconclusiveError("add ledger dispute must provide entries and no targets")
    if dispute.action == "edit" and (len(targets) != 1 or len(proposed) != 1):
        raise LedgerInconclusiveError("edit ledger dispute must have one target and one entry")
    if dispute.action == "edit" and proposed[0].ledger_id != targets[0]:
        raise LedgerInconclusiveError("edit ledger dispute must preserve its ledger ID")
    if dispute.action == "delete" and (not targets or proposed):
        raise LedgerInconclusiveError("delete ledger dispute must have targets and no entries")
    if dispute.action == "split" and (len(targets) != 1 or len(proposed) < 2):
        raise LedgerInconclusiveError(
            "split ledger dispute must have one target and multiple entries"
        )
    if dispute.action == "merge" and (len(targets) < 2 or len(proposed) != 1):
        raise LedgerInconclusiveError(
            "merge ledger dispute must have multiple targets and one entry"
        )
    if dispute.action == "materiality" and (len(targets) != 1 or proposed):
        raise LedgerInconclusiveError(
            "materiality ledger dispute must have one target and no entries"
        )
    proposed_ids = [entry.ledger_id for entry in proposed]
    if len(set(proposed_ids)) != len(proposed_ids):
        raise LedgerInconclusiveError("ledger dispute contains duplicate proposed ledger IDs")


def _validate_referee(
    referee: RefereeDecision | None,
    disputes_by_id: dict[str, LedgerDispute],
    envelope: CaseEnvelope,
) -> None:
    if referee is None:
        return
    dispute = disputes_by_id.get(referee.dispute_id)
    if dispute is None:
        raise LedgerInconclusiveError("referee decision does not identify an audit dispute")
    if referee.selected_disposition is not None or referee.selected_ledger_resolution is None:
        raise LedgerInconclusiveError("referee decision must select one ledger resolution")
    if referee.selected_ledger_resolution == "replace" and not referee.replacement_entries:
        raise LedgerInconclusiveError("replace referee decision requires replacement entries")
    if referee.selected_ledger_resolution != "replace" and referee.replacement_entries:
        raise LedgerInconclusiveError("referee replacement entries require replace resolution")
    unknown_source_ids = set(referee.source_ids) - {
        source.source_id for source in envelope.case.sources
    }
    if unknown_source_ids:
        raise LedgerInconclusiveError("referee decision identifies unknown source IDs")
    if referee.selected_ledger_resolution == "replace":
        replacement_ids = [entry.ledger_id for entry in referee.replacement_entries]
        if len(set(replacement_ids)) != len(replacement_ids):
            raise LedgerInconclusiveError("referee replacement entries duplicate ledger IDs")
    _validate_dispute_shape(dispute)


def _resolution_for(dispute: LedgerDispute, referee: RefereeDecision | None) -> str:
    if referee is not None and referee.dispute_id == dispute.dispute_id:
        assert referee.selected_ledger_resolution is not None
        return referee.selected_ledger_resolution
    return "accept_b"


def _apply_dispute(
    entries: list[LedgerEntry],
    dispute: LedgerDispute,
    resolution: str,
    referee: RefereeDecision | None,
) -> list[LedgerEntry]:
    if resolution == "accept_a":
        return entries
    proposed_entries = (
        referee.replacement_entries
        if resolution == "replace" and referee is not None
        else dispute.proposed_entries
    )
    _validate_transaction_targets(entries, dispute)
    if dispute.action == "add":
        return _apply_add(entries, proposed_entries)
    if dispute.action == "edit":
        return _apply_edit(entries, dispute, proposed_entries)
    if dispute.action == "delete":
        if resolution == "replace":
            raise LedgerInconclusiveError("delete referee replacement is not supported")
        target_ids = set(dispute.target_ledger_ids)
        return _compact_entries([entry for entry in entries if entry.ledger_id not in target_ids])
    if dispute.action == "split":
        return _apply_split(entries, dispute, proposed_entries)
    if dispute.action == "merge":
        return _apply_merge(entries, dispute, proposed_entries)
    if dispute.action == "materiality":
        if resolution == "replace":
            raise LedgerInconclusiveError("materiality referee replacement cannot include entries")
        target_index = _target_index(entries, dispute.target_ledger_ids[0])
        return [
            entry.model_copy(update={"materiality": dispute.materiality}, deep=True)
            if index == target_index
            else entry.model_copy(deep=True)
            for index, entry in enumerate(entries)
        ]
    raise LedgerInconclusiveError(f"unsupported ledger audit action: {dispute.action}")


def _preflight_dispute(
    entries: list[LedgerEntry], dispute: LedgerDispute, referee: RefereeDecision | None
) -> None:
    """Require every audit alternative to be executable before choosing a resolution."""
    _validate_transaction_targets(entries, dispute)
    _validate_action_payload(entries, dispute, dispute.proposed_entries, "audit")
    if (
        referee is not None
        and referee.dispute_id == dispute.dispute_id
        and referee.selected_ledger_resolution == "replace"
    ):
        _validate_action_payload(
            entries, dispute, referee.replacement_entries, "referee replacement"
        )


def _validate_action_payload(
    entries: list[LedgerEntry],
    dispute: LedgerDispute,
    proposed_entries: list[LedgerEntry],
    origin: str,
) -> None:
    if dispute.action == "add":
        _validate_add_payload(entries, proposed_entries, origin)
        return
    if dispute.action == "edit":
        target_index = _target_index(entries, dispute.target_ledger_ids[0])
        proposed = _single_positioned_entry(proposed_entries, target_index, "edit")
        if proposed.ledger_id != dispute.target_ledger_ids[0]:
            raise LedgerInconclusiveError("edit ledger dispute must preserve its ledger ID")
        return
    if dispute.action == "delete":
        if proposed_entries:
            if origin == "referee replacement":
                raise LedgerInconclusiveError("delete referee replacement is not supported")
            raise LedgerInconclusiveError("delete ledger dispute must not provide entries")
        return
    if dispute.action == "split":
        if len(proposed_entries) < 2:
            raise LedgerInconclusiveError(
                "split ledger dispute must have one target and multiple entries"
            )
        target_index = _target_index(entries, dispute.target_ledger_ids[0])
        _validate_span_positions(proposed_entries, target_index, "split ledger dispute")
        _validate_replacement_ids(
            entries, target_index, target_index + 1, proposed_entries, "split"
        )
        return
    if dispute.action == "merge":
        first_index, end_index = _target_span(entries, dispute.target_ledger_ids, "merge")
        proposed = _single_positioned_entry(proposed_entries, first_index, "merge")
        _validate_replacement_ids(entries, first_index, end_index, [proposed], "merge")
        return
    if dispute.action == "materiality":
        if proposed_entries:
            raise LedgerInconclusiveError("materiality ledger dispute must not provide entries")
        return
    raise LedgerInconclusiveError(f"unsupported ledger audit action: {dispute.action}")


def _apply_add(entries: list[LedgerEntry], additions: list[LedgerEntry]) -> list[LedgerEntry]:
    _validate_add_payload(entries, additions, "add")
    additions_by_position = {entry.walk_order: entry for entry in additions}
    survivors = iter(entries)
    result = [
        additions_by_position[position].model_copy(deep=True)
        if position in additions_by_position
        else next(survivors).model_copy(deep=True)
        for position in range(len(entries) + len(additions))
    ]
    return _compact_entries(result)


def _validate_add_payload(
    entries: list[LedgerEntry], additions: list[LedgerEntry], origin: str
) -> None:
    existing_ids = {entry.ledger_id for entry in entries}
    addition_ids = [entry.ledger_id for entry in additions]
    if existing_ids & set(addition_ids):
        raise LedgerInconclusiveError(f"{origin} add ledger dispute reuses an existing ledger ID")
    new_length = len(entries) + len(additions)
    positions = [entry.walk_order for entry in additions]
    if len(set(positions)) != len(positions) or any(
        position < 0 or position >= new_length for position in positions
    ):
        raise LedgerInconclusiveError(
            f"{origin} add ledger dispute has duplicate or out-of-range positions"
        )


def _apply_edit(
    entries: list[LedgerEntry], dispute: LedgerDispute, proposed_entries: list[LedgerEntry]
) -> list[LedgerEntry]:
    target_id = dispute.target_ledger_ids[0]
    target_index = _target_index(entries, target_id)
    proposed = _single_positioned_entry(proposed_entries, target_index, "edit")
    if proposed.ledger_id != target_id:
        raise LedgerInconclusiveError("edit ledger dispute must preserve its ledger ID")
    result = [entry.model_copy(deep=True) for entry in entries]
    result[target_index] = proposed.model_copy(deep=True)
    return result


def _apply_split(
    entries: list[LedgerEntry], dispute: LedgerDispute, proposed_entries: list[LedgerEntry]
) -> list[LedgerEntry]:
    target_index = _target_index(entries, dispute.target_ledger_ids[0])
    expected_positions = list(range(target_index, target_index + len(proposed_entries)))
    if [entry.walk_order for entry in proposed_entries] != expected_positions:
        raise LedgerInconclusiveError(
            "split ledger dispute entries must declare consecutive target positions"
        )
    return _replace_span(entries, target_index, target_index + 1, proposed_entries, "split")


def _apply_merge(
    entries: list[LedgerEntry], dispute: LedgerDispute, proposed_entries: list[LedgerEntry]
) -> list[LedgerEntry]:
    first_index, end_index = _target_span(entries, dispute.target_ledger_ids, "merge")
    proposed = _single_positioned_entry(proposed_entries, first_index, "merge")
    return _replace_span(entries, first_index, end_index, [proposed], "merge")


def _replace_span(
    entries: list[LedgerEntry],
    start: int,
    end: int,
    replacements: list[LedgerEntry],
    operation: str,
) -> list[LedgerEntry]:
    _validate_replacement_ids(entries, start, end, replacements, operation)
    return _compact_entries(
        [
            *[entry.model_copy(deep=True) for entry in entries[:start]],
            *[entry.model_copy(deep=True) for entry in replacements],
            *[entry.model_copy(deep=True) for entry in entries[end:]],
        ]
    )


def _validate_replacement_ids(
    entries: list[LedgerEntry],
    start: int,
    end: int,
    replacements: list[LedgerEntry],
    operation: str,
) -> None:
    retained_ids = {entry.ledger_id for entry in [*entries[:start], *entries[end:]]}
    replacement_ids = [entry.ledger_id for entry in replacements]
    if retained_ids & set(replacement_ids):
        raise LedgerInconclusiveError(f"{operation} ledger dispute duplicates a retained ledger ID")


def _single_positioned_entry(
    entries: list[LedgerEntry], expected_position: int, operation: str
) -> LedgerEntry:
    if len(entries) != 1 or entries[0].walk_order != expected_position:
        raise LedgerInconclusiveError(
            f"{operation} ledger dispute entry must declare target position {expected_position}"
        )
    return entries[0]


def _validate_span_positions(entries: list[LedgerEntry], start: int, operation: str) -> None:
    if [entry.walk_order for entry in entries] != list(range(start, start + len(entries))):
        raise LedgerInconclusiveError(
            f"{operation} entries must declare consecutive target positions"
        )


def _target_span(
    entries: list[LedgerEntry], target_ids: list[str], operation: str
) -> tuple[int, int]:
    target_indexes = sorted(_target_index(entries, target_id) for target_id in target_ids)
    first_index = target_indexes[0]
    if target_indexes != list(range(first_index, first_index + len(target_indexes))):
        raise LedgerInconclusiveError(f"{operation} targets must form a contiguous span")
    return first_index, target_indexes[-1] + 1


def _validate_transaction_targets(entries: list[LedgerEntry], dispute: LedgerDispute) -> None:
    if dispute.action == "add":
        return
    entry_ids = {entry.ledger_id for entry in entries}
    unknown_targets = set(dispute.target_ledger_ids) - entry_ids
    if unknown_targets:
        raise LedgerInconclusiveError(
            "ledger dispute identifies unknown target IDs: " + ", ".join(sorted(unknown_targets))
        )


def _target_index(entries: list[LedgerEntry], target_id: str) -> int:
    for index, entry in enumerate(entries):
        if entry.ledger_id == target_id:
            return index
    raise LedgerInconclusiveError(f"ledger dispute identifies unknown target ID: {target_id}")


def _compact_entries(entries: list[LedgerEntry]) -> list[LedgerEntry]:
    return [
        entry.model_copy(update={"walk_order": index}, deep=True)
        for index, entry in enumerate(entries)
    ]


def _strict_envelope_snapshot(envelope: CaseEnvelope) -> CaseEnvelope:
    if not isinstance(envelope, CaseEnvelope):
        raise TypeError("envelope must be a CaseEnvelope")
    return CaseEnvelope.model_validate(
        envelope.model_dump(mode="python", warnings="error"), strict=True
    )


def _strict_ledger_snapshot(ledger: LegalLedger) -> LegalLedger:
    if not isinstance(ledger, LegalLedger):
        raise TypeError("ledger must be a LegalLedger")
    return LegalLedger.model_validate(
        ledger.model_dump(mode="python", warnings="error"), strict=True
    )


def _strict_audit_snapshot(audit: LedgerAudit) -> LedgerAudit:
    if not isinstance(audit, LedgerAudit) or type(audit.complete) is not bool:
        raise LedgerInconclusiveError("malformed ledger audit")
    return LedgerAudit.model_validate(
        audit.model_dump(mode="python", warnings="error"), strict=True
    )


def _strict_referee_snapshot(referee: RefereeDecision | None) -> RefereeDecision | None:
    if referee is None:
        return None
    if not isinstance(referee, RefereeDecision):
        raise LedgerInconclusiveError("malformed referee decision")
    return RefereeDecision.model_validate(
        referee.model_dump(mode="python", warnings="error"), strict=True
    )


def _validate_envelope_binding(envelope: CaseEnvelope) -> None:
    if envelope.case_fingerprint != model_fingerprint(envelope.case):
        raise ValueError("case envelope does not bind its current case data")
    for source in envelope.case.sources:
        if (
            source.content_hash
            != hashlib.sha256(source.normalized_text.encode("utf-8")).hexdigest()
        ):
            raise ValueError(f"source content hash is invalid: {source.source_id}")


def _source_record_fingerprint(envelope: CaseEnvelope) -> str:
    packet = build_admission_packet(envelope)
    fingerprint = packet.safe_metadata.get("source_record_fingerprint")
    if not isinstance(fingerprint, str) or not _FINGERPRINT_PATTERN.fullmatch(fingerprint):
        raise ValueError("admission packet source_record_fingerprint is invalid")
    return fingerprint


def _raw_walk_order_issue(ledger: LegalLedger) -> bool:
    """Preserve a stable semantic issue for mutated integer walk-order defects."""
    if not isinstance(ledger, LegalLedger) or not isinstance(ledger.entries, list):
        return False
    if not all(
        isinstance(entry, LedgerEntry) and type(entry.walk_order) is int for entry in ledger.entries
    ):
        return False
    return [entry.walk_order for entry in ledger.entries] != list(range(len(ledger.entries)))


def _issue(code: str, message: str, related_ids: list[str] | None = None) -> EvaluationIssue:
    return EvaluationIssue(
        code=code,
        severity=IssueSeverity.ERROR,
        message=message,
        related_ids=related_ids or [],
    )


def _unique_issues(issues: list[EvaluationIssue]) -> list[EvaluationIssue]:
    seen: set[tuple[str, tuple[str, ...]]] = set()
    unique: list[EvaluationIssue] = []
    for issue in issues:
        key = (issue.code, tuple(issue.related_ids))
        if key not in seen:
            seen.add(key)
            unique.append(issue)
    return unique


def _issues_message(issues: list[EvaluationIssue]) -> str:
    return "ledger validation failed: " + ", ".join(issue.code for issue in issues)
