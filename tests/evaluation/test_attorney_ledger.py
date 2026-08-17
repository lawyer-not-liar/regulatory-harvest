from __future__ import annotations

import hashlib
from datetime import date

import pytest

from regulatory_harvest.evaluation.attorney_admission import build_admission_packet, freeze_case
from regulatory_harvest.evaluation.attorney_ledger import (
    LedgerInconclusiveError,
    ledger_disputes,
    ledger_findings,
    seal_ledger,
    validate_ledger,
)
from regulatory_harvest.evaluation.attorney_models import (
    AttorneyEvaluationCase,
    CandidateReport,
    CandidateRole,
    CaseEnvelope,
    EvaluationMode,
    EvaluationSource,
    LedgerAudit,
    LedgerCategory,
    LedgerCitation,
    LedgerDispute,
    LedgerEntry,
    LegalLedger,
    Materiality,
    RefereeDecision,
    RequestedAuthority,
    model_fingerprint,
)
from regulatory_harvest.models import SourceQuality, SourceRole

SOURCE_TEXT = "Section 7. A controller shall document processing activities."
QUOTE = "controller shall document processing activities"


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def evaluation_case() -> AttorneyEvaluationCase:
    candidate_text = "The controller must document its processing activities."
    comparator_text = "Documentation is required for processing activities."
    return AttorneyEvaluationCase(
        case_id="synthetic-case",
        mode=EvaluationMode.CLOSED_UNIVERSE,
        question="What documentation is required?",
        jurisdiction="Example State",
        as_of=date(2026, 8, 11),
        requested_authorities=[
            RequestedAuthority(
                authority_id="example-statute",
                title="Example Privacy Act",
                jurisdiction="Example State",
                authority_type="statute",
                source_ids=["example-statute-1"],
            )
        ],
        sources=[
            EvaluationSource(
                source_id="example-statute-1",
                title="Example Privacy Act",
                normalized_text=SOURCE_TEXT,
                content_hash=_sha256(SOURCE_TEXT),
                jurisdiction="Example State",
                authority_type="statute",
                source_role=SourceRole.OFFICIAL_PRIMARY,
                source_quality=SourceQuality.PRIMARY,
                completeness="complete",
                language="en",
            )
        ],
        candidates=[
            CandidateReport(
                candidate_id="harvest",
                role=CandidateRole.CANDIDATE,
                report_text=candidate_text,
                report_hash=_sha256(candidate_text),
            ),
            CandidateReport(
                candidate_id="comparison",
                role=CandidateRole.COMPARATOR,
                report_text=comparator_text,
                report_hash=_sha256(comparator_text),
            ),
        ],
    )


def admitted_envelope() -> CaseEnvelope:
    case = evaluation_case()
    for candidate in case.candidates:
        candidate.validation_receipt = {
            "schema_version": "1.0",
            "source_hashes": {case.sources[0].source_id: case.sources[0].content_hash},
            "client_facts_hash": _sha256(case.client_facts or ""),
        }
    return freeze_case(case, seed_hex="d" * 64)


def source_record_fingerprint(envelope: CaseEnvelope) -> str:
    fingerprint = build_admission_packet(envelope).safe_metadata["source_record_fingerprint"]
    assert isinstance(fingerprint, str)
    return fingerprint


def entry(
    ledger_id: str = "requirement-1",
    *,
    category: LedgerCategory = LedgerCategory.REQUIREMENT,
    materiality: Materiality = Materiality.MATERIAL,
    quote: str = QUOTE,
    start_char: int | None = None,
    relationship_ids: list[str] | None = None,
    trigger: str | None = None,
    enforcing_authority: str | None = None,
    enforcement_route: str | None = None,
    consequence: str | None = None,
    timing: str | None = None,
    materiality_rationale: str = (
        "The mandatory record controls the regulated controller's compliance."
    ),
) -> LedgerEntry:
    start = SOURCE_TEXT.index(QUOTE) if start_char is None else start_char
    return LedgerEntry(
        ledger_id=ledger_id,
        walk_order=0,
        category=category,
        materiality=materiality,
        actor="controller",
        modality="shall",
        operative_action="document",
        object="processing activities",
        trigger=trigger,
        timing=timing,
        enforcing_authority=enforcing_authority,
        enforcement_route=enforcement_route,
        consequence=consequence,
        relationship_ids=relationship_ids or [],
        proposition="Controllers shall document processing activities.",
        materiality_rationale=materiality_rationale,
        citations=[
            LedgerCitation(
                source_id="example-statute-1",
                start_char=start,
                end_char=start + len(quote),
                quote=quote,
            )
        ],
    )


def at_order(ledger_entry: LedgerEntry, walk_order: int) -> LedgerEntry:
    return ledger_entry.model_copy(update={"walk_order": walk_order})


def valid_ledger(*entries: LedgerEntry) -> LegalLedger:
    envelope = admitted_envelope()
    return LegalLedger(
        case_fingerprint=source_record_fingerprint(envelope),
        entries=list(entries or (entry(),)),
    )


def three_entry_ledger() -> LegalLedger:
    envelope = admitted_envelope()
    return LegalLedger(
        case_fingerprint=source_record_fingerprint(envelope),
        entries=[
            at_order(entry("first"), 0),
            at_order(entry("middle"), 1),
            at_order(entry("last"), 2),
        ],
    )


def ids_and_orders(ledger: LegalLedger) -> list[tuple[str, int]]:
    return [(ledger_entry.ledger_id, ledger_entry.walk_order) for ledger_entry in ledger.entries]


def audit(*disputes: LedgerDispute, complete: bool = True) -> LedgerAudit:
    return LedgerAudit(
        request_fingerprint="a" * 64,
        disputes=list(disputes),
        complete=complete,
    )


def finding_context_ledger() -> LegalLedger:
    return valid_ledger(
        at_order(entry("requirement-1"), 0),
        at_order(entry("first"), 1),
        at_order(entry("second"), 2),
    )


def validated_findings(initial_audit: LedgerAudit) -> list[LedgerDispute]:
    return ledger_findings(admitted_envelope(), finding_context_ledger(), initial_audit)


def dispute(
    dispute_id: str = "audit-1",
    *,
    action: str = "add",
    targets: list[str] | None = None,
    proposed: list[LedgerEntry] | None = None,
    materiality: Materiality = Materiality.SUPPORTING,
) -> LedgerDispute:
    return LedgerDispute(
        dispute_id=dispute_id,
        action=action,  # type: ignore[arg-type]
        target_ledger_ids=targets or [],
        proposed_entries=proposed or [],
        materiality=materiality,
        rationale=(
            "example-statute-1 is missing controller processing activities requirement."
        ),
    )


def referee(
    dispute_id: str, resolution: str, *, replacement: list[LedgerEntry] | None = None
) -> RefereeDecision:
    return RefereeDecision(
        dispute_id=dispute_id,
        selected_ledger_resolution=resolution,  # type: ignore[arg-type]
        replacement_entries=replacement or [],
        rationale="The source record resolves this ledger dispute.",
        source_ids=["example-statute-1"],
    )


def test_ledger_entry_requires_exact_source_slice() -> None:
    """Changing an offset or quotation must invalidate the cited source evidence."""
    envelope = admitted_envelope()
    ledger = LegalLedger(
        case_fingerprint=source_record_fingerprint(envelope),
        entries=[entry(start_char=SOURCE_TEXT.index(QUOTE) + 1)],
    )

    issues = validate_ledger(envelope, ledger)

    assert {issue.code for issue in issues} == {"LEDGER_QUOTE_MISMATCH"}


def test_ledger_binds_admission_source_record_not_candidate_case_fingerprint() -> None:
    """A candidate-containing envelope fingerprint must not bind a source-only ledger."""
    envelope = admitted_envelope()
    ledger = valid_ledger()

    assert ledger.case_fingerprint == source_record_fingerprint(envelope)
    assert ledger.case_fingerprint != envelope.case_fingerprint
    assert validate_ledger(envelope, ledger) == []


def test_sealed_ledger_is_byte_identical_for_candidate_only_case_changes() -> None:
    """Changing reports, identities, receipts, and blind seed cannot affect source-only sealing."""
    first_case = evaluation_case()
    second_case = evaluation_case()
    second_case.candidates[0].candidate_id = "other-candidate"
    second_case.candidates[0].report_text = "An entirely different candidate report."
    second_case.candidates[0].report_hash = _sha256(second_case.candidates[0].report_text)
    second_case.candidates[0].bundle_json = {"candidate": "private"}
    second_case.candidates[0].coverage_review = {"candidate": "private"}
    second_case.candidates[1].candidate_id = "other-comparator"
    second_case.candidates[1].report_text = "An entirely different comparator report."
    second_case.candidates[1].report_hash = _sha256(second_case.candidates[1].report_text)
    for case in (first_case, second_case):
        for candidate in case.candidates:
            candidate.validation_receipt = {
                "schema_version": "1.0",
                "source_hashes": {case.sources[0].source_id: case.sources[0].content_hash},
                "client_facts_hash": _sha256(case.client_facts or ""),
            }
    first = freeze_case(first_case, seed_hex="1" * 64)
    second = freeze_case(second_case, seed_hex="2" * 64)
    first_ledger = LegalLedger(case_fingerprint=source_record_fingerprint(first), entries=[entry()])
    second_ledger = LegalLedger(
        case_fingerprint=source_record_fingerprint(second), entries=[entry()]
    )

    first_sealed = seal_ledger(first, first_ledger, audit(), referee=None)
    second_sealed = seal_ledger(second, second_ledger, audit(), referee=None)

    assert first_sealed.model_dump(mode="json") == second_sealed.model_dump(mode="json")
    assert first_sealed.ledger_fingerprint == second_sealed.ledger_fingerprint


def test_source_side_change_changes_ledger_binding() -> None:
    """A changed source-side question must not reuse the earlier ledger binding."""
    first = admitted_envelope()
    changed_case = evaluation_case()
    changed_case.question = "What records must a controller retain?"
    for candidate in changed_case.candidates:
        candidate.validation_receipt = {
            "schema_version": "1.0",
            "source_hashes": {
                changed_case.sources[0].source_id: changed_case.sources[0].content_hash
            },
            "client_facts_hash": _sha256(changed_case.client_facts or ""),
        }
    second = freeze_case(changed_case, seed_hex="3" * 64)
    first_ledger = LegalLedger(case_fingerprint=source_record_fingerprint(first), entries=[entry()])

    assert source_record_fingerprint(first) != source_record_fingerprint(second)
    assert {issue.code for issue in validate_ledger(second, first_ledger)} == {
        "LEDGER_CASE_MISMATCH"
    }


def test_ledger_rejects_unknown_sources_dangling_relationships_and_commentary_only_rules() -> None:
    """An operative rule cannot be supported by commentary or disconnected ledger nodes."""
    envelope = admitted_envelope()
    ledger = valid_ledger(entry(relationship_ids=["missing-entry"]))
    ledger.entries[0].citations[0].source_id = "missing-source"
    envelope.case.sources[0].source_role = SourceRole.COMMENTARY_ANALYSIS
    envelope.case_fingerprint = model_fingerprint(envelope.case)
    ledger.case_fingerprint = source_record_fingerprint(envelope)

    issues = validate_ledger(envelope, ledger)

    assert {issue.code for issue in issues} == {
        "LEDGER_CITATION_SOURCE_UNKNOWN",
        "LEDGER_RELATIONSHIP_UNKNOWN",
    }


def test_operative_entry_cannot_rely_only_on_commentary_analysis() -> None:
    """Removing the primary-source role check would admit commentary as a legal rule."""
    envelope = admitted_envelope()
    ledger = valid_ledger()
    envelope.case.sources[0].source_role = SourceRole.COMMENTARY_ANALYSIS
    envelope.case_fingerprint = model_fingerprint(envelope.case)
    ledger.case_fingerprint = source_record_fingerprint(envelope)

    issues = validate_ledger(envelope, ledger)

    assert {issue.code for issue in issues} == {"LEDGER_COMMENTARY_ONLY_SUPPORT"}


def test_ledger_requires_category_fields_and_concrete_materiality_rationale() -> None:
    """Penalties and deadlines need the fields that make their legal effect reviewable."""
    envelope = admitted_envelope()
    ledger = LegalLedger(
        case_fingerprint=source_record_fingerprint(envelope),
        entries=[
            entry(
                "penalty-1",
                category=LedgerCategory.PENALTY,
                consequence=None,
                materiality_rationale="important",
            ),
            entry("deadline-1", category=LedgerCategory.DEADLINE, timing=None).model_copy(
                update={"walk_order": 1}
            ),
        ],
    )

    issues = validate_ledger(envelope, ledger)

    assert {issue.code for issue in issues} == {
        "LEDGER_MATERIALITY_RATIONALE_INSUFFICIENT",
        "LEDGER_PENALTY_CONSEQUENCE_MISSING",
        "LEDGER_TRIGGER_LINK_MISSING",
        "LEDGER_DEADLINE_TIMING_MISSING",
    }


def test_valid_operational_enforcement_entry_passes_source_validation() -> None:
    """A linked, exact-cited enforcement entry remains available for sealing."""
    envelope = admitted_envelope()
    ledger = LegalLedger(
        case_fingerprint=source_record_fingerprint(envelope),
        entries=[
            entry(),
            entry(
                "enforcement-1",
                category=LedgerCategory.ENFORCEMENT,
                relationship_ids=["requirement-1"],
                enforcing_authority="Attorney General",
                enforcement_route="civil action",
            ).model_copy(update={"walk_order": 1}),
        ],
    )

    assert validate_ledger(envelope, ledger) == []


def test_enforcement_and_penalty_require_relationship_to_requirement_or_prohibition() -> None:
    """A scope-only link is not a viable triggering rule for enforcement or penalties."""
    envelope = admitted_envelope()
    scope = at_order(entry("scope-1", category=LedgerCategory.SCOPE), 0)
    enforcement = at_order(
        entry(
            "enforcement-1",
            category=LedgerCategory.ENFORCEMENT,
            relationship_ids=["scope-1"],
            trigger="scope applies",
            enforcing_authority="Attorney General",
            enforcement_route="civil action",
        ),
        1,
    )
    penalty = at_order(
        entry(
            "penalty-1",
            category=LedgerCategory.PENALTY,
            relationship_ids=["scope-1"],
            trigger="scope applies",
            consequence="A civil penalty may be imposed.",
        ),
        2,
    )

    issues = validate_ledger(
        envelope,
        LegalLedger(
            case_fingerprint=source_record_fingerprint(envelope),
            entries=[scope, enforcement, penalty],
        ),
    )

    assert {issue.code for issue in issues} == {"LEDGER_TRIGGER_RELATIONSHIP_INVALID"}


@pytest.mark.parametrize(
    "category",
    [LedgerCategory.ENFORCEMENT, LedgerCategory.PENALTY],
)
def test_trigger_string_cannot_replace_required_trigger_relationship(
    category: LedgerCategory,
) -> None:
    """A prose trigger cannot replace a source-reviewable link to the violated rule."""
    envelope = admitted_envelope()
    trigger_only = (
        entry(
            "trigger-only",
            category=category,
            trigger="after a violation",
            enforcing_authority="Attorney General",
            enforcement_route="civil action",
        )
        if category is LedgerCategory.ENFORCEMENT
        else entry(
            "trigger-only",
            category=category,
            trigger="after a violation",
            consequence="A civil penalty may be imposed.",
        )
    )
    ledger = LegalLedger(
        case_fingerprint=source_record_fingerprint(envelope),
        entries=[trigger_only],
    )

    assert {issue.code for issue in validate_ledger(envelope, ledger)} == {
        "LEDGER_TRIGGER_LINK_MISSING"
    }


def test_enforcement_and_penalty_accept_requirement_or_prohibition_relationships() -> None:
    """A cited requirement or prohibition is a viable triggering rule."""
    envelope = admitted_envelope()
    requirement = at_order(entry(), 0)
    prohibition = at_order(entry("prohibition-1", category=LedgerCategory.PROHIBITION), 1)
    enforcement = at_order(
        entry(
            "enforcement-1",
            category=LedgerCategory.ENFORCEMENT,
            relationship_ids=["requirement-1"],
            enforcing_authority="Attorney General",
            enforcement_route="civil action",
        ),
        2,
    )
    penalty = at_order(
        entry(
            "penalty-1",
            category=LedgerCategory.PENALTY,
            relationship_ids=["prohibition-1"],
            consequence="A civil penalty may be imposed.",
        ),
        3,
    )

    assert (
        validate_ledger(
            envelope,
            LegalLedger(
                case_fingerprint=source_record_fingerprint(envelope),
                entries=[requirement, prohibition, enforcement, penalty],
            ),
        )
        == []
    )


@pytest.mark.parametrize(
    "orders",
    [[0, 0], [0, 2], [1, 0], [-1, 0]],
)
def test_ledger_walk_order_must_be_contiguous_unique_and_match_list_order(
    orders: list[int],
) -> None:
    """Walk order gaps, duplicates, negatives, and reordered lists make grading ambiguous."""
    envelope = admitted_envelope()
    ledger = LegalLedger(
        case_fingerprint=source_record_fingerprint(envelope),
        entries=[at_order(entry("first"), orders[0]), at_order(entry("second"), orders[1])],
    )

    assert {issue.code for issue in validate_ledger(envelope, ledger)} == {
        "LEDGER_WALK_ORDER_INVALID"
    }


@pytest.mark.parametrize(
    "mutate",
    [
        lambda ledger, audit_output: setattr(ledger.entries[0].citations[0], "start_char", "13"),
        lambda ledger, audit_output: setattr(ledger.entries[0], "walk_order", "0"),
        lambda ledger, audit_output: setattr(ledger.entries[0], "category", "requirement"),
        lambda ledger, audit_output: setattr(audit_output, "complete", 1),
        lambda ledger, audit_output: setattr(audit_output.disputes[0], "materiality", "supporting"),
    ],
)
def test_public_boundaries_reject_post_validation_coercible_scalar_mutations(mutate) -> None:  # type: ignore[no-untyped-def]
    """Stringified offsets/enums and bool-like values must never be silently coerced."""
    ledger = valid_ledger()
    audit_output = audit(dispute(action="delete", targets=["requirement-1"]))
    mutate(ledger, audit_output)

    with pytest.raises(LedgerInconclusiveError, match="malformed"):
        seal_ledger(admitted_envelope(), ledger, audit_output, referee=None)


def test_audit_addition_with_noncontiguous_walk_order_cannot_be_sealed() -> None:
    """An audit cannot use an out-of-range declared add position."""
    with pytest.raises(LedgerInconclusiveError, match=r"add ledger dispute.*position"):
        seal_ledger(
            admitted_envelope(),
            valid_ledger(),
            audit(dispute(action="add", proposed=[at_order(entry("gapped"), 2)])),
            referee=None,
        )


@pytest.mark.parametrize(
    ("action", "targets"),
    [
        ("add", []),
        ("split", ["requirement-1"]),
    ],
)
def test_remaining_audit_rejects_nontransaction_add_and_split_findings(
    action: str, targets: list[str]
) -> None:
    """Remaining audit findings must stay executable before the ledger can seal."""
    with pytest.raises(LedgerInconclusiveError, match=action):
        seal_ledger(
            admitted_envelope(),
            valid_ledger(),
            audit(
                dispute(
                    f"{action}-finding",
                    action=action,
                    targets=targets,
                    proposed=[],
                    materiality=Materiality.SUPPORTING,
                )
            ),
            referee=None,
        )


@pytest.mark.parametrize(
    ("operation", "targets", "proposed", "expected"),
    [
        (
            "edit",
            ["middle"],
            [at_order(entry("middle", category=LedgerCategory.SCOPE), 1)],
            [("first", 0), ("middle", 1), ("last", 2)],
        ),
        ("delete", ["middle"], [], [("first", 0), ("last", 1)]),
        (
            "split",
            ["middle"],
            [at_order(entry("middle-a"), 1), at_order(entry("middle-b"), 2)],
            [("first", 0), ("middle-a", 1), ("middle-b", 2), ("last", 3)],
        ),
        (
            "merge",
            ["middle", "last"],
            [at_order(entry("merged"), 1)],
            [("first", 0), ("merged", 1)],
        ),
    ],
)
def test_middle_entry_operations_preserve_positions_and_identity_order(
    operation: str,
    targets: list[str],
    proposed: list[LedgerEntry],
    expected: list[tuple[str, int]],
) -> None:
    """Each operation is positional: unaffected identities retain their relative order."""
    sealed = seal_ledger(
        admitted_envelope(),
        three_entry_ledger(),
        audit(dispute(action=operation, targets=targets, proposed=proposed)),
        referee=None,
    )

    assert ids_and_orders(sealed.ledger) == expected


def test_merge_rejects_noncontiguous_target_span() -> None:
    """Merging nonadjacent entries would silently delete a middle identity."""
    with pytest.raises(LedgerInconclusiveError, match="contiguous"):
        seal_ledger(
            admitted_envelope(),
            three_entry_ledger(),
            audit(
                dispute(
                    action="merge",
                    targets=["first", "last"],
                    proposed=[at_order(entry("merged"), 0)],
                )
            ),
            referee=None,
        )


def test_add_uses_declared_positions_and_preserves_existing_relative_order() -> None:
    """Additions occupy exactly their declared positions rather than being appended."""
    sealed = seal_ledger(
        admitted_envelope(),
        three_entry_ledger(),
        audit(
            dispute(
                action="add",
                proposed=[at_order(entry("add-a"), 1), at_order(entry("add-b"), 3)],
            )
        ),
        referee=None,
    )

    assert ids_and_orders(sealed.ledger) == [
        ("first", 0),
        ("add-a", 1),
        ("middle", 2),
        ("add-b", 3),
        ("last", 4),
    ]


@pytest.mark.parametrize(
    "positions",
    [[1, 1], [1, 5]],
)
def test_add_rejects_duplicate_or_out_of_range_declared_positions(positions: list[int]) -> None:
    """Invalid add positions cannot be normalized into a different audit result."""
    with pytest.raises(LedgerInconclusiveError, match=r"add.*position"):
        seal_ledger(
            admitted_envelope(),
            three_entry_ledger(),
            audit(
                dispute(
                    action="add",
                    proposed=[
                        at_order(entry("add-a"), positions[0]),
                        at_order(entry("add-b"), positions[1]),
                    ],
                )
            ),
            referee=None,
        )


@pytest.mark.parametrize(
    ("action", "targets", "proposed"),
    [
        ("edit", ["middle"], [at_order(entry("middle"), 0)]),
        (
            "split",
            ["middle"],
            [at_order(entry("middle-a"), 0), at_order(entry("middle-b"), 2)],
        ),
        ("merge", ["middle", "last"], [at_order(entry("merged"), 0)]),
    ],
)
def test_replacement_operations_reject_position_mismatches(
    action: str, targets: list[str], proposed: list[LedgerEntry]
) -> None:
    """Edit, split, and merge proposals must declare the actual target position."""
    with pytest.raises(LedgerInconclusiveError, match="position"):
        seal_ledger(
            admitted_envelope(),
            three_entry_ledger(),
            audit(dispute(action=action, targets=targets, proposed=proposed)),
            referee=None,
        )


def test_referee_replacement_uses_the_dispute_target_position() -> None:
    """A referee replacement is an alternative positional proposal, never an append."""
    change = dispute(
        action="edit",
        targets=["middle"],
        proposed=[at_order(entry("middle"), 1)],
        materiality=Materiality.MATERIAL,
    )
    sealed = seal_ledger(
        admitted_envelope(),
        three_entry_ledger(),
        audit(change),
        referee=referee(
            "audit-1",
            "replace",
            replacement=[at_order(entry("middle", category=LedgerCategory.SCOPE), 1)],
        ),
    )

    assert ids_and_orders(sealed.ledger) == [
        ("first", 0),
        ("middle", 1),
        ("last", 2),
    ]


def test_referee_replace_reuses_original_action_cardinality_and_position_rules() -> None:
    """A referee cannot turn a split or merge into an arbitrary replacement payload."""
    split = dispute(
        action="split",
        targets=["middle"],
        proposed=[at_order(entry("middle-a"), 1), at_order(entry("middle-b"), 2)],
        materiality=Materiality.MATERIAL,
    )
    with pytest.raises(LedgerInconclusiveError, match="split ledger dispute"):
        seal_ledger(
            admitted_envelope(),
            three_entry_ledger(),
            audit(split),
            referee=referee("audit-1", "replace", replacement=[at_order(entry("only-one"), 1)]),
        )

    merge = dispute(
        action="merge",
        targets=["middle", "last"],
        proposed=[at_order(entry("merged"), 1)],
        materiality=Materiality.MATERIAL,
    )
    with pytest.raises(LedgerInconclusiveError, match="merge ledger dispute"):
        seal_ledger(
            admitted_envelope(),
            three_entry_ledger(),
            audit(merge),
            referee=referee(
                "audit-1",
                "replace",
                replacement=[at_order(entry("one"), 1), at_order(entry("two"), 2)],
            ),
        )

    add = dispute(
        action="add",
        proposed=[at_order(entry("audit-add"), 1)],
        materiality=Materiality.MATERIAL,
    )
    with pytest.raises(LedgerInconclusiveError, match=r"add ledger dispute.*position"):
        seal_ledger(
            admitted_envelope(),
            three_entry_ledger(),
            audit(add),
            referee=referee("audit-1", "replace", replacement=[at_order(entry("bad-add"), 5)]),
        )


def test_referee_replace_applies_valid_merge_and_add_payloads_positionally() -> None:
    """Valid referee alternatives retain the original merge/add positional semantics."""
    merge = dispute(
        action="merge",
        targets=["middle", "last"],
        proposed=[at_order(entry("audit-merged"), 1)],
        materiality=Materiality.MATERIAL,
    )
    merged = seal_ledger(
        admitted_envelope(),
        three_entry_ledger(),
        audit(merge),
        referee=referee("audit-1", "replace", replacement=[at_order(entry("ref-merged"), 1)]),
    )
    assert ids_and_orders(merged.ledger) == [("first", 0), ("ref-merged", 1)]

    addition = dispute(
        action="add",
        proposed=[at_order(entry("audit-add"), 1)],
        materiality=Materiality.MATERIAL,
    )
    added = seal_ledger(
        admitted_envelope(),
        three_entry_ledger(),
        audit(addition),
        referee=referee("audit-1", "replace", replacement=[at_order(entry("ref-add"), 1)]),
    )
    assert ids_and_orders(added.ledger) == [
        ("first", 0),
        ("ref-add", 1),
        ("middle", 2),
        ("last", 3),
    ]


def test_referee_replace_for_delete_is_explicitly_rejected() -> None:
    """Delete has no alternate entry payload, so replace cannot alter its action semantics."""
    deletion = dispute(
        action="delete",
        targets=["middle"],
        materiality=Materiality.MATERIAL,
    )

    with pytest.raises(LedgerInconclusiveError, match="delete referee replacement"):
        seal_ledger(
            admitted_envelope(),
            three_entry_ledger(),
            audit(deletion),
            referee=referee("audit-1", "replace", replacement=[at_order(entry("other"), 1)]),
        )


def test_accept_a_preflights_unknown_targets_and_position_mismatches() -> None:
    """Accepting the status quo does not waive malformed audit transaction structure."""
    unknown_delete = dispute(
        action="delete",
        targets=["unknown"],
        materiality=Materiality.MATERIAL,
    )
    with pytest.raises(LedgerInconclusiveError, match="unknown target"):
        seal_ledger(
            admitted_envelope(),
            three_entry_ledger(),
            audit(unknown_delete),
            referee=referee("audit-1", "accept_a"),
        )

    mismatched_edit = dispute(
        action="edit",
        targets=["middle"],
        proposed=[at_order(entry("middle"), 0)],
        materiality=Materiality.MATERIAL,
    )
    with pytest.raises(LedgerInconclusiveError, match=r"edit ledger dispute.*position"):
        seal_ledger(
            admitted_envelope(),
            three_entry_ledger(),
            audit(mismatched_edit),
            referee=referee("audit-1", "accept_a"),
        )


def test_each_audit_transaction_must_leave_an_intermediate_valid_ledger() -> None:
    """A later deletion cannot cure the dangling penalty created by an earlier deletion."""
    envelope = admitted_envelope()
    ledger = LegalLedger(
        case_fingerprint=source_record_fingerprint(envelope),
        entries=[
            at_order(entry("requirement"), 0),
            at_order(
                entry(
                    "penalty",
                    category=LedgerCategory.PENALTY,
                    relationship_ids=["requirement"],
                    consequence="A civil penalty may be imposed.",
                ),
                1,
            ),
        ],
    )
    delete_requirement = dispute("delete-requirement", action="delete", targets=["requirement"])
    delete_penalty = dispute("delete-penalty", action="delete", targets=["penalty"])

    with pytest.raises(LedgerInconclusiveError, match=r"delete-requirement.*LEDGER_"):
        seal_ledger(
            envelope,
            ledger,
            audit(delete_requirement, delete_penalty),
            referee=None,
        )

    sealed = seal_ledger(
        envelope,
        ledger,
        audit(delete_penalty, delete_requirement),
        referee=None,
    )
    assert sealed.ledger.entries == []


def test_ledger_disputes_fail_closed_for_incomplete_or_duplicate_audits() -> None:
    """A partial or ambiguous audit cannot become a ledger repair instruction."""
    with pytest.raises(LedgerInconclusiveError, match="audit is incomplete"):
        ledger_disputes(audit(complete=False))
    with pytest.raises(LedgerInconclusiveError, match="duplicate ledger dispute"):
        ledger_disputes(audit(dispute("same"), dispute("same")))


def test_ledger_rationale_insufficient_error_has_safe_contract_context() -> None:
    """A short audit rationale exposes only its fixed diagnostic and dispute ID."""
    finding = dispute("audit-1", action="add", proposed=[]).model_copy(
        update={"rationale": "brief"}
    )

    with pytest.raises(LedgerInconclusiveError) as caught:
        validated_findings(audit(finding))

    assert caught.value.code.value == "EVALUATION_AUDIT_RATIONALE_INSUFFICIENT"
    assert caught.value.related_ids == ("audit-1",)


def test_ledger_findings_accept_precise_nontransaction_audit_only() -> None:
    """Initial findings need precise classifications, not executable replacement payloads."""
    initial = audit(
        dispute("missing-duty", action="add", proposed=[]),
        dispute("combined-duty", action="split", targets=["requirement-1"], proposed=[]),
    )

    assert [finding.dispute_id for finding in validated_findings(initial)] == [
        "missing-duty",
        "combined-duty",
    ]
    with pytest.raises(LedgerInconclusiveError, match="concrete rationale"):
        validated_findings(
            audit(
                dispute("generic-finding", action="add", proposed=[]).model_copy(
                    update={"rationale": "Important"}
                )
            )
        )
    with pytest.raises(LedgerInconclusiveError, match="duplicate proposed ledger IDs"):
        validated_findings(
            audit(
                dispute(
                    "ambiguous-finding",
                    action="add",
                    proposed=[entry("duplicate"), entry("duplicate")],
                )
            )
        )


def test_initial_add_finding_requires_new_proposed_ledger_ids() -> None:
    """An initial add proposal cannot relabel an existing entry as a new one."""
    finding = dispute(
        "reused-add-id",
        action="add",
        proposed=[entry("requirement-1")],
    ).model_copy(update={"rationale": "The source record needs a ledger correction."})

    with pytest.raises(LedgerInconclusiveError, match=r"add.*new ledger IDs") as caught:
        validated_findings(audit(finding))

    assert caught.value.code.value == "EVALUATION_PROPOSED_ENTRY_INVALID"
    assert caught.value.related_ids == ("requirement-1",)


@pytest.mark.parametrize(
    ("action", "targets", "proposed"),
    [
        ("add", [], []),
        ("add", [], [entry("added")]),
        ("edit", ["requirement-1"], []),
        ("edit", ["requirement-1"], [entry("requirement-1")]),
        ("delete", ["requirement-1"], []),
        ("split", ["requirement-1"], []),
        ("split", ["requirement-1"], [entry("split-a"), entry("split-b")]),
        ("merge", ["first", "second"], []),
        ("merge", ["first", "second"], [entry("merged")]),
        ("materiality", ["requirement-1"], []),
    ],
)
def test_ledger_findings_accept_action_consistent_optional_payloads(
    action: str,
    targets: list[str],
    proposed: list[LedgerEntry],
) -> None:
    finding = dispute(action=action, targets=targets, proposed=proposed)

    assert validated_findings(audit(finding)) == [finding]


@pytest.mark.parametrize(
    ("action", "targets", "proposed"),
    [
        ("add", ["requirement-1"], []),
        ("edit", [], []),
        ("edit", ["requirement-1", "other"], []),
        ("edit", ["requirement-1"], [entry("wrong-id")]),
        ("edit", ["requirement-1"], [entry("requirement-1"), entry("other")]),
        ("delete", [], []),
        ("delete", ["requirement-1"], [entry("replacement")]),
        ("split", [], []),
        ("split", ["requirement-1", "other"], []),
        ("split", ["requirement-1"], [entry("only-one")]),
        ("merge", ["requirement-1"], []),
        ("merge", ["first", "second"], [entry("a"), entry("b")]),
        ("materiality", [], []),
        ("materiality", ["requirement-1"], [entry("replacement")]),
    ],
)
def test_ledger_findings_reject_action_inconsistent_payloads(
    action: str,
    targets: list[str],
    proposed: list[LedgerEntry],
) -> None:
    with pytest.raises(LedgerInconclusiveError, match=action):
        validated_findings(audit(dispute(action=action, targets=targets, proposed=proposed)))


@pytest.mark.parametrize(
    "rationale",
    [
        "This finding is very important indeed.",
        "The source record needs a ledger correction.",
        "The source record requires this concrete ledger correction.",
        "The section requires this concrete ledger correction.",
        "The source record needs correction 1 2.",
        "The source record needs compliance compliance correction.",
    ],
)
def test_ledger_findings_reject_content_free_rationale(rationale: str) -> None:
    generic = dispute(action="add", targets=[], proposed=[]).model_copy(
        update={"rationale": rationale}
    )

    with pytest.raises(LedgerInconclusiveError, match="rationale"):
        validated_findings(audit(generic))


@pytest.mark.parametrize(
    ("action", "targets", "rationale"),
    [
        (
            "add",
            [],
            (
                "example-statute-1 is missing controller processing activities "
                "requirement."
            ),
        ),
        (
            "split",
            ["requirement-1"],
            "The notice duty combines distinct filing and timing propositions.",
        ),
        (
            "add",
            [],
            "example-statute-1 is missing the requirement at Section 7.",
        ),
    ],
)
def test_ledger_findings_accept_specific_subject_rationales(
    action: str, targets: list[str], rationale: str
) -> None:
    finding = dispute(action=action, targets=targets).model_copy(
        update={"rationale": rationale}
    )

    assert validated_findings(audit(finding)) == [finding]


@pytest.mark.parametrize(
    "rationale",
    [
        "The case metadata needs a ledger correction.",
        "The request fingerprint needs a ledger correction.",
        "The response schema needs a ledger correction.",
        "unknown-source is missing controller processing activities requirement.",
    ],
)
def test_proposal_free_add_requires_known_source_grounding(rationale: str) -> None:
    finding = dispute(action="add", targets=[], proposed=[]).model_copy(
        update={"rationale": rationale}
    )

    with pytest.raises(LedgerInconclusiveError, match="source-grounded") as caught:
        ledger_findings(admitted_envelope(), valid_ledger(), audit(finding))

    assert caught.value.code.value == "EVALUATION_SOURCE_BINDING_INVALID"
    assert caught.value.related_ids == ("audit-1",)


@pytest.mark.parametrize(
    "rationale",
    [
        (
            "example-statute-1 is missing controller processing activities "
            "from the requirement."
        ),
        "example-statute-1 is missing the requirement at Section 7.",
        "example-statute-1 is missing the requirement at sEcTiOn 7.",
    ],
)
def test_proposal_free_add_accepts_known_source_evidence(rationale: str) -> None:
    finding = dispute(action="add", targets=[], proposed=[]).model_copy(
        update={"rationale": rationale}
    )

    assert ledger_findings(admitted_envelope(), valid_ledger(), audit(finding)) == [
        finding
    ]


def test_proposal_free_add_rejects_locator_absent_from_named_source() -> None:
    finding = dispute(action="add", targets=[], proposed=[]).model_copy(
        update={
            "rationale": "example-statute-1 is missing the requirement at Section 999."
        }
    )

    with pytest.raises(LedgerInconclusiveError, match="source-grounded"):
        ledger_findings(admitted_envelope(), valid_ledger(), audit(finding))


def test_proposal_free_add_requires_the_complete_locator_identifier() -> None:
    case = evaluation_case()
    source_text = SOURCE_TEXT.replace("Section 7", "Section 7(b)")
    case.sources[0].normalized_text = source_text
    case.sources[0].content_hash = _sha256(source_text)
    envelope = freeze_case(case, seed_hex="d" * 64)
    ledger_entry = entry()
    start = source_text.index(QUOTE)
    ledger_entry.citations[0] = LedgerCitation(
        source_id="example-statute-1",
        start_char=start,
        end_char=start + len(QUOTE),
        quote=QUOTE,
    )
    proposed_ledger = LegalLedger(
        case_fingerprint=source_record_fingerprint(envelope), entries=[ledger_entry]
    )
    wrong_subdivision = dispute(action="add", proposed=[]).model_copy(
        update={
            "rationale": "example-statute-1 is missing the requirement at Section 7(a)."
        }
    )
    exact_subdivision = wrong_subdivision.model_copy(
        update={
            "rationale": "example-statute-1 is missing the requirement at Section 7(b)."
        }
    )

    with pytest.raises(LedgerInconclusiveError, match="source-grounded"):
        ledger_findings(envelope, proposed_ledger, audit(wrong_subdivision))
    assert ledger_findings(envelope, proposed_ledger, audit(exact_subdivision)) == [
        exact_subdivision
    ]


def test_proposal_free_add_locators_fail_closed_before_source_term_fallback() -> None:
    mixed_false_locator = dispute(action="add", proposed=[]).model_copy(
        update={
            "rationale": (
                "example-statute-1 is missing controller processing activities "
                "requirement at Section 999."
            )
        }
    )
    with pytest.raises(LedgerInconclusiveError, match="source-grounded"):
        ledger_findings(admitted_envelope(), valid_ledger(), audit(mixed_false_locator))

    case = evaluation_case()
    case.sources[0].title = "Example Privacy Act Rule 2"
    envelope = freeze_case(case, seed_hex="d" * 64)
    proposed_ledger = LegalLedger(
        case_fingerprint=source_record_fingerprint(envelope), entries=[entry()]
    )
    all_valid = dispute(action="add", proposed=[]).model_copy(
        update={
            "rationale": (
                "example-statute-1 is missing controller processing activities "
                "requirement at Section 7 and Rule 2."
            )
        }
    )
    one_invalid = all_valid.model_copy(
        update={
            "rationale": (
                "example-statute-1 is missing controller processing activities "
                "requirement at Section 7 and Rule 404."
            )
        }
    )

    assert ledger_findings(envelope, proposed_ledger, audit(all_valid)) == [all_valid]
    with pytest.raises(LedgerInconclusiveError, match="source-grounded"):
        ledger_findings(envelope, proposed_ledger, audit(one_invalid))


def test_add_with_proposal_uses_structured_repair_subject() -> None:
    finding = dispute(action="add", targets=[], proposed=[entry("added")]).model_copy(
        update={"rationale": "The source record needs a ledger correction."}
    )

    assert ledger_findings(admitted_envelope(), valid_ledger(), audit(finding)) == [
        finding
    ]


@pytest.mark.parametrize(
    ("defect", "issue_code"),
    [
        ("unknown-source", "LEDGER_CITATION_SOURCE_UNKNOWN"),
        ("wrong-quote", "LEDGER_QUOTE_MISMATCH"),
        ("out-of-range", "LEDGER_QUOTE_MISMATCH"),
    ],
)
def test_initial_finding_proposed_entries_require_exact_source_support(
    defect: str, issue_code: str
) -> None:
    proposed = entry("invalid-proposed")
    citation = proposed.citations[0]
    if defect == "unknown-source":
        citation.source_id = "unknown-source"
    elif defect == "wrong-quote":
        citation.quote = "processing activities shall be documented"
    else:
        citation.start_char = len(SOURCE_TEXT) + 1
        citation.end_char = len(SOURCE_TEXT) + 2
        citation.quote = "x"
    finding = dispute(
        "invalid-proposed-finding", action="add", proposed=[proposed]
    ).model_copy(update={"rationale": "The source record needs a ledger correction."})

    with pytest.raises(
        LedgerInconclusiveError,
        match=rf"invalid-proposed-finding.*{issue_code}",
    ):
        validated_findings(audit(finding))


def test_initial_finding_rejects_commentary_only_proposed_operative_entry() -> None:
    case = evaluation_case()
    commentary = case.sources[0].model_copy(
        update={
            "source_id": "commentary-1",
            "source_role": SourceRole.COMMENTARY_ANALYSIS,
            "source_quality": SourceQuality.SECONDARY,
        }
    )
    case.sources.append(commentary)
    case.requested_authorities[0].source_ids.append(commentary.source_id)
    envelope = freeze_case(case, seed_hex="d" * 64)
    proposed_ledger = LegalLedger(
        case_fingerprint=source_record_fingerprint(envelope),
        entries=[entry()],
    )
    proposed = entry("commentary-proposed")
    proposed.citations[0].source_id = commentary.source_id
    finding = dispute(action="add", proposed=[proposed]).model_copy(
        update={"rationale": "The source record needs a ledger correction."}
    )

    with pytest.raises(
        LedgerInconclusiveError,
        match=r"audit-1.*LEDGER_COMMENTARY_ONLY_SUPPORT",
    ):
        ledger_findings(envelope, proposed_ledger, audit(finding))


def test_initial_finding_validates_proposed_relationships_in_combined_context() -> None:
    first = entry("split-first", relationship_ids=["split-second"])
    second = entry("split-second", relationship_ids=["requirement-1"])
    finding = dispute(
        action="split",
        targets=["requirement-1"],
        proposed=[first, second],
    )

    assert validated_findings(audit(finding)) == [finding]


def test_non_add_findings_require_known_target_ids() -> None:
    known = dispute(action="split", targets=["requirement-1"], proposed=[])
    unknown = dispute(action="split", targets=["unknown-ledger-id"], proposed=[])

    assert ledger_findings(admitted_envelope(), valid_ledger(), audit(known)) == [known]
    with pytest.raises(LedgerInconclusiveError, match="unknown target"):
        ledger_findings(admitted_envelope(), valid_ledger(), audit(unknown))


def test_unresolved_critical_audit_dispute_is_inconclusive() -> None:
    """Critical audit findings require a bound referee choice before any seal."""
    with pytest.raises(LedgerInconclusiveError, match="critical ledger dispute"):
        seal_ledger(
            admitted_envelope(),
            valid_ledger(),
            audit(
                dispute(
                    action="delete",
                    targets=["requirement-1"],
                    materiality=Materiality.CRITICAL,
                )
            ),
            referee=None,
        )


@pytest.mark.parametrize(
    ("operation", "targets", "proposed", "expected_ids"),
    [
        ("add", [], [at_order(entry("added"), 1)], {"requirement-1", "added"}),
        (
            "edit",
            ["requirement-1"],
            [entry("requirement-1", category=LedgerCategory.SCOPE)],
            {"requirement-1"},
        ),
        ("delete", ["requirement-1"], [], set()),
        (
            "split",
            ["requirement-1"],
            [at_order(entry("part-a"), 0), at_order(entry("part-b"), 1)],
            {"part-a", "part-b"},
        ),
        ("merge", ["requirement-1", "other"], [at_order(entry("merged"), 0)], {"merged"}),
        ("materiality", ["requirement-1"], [], {"requirement-1"}),
    ],
)
def test_supporting_audit_applies_each_operation_deterministically(
    operation: str,
    targets: list[str],
    proposed: list[LedgerEntry],
    expected_ids: set[str],
) -> None:
    """Every structured supporting correction has one deterministic ledger result."""
    base_entries = [entry()]
    if operation == "merge":
        base_entries.append(at_order(entry("other"), 1))
    sealed = seal_ledger(
        admitted_envelope(),
        valid_ledger(*base_entries),
        audit(dispute(action=operation, targets=targets, proposed=proposed)),
        referee=None,
    )

    assert {ledger_entry.ledger_id for ledger_entry in sealed.ledger.entries} == expected_ids
    if operation == "materiality":
        assert sealed.ledger.entries[0].materiality is Materiality.SUPPORTING


def test_material_audit_needs_matching_referee_and_referee_resolution_controls_application() -> (
    None
):
    """A material audit must be bound to its dispute and the selected ledger outcome."""
    change = dispute(
        action="delete",
        targets=["requirement-1"],
        materiality=Materiality.MATERIAL,
    )
    with pytest.raises(LedgerInconclusiveError, match="material ledger dispute"):
        seal_ledger(admitted_envelope(), valid_ledger(), audit(change), referee=None)
    with pytest.raises(LedgerInconclusiveError, match="does not identify an audit dispute"):
        seal_ledger(
            admitted_envelope(), valid_ledger(), audit(change), referee=referee("other", "accept_b")
        )

    retained = seal_ledger(
        admitted_envelope(), valid_ledger(), audit(change), referee=referee("audit-1", "accept_a")
    )
    deleted = seal_ledger(
        admitted_envelope(), valid_ledger(), audit(change), referee=referee("audit-1", "accept_b")
    )

    assert [entry.ledger_id for entry in retained.ledger.entries] == ["requirement-1"]
    assert deleted.ledger.entries == []


def test_replace_referee_uses_replacement_entries_and_rejects_invalid_referee_shapes() -> None:
    """Only a valid replace decision can substitute an audited resolution."""
    change = dispute(
        action="edit",
        targets=["requirement-1"],
        proposed=[at_order(entry("requirement-1"), 0)],
        materiality=Materiality.MATERIAL,
    )
    sealed = seal_ledger(
        admitted_envelope(),
        valid_ledger(),
        audit(change),
        referee=referee(
            "audit-1",
            "replace",
            replacement=[at_order(entry("requirement-1", category=LedgerCategory.SCOPE), 0)],
        ),
    )

    assert sealed.ledger.entries[0].category is LedgerCategory.SCOPE
    invalid = referee("audit-1", "accept_b", replacement=[entry("not-allowed")])
    with pytest.raises(LedgerInconclusiveError, match="replacement entries"):
        seal_ledger(admitted_envelope(), valid_ledger(), audit(change), referee=invalid)


def test_audit_failure_cannot_partially_mutate_the_caller_ledger() -> None:
    """A later invalid correction must not leak an earlier partial repair to callers."""
    original = valid_ledger()
    with pytest.raises(LedgerInconclusiveError, match="unknown target IDs"):
        seal_ledger(
            admitted_envelope(),
            original,
            audit(
                dispute("add", action="add", proposed=[entry("added")]),
                dispute("bad", action="delete", targets=["unknown"]),
            ),
            referee=None,
        )

    assert [ledger_entry.ledger_id for ledger_entry in original.entries] == ["requirement-1"]


def test_sealing_revalidates_mutated_inputs_and_binds_case_audit_and_resolution() -> None:
    """A later mutation cannot evade source checks or preserve a stale sealing fingerprint."""
    envelope = admitted_envelope()
    ledger = valid_ledger()
    ledger.entries[0].citations[0].quote = "not in the source"
    with pytest.raises(LedgerInconclusiveError, match="LEDGER_QUOTE_MISMATCH"):
        seal_ledger(envelope, ledger, audit(), referee=None)

    change = dispute(action="delete", targets=["requirement-1"], materiality=Materiality.MATERIAL)
    retained = seal_ledger(
        envelope, valid_ledger(), audit(change), referee=referee("audit-1", "accept_a")
    )
    deleted = seal_ledger(
        envelope, valid_ledger(), audit(change), referee=referee("audit-1", "accept_b")
    )

    assert retained.audit_fingerprint == deleted.audit_fingerprint
    assert retained.ledger_fingerprint != deleted.ledger_fingerprint


def test_sealed_ledger_serializes_no_candidate_report_content_or_fingerprint() -> None:
    """The sealed source-side artifact cannot expose candidate-derived report data."""
    envelope = admitted_envelope()
    candidate = envelope.case.candidates[0]
    sealed = seal_ledger(envelope, valid_ledger(), audit(), referee=None)
    serialized = str(sealed.model_dump(mode="json"))

    assert candidate.report_text not in serialized
    assert candidate.report_hash not in serialized
