"""Strict, provider-neutral draft models."""

from typing import Literal, Self, cast

from pydantic import (
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    field_validator,
    model_serializer,
    model_validator,
)

from regulatory_harvest.models import (
    AttorneyBrief,
    ClaimKind,
    CoverageDisposition,
    CoverageElementStatus,
    EnforcementClaimRole,
    IssueCategory,
    LeadReviewDisposition,
    PresentationRole,
    PropositionType,
    Severity,
)
from regulatory_harvest.models.base import StrictModel
from regulatory_harvest.models.enums import (
    AtomMateriality,
    AtomRelationshipType,
    LeadDispositionV2,
    UnitDimensionDisposition,
)
from regulatory_harvest.models.request import _non_blank


class ProposedCitation(StrictModel):
    source_id: str
    quote: str
    occurrence: int | None = Field(default=None, ge=1)


class DraftClaim(StrictModel):
    claim_id: str
    text: str
    kind: ClaimKind
    enforcement_roles: list[EnforcementClaimRole] = Field(default_factory=list)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    proposed_citations: list[ProposedCitation] = Field(default_factory=list)

    @field_validator("enforcement_roles")
    @classmethod
    def validate_enforcement_roles(
        cls, values: list[EnforcementClaimRole]
    ) -> list[EnforcementClaimRole]:
        if len(set(values)) != len(values):
            raise ValueError("enforcement_roles must be unique")
        return values


class DraftFinding(StrictModel):
    finding_id: str
    issue_id: str
    title: str
    jurisdiction: str
    authority: str
    severity: Severity
    practical_implication: str
    claims: list[DraftClaim] = Field(default_factory=list)


class DraftIssue(StrictModel):
    issue_id: str
    title: str
    description: str | None = None
    jurisdictions: list[str] = Field(default_factory=list)
    category: IssueCategory = IssueCategory.OTHER
    presentation_role: PresentationRole | None = None


class DraftGap(StrictModel):
    code: str
    message: str
    category: IssueCategory = IssueCategory.OTHER
    presentation_role: PresentationRole | None = None
    jurisdiction: str | None = None
    source_ids: list[str] = Field(default_factory=list)


class DraftLeadReview(StrictModel):
    lead_id: str
    disposition: LeadReviewDisposition
    gap_codes: list[str] = Field(default_factory=list)
    rationale: str

    _validate_text = field_validator("lead_id", "rationale")(_non_blank)

    @field_validator("gap_codes")
    @classmethod
    def validate_gap_codes(cls, values: list[str]) -> list[str]:
        normalized = [_non_blank(value) for value in values]
        if len(set(normalized)) != len(normalized):
            raise ValueError("gap_codes must be unique")
        return normalized

    @model_validator(mode="after")
    def validate_disposition_payload(self) -> Self:
        if self.disposition is LeadReviewDisposition.GAP and not self.gap_codes:
            raise ValueError("gap disposition requires gap_codes")
        if self.disposition is LeadReviewDisposition.NOT_MATERIAL and self.gap_codes:
            raise ValueError("not_material disposition cannot include gap_codes")
        return self


def _optional_non_blank(value: str | None) -> str | None:
    return None if value is None else _non_blank(value)


def _unique_non_blank(values: list[str]) -> list[str]:
    normalized = [_non_blank(value) for value in values]
    if len(set(normalized)) != len(normalized):
        raise ValueError("identifiers must be unique")
    return normalized


class DraftCoverageElement(StrictModel):
    status: CoverageElementStatus
    text: str | None = None

    @model_validator(mode="after")
    def validate_status_text(self) -> Self:
        if self.status is CoverageElementStatus.STATED:
            if self.text is None or not self.text.strip():
                raise ValueError("stated status requires nonblank text")
            self.text = self.text.strip()
        elif self.text is not None:
            raise ValueError(f"{self.status.value} status requires text to be null")
        return self


class DraftCoverageElements(StrictModel):
    subject: DraftCoverageElement
    operative_rule: DraftCoverageElement
    object: DraftCoverageElement
    trigger_or_threshold: DraftCoverageElement
    conditions_or_exceptions: DraftCoverageElement
    timing: DraftCoverageElement
    consequence_or_remedy: DraftCoverageElement
    authority_or_route: DraftCoverageElement


class DraftPropositionCoverage(StrictModel):
    coverage_id: str
    unit_ids: list[str] = Field(default_factory=list)
    lead_ids: list[str] = Field(default_factory=list)
    category: IssueCategory
    proposition_type: PropositionType
    disposition: CoverageDisposition
    elements: DraftCoverageElements | None = None
    claim_ids: list[str] = Field(default_factory=list)
    gap_codes: list[str] = Field(default_factory=list)
    rationale: str | None = None

    _validate_coverage_id = field_validator("coverage_id")(_non_blank)
    _validate_rationale = field_validator("rationale")(_optional_non_blank)

    @field_validator("unit_ids", "lead_ids", "claim_ids", "gap_codes")
    @classmethod
    def validate_identifiers(cls, values: list[str], info: object) -> list[str]:
        try:
            return _unique_non_blank(values)
        except ValueError as error:
            if "unique" in str(error):
                field_name = getattr(info, "field_name", "identifiers")
                raise ValueError(f"{field_name} must be unique") from error
            raise

    @model_validator(mode="after")
    def validate_disposition_payload(self) -> Self:
        if not self.unit_ids and not self.lead_ids:
            raise ValueError("coverage row requires at least one unit_id or lead_id")

        if self.disposition is CoverageDisposition.COVERED:
            if self.elements is None:
                raise ValueError("covered disposition requires elements")
            if not self.claim_ids:
                raise ValueError("covered disposition requires claim_ids")
            if (
                self.elements.subject.status is not CoverageElementStatus.STATED
                or self.elements.operative_rule.status is not CoverageElementStatus.STATED
            ):
                raise ValueError(
                    "covered disposition requires stated subject and operative_rule"
                )
            has_not_established = any(
                element.status is CoverageElementStatus.NOT_ESTABLISHED
                for element in (
                    self.elements.object,
                    self.elements.trigger_or_threshold,
                    self.elements.conditions_or_exceptions,
                    self.elements.timing,
                    self.elements.consequence_or_remedy,
                    self.elements.authority_or_route,
                )
            )
            if has_not_established and not self.gap_codes:
                raise ValueError("not_established elements require gap_codes")
            if not has_not_established and self.gap_codes:
                raise ValueError("gap_codes require a not_established element")
            return self

        if self.disposition is CoverageDisposition.GAP:
            if self.claim_ids:
                raise ValueError("gap disposition cannot include claim_ids")
            if not self.gap_codes:
                raise ValueError("gap disposition requires gap_codes")
            if self.rationale is None:
                raise ValueError("gap disposition requires a rationale")
            if self.elements is not None and any(
                element.status is CoverageElementStatus.STATED
                for element in (
                    self.elements.subject,
                    self.elements.operative_rule,
                    self.elements.object,
                    self.elements.trigger_or_threshold,
                    self.elements.conditions_or_exceptions,
                    self.elements.timing,
                    self.elements.consequence_or_remedy,
                    self.elements.authority_or_route,
                )
            ):
                raise ValueError("gap disposition cannot include stated elements")
            return self

        if self.elements is not None:
            raise ValueError("not_material disposition cannot include elements")
        if self.claim_ids:
            raise ValueError("not_material disposition cannot include claim_ids")
        if self.gap_codes:
            raise ValueError("not_material disposition cannot include gap_codes")
        if self.rationale is None:
            raise ValueError("not_material disposition requires a rationale")
        return self


class _StrictAuthoringModel(StrictModel):
    model_config = ConfigDict(extra="forbid", revalidate_instances="always")


class DraftDimensionReview(_StrictAuthoringModel):
    disposition: UnitDimensionDisposition
    atom_ids: list[str] = Field(default_factory=list)
    gap_codes: list[str] = Field(default_factory=list)
    rationale: str | None = None

    _validate_rationale = field_validator("rationale")(_optional_non_blank)
    _validate_ids = field_validator("atom_ids", "gap_codes")(_unique_non_blank)

    @model_validator(mode="after")
    def validate_disposition_payload(self) -> Self:
        if self.disposition is UnitDimensionDisposition.MAPPED:
            if not self.atom_ids:
                raise ValueError("mapped disposition requires atom_ids")
            if self.gap_codes or self.rationale is not None:
                raise ValueError("mapped disposition permits only atom_ids")
        elif self.disposition is UnitDimensionDisposition.GAP:
            if not self.gap_codes:
                raise ValueError("gap disposition requires gap_codes")
            if self.atom_ids or self.rationale is not None:
                raise ValueError("gap disposition permits only gap_codes")
        elif self.disposition is UnitDimensionDisposition.NOT_PRESENT:
            if self.atom_ids or self.gap_codes or self.rationale is not None:
                raise ValueError("not_present disposition permits no payload")
        elif not self.rationale:
            raise ValueError("not_material disposition requires a rationale")
        elif self.atom_ids or self.gap_codes:
            raise ValueError("not_material disposition permits only a rationale")
        return self


class DraftUnitReviewDimensions(_StrictAuthoringModel):
    authority_status_timing: DraftDimensionReview
    actors_scope_activities: DraftDimensionReview
    definitions_categories: DraftDimensionReview
    duties_rights_prohibitions: DraftDimensionReview
    triggers_thresholds: DraftDimensionReview
    conditions_exceptions_defenses: DraftDimensionReview
    deadlines_transitions: DraftDimensionReview
    enforcement_remedies_consequences: DraftDimensionReview
    cross_references_dependencies: DraftDimensionReview


class DraftUnitReview(_StrictAuthoringModel):
    unit_id: str
    dimensions: DraftUnitReviewDimensions

    _validate_unit_id = field_validator("unit_id")(_non_blank)


class DraftLeadDispositionV2(_StrictAuthoringModel):
    lead_id: str
    disposition: LeadDispositionV2
    atom_ids: list[str] = Field(default_factory=list)
    gap_codes: list[str] = Field(default_factory=list)
    rationale: str | None = None

    _validate_lead_id = field_validator("lead_id")(_non_blank)
    _validate_rationale = field_validator("rationale")(_optional_non_blank)
    _validate_ids = field_validator("atom_ids", "gap_codes")(_unique_non_blank)

    @model_validator(mode="after")
    def validate_disposition_payload(self) -> Self:
        if self.disposition is LeadDispositionV2.MAPPED:
            if not self.atom_ids:
                raise ValueError("mapped disposition requires atom_ids")
            if self.gap_codes or self.rationale is not None:
                raise ValueError("mapped disposition permits only atom_ids")
        elif self.disposition is LeadDispositionV2.GAP:
            if not self.gap_codes:
                raise ValueError("gap disposition requires gap_codes")
            if self.atom_ids or self.rationale is not None:
                raise ValueError("gap disposition permits only gap_codes")
        elif not self.rationale:
            raise ValueError("not_material disposition requires a rationale")
        elif self.atom_ids or self.gap_codes:
            raise ValueError("not_material disposition permits only a rationale")
        return self


class DraftAtomElement(_StrictAuthoringModel):
    status: CoverageElementStatus
    text: str | None = None
    claim_ids: list[str] = Field(default_factory=list)
    gap_codes: list[str] = Field(default_factory=list)

    _validate_text = field_validator("text")(_optional_non_blank)
    _validate_ids = field_validator("claim_ids", "gap_codes")(_unique_non_blank)

    @model_validator(mode="after")
    def validate_status_payload(self) -> Self:
        if self.status is CoverageElementStatus.STATED:
            if self.text is None:
                raise ValueError("stated element requires text")
            if not self.claim_ids:
                raise ValueError("stated element requires claim_ids")
            if self.gap_codes:
                raise ValueError("stated element cannot include gap_codes")
        elif self.status is CoverageElementStatus.NOT_ESTABLISHED:
            if not self.gap_codes:
                raise ValueError("not_established element requires gap_codes")
            if self.text is not None or self.claim_ids:
                raise ValueError("not_established element permits only gap_codes")
        elif self.text is not None or self.claim_ids or self.gap_codes:
            raise ValueError("not_applicable element permits no payload")
        return self


class DraftRuleAtomElements(_StrictAuthoringModel):
    actor: DraftAtomElement
    modality: DraftAtomElement
    operative_action: DraftAtomElement
    object: DraftAtomElement
    trigger: DraftAtomElement
    threshold: DraftAtomElement
    condition: DraftAtomElement
    exception: DraftAtomElement
    timing: DraftAtomElement
    authority: DraftAtomElement
    route: DraftAtomElement
    consequence: DraftAtomElement
    defined_term: DraftAtomElement
    defined_meaning: DraftAtomElement


class DraftRuleAtom(_StrictAuthoringModel):
    atom_id: str
    unit_ids: list[str] = Field(default_factory=list)
    lead_ids: list[str] = Field(default_factory=list)
    category: IssueCategory
    proposition_type: PropositionType
    materiality: AtomMateriality
    elements: DraftRuleAtomElements
    omission_rationale: str

    _validate_text = field_validator("atom_id", "omission_rationale")(_non_blank)
    _validate_targets = field_validator("unit_ids", "lead_ids")(_unique_non_blank)

    @property
    def claim_ids(self) -> list[str]:
        return sorted(
            {
                claim_id
                for field_name in DraftRuleAtomElements.model_fields
                for claim_id in getattr(self.elements, field_name).claim_ids
                if getattr(self.elements, field_name).status is CoverageElementStatus.STATED
            }
        )

    @model_validator(mode="after")
    def validate_target(self) -> Self:
        if not self.unit_ids and not self.lead_ids:
            raise ValueError("atom requires at least one unit_id or lead_id")
        return self


class DraftRuleRelationship(_StrictAuthoringModel):
    relationship_id: str
    relation_type: AtomRelationshipType
    source_atom_id: str
    target_atom_id: str
    claim_ids: list[str] = Field(min_length=1)

    _validate_text = field_validator(
        "relationship_id", "source_atom_id", "target_atom_id"
    )(_non_blank)
    _validate_claim_ids = field_validator("claim_ids")(_unique_non_blank)

    @model_validator(mode="after")
    def reject_self_link(self) -> Self:
        if self.source_atom_id == self.target_atom_id:
            raise ValueError("relationship cannot link an atom to itself")
        return self


class AnalysisDraft(StrictModel):
    issues: list[DraftIssue] = Field(default_factory=list)
    findings: list[DraftFinding] = Field(default_factory=list)
    gaps: list[DraftGap] = Field(default_factory=list)
    lead_reviews: list[DraftLeadReview] = Field(default_factory=list)
    coverage_contract_version: Literal[
        "proposition-coverage-v1", "proposition-coverage-v2"
    ] | None = None
    proposition_coverage: list[DraftPropositionCoverage] = Field(default_factory=list)
    unit_reviews: list[DraftUnitReview] = Field(default_factory=list)
    lead_dispositions_v2: list[DraftLeadDispositionV2] = Field(default_factory=list)
    rule_atoms: list[DraftRuleAtom] = Field(default_factory=list)
    rule_relationships: list[DraftRuleRelationship] = Field(default_factory=list)
    brief: AttorneyBrief | None = None

    @model_serializer(mode="wrap")
    def serialize_versioned_fields(
        self, handler: SerializerFunctionWrapHandler
    ) -> dict[str, object]:
        serialized = cast(dict[str, object], handler(self))
        if self.coverage_contract_version != "proposition-coverage-v2" and not any(
            (
                self.unit_reviews,
                self.lead_dispositions_v2,
                self.rule_atoms,
                self.rule_relationships,
            )
        ):
            for field_name in (
                "unit_reviews",
                "lead_dispositions_v2",
                "rule_atoms",
                "rule_relationships",
            ):
                serialized.pop(field_name, None)
        return serialized

    @model_validator(mode="after")
    def require_profile_for_authored_brief(self) -> Self:
        if self.brief is not None and self.brief.structure_profile is None:
            raise ValueError(
                "authored brief must declare structure_profile regulatory-walk-v1"
            )
        if self.coverage_contract_version == "proposition-coverage-v2" and (
            self.lead_reviews or self.proposition_coverage
        ):
            raise ValueError(
                "proposition-coverage-v2 requires lead_reviews and "
                "proposition_coverage to be empty"
            )
        lead_ids = [review.lead_id for review in self.lead_reviews]
        if len(set(lead_ids)) != len(lead_ids):
            raise ValueError("lead review identifiers must be unique")
        coverage_ids = [row.coverage_id for row in self.proposition_coverage]
        if len(set(coverage_ids)) != len(coverage_ids):
            raise ValueError("coverage identifiers must be unique")
        self.unit_reviews = [
            DraftUnitReview.model_validate(row)
            for row in self.unit_reviews
        ]
        self.lead_dispositions_v2 = [
            DraftLeadDispositionV2.model_validate(row)
            for row in self.lead_dispositions_v2
        ]
        self.rule_atoms = [
            DraftRuleAtom.model_validate(row)
            for row in self.rule_atoms
        ]
        self.rule_relationships = [
            DraftRuleRelationship.model_validate(row)
            for row in self.rule_relationships
        ]
        if self.brief is not None:
            self.brief = AttorneyBrief.model_validate(
                self.brief.model_dump(mode="python", warnings=False)
            )
        for values, label in (
            (self.unit_reviews, "unit review"),
            (self.lead_dispositions_v2, "lead disposition"),
            (self.rule_atoms, "atom"),
            (self.rule_relationships, "relationship"),
        ):
            identifier_field = {
                "unit review": "unit_id",
                "lead disposition": "lead_id",
                "atom": "atom_id",
                "relationship": "relationship_id",
            }[label]
            identifiers = [getattr(row, identifier_field) for row in values]
            if len(set(identifiers)) != len(identifiers):
                raise ValueError(f"{label} identifiers must be unique")
        return self
