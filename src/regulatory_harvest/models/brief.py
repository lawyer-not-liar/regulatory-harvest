"""Structured, adaptive attorney-facing brief models."""

from typing import Self, cast

from pydantic import (
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    field_validator,
    model_serializer,
    model_validator,
)

from .base import StrictModel
from .enums import (
    BriefBlockKind,
    BriefBlockPurpose,
    BriefSectionRole,
    BriefStructureProfile,
)
from .request import _non_blank

_RENDERER_OWNED_TITLES = {
    "bottom line",
    "evidence and validation appendix",
    "executive summary",
    "limitations and open questions",
    "priority and posture",
    "sources consulted",
}


def _unique_nonblank(values: list[str]) -> list[str]:
    normalized = [_non_blank(value) for value in values]
    if len(set(normalized)) != len(normalized):
        raise ValueError("identifiers must be unique")
    return normalized


def _sorted_unique_nonblank(values: list[str]) -> list[str]:
    return sorted(_unique_nonblank(values))


def _section_title(value: str) -> str:
    title = _non_blank(value)
    if title.casefold() in _RENDERER_OWNED_TITLES:
        raise ValueError("title is owned by the deterministic report renderer")
    return title


class _VisibleBindingModel(StrictModel):
    model_config = ConfigDict(extra="forbid", revalidate_instances="always")

    @model_serializer(mode="wrap")
    def serialize_visible_bindings(
        self, handler: SerializerFunctionWrapHandler
    ) -> dict[str, object]:
        serialized = cast(dict[str, object], handler(self))
        for field_name in ("atom_ids", "relationship_ids"):
            if not serialized.get(field_name):
                serialized.pop(field_name, None)
        return serialized


class BriefItem(_VisibleBindingModel):

    text: str
    finding_ids: list[str] = Field(default_factory=list)
    claim_ids: list[str] = Field(default_factory=list)
    enforcement_trigger_claim_ids: list[str] = Field(default_factory=list)
    enforcement_consequence_claim_ids: list[str] = Field(default_factory=list)
    atom_ids: list[str] = Field(default_factory=list)
    relationship_ids: list[str] = Field(default_factory=list)

    _validate_text = field_validator("text")(_non_blank)
    _validate_finding_ids = field_validator("finding_ids")(_unique_nonblank)
    _validate_claim_ids = field_validator(
        "claim_ids",
        "enforcement_trigger_claim_ids",
        "enforcement_consequence_claim_ids",
    )(_unique_nonblank)
    _validate_atomic_bindings = field_validator("atom_ids", "relationship_ids")(
        _sorted_unique_nonblank
    )


class BriefTableRow(_VisibleBindingModel):
    cells: list[str] = Field(min_length=1)
    finding_ids: list[str] = Field(default_factory=list)
    claim_ids: list[str] = Field(default_factory=list)
    enforcement_trigger_claim_ids: list[str] = Field(default_factory=list)
    enforcement_consequence_claim_ids: list[str] = Field(default_factory=list)
    atom_ids: list[str] = Field(default_factory=list)
    relationship_ids: list[str] = Field(default_factory=list)

    @field_validator("cells")
    @classmethod
    def validate_cells(cls, values: list[str]) -> list[str]:
        return [_non_blank(value) for value in values]

    _validate_finding_ids = field_validator("finding_ids")(_unique_nonblank)
    _validate_claim_ids = field_validator(
        "claim_ids",
        "enforcement_trigger_claim_ids",
        "enforcement_consequence_claim_ids",
    )(_unique_nonblank)
    _validate_atomic_bindings = field_validator("atom_ids", "relationship_ids")(
        _sorted_unique_nonblank
    )


class BriefBlock(_VisibleBindingModel):
    kind: BriefBlockKind
    purpose: BriefBlockPurpose
    text: str | None = None
    finding_ids: list[str] = Field(default_factory=list)
    claim_ids: list[str] = Field(default_factory=list)
    enforcement_trigger_claim_ids: list[str] = Field(default_factory=list)
    enforcement_consequence_claim_ids: list[str] = Field(default_factory=list)
    atom_ids: list[str] = Field(default_factory=list)
    relationship_ids: list[str] = Field(default_factory=list)
    items: list[BriefItem] = Field(default_factory=list)
    columns: list[str] = Field(default_factory=list)
    rows: list[BriefTableRow] = Field(default_factory=list)

    @field_validator("text")
    @classmethod
    def validate_text(cls, value: str | None) -> str | None:
        return None if value is None else _non_blank(value)

    _validate_finding_ids = field_validator("finding_ids")(_unique_nonblank)
    _validate_claim_ids = field_validator(
        "claim_ids",
        "enforcement_trigger_claim_ids",
        "enforcement_consequence_claim_ids",
    )(_unique_nonblank)
    _validate_atomic_bindings = field_validator("atom_ids", "relationship_ids")(
        _sorted_unique_nonblank
    )

    @field_validator("columns")
    @classmethod
    def validate_columns(cls, values: list[str]) -> list[str]:
        return [_non_blank(value) for value in values]

    @model_validator(mode="after")
    def validate_payload_for_kind(self) -> Self:
        if self.kind is BriefBlockKind.PARAGRAPH:
            if self.text is None or self.items or self.columns or self.rows:
                raise ValueError("paragraph blocks require only text")
            return self
        if self.kind in {BriefBlockKind.BULLET_LIST, BriefBlockKind.NUMBERED_LIST}:
            if self.text is not None or not self.items or self.columns or self.rows:
                raise ValueError("list blocks require only items")
            if self.finding_ids:
                raise ValueError("list evidence belongs on individual items")
            if (
                self.claim_ids
                or self.enforcement_trigger_claim_ids
                or self.enforcement_consequence_claim_ids
                or self.atom_ids
                or self.relationship_ids
            ):
                raise ValueError("list evidence belongs on individual items")
            return self
        if self.text is not None or self.items or len(self.columns) < 2 or not self.rows:
            raise ValueError("table blocks require columns and rows")
        if self.finding_ids:
            raise ValueError("table evidence belongs on individual rows")
        if (
            self.claim_ids
            or self.enforcement_trigger_claim_ids
            or self.enforcement_consequence_claim_ids
            or self.atom_ids
            or self.relationship_ids
        ):
            raise ValueError("table evidence belongs on individual rows")
        if any(len(row.cells) != len(self.columns) for row in self.rows):
            raise ValueError("table rows must match the column count")
        return self


class BriefSubsection(StrictModel):
    subsection_id: str
    title: str
    blocks: list[BriefBlock] = Field(min_length=1)

    _validate_id = field_validator("subsection_id")(_non_blank)
    _validate_title = field_validator("title")(_section_title)


class BriefSection(StrictModel):
    section_id: str
    title: str
    role: BriefSectionRole | None = None
    blocks: list[BriefBlock] = Field(default_factory=list)
    subsections: list[BriefSubsection] = Field(default_factory=list)

    _validate_id = field_validator("section_id")(_non_blank)
    _validate_title = field_validator("title")(_section_title)

    @model_validator(mode="after")
    def validate_content_and_subsections(self) -> Self:
        if not self.blocks and not self.subsections:
            raise ValueError("section must contain a block or subsection")
        subsection_ids = [subsection.subsection_id for subsection in self.subsections]
        if len(set(subsection_ids)) != len(subsection_ids):
            raise ValueError("subsection identifiers must be unique within a section")
        return self


class AttorneyBrief(StrictModel):
    structure_profile: BriefStructureProfile | None = None
    executive_summary: list[BriefBlock] = Field(min_length=1)
    sections: list[BriefSection] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_section_ids(self) -> Self:
        section_ids = [section.section_id for section in self.sections]
        if len(set(section_ids)) != len(section_ids):
            raise ValueError("section identifiers must be unique")
        return self
