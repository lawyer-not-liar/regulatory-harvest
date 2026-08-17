"""Controlled vocabulary for the canonical bundle."""

from enum import StrEnum


class StageName(StrEnum):
    COLLECT = "collect"
    ORGANIZE = "organize"
    MAP = "map"
    BUILD = "build"
    INSPECT = "inspect"
    NOTE = "note"
    EXPORT = "export"


class StageStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class SourceQuality(StrEnum):
    PRIMARY = "primary"
    SECONDARY = "secondary"
    UNKNOWN = "unknown"
    UNUSABLE = "unusable"


class SourceRole(StrEnum):
    OFFICIAL_PRIMARY = "official_primary"
    SECONDARY = "secondary"
    COMMENTARY_ANALYSIS = "commentary_analysis"


class FetchStatus(StrEnum):
    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class ClaimKind(StrEnum):
    SOURCE_SUPPORTED = "source_supported"
    ANALYSIS = "analysis"


class EnforcementClaimRole(StrEnum):
    TRIGGER = "trigger"
    CONSEQUENCE = "consequence"


class LeadReviewDisposition(StrEnum):
    GAP = "gap"
    NOT_MATERIAL = "not_material"


class CoverageDisposition(StrEnum):
    COVERED = "covered"
    GAP = "gap"
    NOT_MATERIAL = "not_material"


class CoverageElementStatus(StrEnum):
    STATED = "stated"
    NOT_APPLICABLE = "not_applicable"
    NOT_ESTABLISHED = "not_established"


class UnitDimensionDisposition(StrEnum):
    MAPPED = "mapped"
    NOT_PRESENT = "not_present"
    GAP = "gap"
    NOT_MATERIAL = "not_material"


class LeadDispositionV2(StrEnum):
    MAPPED = "mapped"
    GAP = "gap"
    NOT_MATERIAL = "not_material"


class AtomMateriality(StrEnum):
    CRITICAL = "critical"
    MATERIAL = "material"
    SUPPORTING = "supporting"


class AtomRelationshipType(StrEnum):
    QUALIFIES = "qualifies"
    EXCEPTION_TO = "exception_to"
    DEADLINE_FOR = "deadline_for"
    ENFORCES = "enforces"
    TRIGGERED_BY = "triggered_by"
    CONSEQUENCE_OF = "consequence_of"
    APPEALS_FROM = "appeals_from"
    DEFINES = "defines"


class PropositionType(StrEnum):
    STATUS = "status"
    DEFINITION = "definition"
    SCOPE = "scope"
    RIGHT = "right"
    DUTY = "duty"
    PROHIBITION = "prohibition"
    EXCEPTION = "exception"
    DEADLINE = "deadline"
    ENFORCEMENT_TRIGGER = "enforcement_trigger"
    ENFORCEMENT_ROUTE = "enforcement_route"
    REMEDY = "remedy"
    PENALTY = "penalty"
    APPEAL = "appeal"
    IMPLEMENTATION = "implementation"
    OTHER = "other"


class BriefBlockKind(StrEnum):
    PARAGRAPH = "paragraph"
    BULLET_LIST = "bullet_list"
    NUMBERED_LIST = "numbered_list"
    TABLE = "table"


class BriefBlockPurpose(StrEnum):
    LEGAL_ANALYSIS = "legal_analysis"
    APPLICATION = "application"
    CLIENT_FACT = "client_fact"
    LIMITATION = "limitation"


class BriefStructureProfile(StrEnum):
    REGULATORY_WALK_V1 = "regulatory-walk-v1"


class BriefSectionRole(StrEnum):
    KEY_REQUIREMENTS = "key_requirements"
    PENALTIES_ENFORCEMENT = "penalties_enforcement"
    IMPLEMENTATION = "implementation"
    OTHER = "other"


class IssueCategory(StrEnum):
    STATUS = "status"
    SCOPE = "scope"
    REQUIREMENTS = "requirements"
    ENFORCEMENT = "enforcement"
    DEADLINES = "deadlines"
    IMPLEMENTATION = "implementation"
    OTHER = "other"


class PresentationRole(StrEnum):
    TERRITORIAL_SCOPE = "territorial_scope"
    COVERED_ENTITIES = "covered_entities"
    COVERED_ACTIVITIES = "covered_activities"
    EXCLUSIONS_THRESHOLDS = "exclusions_thresholds"
    REQUIREMENT = "requirement"
    ENFORCERS = "enforcers"
    ENFORCEMENT_MECHANISMS = "enforcement_mechanisms"
    PENALTIES_REMEDIES = "penalties_remedies"
    PRIVATE_RIGHT = "private_right"
    CURE_RIGHTS = "cure_rights"
    DEFENSES = "defenses"
    AFFECTED_OPERATIONS = "affected_operations"
    RECOMMENDED_ACTIONS = "recommended_actions"
    DEPENDENCIES = "dependencies"
    EFFORT = "effort"
    CLIENT_FACTS = "client_facts"
    RELATED_AMENDMENT = "related_amendment"
    RELATED_SUPERSESSION = "related_supersession"
    RELATED_IMPLEMENTATION = "related_implementation"
    RELATED_REGIME = "related_regime"


REQUIRED_ISSUE_CATEGORIES = (
    IssueCategory.STATUS,
    IssueCategory.SCOPE,
    IssueCategory.REQUIREMENTS,
    IssueCategory.ENFORCEMENT,
    IssueCategory.DEADLINES,
    IssueCategory.IMPLEMENTATION,
)


class SupportStatus(StrEnum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    INDETERMINATE = "indeterminate"


class ReviewStatus(StrEnum):
    PENDING = "pending"
    RESOLVED = "resolved"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IssueLevel(StrEnum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
