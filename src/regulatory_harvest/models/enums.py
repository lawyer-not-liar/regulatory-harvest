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


class FetchStatus(StrEnum):
    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class ClaimKind(StrEnum):
    SOURCE_SUPPORTED = "source_supported"
    ANALYSIS = "analysis"


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
