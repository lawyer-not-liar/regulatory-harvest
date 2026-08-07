"""Run state and validation result models."""

from datetime import datetime

from pydantic import Field, field_validator, model_validator

from .base import StrictModel
from .enums import IssueLevel, StageName, StageStatus
from .request import _non_blank


class RunError(StrictModel):
    stage: StageName
    category: str
    retryable: bool = False
    message: str
    provider_status_code: int | None = None

    _validate_text = field_validator("category", "message")(_non_blank)


class StageRecord(StrictModel):
    name: StageName
    status: StageStatus = StageStatus.PENDING
    input_fingerprint: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: RunError | None = None


def _pending_stages() -> list[StageRecord]:
    return [StageRecord(name=name) for name in StageName]


class RunManifest(StrictModel):
    run_id: str
    generator_version: str
    created_at: datetime
    updated_at: datetime
    stages: list[StageRecord] = Field(default_factory=_pending_stages)
    provider_metadata: dict[str, str] = Field(default_factory=dict)
    configuration_fingerprint: str | None = None

    _validate_text = field_validator("run_id", "generator_version")(_non_blank)

    @model_validator(mode="after")
    def validate_stage_order(self) -> "RunManifest":
        if [record.name for record in self.stages] != list(StageName):
            raise ValueError("stages must contain every COMBINE stage in order")
        running = sum(record.status is StageStatus.RUNNING for record in self.stages)
        if running > 1:
            raise ValueError("only one stage may be running")
        unfinished_seen = False
        terminal = {StageStatus.COMPLETED, StageStatus.SKIPPED}
        for record in self.stages:
            if record.status not in terminal:
                unfinished_seen = True
            elif unfinished_seen:
                raise ValueError("terminal stage statuses must form a prefix")
        return self

    def stage(self, name: StageName) -> StageRecord:
        return self.stages[list(StageName).index(name)]


class ValidationIssue(StrictModel):
    level: IssueLevel
    code: str
    path: str
    message: str
    related_ids: list[str] = Field(default_factory=list)

    _validate_text = field_validator("code", "path", "message")(_non_blank)


class ValidationReport(StrictModel):
    valid: bool
    issues: list[ValidationIssue] = Field(default_factory=list)
    validated_at: datetime
