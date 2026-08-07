from __future__ import annotations

import asyncio
from datetime import UTC, date, datetime, timedelta

from regulatory_harvest.analysis import (
    AnalysisDraft,
    DraftClaim,
    DraftFinding,
    DraftIssue,
    ProposedCitation,
)
from regulatory_harvest.models import (
    ClaimKind,
    ResearchRequest,
    Severity,
    SourceInput,
    SourceRecord,
)
from regulatory_harvest.providers import ModelRequest, ModelResponse
from regulatory_harvest.storage import sha256_digest

RULE_TEXT = "A controller must document risks."


class TickingClock:
    def __init__(self) -> None:
        self._value = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        current = self._value
        self._value += timedelta(seconds=1)
        return current


class CountingFetcher:
    def __init__(self) -> None:
        self.calls: list[SourceInput] = []

    async def fetch(self, source_input: SourceInput) -> SourceRecord:
        self.calls.append(source_input)
        return SourceRecord(
            source_id="src_rule",
            origin=source_input.location,
            display_name=source_input.title or "Example Rule",
            retrieved_at=datetime(2026, 8, 5, 12, 0, tzinfo=UTC),
            content_hash=sha256_digest(RULE_TEXT.encode()),
            media_type="text/plain",
            normalized_text=RULE_TEXT,
            jurisdiction=source_input.jurisdiction,
        )


class BlockingFetcher(CountingFetcher):
    def __init__(self) -> None:
        super().__init__()
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def fetch(self, source_input: SourceInput) -> SourceRecord:
        self.started.set()
        await self.release.wait()
        return await super().fetch(source_input)


class RecordingProvider:
    def __init__(self, *, fail_first_build: bool = False) -> None:
        self.map_calls = 0
        self.build_calls = 0
        self.fail_first_build = fail_first_build

    async def complete(self, request: ModelRequest) -> ModelResponse:
        if request.operation == "map":
            self.map_calls += 1
            draft = AnalysisDraft(
                issues=[
                    DraftIssue(
                        issue_id="issue-1",
                        title="Documentation",
                        jurisdictions=["US"],
                    )
                ]
            )
        else:
            self.build_calls += 1
            if self.fail_first_build and self.build_calls == 1:
                raise RuntimeError("synthetic provider interruption")
            draft = AnalysisDraft(
                issues=[
                    DraftIssue(
                        issue_id="issue-1",
                        title="Documentation",
                        jurisdictions=["US"],
                    )
                ],
                findings=[
                    DraftFinding(
                        finding_id="finding-1",
                        issue_id="issue-1",
                        title="Document risks",
                        jurisdiction="US",
                        authority="Example Rule",
                        severity=Severity.MEDIUM,
                        practical_implication="Maintain risk documentation.",
                        claims=[
                            DraftClaim(
                                claim_id="claim-1",
                                text=RULE_TEXT,
                                kind=ClaimKind.SOURCE_SUPPORTED,
                                proposed_citations=[
                                    ProposedCitation(
                                        source_id="src_rule",
                                        quote=RULE_TEXT,
                                    )
                                ],
                            )
                        ],
                    )
                ],
            )
        return ModelResponse(
            parsed=draft,
            provider_name="fake",
            model_name="fake-model",
            prompt_fingerprint="a" * 64,
        )


def request(*, question: str = "What must a controller document?") -> ResearchRequest:
    return ResearchRequest(
        request_id="run-1",
        question=question,
        jurisdictions=["US"],
        as_of=date(2026, 8, 5),
        source_inputs=[
            SourceInput(
                location="example-rule.txt",
                title="Example Rule",
                jurisdiction="US",
            )
        ],
    )
