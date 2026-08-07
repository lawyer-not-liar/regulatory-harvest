from datetime import UTC, date, datetime

from regulatory_harvest.analysis.report import render_markdown
from regulatory_harvest.models import (
    DISCLAIMER,
    Gap,
    ResearchBundle,
    ResearchRequest,
    ReviewItem,
    RunManifest,
    SourceFailure,
    SourceInput,
    SourceQuality,
    SourceRecord,
)


def _bundle() -> ResearchBundle:
    now = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
    return ResearchBundle(
        generator_version="0.1.0",
        request=ResearchRequest(
            request_id="demo",
            question="What does *Rule* require?",
            jurisdictions=["US"],
            as_of=date(2026, 8, 5),
            source_inputs=[SourceInput(location="/Users/private/matter/rule.txt")],
        ),
        manifest=RunManifest(
            run_id="demo",
            generator_version="0.1.0",
            created_at=now,
            updated_at=now,
            provider_metadata={"model_provider": "example", "api_key": "secret-value"},
        ),
        sources=[
            SourceRecord(
                source_id="src_failed",
                origin="/Users/private/matter/rule.txt",
                display_name="*Draft* Rule",
                retrieved_at=now,
                media_type="text/plain",
                source_quality=SourceQuality.UNUSABLE,
                fetch_status="failed",
                error=SourceFailure(
                    category="file_error",
                    message="/Users/private/matter/rule.txt: secret-value",
                ),
            )
        ],
        gaps=[
            Gap(
                gap_id="gap-1",
                code="SOURCE_RETRIEVAL_FAILED",
                message="The requested source could not be read.",
                jurisdiction="US",
                source_ids=["src_failed"],
            )
        ],
        review_items=[
            ReviewItem(
                review_id="review-1",
                code="VERIFY_CURRENTNESS",
                message="Confirm the rule remains current.",
            )
        ],
    )


def test_report_surfaces_review_queue_sources_and_disclaimer() -> None:
    """Omitting uncertainty or the review boundary would overstate the output."""
    report = render_markdown(_bundle())

    assert "## Attorney review required" in report
    assert "## Gaps and limitations" in report
    assert "## Sources" in report
    assert "VERIFY_CURRENTNESS" in report
    assert DISCLAIMER in report


def test_report_escapes_metadata_and_hides_sensitive_local_details() -> None:
    """Rendering raw metadata could leak paths, secrets, or Markdown structure."""
    report = render_markdown(_bundle())

    assert "What does \\*Rule\\* require?" in report
    assert "\\*Draft\\* Rule" in report
    assert "/Users/private" not in report
    assert "secret-value" not in report
    assert "rule.txt" in report


def test_report_redacts_windows_paths_and_url_credentials() -> None:
    """Cross-platform paths and URL tokens must not leak through source origins."""
    bundle = _bundle()
    bundle.sources[0].origin = r"C:\Users\private\matter\rule.txt"
    windows_report = render_markdown(bundle)
    bundle.sources[0].origin = "https://user:secret@example.org/rule?token=hidden#private"
    url_report = render_markdown(bundle)

    assert "Users" not in windows_report
    assert "rule.txt" in windows_report
    assert "user:secret" not in url_report
    assert "token=hidden" not in url_report
    assert "#private" not in url_report
    assert "https://example.org/rule" in url_report


def test_report_neutralizes_html_and_inline_code_breakout() -> None:
    """Untrusted bundle text must remain text instead of executable or structural markup."""
    bundle = _bundle()
    bundle.request.question = '<img src=x onerror="alert(1)">'
    bundle.gaps[0].code = "GAP` ## injected"

    report = render_markdown(bundle)

    assert "<img" not in report
    assert "&lt;img" in report
    assert "` ## injected" not in report
    assert "GAP&#96; ## injected" in report
