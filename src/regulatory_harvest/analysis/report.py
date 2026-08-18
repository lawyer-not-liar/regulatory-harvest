"""Deterministic rendering for the attorney brief and its audit companion."""

import html
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PureWindowsPath
from urllib.parse import urlsplit, urlunsplit

from regulatory_harvest.models import (
    BriefBlock,
    BriefBlockKind,
    ClaimKind,
    FetchStatus,
    Finding,
    Gap,
    IssueCategory,
    ResearchBundle,
    SourceQuality,
    SourceRecord,
    SourceRole,
)

_MARKDOWN_CONTROLS = "\\`*_{}[]()#+!|>"
_SOURCE_SECTION_TITLES = {
    SourceRole.OFFICIAL_PRIMARY: "Official and Primary Sources",
    SourceRole.SECONDARY: "Secondary Sources",
    SourceRole.COMMENTARY_ANALYSIS: "Commentary and Analysis",
}
_SOURCE_SECTION_ORDER = (
    "Official and Primary Sources",
    "Secondary Sources",
    "Commentary and Analysis",
    "Unclassified Sources",
)


@dataclass(frozen=True)
class _ReportContext:
    finding_source_ids: Callable[[list[str]], list[str]]
    finding_source_markers: Callable[[list[str]], str]
    claim_source_markers: Callable[[list[str]], str]


def _escape(value: object) -> str:
    text = html.escape(
        str(value).replace("\r", " ").replace("\n", " "), quote=False
    )
    for control in _MARKDOWN_CONTROLS:
        text = text.replace(control, f"\\{control}")
    return text


def _code(value: object) -> str:
    return html.escape(
        str(value).replace("\r", " ").replace("\n", " "), quote=False
    ).replace("`", "&#96;")


def _sanitized_http_url(candidate: str, *, reject_credentials: bool) -> str | None:
    parsed = urlsplit(candidate)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        return None
    if reject_credentials and (parsed.username is not None or parsed.password is not None):
        return None
    safe_host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    try:
        port = parsed.port
    except ValueError:
        return None
    if port is not None:
        safe_host = f"{safe_host}:{port}"
    path = parsed.path.replace("<", "%3C").replace(">", "%3E").replace(" ", "%20")
    return urlunsplit((parsed.scheme, safe_host, path, "", ""))


def _display_origin(source: SourceRecord) -> str:
    safe_url = _sanitized_http_url(source.origin, reject_credentials=False)
    if safe_url is not None:
        return _escape(safe_url)
    name = (
        PureWindowsPath(source.origin).name
        if "\\" in source.origin
        else Path(source.origin).name
    )
    return _escape(name or "local source")


def _public_authority_url(source: SourceRecord) -> str | None:
    candidate = source.canonical_url or source.origin
    return _sanitized_http_url(candidate, reject_credentials=True)


def _quote_block(text: str) -> list[str]:
    safe_lines = [_escape(line) for line in text.splitlines()] or [""]
    return [f"> {line}" for line in safe_lines]


def _source_labels(bundle: ResearchBundle) -> dict[str, str]:
    return {
        source.source_id: f"S{index}"
        for index, source in enumerate(bundle.sources, start=1)
    }


def _iso_datetime(value: datetime) -> str:
    return str(value.isoformat()).replace("+00:00", "Z")


def _source_section(source: SourceRecord) -> str:
    if source.source_role is not None:
        return _SOURCE_SECTION_TITLES[source.source_role]
    if source.source_quality is SourceQuality.PRIMARY:
        return _SOURCE_SECTION_TITLES[SourceRole.OFFICIAL_PRIMARY]
    if source.source_quality is SourceQuality.SECONDARY:
        return _SOURCE_SECTION_TITLES[SourceRole.SECONDARY]
    return "Unclassified Sources"


def _supported_finding(finding: Finding) -> bool:
    return any(
        claim.kind is ClaimKind.SOURCE_SUPPORTED and claim.citation_ids
        for claim in finding.claims
    )


def _report_context(bundle: ResearchBundle) -> _ReportContext:
    source_by_id = {source.source_id: source for source in bundle.sources}
    citation_by_id = {
        citation.citation_id: citation for citation in bundle.citations
    }
    finding_by_id = {finding.finding_id: finding for finding in bundle.findings}
    claim_by_id = {
        claim.claim_id: claim
        for finding in bundle.findings
        for claim in finding.claims
    }
    source_labels = _source_labels(bundle)
    source_order = {
        source.source_id: index for index, source in enumerate(bundle.sources)
    }

    def finding_source_ids(finding_ids: list[str]) -> list[str]:
        discovered: set[str] = set()
        for finding_id in finding_ids:
            finding = finding_by_id.get(finding_id)
            if finding is None:
                continue
            for claim in finding.claims:
                for citation_id in claim.citation_ids:
                    citation = citation_by_id.get(citation_id)
                    if citation is not None and citation.source_id in source_by_id:
                        discovered.add(citation.source_id)
        return sorted(discovered, key=source_order.__getitem__)

    def markers_for_source_ids(source_ids: list[str]) -> str:
        markers: list[str] = []
        for source_id in source_ids:
            label = source_labels[source_id]
            source = source_by_id[source_id]
            public_url = _public_authority_url(source)
            markers.append(f"[{label}]({public_url})" if public_url else f"[{label}]")
        return ", ".join(markers)

    def finding_source_markers(finding_ids: list[str]) -> str:
        return markers_for_source_ids(finding_source_ids(finding_ids))

    def claim_source_markers(claim_ids: list[str]) -> str:
        discovered: set[str] = set()
        for claim_id in claim_ids:
            claim = claim_by_id.get(claim_id)
            if claim is None:
                continue
            for citation_id in claim.citation_ids:
                citation = citation_by_id.get(citation_id)
                if citation is not None and citation.source_id in source_by_id:
                    discovered.add(citation.source_id)
        return markers_for_source_ids(sorted(discovered, key=source_order.__getitem__))

    return _ReportContext(
        finding_source_ids=finding_source_ids,
        finding_source_markers=finding_source_markers,
        claim_source_markers=claim_source_markers,
    )


def _with_markers(
    text: str,
    finding_ids: list[str],
    claim_ids: list[str],
    context: _ReportContext,
) -> str:
    markers = (
        context.claim_source_markers(claim_ids)
        if claim_ids
        else context.finding_source_markers(finding_ids)
    )
    suffix = f" {markers}" if markers else ""
    return f"{_escape(text)}{suffix}"


def _render_block(block: BriefBlock, context: _ReportContext) -> list[str]:
    if block.kind is BriefBlockKind.PARAGRAPH:
        assert block.text is not None
        return [
            _with_markers(block.text, block.finding_ids, block.claim_ids, context),
            "",
        ]
    if block.kind in {BriefBlockKind.BULLET_LIST, BriefBlockKind.NUMBERED_LIST}:
        lines: list[str] = []
        for index, item in enumerate(block.items, start=1):
            prefix = "-" if block.kind is BriefBlockKind.BULLET_LIST else f"{index}."
            lines.append(
                f"{prefix} "
                f"{_with_markers(item.text, item.finding_ids, item.claim_ids, context)}"
            )
        lines.append("")
        return lines

    lines = [
        "| " + " | ".join(_escape(column) for column in block.columns) + " |",
        "| " + " | ".join("---" for _ in block.columns) + " |",
    ]
    for row in block.rows:
        cells = [_escape(cell) for cell in row.cells]
        markers = (
            context.claim_source_markers(row.claim_ids)
            if row.claim_ids
            else context.finding_source_markers(row.finding_ids)
        )
        if markers:
            cells[-1] = f"{cells[-1]} {markers}"
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")
    return lines


def _coverage_state(bundle: ResearchBundle, category: IssueCategory) -> str:
    category_by_issue = {issue.issue_id: issue.category for issue in bundle.issues}
    has_finding = any(
        category_by_issue.get(finding.issue_id) is category and _supported_finding(finding)
        for finding in bundle.findings
    )
    has_gap = any(gap.category is category for gap in bundle.gaps)
    if has_finding and has_gap:
        return "Partial"
    if has_finding:
        return "Established"
    return "Not established"


def _currentness_state(bundle: ResearchBundle) -> str:
    authorities = _principal_authorities(bundle)
    category_by_issue = {issue.issue_id: issue.category for issue in bundle.issues}
    context = _report_context(bundle)
    status_source_ids: set[str] = set()
    for finding in bundle.findings:
        if (
            category_by_issue.get(finding.issue_id) is IssueCategory.STATUS
            and _supported_finding(finding)
        ):
            status_source_ids.update(context.finding_source_ids([finding.finding_id]))
    status_sources = [
        source
        for source in bundle.sources
        if source.source_id in status_source_ids
        and source.fetch_status is FetchStatus.SUCCEEDED
        and source.source_quality is SourceQuality.PRIMARY
    ]
    if status_sources:
        retained_authorities = [
            source.citation or source.title or source.display_name
            for source in status_sources
        ]
    elif authorities:
        retained_authorities = authorities
    else:
        retained_authorities = []
    retained_authorities = list(dict.fromkeys(retained_authorities)) or ["not identified"]
    authority_label = (
        "retained cited primary authority"
        if len(retained_authorities) == 1
        else "retained cited primary authorities"
    )
    retained = "; ".join(_escape(authority) for authority in retained_authorities)
    as_of = bundle.request.as_of.isoformat()
    metadata_dates = sorted(
        {
            match
            for source in status_sources
            if source.supersession is not None
            for match in re.findall(r"\b\d{4}-\d{2}-\d{2}\b", source.supersession)
            if match <= as_of
        }
    )
    if metadata_dates:
        return (
            "Recorded in retained primary-source metadata through "
            f"{metadata_dates[-1]}; {authority_label}: {retained}; "
            "attorney verification required"
        )
    return (
        f"Not independently verified through {as_of}; {authority_label}: {retained}; "
        "attorney verification required"
    )


def _principal_authorities(bundle: ResearchBundle) -> list[str]:
    context = _report_context(bundle)
    cited_source_ids: set[str] = set()
    for finding in bundle.findings:
        if not _supported_finding(finding):
            continue
        cited_source_ids.update(context.finding_source_ids([finding.finding_id]))
    authorities: list[str] = []
    for source in bundle.sources:
        if (
            source.source_id not in cited_source_ids
            or source.fetch_status is not FetchStatus.SUCCEEDED
            or source.source_quality is not SourceQuality.PRIMARY
        ):
            continue
        authority = source.citation or source.title or source.display_name
        if authority not in authorities:
            authorities.append(authority)
    return authorities


def _metadata_lines(bundle: ResearchBundle) -> list[str]:
    jurisdictions = ", ".join(_escape(item) for item in bundle.request.jurisdictions)
    jurisdiction_label = (
        "Jurisdiction" if len(bundle.request.jurisdictions) == 1 else "Jurisdictions"
    )
    authorities = _principal_authorities(bundle)
    authority_label = "Principal authorities" if len(authorities) > 1 else "Principal authority"
    source_scope = (
        "Closed universe of supplied materials"
        if bundle.request.source_mode == "provided-only"
        else "Public-source research"
    )
    effective_dates = sorted(
        {
            source.effective_date
            for source in bundle.sources
            if source.fetch_status is FetchStatus.SUCCEEDED
            and source.effective_date is not None
        }
    )
    lines = [
        f"**{jurisdiction_label}:** {jurisdictions}",
        f"**As of:** {bundle.request.as_of.isoformat()}",
        f"**Research scope:** {source_scope}",
        f"**{authority_label}:** "
        + ("; ".join(_escape(item) for item in authorities) if authorities else "Not established"),
        f"**Currentness:** {_currentness_state(bundle)}",
    ]
    if effective_dates:
        date_label = "Operative date" if len(effective_dates) == 1 else "Operative dates"
        lines.append(f"**{date_label}:** " + ", ".join(_escape(item) for item in effective_dates))
    return [line for item in lines for line in (item, "")]


def _render_adaptive_sections(
    bundle: ResearchBundle, context: _ReportContext
) -> list[str]:
    assert bundle.brief is not None
    lines: list[str] = []
    for section in bundle.brief.sections:
        lines.extend([f"## {_escape(section.title)}", ""])
        for block in section.blocks:
            lines.extend(_render_block(block, context))
        for subsection in section.subsections:
            lines.extend([f"### {_escape(subsection.title)}", ""])
            for block in subsection.blocks:
                lines.extend(_render_block(block, context))
    return lines


def _render_fallback_sections(
    bundle: ResearchBundle, context: _ReportContext
) -> list[str]:
    findings_by_issue: dict[str, list[Finding]] = {}
    for finding in bundle.findings:
        if _supported_finding(finding):
            findings_by_issue.setdefault(finding.issue_id, []).append(finding)

    lines: list[str] = []
    for issue in bundle.issues:
        findings = findings_by_issue.get(issue.issue_id, [])
        if not findings:
            continue
        lines.extend([f"## {_escape(issue.title)}", ""])
        if issue.description:
            lines.extend([_escape(issue.description), ""])
        for finding in findings:
            markers = context.finding_source_markers([finding.finding_id])
            suffix = f" {markers}" if markers else ""
            lines.extend([f"### {_escape(finding.title)}{suffix}", ""])
            for claim in finding.claims:
                if claim.kind is ClaimKind.ANALYSIS:
                    lines.extend([_escape(claim.text), ""])
            lines.extend(
                [
                    f"**Practical implication:** {_escape(finding.practical_implication)}",
                    "",
                ]
            )
    return lines


def _render_limitations(gaps: list[Gap]) -> list[str]:
    if not gaps:
        return []
    lines = ["## Limitations and Open Questions", ""]
    seen: set[str] = set()
    for gap in gaps:
        if gap.message in seen:
            continue
        seen.add(gap.message)
        lines.append(f"- {_escape(gap.message)}")
    lines.append("")
    return lines


def _concise_source_line(source: SourceRecord, label: str) -> str:
    parts = [f"- **{label}. {_escape(source.display_name)}**"]
    if source.citation:
        parts.append(_escape(source.citation))
    if source.publisher:
        parts.append(_escape(source.publisher))
    public_url = _public_authority_url(source)
    if public_url is not None:
        link_label = (
            "Official source"
            if source.source_role is SourceRole.OFFICIAL_PRIMARY
            else "Source"
        )
        parts.append(f"[{link_label}]({public_url})")
    else:
        parts.append(f"Source: {_display_origin(source)}")
    if source.effective_date:
        parts.append(f"Effective date: {_escape(source.effective_date)}")
    if source.fetch_status is FetchStatus.FAILED and source.error is not None:
        parts.append(f"Retrieval failed: {_escape(source.error.category)}")
    return ". ".join(parts) + "."


def _render_sources(bundle: ResearchBundle) -> list[str]:
    labels = _source_labels(bundle)
    lines = ["## Sources Consulted", ""]
    for heading in _SOURCE_SECTION_ORDER:
        sources = [source for source in bundle.sources if _source_section(source) == heading]
        if not sources:
            continue
        lines.extend([f"### {heading}", ""])
        lines.extend(_concise_source_line(source, labels[source.source_id]) for source in sources)
        lines.append("")
    return lines


def render_markdown(bundle: ResearchBundle) -> str:
    """Render the summary-first, adaptive attorney-facing report."""
    context = _report_context(bundle)
    title = bundle.request.matter_title or "Attorney research briefing"
    lines = [f"# {_escape(title)}", "", *_metadata_lines(bundle), "## Executive Summary", ""]

    if bundle.brief is not None:
        for block in bundle.brief.executive_summary:
            lines.extend(_render_block(block, context))
        lines.extend(_render_adaptive_sections(bundle, context))
    else:
        supported = [finding for finding in bundle.findings if _supported_finding(finding)]
        if supported:
            for finding in supported:
                lines.append(
                    "- "
                    + _with_markers(
                        finding.title,
                        [finding.finding_id],
                        [],
                        context,
                    )
                )
            lines.append("")
        else:
            lines.extend(
                [
                    "The retained materials did not support a substantive legal conclusion.",
                    "",
                ]
            )
        lines.extend(_render_fallback_sections(bundle, context))

    lines.extend(_render_limitations(bundle.gaps))
    lines.extend(_render_sources(bundle))
    lines.extend([f"*{_escape(bundle.disclaimer)}*", ""])
    return "\n".join(lines)


def _audit_source(source: SourceRecord, label: str) -> list[str]:
    lines = [
        f"### {label}. {_escape(source.display_name)}",
        "",
        f"- Retained origin: {_display_origin(source)}",
        f"- Retrieval: {source.fetch_status.value}",
        f"- Quality: {source.source_quality.value}",
    ]
    public_url = _public_authority_url(source)
    if public_url is not None:
        lines.append(f"- Canonical source: <{public_url}>")
    for detail_label, value in (
        ("Publisher", source.publisher),
        ("Jurisdiction", source.jurisdiction),
        ("Authority type", source.authority_type),
        ("Citation", source.citation),
        ("Effective date", source.effective_date),
        ("Supersession", source.supersession),
        ("Language", source.language),
    ):
        if value is not None:
            lines.append(f"- {detail_label}: {_escape(value)}")
    if source.fetch_status is FetchStatus.FAILED and source.error is not None:
        lines.append(f"- Failure category: {_escape(source.error.category)}")
    lines.append("")
    return lines


def render_audit_markdown(bundle: ResearchBundle) -> str:
    """Render exact evidence, validation, and run detail outside the attorney report."""
    title = bundle.request.matter_title or "Attorney research briefing"
    source_by_id = {source.source_id: source for source in bundle.sources}
    source_labels = _source_labels(bundle)
    evidence_labels = {
        citation.citation_id: f"E{index}"
        for index, citation in enumerate(bundle.citations, start=1)
    }
    validation_status = (
        "not run"
        if bundle.validation is None
        else "valid"
        if bundle.validation.valid
        else "invalid"
    )
    lines = [
        f"# {_escape(title)}: Evidence and Validation Audit",
        "",
        "## Research Scope",
        "",
        f"**Research question:** {_escape(bundle.request.question)}",
        "",
        "**Jurisdictions:** "
        + ", ".join(_escape(item) for item in bundle.request.jurisdictions),
        "",
        f"**As of:** {bundle.request.as_of.isoformat()}",
        "",
        f"**Source mode:** {_escape(bundle.request.source_mode)}",
        "",
        f"**Deterministic validation:** {validation_status}",
        "",
        "## Retained Sources",
        "",
    ]
    for retained_source in bundle.sources:
        lines.extend(
            _audit_source(retained_source, source_labels[retained_source.source_id])
        )

    lines.extend(["## Exact Evidence", ""])
    if not bundle.citations:
        lines.extend(["No exact evidence excerpt was resolved.", ""])
    for citation in bundle.citations:
        evidence_label = evidence_labels[citation.citation_id]
        source = source_by_id.get(citation.source_id)
        source_label = source_labels.get(citation.source_id, citation.source_id)
        source_name = source.display_name if source is not None else citation.source_id
        citation_text = (
            f", {_escape(source.citation)}"
            if source is not None and source.citation is not None
            else ""
        )
        lines.extend(
            [
                f"### {evidence_label}. {_escape(source_name)}{citation_text} "
                f"({_escape(source_label)})",
                "",
            ]
        )
        lines.extend(_quote_block(citation.quote))
        lines.append("")

    lines.extend(["## Validation and Review", "", "### Research Gap Audit", ""])
    if not bundle.gaps:
        lines.extend(["No research gap code was recorded.", ""])
    for gap in bundle.gaps:
        lines.append(f"- `{_code(gap.code)}`: {_escape(gap.message)}")
    lines.extend(["", "### Deterministic Validation", ""])
    if bundle.validation is None:
        lines.extend(["The bundle has not been validated.", ""])
    elif not bundle.validation.issues:
        lines.extend(["No deterministic validation issues were found.", ""])
    else:
        for issue in bundle.validation.issues:
            lines.append(
                f"- {issue.level.value}: `{_code(issue.code)}` at "
                f"`{_code(issue.path)}`: {_escape(issue.message)}"
            )
        lines.append("")

    lines.extend(["### Attorney Review Required", ""])
    if not bundle.review_items:
        lines.extend(
            [
                "No additional review item was generated, but attorney review remains mandatory.",
                "",
            ]
        )
    for item in bundle.review_items:
        lines.append(f"- `{_code(item.code)}`: {_escape(item.message)}")
    lines.extend(["", bundle.disclaimer, "", "### Methodology and Run Metadata", ""])
    lines.extend(
        [
            "COMBINE stages: Collect, Organize, Map, Build, Inspect, Note, Export.",
            "",
            f"- Run ID: `{_code(bundle.manifest.run_id)}`",
            f"- Generator: `{_code(bundle.generator_version)}`",
            f"- Updated: {_iso_datetime(bundle.manifest.updated_at)}",
        ]
    )
    for key in ("model_provider", "model"):
        value = bundle.manifest.provider_metadata.get(key)
        if value is not None:
            lines.append(f"- {_escape(key.replace('_', ' ').title())}: {_escape(value)}")
    lines.append("")
    return "\n".join(lines)
