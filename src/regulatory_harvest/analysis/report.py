"""Deterministic, review-forward Markdown reporting."""

import html
from pathlib import Path, PureWindowsPath
from urllib.parse import urlsplit, urlunsplit

from regulatory_harvest.models import FetchStatus, ResearchBundle, SourceRecord

_MARKDOWN_CONTROLS = "\\`*_{}[]()#+!|>"


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


def _display_origin(source: SourceRecord) -> str:
    parsed = urlsplit(source.origin)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        hostname = parsed.hostname
        if hostname is None:
            return "public URL"
        safe_host = f"[{hostname}]" if ":" in hostname else hostname
        try:
            port = parsed.port
        except ValueError:
            port = None
        if port is not None:
            safe_host = f"{safe_host}:{port}"
        return _escape(urlunsplit((parsed.scheme, safe_host, parsed.path, "", "")))
    name = (
        PureWindowsPath(source.origin).name
        if "\\" in source.origin
        else Path(source.origin).name
    )
    return _escape(name or "local source")


def _quote_block(text: str) -> list[str]:
    safe_lines = [_escape(line) for line in text.splitlines()] or [""]
    return [f"> {line}" for line in safe_lines]


def render_markdown(bundle: ResearchBundle) -> str:
    """Render a safe report without raw exceptions, secrets, or absolute local paths."""
    source_by_id = {source.source_id: source for source in bundle.sources}
    citation_by_id = {citation.citation_id: citation for citation in bundle.citations}
    validation_status = (
        "not run"
        if bundle.validation is None
        else "valid" if bundle.validation.valid else "invalid"
    )
    lines = [
        "# Regulatory Harvest",
        "",
        f"**Question:** {_escape(bundle.request.question)}",
        "",
        f"**As of:** {bundle.request.as_of.isoformat()}",
        "",
        f"**Jurisdictions:** {', '.join(_escape(item) for item in bundle.request.jurisdictions)}",
        "",
        f"**Validation status:** {validation_status}",
        "",
        "## Findings",
        "",
    ]

    if not bundle.findings:
        lines.extend(["No supported findings were produced.", ""])
    for finding in bundle.findings:
        lines.extend(
            [
                f"### {_escape(finding.title)}",
                "",
                f"- Jurisdiction: {_escape(finding.jurisdiction)}",
                f"- Authority: {_escape(finding.authority)}",
                f"- Severity: {finding.severity.value}",
                f"- Practical implication: {_escape(finding.practical_implication)}",
                "",
            ]
        )
        for claim in finding.claims:
            lines.extend([f"- {_escape(claim.text)}", ""])
            for citation_id in claim.citation_ids:
                citation = citation_by_id.get(citation_id)
                if citation is None:
                    continue
                source = source_by_id.get(citation.source_id)
                source_name = source.display_name if source is not None else citation.source_id
                lines.append(f"  Evidence from {_escape(source_name)}:")
                lines.extend(_quote_block(citation.quote))
                lines.append("")

    lines.extend(["## Gaps and limitations", ""])
    if not bundle.gaps:
        lines.extend(["No explicit gaps were recorded.", ""])
    for gap in bundle.gaps:
        jurisdiction = (
            f" [{_escape(gap.jurisdiction)}]" if gap.jurisdiction is not None else ""
        )
        lines.append(f"- `{_code(gap.code)}`{jurisdiction}: {_escape(gap.message)}")
    lines.append("")

    lines.extend(["## Validation", ""])
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

    lines.extend(["## Attorney review required", ""])
    if not bundle.review_items:
        lines.extend(
            [
                "No additional review items were generated, but attorney review remains mandatory.",
                "",
            ]
        )
    for item in bundle.review_items:
        lines.append(f"- `{_code(item.code)}`: {_escape(item.message)}")
    lines.extend(["", bundle.disclaimer, ""])

    lines.extend(["## Sources", ""])
    if not bundle.sources:
        lines.extend(["No sources were retained.", ""])
    for source in bundle.sources:
        status = source.fetch_status.value
        details = [
            f"- **{_escape(source.display_name)}**",
            f"  - Origin: {_display_origin(source)}",
            f"  - Retrieval: {status}",
            f"  - Quality: {source.source_quality.value}",
        ]
        if source.fetch_status is FetchStatus.FAILED and source.error is not None:
            details.append(f"  - Failure category: {_escape(source.error.category)}")
        lines.extend(details)
    lines.append("")

    lines.extend(
        [
            "## Methodology and run metadata",
            "",
            "COMBINE stages: Collect, Organize, Map, Build, Inspect, Note, Export.",
            "",
            f"- Run ID: `{_code(bundle.manifest.run_id)}`",
            f"- Generator: `{_code(bundle.generator_version)}`",
            f"- Updated: {bundle.manifest.updated_at.isoformat()}",
        ]
    )
    for key in ("model_provider", "model"):
        value = bundle.manifest.provider_metadata.get(key)
        if value is not None:
            lines.append(f"- {_escape(key.replace('_', ' ').title())}: {_escape(value)}")
    lines.append("")
    return "\n".join(lines)
