"""Readable, privacy-conscious triage notes for two existing scan reports.

This is a human-review artifact, not a structured evidence export.
The original JSON reports remain the source of detailed observations.
"""

from html import escape
from pathlib import Path

from lotuswatch.exceptions import ReportAlreadyExistsError, ReportWriteError
from lotuswatch.models import ComparisonReport, ComparisonStatus, Severity

_SEVERITY_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}
_MARKDOWN_SPECIALS = frozenset("\\*_{}[]()#+-.!|>" + chr(96))


def _markdown_text(value: str) -> str:
    """Escape untrusted finding text for use in Markdown prose and tables."""

    one_line = " ".join(value.split())
    one_line = "".join(char if char.isprintable() else "?" for char in one_line)
    escaped_html = escape(one_line, quote=False)
    return "".join(
        f"\\{char}" if char in _MARKDOWN_SPECIALS else char for char in escaped_html
    )


def _timestamp(value: object) -> str:
    """Render timezone-aware model timestamps without local-time assumptions."""

    return value.isoformat().replace("+00:00", "Z")


def render_markdown_triage_report(report: ComparisonReport) -> str:
    """Summarize actionable changes without embedding raw finding evidence."""

    review = [
        (item, item.current_finding)
        for item in report.findings
        if item.status in {ComparisonStatus.ADDED, ComparisonStatus.CHANGED}
        and item.current_finding is not None
    ]
    review.sort(
        key=lambda pair: (
            -_SEVERITY_RANK[pair[1].severity],
            pair[1].id,
        )
    )
    resolved = [
        item.baseline_finding
        for item in report.findings
        if item.status is ComparisonStatus.RESOLVED
        and item.baseline_finding is not None
    ]
    resolved.sort(key=lambda finding: finding.id)

    lines = [
        "# LotusWatch Security Triage Report",
        "",
        "> Generated from two existing scan reports; no new scan was performed.",
        "> Review target information before sharing. Raw evidence is omitted.",
        "",
        f"**Target:** {_markdown_text(report.normalized_target)}",
        f"**Baseline scanned:** {_timestamp(report.baseline.scanned_at)}",
        f"**Current scanned:** {_timestamp(report.current.scanned_at)}",
        f"**Compared at:** {_timestamp(report.compared_at)}",
        "",
        "## Change summary",
        "",
        "| Added | Changed | Resolved | Unchanged |",
        "| ---: | ---: | ---: | ---: |",
        (
            f"| {report.summary.added} | {report.summary.changed} | "
            f"{report.summary.resolved} | {report.summary.unchanged} |"
        ),
        "",
        f"## Findings requiring review ({len(review)})",
        "",
    ]

    if not review:
        lines.extend(["No added or changed findings.", ""])
    else:
        lines.extend(
            [
                "| Severity | Status | Finding ID | Title |",
                "| --- | --- | --- | --- |",
            ]
        )
        for change, finding in review:
            lines.append(
                f"| {finding.severity.value} | {change.status.value} | "
                f"{finding.id} | {_markdown_text(finding.title)} |"
            )
        lines.append("")

        for change, finding in review:
            lines.extend(
                [
                    f"### {finding.id}: {_markdown_text(finding.title)}",
                    "",
                    f"- **Change:** {change.status.value}",
                    f"- **Current severity:** {finding.severity.value}",
                ]
            )
            if (
                change.status is ComparisonStatus.CHANGED
                and change.baseline_finding is not None
            ):
                lines.append(
                    f"- **Baseline severity:** {change.baseline_finding.severity.value}"
                )
            lines.extend(
                [
                    f"- **Description:** {_markdown_text(finding.description)}",
                    (
                        f"- **Suggested remediation:** "
                        f"{_markdown_text(finding.recommendation)}"
                    ),
                    "",
                ]
            )

    lines.extend(
        [
            f"## Resolved findings ({len(resolved)})",
            "",
        ]
    )
    if not resolved:
        lines.extend(["None.", ""])
    else:
        for finding in resolved:
            lines.append(
                f"- {finding.id} ({finding.severity.value}): "
                f"{_markdown_text(finding.title)}"
            )
        lines.append("")

    lines.extend(
        [
            "## Analyst follow-up",
            "",
            "- [ ] Verify changes against the expected website configuration.",
            "- [ ] Review the original JSON scan reports for supporting evidence.",
            "- [ ] Confirm priority with the system owner and track remediation.",
            "- [ ] Re-scan an authorized target to validate the fix.",
            "",
            (
                "LotusWatch findings indicate configuration observations, not proof "
                "of exploitation or compromise."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def write_markdown_triage_report(
    report: ComparisonReport,
    output: Path,
) -> Path:
    """Write a non-overwriting Markdown triage report to an existing directory."""

    output = Path(output)
    if not output.parent.exists():
        raise ReportWriteError(f"Output directory does not exist: {output.parent}")
    if not output.parent.is_dir():
        raise ReportWriteError(f"Output parent is not a directory: {output.parent}")

    payload = render_markdown_triage_report(report)
    try:
        with output.open("x", encoding="utf-8", newline="\n") as report_file:
            report_file.write(payload)
    except FileExistsError as exc:
        raise ReportAlreadyExistsError(f"Report already exists: {output}") from exc
    except OSError as exc:
        raise ReportWriteError(f"Unable to write report: {output}") from exc

    return output
