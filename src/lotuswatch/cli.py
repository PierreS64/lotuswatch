import json
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape

from lotuswatch import __version__
from lotuswatch.checks import (
    CAACheckResult,
    CAACheckStatus,
    DNSQueryResult,
    EmailDNSCheckResult,
    EmailDNSStatus,
    RedirectCheckResult,
    RedirectStatus,
    SecurityHeaderCheckResult,
    TLSCheckResult,
    TLSStatus,
)
from lotuswatch.exceptions import (
    ComparisonError,
    ReportError,
    TargetValidationError,
)
from lotuswatch.models import (
    ComparisonReport,
    ComparisonStatus,
    Finding,
    FindingComparison,
    ScanReport,
    Severity,
    compare_reports,
)
from lotuswatch.monitoring_cli import monitor_app
from lotuswatch.policy import (
    comparison_findings_meet_threshold,
    scan_findings_meet_threshold,
)
from lotuswatch.reporters import (
    load_json_report,
    write_json_comparison_report,
    write_json_report,
    write_markdown_triage_report,
)
from lotuswatch.scanner import execute_scan
from lotuswatch.target import normalize_target


class OutputFormat(StrEnum):
    """Output formats supported by the scan command."""

    CONSOLE = "console"
    JSON = "json"


class CompareOutputFormat(StrEnum):
    """Output formats supported by the comparison command."""

    CONSOLE = "console"
    JSON = "json"
    MARKDOWN = "markdown"


app = typer.Typer(
    name="lotuswatch",
    help="Monitor websites and identify security configuration risks.",
    no_args_is_help=True,
)
app.add_typer(monitor_app, name="monitor")

console = Console()

MAX_CONSOLE_CAA_RECORDS = 5
MAX_CONSOLE_DNS_VALUE_LENGTH = 120
MAX_CONSOLE_COMPARISON_VALUE_LENGTH = 240


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the installed LotusWatch version and exit.",
        ),
    ] = False,
) -> None:
    """LotusWatch website security monitoring tool."""


@app.command()
def scan(
    target: Annotated[
        str,
        typer.Argument(help="Domain or URL that you are authorized to inspect."),
    ],
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", help="Output format."),
    ] = OutputFormat.CONSOLE,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Path for the generated report.",
        ),
    ] = None,
    fail_on: Annotated[
        Severity | None,
        typer.Option(
            "--fail-on",
            help=("Return exit code 1 when any finding has this severity or higher."),
        ),
    ] = None,
) -> None:
    """Inspect the security configuration of a website."""

    if output_format is OutputFormat.JSON and output is None:
        raise typer.BadParameter(
            "--output is required when --format json is used.",
            param_hint="--output",
        )

    if output_format is OutputFormat.CONSOLE and output is not None:
        raise typer.BadParameter(
            "--output requires --format json.",
            param_hint="--output",
        )

    try:
        normalized_target = normalize_target(target)
    except TargetValidationError as exc:
        raise typer.BadParameter(str(exc), param_hint="target") from exc

    console.print("[bold green]LotusWatch[/bold green] is preparing to scan:")
    console.print(f"Input: [cyan]{normalized_target.original}[/cyan]")
    console.print(f"Normalized: [cyan]{normalized_target.url}[/cyan]")

    execution = execute_scan(
        normalized_target,
        lotuswatch_version=__version__,
    )
    _render_redirect_result(
        execution.redirect_result,
        execution.redirect_findings,
    )
    _render_tls_result(execution.tls_result, execution.tls_findings)
    _render_header_result(execution.header_result, execution.header_findings)
    _render_caa_result(execution.caa_result, execution.caa_findings)
    _render_email_dns_result(
        execution.email_dns_result,
        execution.email_dns_findings,
    )
    _render_scan_summary(
        execution.recorded_checks,
        execution.completed_checks,
        execution.findings,
    )

    if output_format is OutputFormat.JSON:
        assert output is not None

        try:
            report_path = write_json_report(execution.report, output)
        except ReportError as exc:
            raise typer.BadParameter(
                str(exc),
                param_hint="--output",
            ) from exc

        console.print(f"\n[green]Report written:[/green] {report_path}")

    if fail_on is not None and scan_findings_meet_threshold(
        execution.findings,
        fail_on,
    ):
        _raise_policy_exit(fail_on, comparison=False)


@app.command()
def compare(
    baseline: Annotated[
        Path,
        typer.Argument(help="Path to the older baseline scan report."),
    ],
    current: Annotated[
        Path,
        typer.Argument(help="Path to the newer current scan report."),
    ],
    output_format: Annotated[
        CompareOutputFormat,
        typer.Option("--format", help="Output format (console, json, markdown)."),
    ] = CompareOutputFormat.CONSOLE,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Path for the generated comparison report.",
        ),
    ] = None,
    fail_on: Annotated[
        Severity | None,
        typer.Option(
            "--fail-on",
            help=(
                "Return exit code 1 when an added or changed current finding "
                "has this severity or higher."
            ),
        ),
    ] = None,
) -> None:
    """Compare two LotusWatch scan reports without running a new scan."""

    if output_format is not CompareOutputFormat.CONSOLE and output is None:
        raise typer.BadParameter(
            "--output is required for json/markdown.",
            param_hint="--output",
        )

    if output_format is CompareOutputFormat.CONSOLE and output is not None:
        raise typer.BadParameter(
            "--output requires --format json or markdown.",
            param_hint="--output",
        )

    baseline_report = _load_comparison_input(baseline, "baseline")
    current_report = _load_comparison_input(current, "current")

    try:
        comparison = compare_reports(baseline_report, current_report)
    except ComparisonError as exc:
        raise typer.BadParameter(
            str(exc),
            param_hint="baseline/current",
        ) from exc

    if output_format is CompareOutputFormat.CONSOLE:
        _render_comparison(comparison)
    else:
        assert output is not None

        try:
            if output_format is CompareOutputFormat.JSON:
                report_path = write_json_comparison_report(comparison, output)
            else:
                report_path = write_markdown_triage_report(comparison, output)
        except ReportError as exc:
            raise typer.BadParameter(
                str(exc),
                param_hint="--output",
            ) from exc

        console.print(f"[green]Comparison report written:[/green] {report_path}")
        console.print(
            "[yellow]Review this file before sharing; it may contain "
            "sensitive report data.[/yellow]"
        )

    if fail_on is not None and comparison_findings_meet_threshold(
        comparison,
        fail_on,
    ):
        _raise_policy_exit(fail_on, comparison=True)


def _raise_policy_exit(threshold: Severity, *, comparison: bool) -> None:
    """Report a matched opt-in policy and return its documented exit code."""

    subject = "Added or changed finding" if comparison else "Finding"
    console.print(
        f"\n[red]POLICY FAIL[/red] {subject} severity threshold met: "
        f"{threshold.value} or higher. Returning exit code 1."
    )
    raise typer.Exit(code=1)


def _load_comparison_input(report_path: Path, param_hint: str) -> ScanReport:
    """Load one CLI comparison input with a parameter-specific error."""

    try:
        return load_json_report(report_path)
    except ReportError as exc:
        raise typer.BadParameter(str(exc), param_hint=param_hint) from exc


def _render_comparison(comparison: ComparisonReport) -> None:
    """Render a concise comparison without listing unchanged findings."""

    console.print("[bold green]LotusWatch[/bold green] report comparison")
    console.print(f"Target: [cyan]{escape(comparison.normalized_target)}[/cyan]")
    console.print(
        "Baseline: "
        f"{_display_timestamp(comparison.baseline.scanned_at)} "
        f"(LotusWatch {escape(comparison.baseline.lotuswatch_version)})"
    )
    console.print(
        "Current: "
        f"{_display_timestamp(comparison.current.scanned_at)} "
        f"(LotusWatch {escape(comparison.current.lotuswatch_version)})"
    )

    console.print("\n[bold]Comparison summary[/bold]")
    console.print(f"Added: {comparison.summary.added}")
    console.print(f"Resolved: {comparison.summary.resolved}")
    console.print(f"Changed: {comparison.summary.changed}")
    console.print(f"Unchanged: {comparison.summary.unchanged}")

    changed_total = (
        comparison.summary.added
        + comparison.summary.resolved
        + comparison.summary.changed
    )
    if changed_total == 0:
        console.print("[green]PASS[/green] No finding changes detected.")
    else:
        console.print(
            f"[yellow]CHANGES[/yellow] {changed_total} finding change(s) detected."
        )

    _render_comparison_section(
        "Added findings",
        ComparisonStatus.ADDED,
        comparison.findings,
    )
    _render_comparison_section(
        "Resolved findings",
        ComparisonStatus.RESOLVED,
        comparison.findings,
    )
    _render_comparison_section(
        "Changed findings",
        ComparisonStatus.CHANGED,
        comparison.findings,
    )


def _render_comparison_section(
    title: str,
    status: ComparisonStatus,
    comparisons: list[FindingComparison],
) -> None:
    """Render one change section and omit unchanged finding details."""

    matching = [item for item in comparisons if item.status is status]
    console.print(f"\n[bold]{title} ({len(matching)})[/bold]")

    if not matching:
        console.print("None.")
        return

    for comparison in matching:
        if status is ComparisonStatus.ADDED:
            finding = comparison.current_finding
        else:
            finding = comparison.baseline_finding

        assert finding is not None
        console.print(
            f"- [yellow]{finding.id}[/yellow] "
            f"({finding.severity.value}) - {escape(finding.title)}"
        )
        console.print(f"  Fingerprint: {comparison.fingerprint}")

        if status is ComparisonStatus.CHANGED:
            _render_changed_finding_fields(comparison)


def _render_changed_finding_fields(comparison: FindingComparison) -> None:
    """Render bounded baseline and current values for changed fields."""

    baseline = comparison.baseline_finding
    current = comparison.current_finding
    assert baseline is not None and current is not None
    baseline_data = baseline.model_dump(mode="json")
    current_data = current.model_dump(mode="json")

    for field in (
        "severity",
        "title",
        "description",
        "evidence",
        "recommendation",
        "reference",
    ):
        if baseline_data[field] == current_data[field]:
            continue

        label = field.replace("_", " ").title()
        console.print(
            f"  {label} baseline: "
            f"{escape(_comparison_display_value(baseline_data[field]))}"
        )
        console.print(
            f"  {label} current: "
            f"{escape(_comparison_display_value(current_data[field]))}"
        )


def _comparison_display_value(value: object) -> str:
    """Serialize and bound one comparison field for console output."""

    serialized = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    if len(serialized) <= MAX_CONSOLE_COMPARISON_VALUE_LENGTH:
        return serialized

    return f"{serialized[:MAX_CONSOLE_COMPARISON_VALUE_LENGTH]}..."


def _display_timestamp(value: datetime) -> str:
    """Render a UTC model timestamp with the JSON-style Z suffix."""

    return value.isoformat().replace("+00:00", "Z")


def _render_redirect_result(
    result: RedirectCheckResult,
    findings: list[Finding],
) -> None:
    console.print("\n[bold]HTTP to HTTPS redirect[/bold]")

    if result.passed:
        console.print("[green]PASS[/green] HTTP redirects to HTTPS.")

        if result.final_status_code is not None and result.final_status_code >= 400:
            console.print(
                "[yellow]WARNING[/yellow] "
                "HTTPS destination returned status "
                f"{result.final_status_code}."
            )
    elif result.status in {
        RedirectStatus.TIMEOUT,
        RedirectStatus.CONNECTION_ERROR,
    }:
        console.print(f"[yellow]ERROR[/yellow] {result.error}")
    else:
        console.print("[red]FAIL[/red] HTTP does not redirect safely to HTTPS.")

    console.print(f"Initial URL: [cyan]{result.initial_url}[/cyan]")
    console.print(f"Final URL: [cyan]{result.final_url}[/cyan]")
    console.print(f"Redirects: {result.redirect_count}")
    console.print(f"Initial status: {_display_value(result.initial_status_code)}")
    console.print(f"Final status: {_display_value(result.final_status_code)}")
    _render_findings(findings)


def _render_tls_result(
    result: TLSCheckResult,
    findings: list[Finding],
) -> None:
    console.print("\n[bold]TLS certificate[/bold]")

    if result.status is TLSStatus.VERIFICATION_ERROR:
        console.print(f"[red]FAIL[/red] {result.error}")
    elif not result.passed:
        console.print(f"[yellow]ERROR[/yellow] {result.error}")
    elif findings:
        console.print("[yellow]WARNING[/yellow] TLS certificate needs attention.")
    else:
        console.print("[green]PASS[/green] TLS certificate verified successfully.")

    console.print(f"Endpoint: [cyan]{result.hostname}:{result.port}[/cyan]")
    console.print(f"TLS version: {_display_value(result.tls_version)}")
    console.print(f"Expires: {_display_value(result.not_after)}")
    console.print(f"Days remaining: {_display_value(result.days_until_expiry)}")
    _render_findings(findings)


def _render_header_result(
    result: SecurityHeaderCheckResult,
    findings: list[Finding],
) -> None:
    console.print("\n[bold]HTTP security headers[/bold]")

    if not result.passed:
        console.print(f"[yellow]ERROR[/yellow] {result.error}")
    elif findings:
        console.print(
            "[yellow]WARNING[/yellow] "
            "One or more defense-in-depth controls need attention."
        )
    else:
        console.print("[green]PASS[/green] Selected security headers are present.")

    console.print(f"Final URL: [cyan]{result.final_url}[/cyan]")
    console.print(f"Status: {_display_value(result.status_code)}")
    console.print(f"Redirects: {result.redirect_count}")

    for observation in result.headers:
        state = (
            "[green]PRESENT[/green]"
            if observation.present
            else "[yellow]MISSING[/yellow]"
        )
        console.print(f"{state} {observation.name}")

    _render_findings(findings)


def _render_findings(findings: list[Finding]) -> None:
    for finding in findings:
        console.print(
            f"Finding: [yellow]{finding.id}[/yellow] "
            f"({finding.severity.value}) - {finding.title}"
        )


def _render_caa_result(
    result: CAACheckResult,
    findings: list[Finding],
) -> None:
    console.print("\n[bold]DNS CAA records[/bold]")

    if result.status is CAACheckStatus.NOT_APPLICABLE:
        console.print("[yellow]WARNING[/yellow] CAA is not applicable to this target.")
    elif not result.completed:
        error = result.error or "CAA check did not produce a complete conclusion."
        console.print(f"[yellow]ERROR[/yellow] {escape(error)}")
    elif findings:
        console.print("[yellow]WARNING[/yellow] CAA policy needs attention.")
    else:
        console.print("[green]PASS[/green] Effective CAA policy was observed.")

    console.print(f"Hostname: [cyan]{result.hostname}[/cyan]")
    console.print(f"Queries: {len(result.queried_names)}")
    console.print(f"Effective name: {_display_value(result.effective_name)}")
    console.print(f"CAA records: {len(result.records)}")

    for record in result.records[:MAX_CONSOLE_CAA_RECORDS]:
        console.print(
            "CAA: "
            f"flags={record.flags} "
            f"tag={escape(record.tag)} "
            f"value={escape(_short_dns_value(record.value))}"
        )

    remaining_records = len(result.records) - MAX_CONSOLE_CAA_RECORDS

    if remaining_records > 0:
        console.print(f"CAA: {remaining_records} additional record(s) not displayed.")

    _render_findings(findings)


def _render_email_dns_result(
    result: EmailDNSCheckResult,
    findings: list[Finding],
) -> None:
    console.print("\n[bold]DNS email authentication[/bold]")

    if result.status is EmailDNSStatus.NOT_APPLICABLE:
        console.print(
            "[yellow]WARNING[/yellow] Email DNS checks are not applicable "
            "to this target."
        )
    elif not result.completed:
        console.print(
            "[yellow]ERROR[/yellow] One or more email DNS conclusions are incomplete."
        )
    elif findings:
        console.print(
            "[yellow]WARNING[/yellow] Email authentication posture needs attention."
        )
    else:
        console.print("[green]PASS[/green] SPF and DMARC observations completed.")

    console.print(f"Hostname: [cyan]{result.hostname}[/cyan]")
    _render_email_query("SPF", result.spf_query, len(result.spf_records))
    _render_email_query("DMARC", result.dmarc_query, len(result.dmarc_records))
    console.print(f"DMARC policy: {_display_value(result.dmarc_policy)}")
    _render_findings(findings)


def _render_email_query(
    label: str,
    query: DNSQueryResult | None,
    matching_records: int,
) -> None:
    if query is None:
        console.print(f"{label} query: N/A")
        console.print(f"{label} records: 0")
        return

    console.print(
        f"{label} query: [cyan]{query.query_name}[/cyan] ({query.status.value})"
    )
    console.print(f"{label} records: {matching_records}")

    if query.error is not None:
        console.print(f"{label} error: {escape(query.error)}")


def _render_scan_summary(
    recorded_checks: int,
    completed_checks: int,
    findings: list[Finding],
) -> None:
    severity_counts = {
        severity: sum(finding.severity is severity for finding in findings)
        for severity in Severity
    }

    console.print("\n[bold]Scan summary[/bold]")
    console.print(f"Checks recorded: {recorded_checks}")
    console.print(f"Checks completed: {completed_checks}/{recorded_checks}")
    console.print(f"Findings: {len(findings)}")
    console.print(
        "Severity: "
        f"critical {severity_counts[Severity.CRITICAL]}, "
        f"high {severity_counts[Severity.HIGH]}, "
        f"medium {severity_counts[Severity.MEDIUM]}, "
        f"low {severity_counts[Severity.LOW]}, "
        f"info {severity_counts[Severity.INFO]}"
    )


def _display_value(value: object | None) -> str:
    return "N/A" if value is None else str(value)


def _short_dns_value(value: str) -> str:
    if len(value) <= MAX_CONSOLE_DNS_VALUE_LENGTH:
        return value

    return f"{value[:MAX_CONSOLE_DNS_VALUE_LENGTH]}..."


if __name__ == "__main__":
    app()
