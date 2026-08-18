from enum import StrEnum
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

import typer
from rich.console import Console

from lotuswatch import __version__
from lotuswatch.checks import (
    RedirectCheckResult,
    RedirectStatus,
    SecurityHeaderCheckResult,
    SecurityHeaderStatus,
    TLSCheckResult,
    TLSStatus,
    check_http_to_https_redirect,
    check_security_headers,
    check_tls_certificate,
    redirect_result_to_finding,
    security_header_result_to_findings,
    tls_result_to_findings,
)
from lotuswatch.exceptions import ReportError, TargetValidationError
from lotuswatch.models import Finding, ScanReport, Severity
from lotuswatch.reporters import write_json_report
from lotuswatch.target import normalize_target


class OutputFormat(StrEnum):
    """Output formats supported by the scan command."""

    CONSOLE = "console"
    JSON = "json"


app = typer.Typer(
    name="lotuswatch",
    help="Monitor websites and identify security configuration risks.",
    no_args_is_help=True,
)

console = Console()


@app.callback()
def main() -> None:
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

    redirect_result = check_http_to_https_redirect(normalized_target)
    redirect_finding = redirect_result_to_finding(redirect_result)
    redirect_findings = (
        [redirect_finding] if redirect_finding is not None else []
    )
    _render_redirect_result(redirect_result, redirect_findings)

    tls_result = check_tls_certificate(normalized_target)
    tls_findings = tls_result_to_findings(tls_result)
    _render_tls_result(tls_result, tls_findings)

    header_endpoint = _redirect_https_endpoint(redirect_result)
    header_result = check_security_headers(
        normalized_target,
        endpoint_url=header_endpoint,
    )
    header_findings = security_header_result_to_findings(header_result)
    _render_header_result(header_result, header_findings)

    findings = redirect_findings + tls_findings + header_findings
    completed_checks = _completed_check_count(
        redirect_result,
        tls_result,
        header_result,
    )
    _render_scan_summary(completed_checks, findings)

    checks = [
        _named_check_data("http_to_https_redirect", redirect_result),
        _named_check_data("tls_certificate", tls_result),
        _named_check_data("http_security_headers", header_result),
    ]

    if output_format is OutputFormat.JSON:
        assert output is not None

        report = ScanReport.create(
            lotuswatch_version=__version__,
            original_target=normalized_target.original,
            normalized_url=normalized_target.url,
            checks=checks,
            findings=findings,
        )

        try:
            report_path = write_json_report(report, output)
        except ReportError as exc:
            raise typer.BadParameter(
                str(exc),
                param_hint="--output",
            ) from exc

        console.print(f"\n[green]Report written:[/green] {report_path}")


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
        state = "[green]PRESENT[/green]" if observation.present else "[yellow]MISSING[/yellow]"
        console.print(f"{state} {observation.name}")

    _render_findings(findings)


def _render_findings(findings: list[Finding]) -> None:
    for finding in findings:
        console.print(
            f"Finding: [yellow]{finding.id}[/yellow] "
            f"({finding.severity.value}) - {finding.title}"
        )


def _render_scan_summary(
    completed_checks: int,
    findings: list[Finding],
) -> None:
    severity_counts = {
        severity: sum(finding.severity is severity for finding in findings)
        for severity in Severity
    }

    console.print("\n[bold]Scan summary[/bold]")
    console.print("Checks recorded: 3")
    console.print(f"Checks completed: {completed_checks}/3")
    console.print(f"Findings: {len(findings)}")
    console.print(
        "Severity: "
        f"critical {severity_counts[Severity.CRITICAL]}, "
        f"high {severity_counts[Severity.HIGH]}, "
        f"medium {severity_counts[Severity.MEDIUM]}, "
        f"low {severity_counts[Severity.LOW]}, "
        f"info {severity_counts[Severity.INFO]}"
    )


def _completed_check_count(
    redirect_result: RedirectCheckResult,
    tls_result: TLSCheckResult,
    header_result: SecurityHeaderCheckResult,
) -> int:
    redirect_completed = redirect_result.status not in {
        RedirectStatus.TIMEOUT,
        RedirectStatus.CONNECTION_ERROR,
    }
    tls_completed = tls_result.status in {
        TLSStatus.PASSED,
        TLSStatus.VERIFICATION_ERROR,
    }
    headers_completed = header_result.status is SecurityHeaderStatus.COMPLETED

    return sum((redirect_completed, tls_completed, headers_completed))


def _redirect_https_endpoint(result: RedirectCheckResult) -> str | None:
    if urlsplit(result.final_url).scheme.casefold() == "https":
        return result.final_url

    return None


def _named_check_data(name: str, result) -> dict:
    data = result.model_dump(mode="json")
    data["name"] = name
    return data


def _display_value(value: object | None) -> str:
    return "N/A" if value is None else str(value)


if __name__ == "__main__":
    app()
