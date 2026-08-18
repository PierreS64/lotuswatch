from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from lotuswatch import __version__
from lotuswatch.checks import (
    RedirectStatus,
    check_http_to_https_redirect,
    redirect_result_to_finding,
)
from lotuswatch.exceptions import ReportError, TargetValidationError
from lotuswatch.models import ScanReport
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
    console.print("\n[bold]HTTP to HTTPS redirect[/bold]")

    result = check_http_to_https_redirect(normalized_target)
    finding = redirect_result_to_finding(result)

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
    console.print(f"Initial status: {result.initial_status_code or 'N/A'}")
    console.print(f"Final status: {result.final_status_code or 'N/A'}")

    if finding is not None:
        console.print(f"Finding: [yellow]{finding.id}[/yellow] - {finding.title}")

    if output_format is OutputFormat.JSON:
        assert output is not None

        check_data = result.model_dump(mode="json")
        check_data["name"] = "http_to_https_redirect"

        findings = [finding] if finding is not None else []
        report = ScanReport.create(
            lotuswatch_version=__version__,
            original_target=normalized_target.original,
            normalized_url=normalized_target.url,
            checks=[check_data],
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


if __name__ == "__main__":
    app()
