from typing import Annotated

import typer
from rich.console import Console

from lotuswatch.checks import (
    RedirectStatus,
    check_http_to_https_redirect,
    redirect_result_to_finding,
)
from lotuswatch.exceptions import TargetValidationError
from lotuswatch.target import normalize_target

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
) -> None:
    """Inspect the security configuration of a website."""

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
        console.print(f"Finding: [yellow]{finding.id}[/yellow] — {finding.title}")


if __name__ == "__main__":
    app()
