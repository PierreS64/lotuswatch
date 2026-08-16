from typing import Annotated

import typer
from rich.console import Console

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
    console.print("[yellow]Scanner checks will be implemented next.[/yellow]")


if __name__ == "__main__":
    app()
