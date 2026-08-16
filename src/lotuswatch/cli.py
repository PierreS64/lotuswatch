from typing import Annotated

import typer
from rich.console import Console

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

    console.print("[bold green]LotusWatch[/bold green] is preparing to scan:")
    console.print(f"Target: [cyan]{target}[/cyan]")
    console.print("[yellow]Scanner checks will be implemented next.[/yellow]")


if __name__ == "__main__":
    app()
