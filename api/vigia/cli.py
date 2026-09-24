"""Vigía command-line interface. `vigia scan --passive <domain>` lands in Phase 2."""

import typer

app = typer.Typer(help="Vigía — External Attack Surface Management OSINT agent.")


@app.command()
def version() -> None:
    """Print the installed Vigía version."""
    from vigia import __version__

    typer.echo(__version__)


if __name__ == "__main__":
    app()
