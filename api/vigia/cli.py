"""Vigía command-line interface."""

import asyncio

import typer

app = typer.Typer(help="Vigía — External Attack Surface Management OSINT agent.")


@app.command()
def version() -> None:
    """Print the installed Vigía version."""
    from vigia import __version__

    typer.echo(__version__)


@app.command()
def scan(
    domain: str = typer.Argument(..., help="Target domain — must be your own or authorized."),
    passive: bool = typer.Option(
        True, "--passive/--no-passive", help="Only the --passive pipeline exists so far."
    ),
) -> None:
    """Run the deterministic passive-tool pipeline against DOMAIN (no LLM)."""
    if not passive:
        typer.echo("Only --passive is implemented (active mode lands in Phase 7).", err=True)
        raise typer.Exit(code=1)

    asyncio.run(_run_scan(domain))


async def _run_scan(domain: str) -> None:
    from vigia.config import get_settings
    from vigia.db.session import session_scope
    from vigia.pipeline import run_passive_scan

    settings = get_settings()
    async with session_scope() as session:
        summary = await run_passive_scan(session, domain, settings)

    typer.echo(f"\nScan {summary.scan_id} for {summary.domain}: {summary.status}", err=True)
    typer.echo(f"  assets: {summary.assets_count}  findings: {summary.findings_count}", err=True)
    for tool, status in sorted(summary.tool_statuses.items()):
        typer.echo(f"  {tool}: {status}", err=True)


if __name__ == "__main__":
    app()
