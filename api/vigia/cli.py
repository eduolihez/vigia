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
def ethics(
    accept: bool = typer.Option(False, "--accept", help="Accept the ethical-use notice."),
) -> None:
    """Show (or accept) the ethical-use notice required before any scan can run."""
    from vigia.ethics import ETHICS_NOTICE

    asyncio.run(_run_ethics(accept))
    if not accept:
        typer.echo(ETHICS_NOTICE)
        typer.echo("\nRun `vigia ethics --accept` to accept it.")


async def _run_ethics(do_accept: bool) -> None:
    from vigia.db.session import session_scope
    from vigia.ethics import accept as accept_notice
    from vigia.ethics import is_accepted

    async with session_scope() as session:
        if do_accept:
            await accept_notice(session)
            typer.echo("Ethical-use notice accepted.", err=True)
        else:
            accepted = await is_accepted(session)
            typer.echo(f"Accepted: {accepted}", err=True)


@app.command()
def scan(
    domain: str = typer.Argument(..., help="Target domain — must be your own or authorized."),
    agent: bool = typer.Option(
        False, "--agent", help="Use the LLM-driven agent instead of the deterministic pipeline."
    ),
    model: str = typer.Option(
        None, "--model", help="Override the planner model for this scan (agent mode only)."
    ),
) -> None:
    """Run a passive scan against DOMAIN.

    By default this runs the deterministic pipeline (Phase 2, no LLM). Pass --agent
    to instead let the LLM planner (Phase 3) decide the sequence of tool calls.
    Active mode isn't implemented yet (Phase 7).
    """
    if agent:
        asyncio.run(_run_agent_scan(domain, model))
    else:
        asyncio.run(_run_pipeline_scan(domain))


async def _run_pipeline_scan(domain: str) -> None:
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


async def _run_agent_scan(domain: str, model_override: str | None) -> None:
    from vigia.agent.orchestrator import run_agent_scan
    from vigia.config import get_settings
    from vigia.db.session import session_scope
    from vigia.ethics import EthicsNoticeNotAccepted

    settings = get_settings()
    try:
        async with session_scope() as session:
            async for event in run_agent_scan(
                session, domain, settings, model_override=model_override
            ):
                typer.echo(f"[{event.type.value}] {event.data}", err=True)
    except EthicsNoticeNotAccepted as exc:
        typer.echo(str(exc), err=True)
        typer.echo("Run `vigia ethics --accept` first.", err=True)
        raise typer.Exit(code=1) from exc


if __name__ == "__main__":
    app()
