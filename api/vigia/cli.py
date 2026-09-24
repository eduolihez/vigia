"""Vigía command-line interface."""

import asyncio
from pathlib import Path

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
    model: str | None = typer.Option(
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


@app.command()
def score(scan_id: str = typer.Argument(..., help="Scan id to (re)score.")) -> None:
    """Run the Risk Engine over a completed scan's findings, in place."""
    asyncio.run(_run_score(scan_id))


async def _run_score(scan_id: str) -> None:
    import httpx

    from vigia.db.session import session_scope
    from vigia.risk.engine import score_scan_findings

    async with session_scope() as session, httpx.AsyncClient() as client:
        count = await score_scan_findings(session, scan_id, client)

    typer.echo(f"Re-scored {count} finding(s) for scan {scan_id}.", err=True)


@app.command()
def report(
    scan_id: str = typer.Argument(..., help="Scan id to generate a report for."),
    format: str = typer.Option("md", "--format", help="Output format: md, json, or pdf."),
    out: Path | None = typer.Option(  # noqa: B008 — standard typer pattern
        None, "--out", help="Output file path (default: stdout)."
    ),
    model: str | None = typer.Option(
        None, "--model", help="Override the planner model for this report."
    ),
) -> None:
    """Generate a report for SCAN_ID: draft it with the planner, validate it against
    the scan's own evidence (no invented entities), and export it."""
    if format not in ("md", "json", "pdf"):
        typer.echo(f"Unknown format {format!r}; use md, json, or pdf.", err=True)
        raise typer.Exit(code=1)
    asyncio.run(_run_report(scan_id, format, out, model))


async def _run_report(scan_id: str, fmt: str, out: Path | None, model_override: str | None) -> None:
    from sqlalchemy import select
    from sqlmodel import col

    from vigia.agent.llm_client import OllamaStructuredGenerator
    from vigia.config import get_settings
    from vigia.db.models import Finding, Scan
    from vigia.db.session import session_scope
    from vigia.report.exporters.json_export import to_json_dict
    from vigia.report.exporters.markdown import to_markdown
    from vigia.report.exporters.pdf import markdown_to_pdf_bytes
    from vigia.report.writer import generate_report

    settings = get_settings()
    model = model_override or settings.planner_model

    async with session_scope() as session:
        scan = await session.get(Scan, scan_id)
        if scan is None:
            typer.echo(f"No scan found with id {scan_id!r}.", err=True)
            raise typer.Exit(code=1)

        generator = OllamaStructuredGenerator(host=settings.ollama_host, model=model)
        result = await generate_report(session, scan, generator)

        findings = (
            (await session.execute(select(Finding).where(col(Finding.scan_id) == scan_id)))
            .scalars()
            .all()
        )

        if result.dropped_items:
            typer.echo(
                f"Warning: {len(result.dropped_items)} item(s) dropped during validation "
                f"(unverifiable entities): {result.dropped_items}",
                err=True,
            )

        if fmt == "json":
            import json

            content: str | bytes = json.dumps(to_json_dict(scan, result, list(findings)), indent=2)
        elif fmt == "pdf":
            markdown_text = to_markdown(scan, result, list(findings))
            content = await markdown_to_pdf_bytes(markdown_text)
        else:
            content = to_markdown(scan, result, list(findings))

    if out:
        if isinstance(content, bytes):
            await asyncio.to_thread(out.write_bytes, content)
        else:
            await asyncio.to_thread(out.write_text, content, encoding="utf-8")
        typer.echo(f"Wrote report to {out}", err=True)
    elif isinstance(content, bytes):
        typer.echo("PDF output requires --out <path>.", err=True)
        raise typer.Exit(code=1)
    else:
        typer.echo(content)


if __name__ == "__main__":
    app()
