"""screenshot — full-page PNG of a hostname via headless Chromium (Phase 7).

Uses Playwright, already a dependency for the Phase 4 PDF report exporter
(`report/exporters/pdf.py`) — no new browser automation dependency added. The PNG
itself becomes the tool's evidence (`Evidence.raw_output`); a page title matching a
short list of common exposed-admin-panel product names is reported as a finding, so
a human reviewing the report knows to look at the screenshot.

Active mode only — this renders the real page from the target host, including
executing its JavaScript.
"""

from __future__ import annotations

import time

from playwright.async_api import async_playwright
from pydantic import BaseModel

from vigia.tools.base import FindingCandidate, ToolMode, ToolResult, ToolSpec, finalize

SPEC = ToolSpec(
    name="screenshot",
    mode=ToolMode.ACTIVE,
    requires_api_key=False,
    description="Takes a full-page screenshot of a hostname via headless Chromium.",
)

NAVIGATION_TIMEOUT_MS = 15_000
ADMIN_PANEL_TITLE_KEYWORDS = (
    "phpmyadmin",
    "jenkins",
    "kibana",
    "grafana",
    "swagger ui",
    "pgadmin",
    "adminer",
    "rabbitmq management",
)


class ScreenshotInput(BaseModel):
    hostname: str
    path: str = "/"
    _base_url: str | None = None  # test-only override; never set by the planner


async def run(input: ScreenshotInput) -> ToolResult:
    start = time.monotonic()
    base = input._base_url or f"https://{input.hostname}"
    url = f"{base}{input.path}"

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            try:
                page = await browser.new_page(viewport={"width": 1280, "height": 800})
                try:
                    response = await page.goto(
                        url, timeout=NAVIGATION_TIMEOUT_MS, wait_until="networkidle"
                    )
                except Exception:
                    if input._base_url or not url.startswith("https://"):
                        raise
                    # Some hosts only serve plain HTTP — same fallback as http_probe.
                    url = f"http://{input.hostname}{input.path}"
                    response = await page.goto(
                        url, timeout=NAVIGATION_TIMEOUT_MS, wait_until="networkidle"
                    )
                title = await page.title()
                final_url = page.url
                png_bytes = await page.screenshot(full_page=True)
            finally:
                await browser.close()
    except Exception as exc:  # navigation failures are expected/common, not a crash
        return finalize(SPEC.name, start, error=f"screenshot: could not render {url}: {exc}")

    findings: list[FindingCandidate] = []
    title_lower = title.lower()
    for keyword in ADMIN_PANEL_TITLE_KEYWORDS:
        if keyword in title_lower:
            findings.append(
                FindingCandidate(
                    type="exposed_admin_panel",
                    title=f"Possible exposed admin panel at {input.hostname}: {title}",
                    detail=(
                        f"Page title {title!r} at {final_url} matches a known "
                        "admin-tool product name."
                    ),
                    asset_value=input.hostname,
                )
            )
            break

    return finalize(
        SPEC.name,
        start,
        raw_output=png_bytes,
        findings=findings,
        error=None if response is not None else "screenshot: no response received",
    )
