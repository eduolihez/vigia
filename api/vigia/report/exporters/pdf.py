"""PDF export via a headless Chromium (Playwright), rendering the same Markdown the
`.md` exporter produces.

Verified live 2026-09-24: `playwright`'s sync API renders HTML to a real PDF file
locally without any extra native dependencies — WeasyPrint (the brief's other
option) needs GTK/Pango/Cairo system libraries that aren't available on every dev
machine (confirmed failing here); Playwright bundles its own Chromium instead. See
ADR-016 in docs/decisions.md.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from markdown_it import MarkdownIt
from playwright.async_api import async_playwright

_CSS = """
body { font-family: -apple-system, Helvetica, Arial, sans-serif; color: #1a1a1a;
       max-width: 800px; margin: 2rem auto; line-height: 1.5; }
h1 { color: #0a0e14; border-bottom: 3px solid #16a34a; padding-bottom: 0.3rem; }
h2 { color: #0a0e14; margin-top: 2rem; border-bottom: 1px solid #ddd; }
h3 { color: #16a34a; }
code { background: #f0f0f0; padding: 0.1rem 0.3rem; border-radius: 3px; }
"""


def _markdown_to_html(markdown_text: str) -> str:
    body = MarkdownIt().render(markdown_text)
    return (
        f"<!doctype html><html><head><meta charset='utf-8'><style>{_CSS}</style>"
        f"</head><body>{body}</body></html>"
    )


async def markdown_to_pdf_bytes(markdown_text: str) -> bytes:
    html = _markdown_to_html(markdown_text)
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        try:
            page = await browser.new_page()
            await page.set_content(html)
            return await page.pdf(format="A4", margin={"top": "1cm", "bottom": "1cm"})
        finally:
            await browser.close()


def markdown_to_pdf_file(markdown_text: str, output_path: Path) -> None:
    pdf_bytes = asyncio.run(markdown_to_pdf_bytes(markdown_text))
    output_path.write_bytes(pdf_bytes)
