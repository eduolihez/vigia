"""screenshot tests — run against a real local HTTP server (127.0.0.1, ephemeral
port), the same "real bytes, local target" philosophy as the PDF exporter's own
real-Chromium test. `input._base_url` is a test-only override (not part of the
tool's LLM-facing schema — see `screenshot.py`) that points the tool at that local
server instead of `https://{hostname}`.
"""

from __future__ import annotations

import http.server
import threading
from collections.abc import Iterator

import pytest

from vigia.tools.screenshot import ScreenshotInput, run


class _Handler(http.server.BaseHTTPRequestHandler):
    title = "OK"

    def do_GET(self) -> None:  # noqa: N802 — stdlib API name
        body = f"<html><head><title>{self.title}</title></head><body>hi</body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # silence stdout
        pass


def _make_handler(title: str) -> type[_Handler]:
    return type("_TitledHandler", (_Handler,), {"title": title})


@pytest.fixture
def local_server() -> Iterator[str]:
    def _start(title: str) -> tuple[http.server.ThreadingHTTPServer, str]:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(title))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        return server, f"http://127.0.0.1:{port}"

    servers: list[http.server.ThreadingHTTPServer] = []

    def factory(title: str = "OK") -> str:
        server, base_url = _start(title)
        servers.append(server)
        return base_url

    yield factory  # type: ignore[misc]
    for server in servers:
        server.shutdown()


async def test_run_captures_a_real_png_screenshot(local_server: object) -> None:
    base_url = local_server("Plain Page")  # type: ignore[operator]
    input = ScreenshotInput(hostname="screenshot.example.test")
    input._base_url = base_url

    result = await run(input)

    assert result.error is None
    assert result.raw_output.startswith(b"\x89PNG\r\n\x1a\n")
    assert len(result.raw_output) > 100
    assert result.findings_candidates == []


async def test_run_flags_exposed_admin_panel_title(local_server: object) -> None:
    base_url = local_server("Jenkins")  # type: ignore[operator]
    input = ScreenshotInput(hostname="ci.example.test")
    input._base_url = base_url

    result = await run(input)

    assert result.error is None
    types = {f.type for f in result.findings_candidates}
    assert "exposed_admin_panel" in types


async def test_run_reports_error_for_unreachable_host() -> None:
    input = ScreenshotInput(hostname="unreachable.example.test")
    input._base_url = "http://127.0.0.1:1"

    result = await run(input)

    assert result.error is not None
