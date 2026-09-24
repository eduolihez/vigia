import json

import pytest

import vigia.tools.typosquat as typosquat_module
from vigia.tools.typosquat import TyposquatInput, run


async def test_typosquat_reports_registered_permutations(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = json.dumps(
        [
            {"domain": "examp1e.com", "fuzzer": "homoglyph", "dns_a": ["1.2.3.4"]},
            {"domain": "example.com", "fuzzer": "original", "dns_a": ["93.184.216.34"]},
        ]
    ).encode()

    async def fake_run_subprocess(
        *args: str, timeout_seconds: float = 60.0
    ) -> tuple[int, bytes, bytes]:
        return 0, payload, b""

    monkeypatch.setattr(typosquat_module, "run_subprocess", fake_run_subprocess)

    result = await run(TyposquatInput(domain="example.com"))

    assert len(result.findings_candidates) == 1
    assert "examp1e.com" in result.findings_candidates[0].title
    assert result.error is None


async def test_typosquat_missing_binary_is_graceful(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_run_subprocess(
        *args: str, timeout_seconds: float = 60.0
    ) -> tuple[int, bytes, bytes]:
        raise FileNotFoundError()

    monkeypatch.setattr(typosquat_module, "run_subprocess", fake_run_subprocess)

    result = await run(TyposquatInput(domain="example.com"))

    assert result.error == "dnstwist binary not found on PATH"
