import pytest

import vigia.tools.subfinder_enum as subfinder_module
from vigia.tools.subfinder_enum import SubfinderEnumInput, run


async def test_subfinder_enum_parses_json_lines(monkeypatch: pytest.MonkeyPatch) -> None:
    stdout = (
        b'{"host":"www.example.com","input":"example.com","source":"crtsh"}\n'
        b'{"host":"example.com","input":"example.com","source":"crtsh"}\n'
    )

    async def fake_run_subprocess(
        *args: str, timeout_seconds: float = 60.0
    ) -> tuple[int, bytes, bytes]:
        return 0, stdout, b""

    monkeypatch.setattr(subfinder_module, "run_subprocess", fake_run_subprocess)

    result = await run(SubfinderEnumInput(domain="example.com"))

    assert [a.value for a in result.assets_discovered] == ["www.example.com"]
    assert result.error is None


async def test_subfinder_enum_missing_binary_is_graceful(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_run_subprocess(
        *args: str, timeout_seconds: float = 60.0
    ) -> tuple[int, bytes, bytes]:
        raise FileNotFoundError()

    monkeypatch.setattr(subfinder_module, "run_subprocess", fake_run_subprocess)

    result = await run(SubfinderEnumInput(domain="example.com"))

    assert result.error == "subfinder binary not found on PATH"
