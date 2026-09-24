from __future__ import annotations

from httpx import ASGITransport, AsyncClient

from vigia.api.main import app


async def test_ethics_status_and_accept_round_trip() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        accept_response = await client.post("/ethics/accept")
        status_response = await client.get("/ethics")

    assert accept_response.status_code == 200
    assert accept_response.json()["accepted"] is True
    assert "authorized" in accept_response.json()["notice"].lower()

    assert status_response.status_code == 200
    assert status_response.json()["accepted"] is True
