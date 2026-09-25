"""Settings endpoints (Phase 6): runtime model/budget overrides and encrypted API
key management, none of which touches the network or Ollama.
"""

from __future__ import annotations

from httpx import ASGITransport, AsyncClient

from vigia.api.main import app


async def test_read_settings_returns_defaults() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/settings")

    assert response.status_code == 200
    body = response.json()
    assert "planner_model" in body
    assert "extractor_model" in body
    assert body["configured_api_keys"] == {
        "censys_api_id": False,
        "censys_api_secret": False,
        "github_token": False,
        "hibp_api_key": False,
    }


async def test_update_settings_overrides_model_choice() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.put("/settings", json={"planner_model": "custom-model:1b"})
        assert response.status_code == 200
        assert response.json()["planner_model"] == "custom-model:1b"

        # Clearing with an empty string reverts to the env/default value.
        cleared = await client.put("/settings", json={"planner_model": ""})
        assert cleared.status_code == 200
        assert cleared.json()["planner_model"] != "custom-model:1b"


async def test_update_settings_stores_api_key_and_never_echoes_it_back() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.put(
            "/settings", json={"api_keys": {"github_token": "ghp_secret123"}}
        )
        assert response.status_code == 200
        body = response.json()
        assert body["configured_api_keys"]["github_token"] is True
        assert "ghp_secret123" not in response.text

        cleared = await client.put("/settings", json={"api_keys": {"github_token": ""}})
        assert cleared.json()["configured_api_keys"]["github_token"] is False


async def test_update_settings_ignores_unknown_api_key_source() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.put("/settings", json={"api_keys": {"not_a_real_source": "x"}})
    assert response.status_code == 200
