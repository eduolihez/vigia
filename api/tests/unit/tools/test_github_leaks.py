import httpx
import respx

from vigia.tools.github_leaks import GithubLeaksInput, run


async def test_github_leaks_without_token_is_graceful() -> None:
    async with httpx.AsyncClient() as client:
        result = await run(GithubLeaksInput(domain="example.com"), client, token=None)

    assert result.error == "GitHub token not configured"


@respx.mock
async def test_github_leaks_parses_matches() -> None:
    respx.get("https://api.github.com/search/code").respond(
        json={
            "items": [
                {
                    "path": "config/settings.py",
                    "html_url": "https://github.com/acme/app/blob/main/config/settings.py",
                    "repository": {"full_name": "acme/app"},
                }
            ]
        }
    )

    async with httpx.AsyncClient() as client:
        result = await run(GithubLeaksInput(domain="example.com"), client, token="ghp_fake")

    assert len(result.findings_candidates) == 1
    assert "acme/app" in result.findings_candidates[0].title
