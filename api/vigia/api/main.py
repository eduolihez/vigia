"""FastAPI application entrypoint."""

from fastapi import FastAPI
from sqlalchemy import text

from vigia import __version__
from vigia.api.deps import SessionDep
from vigia.api.scans import router as scans_router

app = FastAPI(title="Vigía API", version=__version__)
app.include_router(scans_router)


@app.get("/health")
async def health(session: SessionDep) -> dict[str, str]:
    try:
        await session.execute(text("SELECT 1"))
        db_status = "ok"
    except Exception:
        db_status = "error"
    return {"status": "ok", "db": db_status}
