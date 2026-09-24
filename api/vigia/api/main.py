"""FastAPI application entrypoint."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from vigia import __version__
from vigia.api.deps import SessionDep
from vigia.api.ethics import router as ethics_router
from vigia.api.scans import router as scans_router
from vigia.config import get_settings

app = FastAPI(title="Vigía API", version=__version__)
app.include_router(scans_router)
app.include_router(ethics_router)

_settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=_settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health(session: SessionDep) -> dict[str, str]:
    try:
        await session.execute(text("SELECT 1"))
        db_status = "ok"
    except Exception:
        db_status = "error"
    return {"status": "ok", "db": db_status}
