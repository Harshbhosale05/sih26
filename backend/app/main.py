import logging
import shutil
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api import (
    captures_router,
    findings_router,
    intel_router,
    overview_router,
    posture_router,
    sessions_router,
)
from app.config import get_settings
from app.db import init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    settings = get_settings()
    logger.info("SecureMailScope API %s", __version__)
    logger.info("data dir: %s", settings.data_dir)
    for tool in ("tshark", "capinfos", "editcap"):
        logger.info("  %-9s %s", tool, shutil.which(tool) or "MISSING")
    yield


app = FastAPI(
    title="SecureMailScope",
    description=(
        "Passive cryptographic posture and behavioural intelligence for "
        "enterprise email infrastructure (SIH26159)."
    ),
    version=__version__,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(captures_router)
app.include_router(sessions_router)
app.include_router(findings_router)
app.include_router(overview_router)
app.include_router(posture_router)
app.include_router(intel_router)


@app.get("/api/health", tags=["system"])
def health() -> dict:
    """Liveness plus the tool inventory analysis depends on."""
    tools = {name: shutil.which(name) for name in ("tshark", "capinfos", "editcap")}
    return {
        "status": "ok" if all(tools.values()) else "degraded",
        "version": __version__,
        "tools": {k: bool(v) for k, v in tools.items()},
    }


# Dashboard. Mounted last so it never shadows an /api route.
_STATIC = Path(__file__).parent / "static"
if _STATIC.is_dir():
    app.mount("/", StaticFiles(directory=str(_STATIC), html=True), name="dashboard")
