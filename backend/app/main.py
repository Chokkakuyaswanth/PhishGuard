import sys
from contextlib import asynccontextmanager
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.db.database import init_db
from app.routers import health, scan, history, export
from app.services.ml_service import MLService
from cti.http_client import aclose as close_cti_client, warmup as warm_cti_client


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    # Load eagerly: a lazy first predict costs ~2.8 s, which the extension
    # would pay on the user's first navigation after every restart.
    MLService.load()
    await warm_cti_client()
    yield
    await close_cti_client()


app = FastAPI(
    title="PhishGuard API",
    description="ML-powered phishing URL detection with CTI enrichment",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/api", tags=["health"])
app.include_router(scan.router, prefix="/api", tags=["scan"])
app.include_router(history.router, prefix="/api", tags=["history"])
app.include_router(export.router, prefix="/api", tags=["export"])
