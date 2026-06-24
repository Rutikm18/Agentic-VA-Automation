import logging
from contextlib import asynccontextmanager

import os

import structlog
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.auth.middleware import TenantIsolationMiddleware
from app.auth.router import router as auth_router
from app.config import get_settings
from app.dependencies import close_redis
from app.routers.ad import router as ad_router
from app.routers.agents import router as agents_router
from app.routers.ai_report import router as ai_report_router
from app.routers.attack_paths import router as attack_paths_router
from app.routers.detection import router as detection_router
from app.routers.engagements import router as eng_router
from app.routers.exploits import router as exploits_router
from app.routers.findings import router as findings_router
from app.routers.health import router as health_router
from app.routers.vuln_scans import router as vuln_router

settings = get_settings()

# ── Structlog configuration ───────────────────────────────────────────────────

shared_processors = [
    structlog.contextvars.merge_contextvars,
    structlog.processors.add_log_level,
    structlog.processors.TimeStamper(fmt="iso"),
    structlog.processors.StackInfoRenderer(),
]

if settings.is_production:
    structlog.configure(
        processors=[*shared_processors, structlog.processors.JSONRenderer()],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        logger_factory=structlog.PrintLoggerFactory(),
    )
else:
    structlog.configure(
        processors=[*shared_processors, structlog.dev.ConsoleRenderer()],
        wrapper_class=structlog.make_filtering_bound_logger(logging.DEBUG),
        logger_factory=structlog.PrintLoggerFactory(),
    )

logger = structlog.get_logger()


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("adversa_api.startup", env=settings.app_env)
    yield
    logger.info("adversa_api.shutdown")
    await close_redis()


# ── App factory ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="ADVERSA VAPT Platform API",
    description=(
        "Backend for the ADVERSA automated Network VAPT platform. "
        "Handles multi-tenant engagements, asset management, finding triage, "
        "attack path analysis, and detection coverage."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# ── Middleware (order matters: outermost first) ───────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(TenantIsolationMiddleware)


# ── Global exception handlers ─────────────────────────────────────────────────

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.error("unhandled_exception", path=request.url.path, exc=str(exc), exc_info=exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )


# ── Routers ───────────────────────────────────────────────────────────────────

app.include_router(health_router)
app.include_router(auth_router)
app.include_router(eng_router)
app.include_router(findings_router)
app.include_router(agents_router)
app.include_router(vuln_router)
app.include_router(exploits_router)
app.include_router(ad_router)
app.include_router(attack_paths_router)
app.include_router(detection_router)
app.include_router(ai_report_router)


# ── Operator dashboard (static, served same-origin so no CORS / token wiring) ──

_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(_STATIC_DIR):
    app.mount("/dashboard", StaticFiles(directory=_STATIC_DIR, html=True), name="dashboard")


@app.get("/", include_in_schema=False)
async def _root_redirect():
    return RedirectResponse(url="/dashboard/")
