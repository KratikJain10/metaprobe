"""
FastAPI application factory with lifespan management.

Handles:
- MongoDB connection lifecycle (connect on startup, close on shutdown)
- Redis cache lifecycle
- Background task manager initialisation and cleanup
- Middleware stack (CORS, correlation ID, timing, rate limiting)
- Global exception handling
- Router registration
"""

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.cache import RedisCache
from app.config import settings
from app.database import close_mongodb_connection, connect_to_mongodb
from app.metrics import setup_metrics
from app.middleware import CorrelationIdMiddleware, TimingMiddleware
from app.repositories.metadata_repo import MetadataRepository
from app.routes.metadata import router as metadata_router
from app.services.background import BackgroundTaskManager

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Rate limiter
limiter = Limiter(key_func=get_remote_address, default_limits=[settings.RATE_LIMIT])


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler.

    Startup:
      1. Connect to MongoDB (with retry logic for Docker startup delays).
      2. Connect to Redis (graceful degradation if unavailable).
      3. Initialise the repository and background task manager.
      4. Store dependencies in app.state for DI access.

    Shutdown:
      1. Cancel all in-flight background tasks.
      2. Close Redis connection.
      3. Close the MongoDB connection.
    """
    # ── Startup ─────────────────────────────────────────────────────────
    logger.info("Starting Metaprobe Service v%s...", settings.APP_VERSION)
    app.state.start_time = time.time()

    await connect_to_mongodb()

    # Redis (optional — degrades gracefully)
    cache = RedisCache()
    await cache.connect()
    app.state.cache = cache

    repository = MetadataRepository(cache=cache)
    task_manager = BackgroundTaskManager(repository=repository)

    app.state.repository = repository
    app.state.task_manager = task_manager

    logger.info("Application startup complete.")

    yield

    # ── Shutdown ────────────────────────────────────────────────────────
    logger.info("Shutting down...")
    if app.state.task_manager:
        await app.state.task_manager.cancel_all()
    await cache.close()
    await close_mongodb_connection()
    logger.info("Shutdown complete.")


# ── App Instance ────────────────────────────────────────────────────────────

app = FastAPI(
    title="Metaprobe",
    description=(
        "A security-first HTTP intelligence platform that collects, caches, "
        "and analyzes HTTP metadata (headers, cookies, SSL, page source) for "
        "any URL. Features security analysis with A–F grading, bulk collection, "
        "WebSocket live feed, and Redis caching."
    ),
    version=settings.APP_VERSION,
    lifespan=lifespan,
)

# ── Middleware Stack ────────────────────────────────────────────────────────
# Order matters: outermost middleware runs first

app.add_middleware(TimingMiddleware)
app.add_middleware(CorrelationIdMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

# ── Prometheus Metrics ─────────────────────────────────────────────────────
setup_metrics(app)

# ── Register Routes ────────────────────────────────────────────────────────
app.include_router(metadata_router)

# Import and register analysis + websocket routes (created in Phase 2/3)
try:
    from app.routes.analysis import router as analysis_router

    app.include_router(analysis_router)
except ImportError:
    pass

try:
    from app.routes.websocket import router as ws_router

    app.include_router(ws_router)
except ImportError:
    pass


# ── Global Exception Handlers ──────────────────────────────────────────────


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Catch-all handler to prevent 500 errors from leaking stack traces."""
    correlation_id = getattr(request.state, "correlation_id", "unknown")
    logger.exception(
        "Unhandled exception on %s %s [correlation_id=%s]",
        request.method,
        request.url,
        correlation_id,
    )
    return JSONResponse(
        status_code=500,
        content={
            "detail": "An internal server error occurred.",
            "error_type": "internal_error",
            "correlation_id": correlation_id,
        },
    )


# ── Health Check ────────────────────────────────────────────────────────────


@app.get(
    "/health",
    tags=["system"],
    summary="Health check with dependency status",
    description=(
        "Returns the health status of the service and its dependencies "
        "(MongoDB, Redis). Includes uptime in seconds."
    ),
)
async def health_check(request: Request):
    """Enhanced health check with dependency statuses."""
    import time as _time

    cache: RedisCache = request.app.state.cache
    start_time = getattr(request.app.state, "start_time", _time.time())

    # Check MongoDB
    mongo_status = "connected"
    try:
        from app.database import get_database

        db = get_database()
        await db.command("ping")
    except Exception:
        mongo_status = "disconnected"

    return {
        "status": "healthy",
        "service": "metaprobe",
        "version": settings.APP_VERSION,
        "dependencies": {
            "mongodb": mongo_status,
            "redis": "connected" if cache.is_connected else "disconnected",
        },
        "uptime_seconds": round(_time.time() - start_time, 1),
    }


# ── Root redirect ────────────────────────────────────────────────────────────


@app.get("/", include_in_schema=False)
async def root():
    """Redirect root to the interactive API docs."""
    from fastapi.responses import RedirectResponse

    return RedirectResponse(url="/docs")
