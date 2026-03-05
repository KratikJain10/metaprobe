"""
Prometheus metrics instrumentation for Metaprobe.

Provides automatic HTTP metrics collection and custom
application-specific counters and histograms.
"""

from prometheus_fastapi_instrumentator import Instrumentator
from prometheus_client import Counter, Histogram, Gauge

# ── Custom Metrics ──────────────────────────────────────────────────────────

# Collection metrics
collections_total = Counter(
    "metaprobe_collections_total",
    "Total number of metadata collections attempted",
    ["method", "status"],
)

collection_duration_seconds = Histogram(
    "metaprobe_collection_duration_seconds",
    "Time spent collecting metadata from a URL",
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0],
)

# Analysis metrics
analyses_total = Counter(
    "metaprobe_analyses_total",
    "Total number of security analyses performed",
)

analysis_grade_total = Counter(
    "metaprobe_analysis_grade_total",
    "Security analysis results by grade",
    ["grade"],
)

# Background task metrics
active_background_tasks = Gauge(
    "metaprobe_active_background_tasks",
    "Number of currently active background collection tasks",
)

# Cache metrics
cache_hits_total = Counter(
    "metaprobe_cache_hits_total",
    "Total number of cache hits",
)

cache_misses_total = Counter(
    "metaprobe_cache_misses_total",
    "Total number of cache misses",
)


def setup_metrics(app):
    """
    Attach Prometheus instrumentation to the FastAPI app.

    This adds automatic HTTP request/response metrics and
    exposes a /metrics endpoint for Prometheus scraping.
    """
    instrumentator = Instrumentator(
        should_group_status_codes=True,
        should_ignore_untemplated=True,
        excluded_handlers=["/metrics", "/health"],
    )
    instrumentator.instrument(app).expose(app, endpoint="/metrics", tags=["system"])
