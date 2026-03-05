# Metaprobe

[![CI](https://github.com/KratikJain10/metaprobe/actions/workflows/ci.yml/badge.svg)](https://github.com/KratikJain10/metaprobe/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

**A security-first HTTP intelligence platform** that collects, caches, and analyzes HTTP metadata for any URL. Features a built-in Security Analysis Engine with A+ through F grading, bulk collection, WebSocket live feed, Redis caching, and Prometheus observability.

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🛡️ **Security Analysis** | Grades any URL's security posture (A+ to F) — checks headers, cookies, SSL/TLS, tech fingerprinting |
| ⚡ **Async Collection** | Non-blocking HTTP metadata collection with background task deduplication |
| 📦 **Bulk Operations** | Collect metadata for up to 50 URLs concurrently with throttled parallelism |
| 🔌 **WebSocket Feed** | Real-time bidirectional collection with live progress streaming |
| 🗄️ **Redis Caching** | Sub-millisecond reads with TTL-based cache invalidation (graceful degradation) |
| 📊 **Prometheus Metrics** | Built-in `/metrics` endpoint for monitoring and alerting |
| 🔒 **Production-Ready** | Rate limiting, CORS, correlation IDs, structured logging, health checks |
| 📤 **Export** | Export all metadata as JSON or CSV |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          FastAPI Application                            │
│                                                                         │
│  ┌─── Middleware Stack ──────────────────────────────────────────────┐  │
│  │  CORS → CorrelationID → Timing → Rate Limiting → Prometheus      │  │
│  └──────────────────────────────────────────────────────────────────-┘  │
│                                                                         │
│  ┌── Routes ────────────────────────────────────────────────────────┐   │
│  │  POST /metadata       POST /metadata/bulk    POST /analyze       │   │
│  │  GET  /metadata       GET  /metadata/list    GET  /analyze       │   │
│  │  GET  /metadata/status DELETE /metadata      WS /ws/collect      │   │
│  │  GET  /metadata/export GET /health           GET /metrics        │   │
│  └─────────────────────────────┬────────────────────────────────────┘   │
│                                │                                        │
│  ┌── Service Layer ────────────┴────────────────────────────────────┐   │
│  │  MetadataCollector │ BackgroundTaskManager │ SecurityAnalyzer     │   │
│  │  (httpx async)     │ (asyncio + dedup)     │ (header/cookie/SSL) │   │
│  └─────────────────────────────┬────────────────────────────────────┘   │
│                                │                                        │
│  ┌── Repository Layer ─────────┴────────────────────────────────────┐   │
│  │          MetadataRepository (cache-aside pattern)                 │   │
│  └──────────┬─────────────────────────────┬─────────────────────────┘   │
└─────────────┼─────────────────────────────┼─────────────────────────────┘
              │                             │
   ┌──────────▼──────────┐      ┌───────────▼────────────┐
   │     MongoDB 7       │      │     Redis 7 (cache)    │
   │  (indexed on url)   │      │   (TTL + LRU eviction) │
   └─────────────────────┘      └────────────────────────┘
```

---

## Quick Start

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/)

### Run the Service

```bash
git clone https://github.com/KratikJain10/metaprobe.git
cd metaprobe
docker-compose up --build
```

The API will be available at **http://localhost:8001** · Swagger docs at **http://localhost:8001/docs**

### Makefile Commands

```bash
make run        # Build and start (foreground)
make up         # Build and start (detached)
make down       # Stop containers
make clean      # Stop + wipe all data
make test       # Run tests with coverage inside Docker
make test-local # Run tests locally
make lint       # Run linting (ruff)
make typecheck  # Run type checking (mypy)
make fix        # Auto-fix lint issues
make logs       # Tail API logs
make docs       # Open Swagger UI
```

---

## API Reference

### Core Metadata Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/metadata` | `POST` | Collect and store metadata for a URL |
| `/metadata` | `GET` | Retrieve stored metadata (triggers background collection on miss) |
| `/metadata` | `DELETE` | Remove stored metadata for a URL |
| `/metadata/status` | `GET` | Check background collection status |
| `/metadata/list` | `GET` | Paginated list with search and sort |
| `/metadata/bulk` | `POST` | Bulk collect up to 50 URLs concurrently |
| `/metadata/export` | `GET` | Export all data as JSON or CSV |

### Security Analysis

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/analyze` | `POST` | Collect + analyze a URL's security posture |
| `/analyze` | `GET` | Analyze already-stored metadata |

### System

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | `GET` | Health check with dependency status |
| `/metrics` | `GET` | Prometheus metrics |
| `/ws/collect` | `WS` | Real-time collection feed |

---

### Security Analysis Example

```bash
curl -X POST http://localhost:8001/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

```json
{
  "url": "https://example.com",
  "grade": "C",
  "score": 55,
  "findings": [
    {
      "category": "header",
      "severity": "high",
      "title": "Missing Content-Security-Policy (CSP)",
      "description": "No CSP header detected. Without CSP, the site is more vulnerable to XSS attacks.",
      "recommendation": "Implement a Content-Security-Policy header."
    },
    {
      "category": "header",
      "severity": "high",
      "title": "Missing Strict-Transport-Security (HSTS)",
      "description": "The server does not enforce HTTPS via HSTS.",
      "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'."
    }
  ],
  "summary": {"critical": 0, "high": 2, "medium": 2, "low": 2, "info": 1},
  "technologies": ["server: ECS (dca/24A0)"],
  "ssl_info": {
    "subject": "www.example.org",
    "issuer": "DigiCert Inc",
    "days_until_expiry": 312
  },
  "analyzed_at": "2026-03-05T12:00:00Z"
}
```

---

### Bulk Collection Example

```bash
curl -X POST http://localhost:8001/metadata/bulk \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://example.com", "https://httpbin.org/html", "https://github.com"]}'
```

```json
{
  "total": 3,
  "succeeded": 3,
  "failed": 0,
  "results": [
    {"url": "https://example.com", "status": "success", "error": null},
    {"url": "https://httpbin.org/html", "status": "success", "error": null},
    {"url": "https://github.com", "status": "success", "error": null}
  ]
}
```

---

### WebSocket Live Feed

```bash
# Using websocat
websocat ws://localhost:8001/ws/collect
# Send: {"url": "https://example.com"}
# Receive: {"type": "started", "url": "...", "timestamp": "..."}
# Receive: {"type": "completed", "url": "...", "metadata": {...}, "timestamp": "..."}
```

---

## Testing

```bash
# Run all 56 tests with coverage (Docker)
docker-compose run --rm api pytest -v --cov=app --cov-report=term-missing

# Run locally
pytest -v --cov=app --cov-report=term-missing
```

### Test Suite

| Suite | Tests | What's Tested |
|-------|-------|---------------|
| `test_analyzer.py` | 16 | Header detection, cookie analysis, scoring, grading, technology fingerprinting |
| `test_api.py` | 9 | POST/GET/status/health endpoints, background collection E2E |
| `test_bulk.py` | 12 | Bulk collection, pagination, search, delete, JSON/CSV export |
| `test_analysis_api.py` | 5 | POST/GET /analyze endpoints, error handling |
| `test_middleware.py` | 4 | Correlation ID, timing header, health dependencies |
| `test_collector.py` | 6 | HTTP collection, cookies, redirects, timeouts, large payloads |
| `test_repository.py` | 6 | CRUD operations, upsert idempotency |
| **Total** | **56** | |

---

## Project Structure

```
├── app/
│   ├── main.py                    # App factory, middleware stack, lifespan
│   ├── config.py                  # Pydantic Settings (env-based)
│   ├── cache.py                   # Redis cache with graceful degradation
│   ├── database.py                # Motor async MongoDB + retry logic
│   ├── dependencies.py            # FastAPI Depends() DI functions
│   ├── middleware.py              # Correlation ID + timing middleware
│   ├── metrics.py                 # Prometheus instrumentation
│   ├── models/
│   │   ├── schemas.py             # Request/response Pydantic models
│   │   └── analysis.py            # Security analysis models
│   ├── repositories/
│   │   └── metadata_repo.py       # MongoDB CRUD + cache-aside pattern
│   ├── routes/
│   │   ├── metadata.py            # Core + bulk + export endpoints
│   │   ├── analysis.py            # Security analysis endpoints
│   │   └── websocket.py           # WebSocket live collection
│   └── services/
│       ├── collector.py           # HTTP metadata fetcher (httpx)
│       ├── background.py          # Background task manager (asyncio)
│       └── analyzer.py            # Security Analysis Engine
├── tests/                         # 56 tests (unit + integration)
├── Dockerfile                     # Multi-stage build, non-root user
├── docker-compose.yml             # API + MongoDB + Redis
├── requirements.txt               # Python dependencies
├── pyproject.toml                 # Ruff, mypy, pytest, coverage config
├── .pre-commit-config.yaml        # Pre-commit hooks
├── .github/workflows/ci.yml       # CI pipeline (lint → typecheck → test → docker)
├── Makefile                       # Developer shortcuts
├── CONTRIBUTING.md                # Contribution guide
└── LICENSE                        # MIT
```

---

## Configuration

All settings via environment variables (see [`.env.example`](.env.example)):

| Variable | Default | Description |
|----------|---------|-------------|
| `MONGO_URI` | `mongodb://mongodb:27017` | MongoDB connection string |
| `MONGO_DB_NAME` | `metadata_inventory` | Database name |
| `REDIS_URL` | `redis://redis:6379/0` | Redis connection string |
| `CACHE_TTL_SECONDS` | `3600` | Cache entry TTL (seconds) |
| `REQUEST_TIMEOUT` | `30` | HTTP request timeout (seconds) |
| `RATE_LIMIT` | `30/minute` | API rate limit per IP |
| `CORS_ORIGINS` | `["*"]` | Allowed CORS origins |
| `APP_VERSION` | `2.0.0` | Application version |
| `LOG_LEVEL` | `INFO` | Logging level |

---

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Layered architecture** (routes → services → repos → DB) | Clean separation; each layer independently testable and replaceable |
| **FastAPI Depends() DI** | Type-safe dependency injection; no module-level globals |
| **Security Analysis Engine** | Provides unique value — security grading like SecurityHeaders.com |
| **Cache-aside pattern with Redis** | Sub-millisecond reads; graceful degradation if Redis is down |
| **WebSocket live feed** | Demonstrates real-time async expertise beyond basic REST |
| **Semaphore-throttled bulk collection** | Prevents resource exhaustion during concurrent collection |
| **Correlation ID middleware** | End-to-end request tracing across logs and responses |
| **Prometheus instrumentation** | Production-grade observability with custom application metrics |
| **Multi-stage Dockerfile** | Minimal image size; non-root user for security |
| **CI pipeline** (lint → typecheck → test → docker) | Enforces code quality before merge |

---

## License

[MIT](LICENSE)
