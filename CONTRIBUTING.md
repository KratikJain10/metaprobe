# Contributing to Metaprobe

Thanks for your interest in contributing! Here's how to get started.

## Development Setup

```bash
# Clone and enter the project
git clone https://github.com/KratikJain10/metaprobe.git
cd metaprobe

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install all dependencies
pip install -r requirements.txt

# Install pre-commit hooks
pre-commit install
```

## Running Locally

```bash
# Start all services (API + MongoDB + Redis)
docker-compose up --build

# Or run just the tests (no Docker needed for unit tests)
pytest -v --cov=app
```

## Code Quality

We enforce code quality via CI. Before pushing, run:

```bash
make lint       # Ruff lint + format check
make typecheck  # mypy type checking
make test-local # Run tests with coverage
make fix        # Auto-fix lint issues
```

## Pull Request Process

1. Fork the repo and create a feature branch from `main`
2. Write tests for any new functionality
3. Ensure `make lint`, `make typecheck`, and `make test-local` pass
4. Update documentation if you're adding/changing endpoints
5. Open a PR with a clear description of the change

## Project Structure

```
app/
├── main.py              # App factory, middleware, lifespan
├── config.py            # Environment-based settings
├── cache.py             # Redis caching layer
├── database.py          # MongoDB connection manager
├── dependencies.py      # FastAPI DI functions
├── middleware.py         # Correlation ID, timing middleware
├── metrics.py           # Prometheus instrumentation
├── models/
│   ├── schemas.py       # Request/response Pydantic models
│   └── analysis.py      # Security analysis models
├── repositories/
│   └── metadata_repo.py # MongoDB data access layer
├── routes/
│   ├── metadata.py      # Core CRUD + bulk/export endpoints
│   ├── analysis.py      # Security analysis endpoints
│   └── websocket.py     # WebSocket live collection
└── services/
    ├── collector.py     # HTTP metadata fetcher
    ├── background.py    # Background task manager
    └── analyzer.py      # Security analysis engine
```
