"""
Shared test fixtures for the Metaprobe test suite.

Provides:
- Async event loop configuration
- Test MongoDB database (mongomock-motor for unit tests)
- Repository, task manager, and cache instances
- FastAPI test client
"""

import asyncio
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from mongomock_motor import AsyncMongoMockClient

from app.cache import RedisCache
from app.models.schemas import MetadataDocument
from app.repositories.metadata_repo import MetadataRepository
from app.services.background import BackgroundTaskManager





@pytest_asyncio.fixture
async def mock_db():
    """
    Provide a mock MongoDB database using mongomock-motor.

    Each test gets a fresh database to prevent cross-test contamination.
    """
    client = AsyncMongoMockClient()
    db = client["test_metadata_inventory"]
    await db.metadata.create_index("url", unique=True)
    yield db
    client.close()


@pytest_asyncio.fixture
async def mock_cache():
    """
    Provide a disabled Redis cache for testing.

    The cache is intentionally disconnected so tests validate
    the MongoDB path without Redis dependency.
    """
    cache = RedisCache()
    # Don't call connect — leave in disconnected state
    return cache


@pytest_asyncio.fixture
async def repository(mock_db, mock_cache) -> MetadataRepository:
    """Provide a MetadataRepository backed by the mock database."""
    return MetadataRepository(database=mock_db, cache=mock_cache)


@pytest_asyncio.fixture
async def task_manager(repository) -> BackgroundTaskManager:
    """Provide a BackgroundTaskManager with the test repository."""
    manager = BackgroundTaskManager(repository=repository)
    yield manager
    await manager.cancel_all()


@pytest_asyncio.fixture
async def test_client(mock_db, mock_cache, repository, task_manager) -> AsyncGenerator:
    """
    Provide an async HTTP test client for the FastAPI application.

    Injects the test database, repository, task manager, and cache
    to avoid connecting to real MongoDB/Redis instances.
    """
    from app.main import app

    # Inject test dependencies into app state
    app.state.repository = repository
    app.state.task_manager = task_manager
    app.state.cache = mock_cache

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest_asyncio.fixture
async def sample_metadata() -> MetadataDocument:
    """Provide a sample MetadataDocument for testing."""
    from datetime import datetime, timezone

    return MetadataDocument(
        url="https://example.com",
        headers={
            "content-type": "text/html; charset=UTF-8",
            "server": "ECS",
            "strict-transport-security": "max-age=31536000; includeSubDomains",
        },
        cookies={"session": "abc123"},
        page_source="<!doctype html><html><head><title>Example</title></head></html>",
        collected_at=datetime(2026, 3, 3, 12, 0, 0, tzinfo=timezone.utc),
    )
