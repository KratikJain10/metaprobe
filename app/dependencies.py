"""
FastAPI dependency injection functions.

Provides typed dependency accessors for shared application resources
(repository, task manager, redis cache) via FastAPI's Depends() system.
Replaces module-level globals with proper DI.
"""

from typing import cast

from fastapi import Request

from app.cache import RedisCache
from app.repositories.metadata_repo import MetadataRepository
from app.services.background import BackgroundTaskManager


def get_repository(request: Request) -> MetadataRepository:
    """Retrieve the MetadataRepository from application state."""
    return cast(MetadataRepository, request.app.state.repository)


def get_task_manager(request: Request) -> BackgroundTaskManager:
    """Retrieve the BackgroundTaskManager from application state."""
    return cast(BackgroundTaskManager, request.app.state.background_tasks)


def get_cache(request: Request) -> RedisCache:
    """Retrieve the RedisCache from application state."""
    return cast(RedisCache, request.app.state.redis_cache)
