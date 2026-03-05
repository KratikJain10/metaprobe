"""
FastAPI dependency injection functions.

Provides typed dependency accessors for shared application resources
(repository, task manager, redis cache) via FastAPI's Depends() system.
Replaces module-level globals with proper DI.
"""

from fastapi import Request

from app.cache import RedisCache
from app.repositories.metadata_repo import MetadataRepository
from app.services.background import BackgroundTaskManager


def get_repository(request: Request) -> MetadataRepository:
    """Retrieve the MetadataRepository from application state."""
    repo: MetadataRepository = request.app.state.repository
    return repo


def get_task_manager(request: Request) -> BackgroundTaskManager:
    """Retrieve the BackgroundTaskManager from application state."""
    mgr: BackgroundTaskManager = request.app.state.task_manager
    return mgr


def get_cache(request: Request) -> RedisCache:
    """Retrieve the RedisCache from application state."""
    cache: RedisCache = request.app.state.cache
    return cache
