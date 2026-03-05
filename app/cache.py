"""
Redis caching layer for metadata documents.

Implements a simple async cache with TTL-based expiration.
Gracefully degrades — all operations are no-ops if Redis
is unavailable, so the service never fails due to cache issues.
"""

import json
import logging
from typing import Any

import redis.asyncio as redis

from app.config import settings

logger = logging.getLogger(__name__)


class RedisCache:
    """
    Async Redis cache with graceful degradation.

    All public methods catch Redis errors and return None / False
    so the caller can fall through to the primary data store.
    """

    def __init__(self, redis_client: redis.Redis | None = None) -> None:
        self._redis = redis_client
        self._connected = False

    async def connect(self) -> None:
        """Establish a connection to Redis."""
        try:
            self._redis = redis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=5,
            )
            await self._redis.ping()
            self._connected = True
            logger.info("Connected to Redis successfully.")
        except Exception as exc:
            logger.warning("Redis not available, caching disabled: %s", exc)
            self._connected = False

    async def close(self) -> None:
        """Close the Redis connection."""
        if self._redis is not None:
            await self._redis.close()
            self._connected = False
            logger.info("Redis connection closed.")

    @property
    def is_connected(self) -> bool:
        """Check if Redis is available."""
        return self._connected

    async def get(self, key: str) -> dict[str, Any] | None:
        """
        Retrieve a cached value by key.

        Returns None on cache miss or if Redis is unavailable.
        """
        if not self._connected or self._redis is None:
            return None
        try:
            data = await self._redis.get(f"metaprobe:{key}")
            if data is not None:
                logger.debug("Cache HIT for key: %s", key)
                result: dict[str, Any] = json.loads(data)
                return result
            logger.debug("Cache MISS for key: %s", key)
            return None
        except Exception as exc:
            logger.warning("Redis GET error for %s: %s", key, exc)
            return None

    async def set(self, key: str, value: dict[str, Any], ttl: int | None = None) -> bool:
        """
        Store a value in cache with optional TTL (seconds).

        Returns True on success, False on failure.
        """
        if not self._connected or self._redis is None:
            return False
        try:
            ttl = ttl or settings.CACHE_TTL_SECONDS
            await self._redis.set(
                f"metaprobe:{key}",
                json.dumps(value, default=str),
                ex=ttl,
            )
            logger.debug("Cache SET for key: %s (TTL=%ds)", key, ttl)
            return True
        except Exception as exc:
            logger.warning("Redis SET error for %s: %s", key, exc)
            return False

    async def invalidate(self, key: str) -> bool:
        """
        Remove a key from cache.

        Returns True if the key was deleted, False otherwise.
        """
        if not self._connected or self._redis is None:
            return False
        try:
            result = await self._redis.delete(f"metaprobe:{key}")
            logger.debug("Cache INVALIDATE for key: %s (deleted=%d)", key, result)
            return bool(result > 0)
        except Exception as exc:
            logger.warning("Redis DELETE error for %s: %s", key, exc)
            return False
