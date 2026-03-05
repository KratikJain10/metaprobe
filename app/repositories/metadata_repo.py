"""
MongoDB repository for metadata documents.

Encapsulates all database operations, providing a clean interface
between the service layer and the database. Supports optional
Redis cache integration for read-through caching.
"""

import logging
from typing import Any, cast

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.cache import RedisCache
from app.database import get_database
from app.models.schemas import MetadataDocument

logger = logging.getLogger(__name__)


class MetadataRepository:
    """Data access layer for the metadata collection in MongoDB."""

    COLLECTION_NAME = "metadata"

    def __init__(
        self,
        database: AsyncIOMotorDatabase | None = None,
        cache: RedisCache | None = None,
    ) -> None:
        """
        Initialise with optional database and cache instances.

        If none are provided, the global database connection is used
        and caching is disabled. This allows injecting test doubles.
        """
        self._db = database
        self._cache = cache

    @property
    def _collection(self):
        """Lazy access to the metadata collection."""
        db = self._db or get_database()
        return db[self.COLLECTION_NAME]

    async def find_by_url(self, url: str) -> MetadataDocument | None:
        """
        Look up a metadata record by its URL.

        Checks Redis cache first (if available), then falls back
        to MongoDB. Cache is populated on miss.
        """
        # Try cache first
        if self._cache is not None:
            cached = await self._cache.get(url)
            if cached is not None:
                return MetadataDocument.from_mongo_dict(cached)

        # Fall back to MongoDB
        document = await self._collection.find_one({"url": url})
        if document is None:
            return None

        result = MetadataDocument.from_mongo_dict(document)

        # Populate cache on miss
        if self._cache is not None:
            await self._cache.set(url, result.to_mongo_dict())

        return result

    async def upsert_metadata(self, metadata: MetadataDocument) -> None:
        """
        Insert or update a metadata record (write-through).

        Writes to both MongoDB and Redis cache simultaneously.
        """
        data = metadata.to_mongo_dict()
        await self._collection.replace_one(
            {"url": metadata.url},
            data,
            upsert=True,
        )

        # Write-through to cache
        if self._cache is not None:
            await self._cache.set(metadata.url, data)

        logger.info("Upserted metadata for URL: %s", metadata.url)

    async def delete_metadata(self, url: str) -> bool:
        """
        Delete metadata for a given URL.

        Also invalidates the cache entry.
        """
        result = await self._collection.delete_one({"url": url})

        # Invalidate cache
        if self._cache:
            await self._cache.invalidate(url)

        return cast(bool, result.deleted_count > 0)

    async def count_metadata(self) -> int:
        """Count total metadata records."""
        return cast(int, await self._collection.count_documents({}))

    async def list_metadata(
        self,
        skip: int = 0,
        limit: int = 20,
        search: str | None = None,
        sort: str = "desc",
    ) -> tuple[list[MetadataDocument], int]:
        """
        List metadata records with pagination, filtering, and sorting.

        Args:
            skip: Number of records to skip.
            limit: Maximum number of records to return.
            search: Optional URL substring filter (case-insensitive).
            sort: Sort direction by collected_at ('asc' or 'desc').

        Returns:
            Tuple of (list of documents, total count matching filter).
        """
        query: dict[str, Any] = {}
        if search:
            query["url"] = {"$regex": search, "$options": "i"}

        sort_direction = -1 if sort == "desc" else 1

        total = await self._collection.count_documents(query)
        cursor = (
            self._collection.find(query)
            .sort("collected_at", sort_direction)
            .skip(skip)
            .limit(limit)
        )

        documents = []
        async for doc in cursor:
            documents.append(MetadataDocument.from_mongo_dict(doc))

        return documents, total
