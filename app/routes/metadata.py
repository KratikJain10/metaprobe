"""
API routes for the Metaprobe Service.

Provides endpoints for:
- POST /metadata        : Synchronously collect and store metadata for a URL.
- GET  /metadata        : Retrieve stored metadata, or trigger background collection.
- GET  /metadata/status : Check the status of a background collection task.
- DELETE /metadata      : Remove stored metadata for a URL.
- GET  /metadata/list   : Paginated listing of all collected metadata.
- POST /metadata/bulk   : Bulk collection for multiple URLs.
- GET  /metadata/export : Export metadata in JSON or CSV format.
"""

import asyncio
import csv
import io
import logging
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse, StreamingResponse

from app.dependencies import get_cache, get_repository, get_task_manager
from app.cache import RedisCache
from app.models.schemas import (
    AcceptedResponse,
    BulkRequest,
    BulkResponse,
    BulkResultItem,
    ErrorResponse,
    MetadataListResponse,
    MetadataRequest,
    MetadataResponse,
    StatusResponse,
)
from app.repositories.metadata_repo import MetadataRepository
from app.services.background import BackgroundTaskManager
from app.services.collector import CollectionError, collect_metadata

logger = logging.getLogger(__name__)

router = APIRouter(tags=["metadata"])


def _validate_url(url: str) -> None:
    """Validate that a URL has a valid HTTP(S) scheme and netloc."""
    parsed = urlparse(url)
    if not parsed.scheme or parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid URL: '{url}'. URL must start with http:// or https://.",
        )


# ── POST /metadata ──────────────────────────────────────────────────────────


@router.post(
    "/metadata",
    response_model=MetadataResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        422: {"model": ErrorResponse, "description": "Invalid URL format."},
        502: {"model": ErrorResponse, "description": "Failed to fetch the URL."},
    },
    summary="Collect metadata for a URL",
    description=(
        "Fetches the HTTP headers, cookies, and page source for the given URL "
        "and stores the result in the database. If metadata for this URL "
        "already exists, it is replaced with freshly collected data."
    ),
)
async def create_metadata(
    request: MetadataRequest,
    repo: MetadataRepository = Depends(get_repository),
) -> MetadataResponse:
    """Synchronously collect and store metadata for a given URL."""
    url = str(request.url)

    try:
        document = await collect_metadata(url)
    except CollectionError as exc:
        logger.error("Collection failed for POST %s: %s", url, exc.reason)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to collect metadata: {exc.reason}",
        )

    await repo.upsert_metadata(document)
    logger.info("POST /metadata — stored metadata for %s", url)

    return MetadataResponse(
        url=document.url,
        headers=document.headers,
        cookies=document.cookies,
        page_source=document.page_source,
        collected_at=document.collected_at,
    )


# ── GET /metadata ───────────────────────────────────────────────────────────


@router.get(
    "/metadata",
    response_model=MetadataResponse,
    responses={
        200: {"model": MetadataResponse, "description": "Metadata found and returned."},
        202: {"model": AcceptedResponse, "description": "Metadata not found; collection scheduled."},
        422: {"model": ErrorResponse, "description": "Invalid URL format."},
    },
    summary="Retrieve metadata for a URL",
    description=(
        "Checks the database for existing metadata for the given URL. "
        "If found, returns the full dataset immediately. If not found, "
        "returns a 202 Accepted response and schedules background collection."
    ),
)
async def get_metadata(
    url: str = Query(
        ...,
        description="The URL to retrieve metadata for.",
        examples=["https://example.com"],
    ),
    repo: MetadataRepository = Depends(get_repository),
    task_manager: BackgroundTaskManager = Depends(get_task_manager),
) -> MetadataResponse | AcceptedResponse:
    """Retrieve metadata for a URL, or schedule background collection."""
    _validate_url(url)

    document = await repo.find_by_url(url)

    if document is not None:
        logger.info("GET /metadata — cache hit for %s", url)
        return MetadataResponse(
            url=document.url,
            headers=document.headers,
            cookies=document.cookies,
            page_source=document.page_source,
            collected_at=document.collected_at,
        )

    task_manager.schedule_collection(url)
    logger.info("GET /metadata — cache miss for %s, scheduled background collection", url)

    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content=AcceptedResponse(url=url).model_dump(),
    )


# ── GET /metadata/status ─────────────────────────────────────────────────────


@router.get(
    "/metadata/status",
    response_model=StatusResponse,
    responses={
        422: {"model": ErrorResponse, "description": "Invalid URL format."},
    },
    summary="Check background collection status for a URL",
    description=(
        "Returns the current collection status for a given URL. "
        "Useful for polling after receiving a 202 Accepted from GET /metadata.\n\n"
        "- **`pending`** — a background task is currently in progress.\n"
        "- **`completed`** — data has been collected and is available via GET /metadata.\n"
        "- **`not_found`** — no active task; the URL may not have been requested yet."
    ),
)
async def get_metadata_status(
    url: str = Query(
        ...,
        description="The URL to check collection status for.",
        examples=["https://example.com"],
    ),
    repo: MetadataRepository = Depends(get_repository),
    task_manager: BackgroundTaskManager = Depends(get_task_manager),
) -> StatusResponse:
    """Check whether a background metadata collection task is pending or done."""
    _validate_url(url)

    document = await repo.find_by_url(url)
    if document is not None:
        return StatusResponse(url=url, task_status="completed")

    raw_status = task_manager.get_task_status(url)
    if raw_status == "pending":
        return StatusResponse(url=url, task_status="pending")

    return StatusResponse(url=url, task_status="not_found")


# ── DELETE /metadata ─────────────────────────────────────────────────────────


@router.delete(
    "/metadata",
    status_code=status.HTTP_200_OK,
    responses={
        404: {"model": ErrorResponse, "description": "URL not found."},
        422: {"model": ErrorResponse, "description": "Invalid URL format."},
    },
    summary="Delete stored metadata for a URL",
    description="Removes metadata for the given URL from the database and cache.",
)
async def delete_metadata(
    url: str = Query(..., description="The URL to delete metadata for."),
    repo: MetadataRepository = Depends(get_repository),
) -> dict:
    """Delete stored metadata for a URL."""
    _validate_url(url)

    deleted = await repo.delete_by_url(url)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No metadata found for URL: {url}",
        )

    logger.info("DELETE /metadata — removed metadata for %s", url)
    return {"message": f"Metadata for {url} deleted successfully.", "url": url}


# ── GET /metadata/list ────────────────────────────────────────────────────────


@router.get(
    "/metadata/list",
    response_model=MetadataListResponse,
    summary="List all collected metadata (paginated)",
    description=(
        "Returns a paginated list of all stored metadata records. "
        "Supports filtering by URL pattern and sorting by collection date."
    ),
)
async def list_metadata(
    skip: int = Query(0, ge=0, description="Number of records to skip."),
    limit: int = Query(20, ge=1, le=100, description="Max records to return."),
    search: str | None = Query(None, description="Filter by URL substring (case-insensitive)."),
    sort: str = Query("desc", pattern="^(asc|desc)$", description="Sort by collected_at."),
    repo: MetadataRepository = Depends(get_repository),
) -> MetadataListResponse:
    """List all collected metadata with pagination and filtering."""
    items, total = await repo.list_metadata(
        skip=skip, limit=limit, search=search, sort=sort
    )

    results = [
        MetadataResponse(
            url=doc.url,
            headers=doc.headers,
            cookies=doc.cookies,
            page_source=doc.page_source,
            collected_at=doc.collected_at,
        )
        for doc in items
    ]

    return MetadataListResponse(
        items=results,
        total=total,
        skip=skip,
        limit=limit,
    )


# ── POST /metadata/bulk ──────────────────────────────────────────────────────


@router.post(
    "/metadata/bulk",
    response_model=BulkResponse,
    status_code=status.HTTP_200_OK,
    summary="Bulk collect metadata for multiple URLs",
    description=(
        "Accepts a list of URLs and collects metadata for all of them concurrently. "
        "Returns results for each URL, including any failures. "
        "Uses a semaphore to limit concurrency to 10 simultaneous requests."
    ),
)
async def bulk_collect(
    request: BulkRequest,
    repo: MetadataRepository = Depends(get_repository),
) -> BulkResponse:
    """Collect metadata for multiple URLs concurrently."""
    semaphore = asyncio.Semaphore(10)
    results: list[BulkResultItem] = []

    async def _collect_one(url: str) -> BulkResultItem:
        async with semaphore:
            try:
                document = await collect_metadata(url)
                await repo.upsert_metadata(document)
                return BulkResultItem(url=url, status="success")
            except CollectionError as exc:
                return BulkResultItem(url=url, status="failed", error=exc.reason)
            except Exception as exc:
                return BulkResultItem(
                    url=url, status="failed", error=str(exc)
                )

    urls = [str(u) for u in request.urls]
    tasks = [_collect_one(url) for url in urls]
    results = await asyncio.gather(*tasks)

    succeeded = sum(1 for r in results if r.status == "success")
    failed = sum(1 for r in results if r.status == "failed")

    return BulkResponse(
        total=len(urls),
        succeeded=succeeded,
        failed=failed,
        results=list(results),
    )


# ── GET /metadata/export ─────────────────────────────────────────────────────


@router.get(
    "/metadata/export",
    summary="Export all metadata as JSON or CSV",
    description="Export all stored metadata records. Supports JSON and CSV formats.",
)
async def export_metadata(
    format: str = Query("json", pattern="^(json|csv)$", description="Export format."),
    repo: MetadataRepository = Depends(get_repository),
):
    """Export all metadata in JSON or CSV format."""
    items, _ = await repo.list_metadata(skip=0, limit=10000, search=None, sort="desc")

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["url", "collected_at", "headers", "cookies"])
        for doc in items:
            writer.writerow([
                doc.url,
                doc.collected_at.isoformat(),
                str(doc.headers),
                str(doc.cookies),
            ])
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=metaprobe_export.csv"},
        )

    # JSON format
    data = [
        {
            "url": doc.url,
            "headers": doc.headers,
            "cookies": doc.cookies,
            "page_source": doc.page_source,
            "collected_at": doc.collected_at.isoformat(),
        }
        for doc in items
    ]
    return JSONResponse(content=data)
