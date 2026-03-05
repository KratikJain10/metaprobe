"""
API routes for security analysis.

Provides endpoints for:
- POST /analyze : Collect metadata + run full security analysis in one shot.
- GET  /analyze : Run analysis on already-stored metadata (no re-fetch).
"""

import logging
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.dependencies import get_repository
from app.models.analysis import AnalyzeRequest, SecurityReport
from app.models.schemas import ErrorResponse
from app.repositories.metadata_repo import MetadataRepository
from app.services.analyzer import SecurityAnalyzer
from app.services.collector import CollectionError, collect_metadata

logger = logging.getLogger(__name__)

router = APIRouter(tags=["security analysis"])

# Reusable analyzer instance (stateless)
_analyzer = SecurityAnalyzer()


def _validate_url(url: str) -> None:
    """Validate that a URL has a valid HTTP(S) scheme and netloc."""
    parsed = urlparse(url)
    if not parsed.scheme or parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid URL: '{url}'. URL must start with http:// or https://.",
        )


@router.post(
    "/analyze",
    response_model=SecurityReport,
    status_code=status.HTTP_200_OK,
    responses={
        422: {"model": ErrorResponse, "description": "Invalid URL format."},
        502: {"model": ErrorResponse, "description": "Failed to fetch the URL."},
    },
    summary="Collect and analyze a URL's security posture",
    description=(
        "Fetches the URL's HTTP metadata and runs a comprehensive security "
        "analysis. Returns a security report with grade (A+ to F), findings, "
        "SSL details, and detected technologies. The collected metadata is "
        "also stored for future retrieval."
    ),
)
async def analyze_url(
    request: AnalyzeRequest,
    repo: MetadataRepository = Depends(get_repository),
) -> SecurityReport:
    """Collect metadata and run security analysis."""
    url = request.url
    _validate_url(url)

    try:
        document = await collect_metadata(url)
    except CollectionError as exc:
        logger.error("Collection failed for analysis of %s: %s", url, exc.reason)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to collect metadata: {exc.reason}",
        ) from exc

    # Store the collected metadata
    await repo.upsert_metadata(document)

    # Run security analysis
    report = _analyzer.analyze(
        url=document.url,
        headers=document.headers,
        cookies=document.cookies,
    )

    logger.info(
        "POST /analyze — %s scored %d (%s) with %d findings",
        url,
        report.score,
        report.grade,
        len(report.findings),
    )

    return report


@router.get(
    "/analyze",
    response_model=SecurityReport,
    responses={
        404: {"model": ErrorResponse, "description": "No stored metadata for this URL."},
        422: {"model": ErrorResponse, "description": "Invalid URL format."},
    },
    summary="Analyze stored metadata for a URL",
    description=(
        "Runs security analysis on previously collected metadata. "
        "Does not re-fetch the URL — uses data already in the database. "
        "Use POST /analyze to collect and analyze in one step."
    ),
)
async def analyze_stored(
    url: str = Query(
        ...,
        description="The URL to analyze stored metadata for.",
        examples=["https://example.com"],
    ),
    repo: MetadataRepository = Depends(get_repository),
) -> SecurityReport:
    """Analyze already-stored metadata for a URL."""
    _validate_url(url)

    document = await repo.find_by_url(url)
    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"No stored metadata for '{url}'. "
                f"Use POST /analyze to collect and analyze in one step."
            ),
        )

    report = _analyzer.analyze(
        url=document.url,
        headers=document.headers,
        cookies=document.cookies,
    )

    logger.info(
        "GET /analyze — %s scored %d (%s) with %d findings",
        url,
        report.score,
        report.grade,
        len(report.findings),
    )

    return report
