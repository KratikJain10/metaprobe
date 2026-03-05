"""
Pydantic models for request validation and response serialization.

Provides strict type-checked schemas for the API layer,
ensuring data integrity between client ↔ API ↔ database.
"""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, HttpUrl

# ── Request Models ──────────────────────────────────────────────────────────


class MetadataRequest(BaseModel):
    """Request body for POST /metadata endpoint."""

    url: HttpUrl = Field(
        ...,
        description="The URL to collect metadata from.",
        examples=["https://example.com"],
    )


class BulkRequest(BaseModel):
    """Request body for POST /metadata/bulk endpoint."""

    urls: list[HttpUrl] = Field(
        ...,
        description="List of URLs to collect metadata from.",
        min_length=1,
        max_length=50,
        examples=[["https://example.com", "https://httpbin.org/html"]],
    )


# ── Response Models ─────────────────────────────────────────────────────────


class MetadataResponse(BaseModel):
    """Full metadata response returned when data is available."""

    url: str = Field(..., description="The original URL.")
    headers: dict[str, str] = Field(
        default_factory=dict,
        description="HTTP response headers from the URL.",
    )
    cookies: dict[str, str] = Field(
        default_factory=dict,
        description="Cookies set by the URL's response.",
    )
    page_source: str = Field(
        default="",
        description="Full HTML page source of the URL.",
    )
    collected_at: datetime = Field(
        ...,
        description="Timestamp when the metadata was collected.",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "url": "https://example.com",
                    "headers": {"content-type": "text/html; charset=UTF-8"},
                    "cookies": {},
                    "page_source": "<!doctype html>...",
                    "collected_at": "2026-03-03T18:00:00Z",
                }
            ]
        }
    }


class AcceptedResponse(BaseModel):
    """Response for 202 Accepted when metadata is not yet available."""

    message: str = Field(
        default="Request accepted. Metadata collection has been scheduled.",
        description="Acknowledgement message.",
    )
    url: str = Field(..., description="The URL queued for collection.")
    status: str = Field(
        default="pending",
        description="Current status of the collection job.",
    )


class StatusResponse(BaseModel):
    """Response for GET /metadata/status — reflects background task state."""

    url: str = Field(..., description="The queried URL.")
    task_status: str = Field(
        ...,
        description=(
            "'pending' — collection is in progress. "
            "'completed' — data is available (GET /metadata will return 200). "
            "'not_found' — no active task; URL may never have been requested."
        ),
    )


class ErrorResponse(BaseModel):
    """Structured error response."""

    detail: str = Field(..., description="Human-readable error description.")
    error_type: str = Field(
        default="error",
        description="Category of the error.",
    )


class MetadataListResponse(BaseModel):
    """Paginated list of metadata records."""

    items: list[MetadataResponse] = Field(
        default_factory=list, description="List of metadata records."
    )
    total: int = Field(..., description="Total number of matching records.")
    skip: int = Field(..., description="Number of records skipped.")
    limit: int = Field(..., description="Page size limit.")


class BulkResultItem(BaseModel):
    """Result for a single URL in a bulk collection."""

    url: str = Field(..., description="The target URL.")
    status: str = Field(..., description="'success' or 'failed'.")
    error: str | None = Field(None, description="Error message if failed.")


class BulkResponse(BaseModel):
    """Response for POST /metadata/bulk."""

    total: int = Field(..., description="Total URLs submitted.")
    succeeded: int = Field(..., description="Successful collections.")
    failed: int = Field(..., description="Failed collections.")
    results: list[BulkResultItem] = Field(default_factory=list, description="Per-URL results.")


# ── Internal / Database Models ──────────────────────────────────────────────


class MetadataDocument(BaseModel):
    """
    Internal representation of a metadata record stored in MongoDB.

    This is not exposed directly to the API; it is used by the repository
    layer to structure data going into and coming out of the database.
    """

    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    page_source: str = ""
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def to_mongo_dict(self) -> dict[str, Any]:
        """Serialize to a dict suitable for MongoDB insertion."""
        return self.model_dump()

    @classmethod
    def from_mongo_dict(cls, data: dict[str, Any]) -> "MetadataDocument":
        """Deserialize from a MongoDB document, dropping the _id field."""
        data.pop("_id", None)
        return cls(**data)
