"""
Tests for bulk collection and pagination endpoints.
"""

from datetime import UTC

import pytest
import respx
from httpx import Response

from app.models.schemas import MetadataDocument


@pytest.mark.asyncio
class TestBulkCollect:
    """Tests for POST /metadata/bulk endpoint."""

    @respx.mock
    async def test_bulk_collect_success(self, test_client):
        """Bulk collect should return results for each URL."""
        urls = ["https://site1.example.com", "https://site2.example.com"]

        for url in urls:
            respx.get(url).mock(
                return_value=Response(
                    200, text="<html></html>", headers={"content-type": "text/html"}
                )
            )

        response = await test_client.post(
            "/metadata/bulk",
            json={"urls": urls},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2
        assert data["succeeded"] == 2
        assert data["failed"] == 0
        assert len(data["results"]) == 2

    @respx.mock
    async def test_bulk_collect_partial_failure(self, test_client):
        """Bulk collect should handle partial failures."""
        import httpx

        respx.get("https://good.example.com").mock(return_value=Response(200, text="<html></html>"))
        respx.get("https://bad.example.com").mock(
            side_effect=httpx.ConnectError("connection refused")
        )

        response = await test_client.post(
            "/metadata/bulk",
            json={"urls": ["https://good.example.com", "https://bad.example.com"]},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["succeeded"] == 1
        assert data["failed"] == 1

    async def test_bulk_empty_list_returns_422(self, test_client):
        """Empty URL list should return validation error."""
        response = await test_client.post("/metadata/bulk", json={"urls": []})
        assert response.status_code == 422


@pytest.mark.asyncio
class TestListMetadata:
    """Tests for GET /metadata/list endpoint."""

    async def test_list_empty(self, test_client):
        """List should return empty results with zero total."""
        response = await test_client.get("/metadata/list")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["items"] == []

    async def test_list_with_data(self, test_client, repository):
        """List should return stored metadata."""
        from datetime import datetime

        doc = MetadataDocument(
            url="https://listed.example.com",
            headers={"content-type": "text/html"},
            cookies={},
            page_source="<html></html>",
            collected_at=datetime.now(UTC),
        )
        await repository.upsert_metadata(doc)

        response = await test_client.get("/metadata/list")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 1
        urls = [item["url"] for item in data["items"]]
        assert "https://listed.example.com" in urls

    async def test_list_pagination(self, test_client, repository):
        """Pagination should limit results correctly."""
        from datetime import datetime

        for i in range(5):
            doc = MetadataDocument(
                url=f"https://page{i}.example.com",
                headers={},
                cookies={},
                page_source="",
                collected_at=datetime.now(UTC),
            )
            await repository.upsert_metadata(doc)

        response = await test_client.get("/metadata/list", params={"limit": 2, "skip": 0})
        assert response.status_code == 200
        data = response.json()
        assert len(data["items"]) == 2
        assert data["total"] >= 5

    async def test_list_search_filter(self, test_client, repository):
        """Search should filter by URL substring."""
        from datetime import datetime

        for url in ["https://apple.example.com", "https://banana.example.com"]:
            doc = MetadataDocument(
                url=url,
                headers={},
                cookies={},
                page_source="",
                collected_at=datetime.now(UTC),
            )
            await repository.upsert_metadata(doc)

        response = await test_client.get("/metadata/list", params={"search": "apple"})
        assert response.status_code == 200
        data = response.json()
        assert all("apple" in item["url"] for item in data["items"])


@pytest.mark.asyncio
class TestDeleteMetadata:
    """Tests for DELETE /metadata endpoint."""

    async def test_delete_existing(self, test_client, repository):
        """Delete should remove stored metadata and return success."""
        from datetime import datetime

        url = "https://delete-me.example.com"
        doc = MetadataDocument(
            url=url,
            headers={},
            cookies={},
            page_source="",
            collected_at=datetime.now(UTC),
        )
        await repository.upsert_metadata(doc)

        response = await test_client.delete("/metadata", params={"url": url})
        assert response.status_code == 200
        assert "deleted" in response.json()["message"].lower()

    async def test_delete_nonexistent_returns_404(self, test_client):
        """Delete should return 404 for non-existent URL."""
        response = await test_client.delete(
            "/metadata", params={"url": "https://ghost.example.com"}
        )
        assert response.status_code == 404


@pytest.mark.asyncio
class TestExportMetadata:
    """Tests for GET /metadata/export endpoint."""

    async def test_export_json(self, test_client, repository):
        """Export in JSON should return valid JSON array."""
        from datetime import datetime

        doc = MetadataDocument(
            url="https://export.example.com",
            headers={"content-type": "text/html"},
            cookies={},
            page_source="<html></html>",
            collected_at=datetime.now(UTC),
        )
        await repository.upsert_metadata(doc)

        response = await test_client.get("/metadata/export", params={"format": "json"})
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1

    async def test_export_csv(self, test_client, repository):
        """Export in CSV should return CSV content."""
        from datetime import datetime

        doc = MetadataDocument(
            url="https://csvexport.example.com",
            headers={"content-type": "text/html"},
            cookies={},
            page_source="<html></html>",
            collected_at=datetime.now(UTC),
        )
        await repository.upsert_metadata(doc)

        response = await test_client.get("/metadata/export", params={"format": "csv"})
        assert response.status_code == 200
        assert "csv" in response.headers.get("content-type", "").lower()
