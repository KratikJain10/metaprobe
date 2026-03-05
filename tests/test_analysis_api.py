"""
Integration tests for the security analysis API endpoints.

Tests the full POST /analyze and GET /analyze flow.
"""

import pytest
import respx
from httpx import Response

from app.models.schemas import MetadataDocument


@pytest.mark.asyncio
class TestPostAnalyze:
    """Tests for POST /analyze endpoint."""

    @respx.mock
    async def test_analyze_valid_url_returns_report(self, test_client):
        """POST /analyze with a valid URL should return a security report."""
        url = "https://httpbin.org/html"
        html = "<html><body><h1>Hello</h1></body></html>"

        respx.get(url).mock(
            return_value=Response(
                200,
                text=html,
                headers={"content-type": "text/html", "server": "nginx"},
            )
        )

        response = await test_client.post(
            "/analyze",
            json={"url": url},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["url"] == url
        assert "grade" in data
        assert "score" in data
        assert "findings" in data
        assert "summary" in data
        assert "technologies" in data
        assert "analyzed_at" in data
        assert data["score"] >= 0
        assert data["score"] <= 100

    async def test_analyze_invalid_url_returns_422(self, test_client):
        """POST /analyze with an invalid URL should return 422."""
        response = await test_client.post(
            "/analyze",
            json={"url": "not-a-url"},
        )
        assert response.status_code == 422

    @respx.mock
    async def test_analyze_unreachable_url_returns_502(self, test_client):
        """POST /analyze with an unreachable URL should return 502."""
        import httpx

        url = "https://unreachable.test"
        respx.get(url).mock(side_effect=httpx.ConnectError("connection refused"))

        response = await test_client.post(
            "/analyze",
            json={"url": url},
        )
        assert response.status_code == 502


@pytest.mark.asyncio
class TestGetAnalyze:
    """Tests for GET /analyze endpoint."""

    async def test_analyze_stored_metadata(self, test_client, repository):
        """GET /analyze with stored metadata should return analysis."""
        from datetime import datetime, timezone

        url = "https://stored.example.com"
        doc = MetadataDocument(
            url=url,
            headers={"content-type": "text/html", "x-frame-options": "DENY"},
            cookies={},
            page_source="<html></html>",
            collected_at=datetime.now(timezone.utc),
        )
        await repository.upsert_metadata(doc)

        response = await test_client.get("/analyze", params={"url": url})

        assert response.status_code == 200
        data = response.json()
        assert data["url"] == url
        assert "grade" in data
        assert isinstance(data["findings"], list)

    async def test_analyze_missing_url_returns_404(self, test_client):
        """GET /analyze for a URL with no stored metadata should return 404."""
        response = await test_client.get(
            "/analyze", params={"url": "https://never-stored.example.com"}
        )
        assert response.status_code == 404
