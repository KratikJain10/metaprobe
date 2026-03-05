"""
Tests for the middleware stack.

Tests correlation ID propagation and timing header.
"""

import pytest


@pytest.mark.asyncio
class TestMiddleware:
    """Tests for custom middleware."""

    async def test_correlation_id_generated(self, test_client):
        """Response should include a generated X-Correlation-ID."""
        response = await test_client.get("/health")
        assert "x-correlation-id" in response.headers
        # Should be a valid UUID format (8-4-4-4-12)
        correlation_id = response.headers["x-correlation-id"]
        assert len(correlation_id) == 36

    async def test_correlation_id_echoed(self, test_client):
        """Client-provided correlation ID should be echoed back."""
        custom_id = "my-custom-trace-123"
        response = await test_client.get(
            "/health",
            headers={"X-Correlation-ID": custom_id},
        )
        assert response.headers.get("x-correlation-id") == custom_id

    async def test_timing_header_present(self, test_client):
        """Response should include X-Process-Time header."""
        response = await test_client.get("/health")
        assert "x-process-time" in response.headers
        timing = response.headers["x-process-time"]
        assert timing.endswith("ms")

    async def test_health_returns_dependencies(self, test_client):
        """Health check should return dependency statuses."""
        response = await test_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "dependencies" in data
        assert "mongodb" in data["dependencies"]
        assert "redis" in data["dependencies"]
        assert "version" in data
        assert "uptime_seconds" in data
