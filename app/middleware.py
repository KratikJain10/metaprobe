"""
Custom middleware for request processing.

Provides:
- Correlation ID generation and propagation for request tracing
- Request timing with X-Process-Time header
- Structured JSON logging with correlation context
"""

import logging
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)

# Header name for correlation ID
CORRELATION_ID_HEADER = "X-Correlation-ID"


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """
    Inject a unique correlation ID into every request/response cycle.

    If the client sends an X-Correlation-ID header, it is reused.
    Otherwise, a new UUID is generated. The ID is attached to the
    response headers for end-to-end tracing.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        correlation_id = request.headers.get(CORRELATION_ID_HEADER, str(uuid.uuid4()))
        # Store on request state for downstream access
        request.state.correlation_id = correlation_id

        response = await call_next(request)
        response.headers[CORRELATION_ID_HEADER] = correlation_id
        return response


class TimingMiddleware(BaseHTTPMiddleware):
    """
    Measure request processing time and expose via X-Process-Time header.

    Value is in milliseconds, rounded to 2 decimal places.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start = time.perf_counter()
        response = await call_next(request)
        duration_ms = (time.perf_counter() - start) * 1000
        response.headers["X-Process-Time"] = f"{duration_ms:.2f}ms"
        return response
