"""
WebSocket route for real-time metadata collection.

Provides a live, bidirectional connection where clients can:
1. Send URLs as JSON messages
2. Receive real-time progress updates as each URL is collected
3. Get immediate error feedback for failed collections
"""

import contextlib
import json
import logging
from datetime import UTC, datetime

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.services.collector import CollectionError, collect_metadata

logger = logging.getLogger(__name__)

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/collect")
async def websocket_collect(websocket: WebSocket):
    """
    WebSocket endpoint for real-time metadata collection.

    Protocol:
    - Client sends: {"url": "https://example.com"}
    - Server responds with progress messages:
      - {"type": "started", "url": "...", "timestamp": "..."}
      - {"type": "completed", "url": "...", "metadata": {...}, "timestamp": "..."}
      - {"type": "error", "url": "...", "error": "...", "timestamp": "..."}
    - Client can send multiple URLs — each is processed sequentially.
    - Send {"type": "ping"} to keep the connection alive.
    """
    await websocket.accept()
    logger.info("WebSocket connection established")

    try:
        while True:
            # Wait for a message from the client
            raw = await websocket.receive_text()

            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                await websocket.send_json({
                    "type": "error",
                    "error": "Invalid JSON. Expected: {\"url\": \"https://...\"}",
                    "timestamp": datetime.now(UTC).isoformat(),
                })
                continue

            # Handle ping
            if message.get("type") == "ping":
                await websocket.send_json({
                    "type": "pong",
                    "timestamp": datetime.now(UTC).isoformat(),
                })
                continue

            # Extract URL
            url = message.get("url")
            if not url:
                await websocket.send_json({
                    "type": "error",
                    "error": "Missing 'url' field.",
                    "timestamp": datetime.now(UTC).isoformat(),
                })
                continue

            # Send start notification
            await websocket.send_json({
                "type": "started",
                "url": url,
                "timestamp": datetime.now(UTC).isoformat(),
            })

            # Collect metadata
            try:
                document = await collect_metadata(url)
                await websocket.send_json({
                    "type": "completed",
                    "url": url,
                    "metadata": {
                        "headers": document.headers,
                        "cookies": document.cookies,
                        "page_source_length": len(document.page_source),
                        "collected_at": document.collected_at.isoformat(),
                    },
                    "timestamp": datetime.now(UTC).isoformat(),
                })
                logger.info("WebSocket — collected metadata for %s", url)

            except CollectionError as exc:
                await websocket.send_json({
                    "type": "error",
                    "url": url,
                    "error": exc.reason,
                    "timestamp": datetime.now(UTC).isoformat(),
                })
                logger.warning("WebSocket — collection failed for %s: %s", url, exc.reason)

    except WebSocketDisconnect:
        logger.info("WebSocket connection closed")
    except Exception:
        logger.exception("WebSocket unexpected error")
        with contextlib.suppress(Exception):
            await websocket.close()
