"""WebSocket fan-out to every connected dashboard."""
from __future__ import annotations

import json
from typing import Any

from fastapi import WebSocket


class Hub:
    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.clients.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self.clients.discard(ws)

    async def broadcast(self, message: dict[str, Any]) -> None:
        text = json.dumps(message)
        for ws in list(self.clients):
            try:
                await ws.send_text(text)
            except Exception:  # client went away mid-send
                self.disconnect(ws)


hub = Hub()
