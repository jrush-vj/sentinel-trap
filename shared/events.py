"""Event construction + fire-and-forget delivery to the monitor (see contracts/events.md)."""
from __future__ import annotations

import asyncio
import logging
import uuid
from collections import deque
from typing import Any

import httpx

from shared.util import env_str, now_iso, truncate

log = logging.getLogger("events")

BUFFER_LIMIT = 500


def make_event(
    action: str,
    *,
    session_id: str = "system",
    fingerprint: str = "",
    attacker_ip: str = "",
    channel: str = "web",
    payload: str = "",
    verdict: str = "clean",
    risk: int = 0,
    rule_id: str | None = None,
    detail: str = "",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "ts": now_iso(),
        "session_id": session_id,
        "fingerprint": fingerprint,
        "attacker_ip": attacker_ip,
        "channel": channel,
        "action": action,
        "payload": truncate(payload or ""),
        "verdict": verdict,
        "risk": max(0, min(10, int(risk))),
        "rule_id": rule_id,
        "detail": detail,
    }
    if extra:
        event["extra"] = extra
    return event


class EventSender:
    """Buffers events in memory (bounded) and ships them to the monitor in the background.

    `emit()` never blocks and never raises, so request handling is never slowed by the monitor.
    """

    def __init__(self, monitor_url: str | None = None) -> None:
        self.url = (monitor_url or env_str("MONITOR_URL", "http://monitor:9000")).rstrip("/") + "/events"
        self.buffer: deque[dict[str, Any]] = deque(maxlen=BUFFER_LIMIT)
        self._wake = asyncio.Event()
        self._task: asyncio.Task | None = None

    def emit(self, event: dict[str, Any]) -> None:
        self.buffer.append(event)  # oldest events drop off when the buffer is full
        self._wake.set()

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()

    async def _run(self) -> None:
        async with httpx.AsyncClient(timeout=3.0) as client:
            while True:
                await self._wake.wait()
                self._wake.clear()
                while self.buffer:
                    batch = list(self.buffer)[:50]
                    try:
                        resp = await client.post(self.url, json=batch)
                        resp.raise_for_status()
                    except Exception as exc:  # monitor down: keep buffered, retry shortly
                        log.debug("monitor unreachable (%s); %d buffered", exc, len(self.buffer))
                        await asyncio.sleep(2)
                        continue
                    sent = {event["id"] for event in batch}
                    while self.buffer and self.buffer[0]["id"] in sent:
                        self.buffer.popleft()
