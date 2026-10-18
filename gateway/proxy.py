"""Thin async reverse proxy to the app or honeypot. Body is read fully before forwarding so the
gateway can inspect it; the upstream response is relayed verbatim (status, headers, body)."""
from __future__ import annotations

import httpx
from fastapi import Request
from fastapi.responses import Response

# Hop-by-hop headers that must not be forwarded.
_DROP = {"host", "content-length", "connection", "keep-alive", "transfer-encoding", "upgrade"}

_client: httpx.AsyncClient | None = None


def client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=3.0), follow_redirects=False)
    return _client


async def forward(request: Request, upstream_base: str, body: bytes, extra_headers: dict[str, str] | None = None) -> Response:
    url = upstream_base.rstrip("/") + request.url.path
    headers = {k: v for k, v in request.headers.items() if k.lower() not in _DROP}
    if extra_headers:
        headers.update(extra_headers)
    upstream = await client().request(
        request.method, url, params=request.query_params, headers=headers, content=body,
    )
    resp_headers = {k: v for k, v in upstream.headers.items() if k.lower() not in _DROP}
    return Response(content=upstream.content, status_code=upstream.status_code,
                    headers=resp_headers, media_type=upstream.headers.get("content-type"))


async def aclose() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None
