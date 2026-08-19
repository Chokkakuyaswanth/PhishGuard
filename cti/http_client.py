"""Shared httpx client for CTI adapters.

Constructing an AsyncClient builds an SSL context, which takes ~500 ms and runs
synchronously on the event loop. Doing that per request blew the scan latency
budget and starved concurrent DNS lookups, so every adapter reuses one client.
"""
import asyncio

import httpx

_client: httpx.AsyncClient | None = None
_lock = asyncio.Lock()


async def get_client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        async with _lock:
            if _client is None or _client.is_closed:
                _client = httpx.AsyncClient(
                    timeout=10.0,
                    limits=httpx.Limits(max_connections=32, max_keepalive_connections=16),
                    headers={"User-Agent": "PhishGuard/1.0"},
                )
    return _client


async def warmup() -> None:
    """Pay the SSL-context cost at startup instead of on a user's first scan."""
    await get_client()


async def aclose() -> None:
    global _client
    if _client is not None and not _client.is_closed:
        await _client.aclose()
    _client = None
