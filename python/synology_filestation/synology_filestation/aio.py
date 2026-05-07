"""Async API for the Synology FileStation client.

Mirrors the sync ``synology_filestation.Client`` surface but every method
returns a coroutine. Backed by ``pyo3-async-runtimes`` on the Rust side, so
the underlying Tokio reactor is shared across all async clients in a process.

Usage::

    import asyncio
    from synology_filestation.aio import AsyncClient

    async def main():
        nas = await AsyncClient.login("nas.example.com", 5001, "alice", "secret")
        try:
            data = await nas.download("/photos/2026/img.orf")
        finally:
            await nas.logout()

    asyncio.run(main())
"""
from __future__ import annotations

from ._native import AsyncClient

__all__ = ["AsyncClient"]
