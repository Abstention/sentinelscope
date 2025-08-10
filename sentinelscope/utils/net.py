from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager


@asynccontextmanager
async def cancel_on_timeout(timeout_seconds: float):
    try:
        yield
    except asyncio.TimeoutError:
        raise


async def gather_with_concurrency(limit: int, *tasks):
    semaphore = asyncio.Semaphore(limit)

    async def sem_task(coro):
        async with semaphore:
            return await coro

    return await asyncio.gather(*(sem_task(t) for t in tasks))

