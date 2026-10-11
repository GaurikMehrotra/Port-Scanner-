import asyncio
import time

from labscan.ratelimit import TokenBucket


async def test_shared_rate_limit() -> None:
    bucket = TokenBucket(20)
    tick = time.monotonic()
    await asyncio.gather(*(bucket.acquire() for _ in range(5)))
    assert time.monotonic() - tick >= 0.19
