"""Shared monotonic token bucket with a one-token burst capacity."""

import asyncio
import time


class TokenBucket:
    def __init__(self, rate: float) -> None:
        if rate <= 0:
            raise ValueError("Rate must be positive")
        self.rate = rate
        self._tokens = 1.0
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(1.0, self._tokens + (now - self._updated) * self.rate)
                self._updated = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                await asyncio.sleep((1.0 - self._tokens) / self.rate)
