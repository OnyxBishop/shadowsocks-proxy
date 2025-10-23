import asyncio
import time
from typing import Optional


class RateLimiter:
    def __init__(self, rate_bytes_per_sec: int, burst_size: Optional[int] = None):
        self.rate = rate_bytes_per_sec
        self.burst = burst_size or rate_bytes_per_sec * 2
        self.tokens = self.burst
        self.last_update = time.monotonic()
        self.lock = asyncio.Lock()

    async def consume(self, bytes_count: int) -> float:
        async with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.last_update = now

            if self.tokens >= bytes_count:
                self.tokens -= bytes_count
                return 0.0

            needed_tokens = bytes_count - self.tokens
            wait_time = needed_tokens / self.rate
            self.tokens = 0
            return wait_time


class DynamicRateLimiter(RateLimiter):
    def __init__(self, initial_rate: int, min_rate: int, max_rate: int):
        super().__init__(initial_rate)
        self.min_rate = min_rate
        self.max_rate = max_rate
        self.current_rate = initial_rate

    async def update_rate(self, new_rate: int):
        async with self.lock:
            new_rate = max(self.min_rate, min(self.max_rate, new_rate))

            if self.current_rate > 0:
                self.tokens = self.tokens * new_rate / self.current_rate

            self.current_rate = new_rate
            self.rate = new_rate
            self.burst = new_rate * 2
