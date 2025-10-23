import asyncio
import logging
import time
from collections import defaultdict

from .user_connection_manager import UserConnectionManager
from ..config.bandwidth_config import BandwidthConfig
from ..entities.rate_limiter import DynamicRateLimiter

logger = logging.getLogger(__name__)


class BandwidthManager:
    def __init__(self, connection_manager: UserConnectionManager):
        self.connection_manager = connection_manager
        self.total_bandwidth = BandwidthConfig.TOTAL_BANDWIDTH
        self.reserved_bandwidth = BandwidthConfig.RESERVED_BANDWIDTH
        self.min_user_bandwidth = BandwidthConfig.MIN_USER_RATE
        self.optimal_bandwidth = BandwidthConfig.OPTIMAL_USER_RATE
        self.max_user_bandwidth = BandwidthConfig.MAX_USER_RATE

        self.bandwidth_stats = defaultdict(lambda: {'bytes': 0, 'timestamp': time.monotonic()})
        self.update_interval = 2.0

    async def get_active_users_count(self) -> int:
        active = 0
        async with self.connection_manager.connection_lock:
            for username, limiter in self.connection_manager.rate_limiters.items():
                if username in self.bandwidth_stats:
                    # 60 second window for YouTube chunks
                    if time.monotonic() - self.bandwidth_stats[username]['timestamp'] < 60:
                        active += 1
        return active

    async def calculate_fair_bandwidth(self) -> int:
        active_users = await self.get_active_users_count()

        if active_users == 0:
            return self.max_user_bandwidth

        available = self.total_bandwidth - self.reserved_bandwidth
        fair_share = available // active_users

        if fair_share < self.min_user_bandwidth:
            return self.min_user_bandwidth
        elif fair_share > self.max_user_bandwidth:
            return self.max_user_bandwidth
        else:
            return fair_share

    async def update_all_rates(self):
        fair_bandwidth = await self.calculate_fair_bandwidth()

        async with self.connection_manager.connection_lock:
            for username, limiter in self.connection_manager.rate_limiters.items():
                if isinstance(limiter, DynamicRateLimiter):
                    await limiter.update_rate(fair_bandwidth)

        logger.info(f"Updated rates: {len(self.connection_manager.rate_limiters)} users, "
                    f"{fair_bandwidth / 1024 / 1024:.1f} MB/s each")

    async def track_usage(self, username: str, bytes_count: int):
        self.bandwidth_stats[username]['bytes'] += bytes_count
        self.bandwidth_stats[username]['timestamp'] = time.monotonic()

    async def start_monitoring(self):
        while True:
            await asyncio.sleep(self.update_interval)
            await self.update_all_rates()

            current_time = time.monotonic()
            for username in list(self.bandwidth_stats.keys()):
                if current_time - self.bandwidth_stats[username]['timestamp'] > 30:
                    del self.bandwidth_stats[username]
