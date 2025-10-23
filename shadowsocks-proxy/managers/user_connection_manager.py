import asyncio
import json
import logging
import os
import re
import time
from collections import defaultdict
from typing import Dict, Set, Optional

import redis.asyncio as redis

from ..config.bandwidth_config import BandwidthConfig
from ..entities.rate_limiter import RateLimiter, DynamicRateLimiter

logger = logging.getLogger(__name__)


class UserConnectionManager:
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client

        self.user_connections: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))
        self.user_total_connections: Dict[str, int] = defaultdict(int)
        self.rate_limiters: Dict[str, RateLimiter] = {}
        self.user_last_activity: Dict[str, float] = {}

        self.max_conns_per_user = BandwidthConfig.MAX_CONNECTIONS_PER_USER
        self.max_conns_per_ip = BandwidthConfig.MAX_CONNECTIONS_PER_IP

        self.min_user_rate = BandwidthConfig.MIN_USER_RATE
        self.optimal_rate = BandwidthConfig.OPTIMAL_USER_RATE
        self.max_user_rate = BandwidthConfig.MAX_USER_RATE
        self.total_bandwidth = BandwidthConfig.TOTAL_BANDWIDTH

        # Load domain whitelist from JSON config
        self.allowed_domains = self._load_domain_whitelist()
        self.allowed_ips = {'8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1'}

        self.connection_lock = asyncio.Lock()
        self.connection_timeout = 600  # 10 minutes inactivity = abandoned

    def _load_domain_whitelist(self) -> re.Pattern:
        """Load domain whitelist from JSON config"""
        config_path = os.path.join(os.path.dirname(__file__), '..', 'domains.json')
        self.domains_config_path = config_path

        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)

            # Combine all domain categories
            all_domains = []
            all_domains.extend(config.get('domains', []))
            all_domains.extend(config.get('google_services', []))
            all_domains.extend(config.get('dns_servers', []))

            # Escape dots and create regex pattern
            escaped_domains = [d.replace('.', '\\.') for d in all_domains]
            pattern = '(?:^|\\.)(?:' + '|'.join(escaped_domains) + ')$'

            logger.info(f"Loaded {len(all_domains)} domains from whitelist config")

            self.domains_mtime = os.path.getmtime(config_path)

            return re.compile(pattern, re.IGNORECASE)

        except Exception as e:
            logger.error(f"Failed to load domains.json: {e}")
            self.domains_mtime = 0
            # Fallback to minimal set
            return re.compile(r'(?:^|\.)(?:youtube\.com|youtu\.be|googlevideo\.com|ytimg\.com)$', re.IGNORECASE)

    async def reload_domains_if_changed(self):
        """Check domains.json changes and reload if necessary"""
        try:
            if not hasattr(self, 'domains_config_path'):
                return

            current_mtime = os.path.getmtime(self.domains_config_path)

            if current_mtime > self.domains_mtime:
                logger.info("[Hot Reload] Detected changes in domains.json, reloading...")
                new_pattern = self._load_domain_whitelist()

                async with self.connection_lock:
                    self.allowed_domains = new_pattern

                logger.info("[Hot Reload] domains.json successfully reloaded")

        except Exception as e:
            logger.error(f"[Hot Reload] Failed to reload domains.json: {e}")

    def is_domain_allowed(self, domain: str) -> bool:
        return bool(self.allowed_domains.search(domain))

    def is_ip_allowed(self, ip_str: str) -> bool:
        """Check if IP is allowed (DNS servers only)"""
        return ip_str in self.allowed_ips

    async def can_connect(self, username: str, peer_ip: str, conn_id: str) -> bool:
        async with self.connection_lock:
            total_conns = self.user_total_connections[username]
            if total_conns >= self.max_conns_per_user:
                return False

            ip_conns = self.user_connections[username][peer_ip]
            if len(ip_conns) >= self.max_conns_per_ip:
                return False

            self.user_connections[username][peer_ip].add(conn_id)
            self.user_total_connections[username] += 1
            self.user_last_activity[username] = time.monotonic()

            if username not in self.rate_limiters:
                self.rate_limiters[username] = DynamicRateLimiter(
                    self.optimal_rate,
                    self.min_user_rate,
                    self.optimal_rate * 2
                )

            return True

    async def disconnect(self, username: str, peer_ip: str, connection_id: str):
        async with self.connection_lock:
            if username in self.user_connections and peer_ip in self.user_connections[username]:
                self.user_connections[username][peer_ip].discard(connection_id)

                if not self.user_connections[username][peer_ip]:
                    del self.user_connections[username][peer_ip]

                self.user_total_connections[username] = max(0, self.user_total_connections[username] - 1)

                if self.user_total_connections[username] == 0:
                    self.user_connections.pop(username, None)
                    self.user_total_connections.pop(username, None)
                    self.rate_limiters.pop(username, None)

    def get_rate_limiter(self, username: str) -> Optional[RateLimiter]:
        return self.rate_limiters.get(username)

    async def cleanup_abandoned_connections(self):
        """Garbage collection for connections that didn't call disconnect()"""
        async with self.connection_lock:
            now = time.monotonic()
            abandoned_users = []

            for username, last_active in self.user_last_activity.items():
                if now - last_active > self.connection_timeout:
                    abandoned_users.append(username)

            for username in abandoned_users:
                logger.warning(f"[GC] Cleaning up abandoned connections for {username}")
                self.user_connections.pop(username, None)
                self.user_total_connections.pop(username, None)
                self.rate_limiters.pop(username, None)
                self.user_last_activity.pop(username, None)

            if abandoned_users:
                logger.info(f"[GC] Cleaned {len(abandoned_users)} abandoned users")
