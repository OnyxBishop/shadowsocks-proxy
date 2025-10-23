import asyncio
import gc
import logging
import os
import signal

import redis.asyncio as redis
from domains_validator import validate_domains_file

from config.bandwidth_config import BandwidthConfig
from managers.user_connection_manager import UserConnectionManager
from managers.bandwidth_manager import BandwidthManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class CustomProxyServer:
    def __init__(self, redis_url: str = "redis://localhost:6379", protocol: str = "shadowsocks"):
        self.redis_url = redis_url
        self.redis_client = None
        self.connection_manager = None
        self.bandwidth_manager = None
        self.server = None
        self.buffer_size = BandwidthConfig.BUFFER_SIZE

        self.protocol = protocol.lower()
        self.ss_server = None

        # Global semaphore for limiting total connections
        self.connection_semaphore = asyncio.Semaphore(BandwidthConfig.MAX_TOTAL_CONNECTIONS)
        self.active_connections = 0

    async def init(self):
        # Validate domains.json on startup (fail-fast)
        try:
            validate_domains_file("./domains.json")
        except (FileNotFoundError, ValueError) as e:
            logger.error(f"CRITICAL: domains.json validation failed: {e}")
            raise SystemExit(1)

        self.redis_client = redis.from_url(self.redis_url)
        self.connection_manager = UserConnectionManager(self.redis_client)
        self.bandwidth_manager = BandwidthManager(self.connection_manager)

        from shadowsocks_handler import ShadowsocksServer
        self.ss_server = ShadowsocksServer(
            self.connection_manager,
            self.bandwidth_manager,
            self.buffer_size
        )

        logger.info("Shadowsocks protocol selected")

        asyncio.create_task(self.bandwidth_manager.start_monitoring())
        asyncio.create_task(self._run_connection_gc())
        asyncio.create_task(self._run_domains_watcher())
        logger.info("Proxy server initialized with hot reload for domains.json")

    async def _run_connection_gc(self):
        """Periodic cleanup of abandoned connections"""
        while True:
            await asyncio.sleep(300)  # Every 5 minutes
            try:
                await self.connection_manager.cleanup_abandoned_connections()
            except Exception as e:
                logger.error(f"Error in connection GC: {e}")

    async def _run_domains_watcher(self):
        """Periodic check for domains.json changes"""
        while True:
            await asyncio.sleep(10)  # Check every 10 seconds
            try:
                await self.connection_manager.reload_domains_if_changed()
            except Exception as e:
                logger.error(f"Error in domains watcher: {e}")

    async def custom_handler(self, reader, writer):
        # Limit total concurrent connections
        async with self.connection_semaphore:
            self.active_connections += 1
            try:
                logger.debug(f"Active connections: {self.active_connections}/{BandwidthConfig.MAX_TOTAL_CONNECTIONS}")

                if self.protocol == "shadowsocks":
                    await self.ss_server.handle_connection(reader, writer)
                    return
            finally:
                self.active_connections -= 1

    async def start(self, host: str = "0.0.0.0", port: int = 1080):
        await self.init()

        self.server = await asyncio.start_server(
            self.custom_handler, host, port
        )

        logger.info(f"{self.protocol.upper()} proxy server started on {host}:{port}")

        async with self.server:
            await self.server.serve_forever()


async def setup_optimizations():
    gc.collect()

    import socket
    socket.setdefaulttimeout(300)

    if hasattr(asyncio, 'set_event_loop_policy'):
        try:
            import uvloop
            asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
            logger.info("Using uvloop")
        except ImportError:
            pass


async def main():
    await setup_optimizations()

    # Configuration from environment variables
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    host = os.getenv("PROXY_HOST", "0.0.0.0")
    port = int(os.getenv("PROXY_PORT", "1080"))
    protocol = os.getenv("PROXY_PROTOCOL", "shadowsocks")

    if protocol != "shadowsocks":
        logger.error(f"Unknown protocol: {protocol}")
        raise ValueError("PROXY_PROTOCOL must be 'shadowsocks'")

    proxy = CustomProxyServer(redis_url=redis_url, protocol=protocol)

    # Graceful shutdown handler
    shutdown_event = asyncio.Event()

    def handle_shutdown(sig, frame):
        logger.info(f"Received signal {sig}, initiating graceful shutdown...")
        shutdown_event.set()

    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)

    server_task = asyncio.create_task(proxy.start(host=host, port=port))

    await shutdown_event.wait()

    logger.info("🛑 Shutdown signal received, starting graceful shutdown...")

    logger.info("⏳ Stopping proxy server...")
    if proxy.server:
        proxy.server.close()
        await proxy.server.wait_closed()
        logger.info("✅ Proxy server stopped")

    logger.info("⏳ Cancelling server_task...")
    server_task.cancel()
    try:
        await server_task
    except asyncio.CancelledError:
        logger.info("✅ Server_task cancelled")

    logger.info("⏳ Closing Redis connection...")
    if proxy.redis_client:
        await proxy.redis_client.aclose()
        logger.info("✅ Redis connection closed")

    logger.info("🎉 Graceful shutdown complete, all connections closed")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
