import asyncio
import gc
import logging
import os
import signal

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class CustomProxyServer:
    def __init__(self, protocol: str = "shadowsocks"):
        self.server = None
        self.buffer_size = 65536
        self.protocol = protocol.lower()
        self.ss_server = None

    async def init(self):
        from shadowsocks_handler import ShadowsocksServer
        self.ss_server = ShadowsocksServer(self.buffer_size)

    async def custom_handler(self, reader, writer):
        if self.protocol == "shadowsocks":
            await self.ss_server.handle_connection(reader, writer)
            return

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

    host = os.getenv("PROXY_HOST", "0.0.0.0")
    port = int(os.getenv("PROXY_PORT", "1080"))
    protocol = os.getenv("PROXY_PROTOCOL", "shadowsocks")

    if protocol != "shadowsocks":
        logger.error(f"Unknown protocol: {protocol}")
        raise ValueError("PROXY_PROTOCOL must be 'shadowsocks'")

    proxy = CustomProxyServer(protocol=protocol)

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

    logger.info("🎉 Graceful shutdown complete, all connections closed")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
