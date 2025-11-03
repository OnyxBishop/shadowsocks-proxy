import asyncio
import gc
import logging
import os
import signal

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class CustomProxyServer:
    def __init__(self, protocol: str = "shadowsocks"):
        logger.info(f"[INIT] CustomProxyServer initializing with protocol={protocol}")
        self.server = None
        self.buffer_size = 65536
        self.protocol = protocol.lower()
        self.ss_server = None
        logger.info(f"[INIT] CustomProxyServer initialized, protocol={self.protocol}")

    async def init(self):
        logger.info("[INIT] Starting server initialization...")
        from shadowsocks_handler import ShadowsocksServer
        logger.info("[INIT] Imported ShadowsocksServer module")
        self.ss_server = ShadowsocksServer(buffer_size=self.buffer_size)
        logger.info("[INIT] ShadowsocksServer instance created")

    async def custom_handler(self, reader, writer):
        if self.protocol == "shadowsocks":
            await self.ss_server.handle_connection(reader, writer)
            return

    async def start(self, host: str = "0.0.0.0", port: int = 1080):
        logger.info(f"[START] Starting server on {host}:{port}...")
        await self.init()
        logger.info("[START] Initialization complete")

        logger.info(f"[START] Creating asyncio server on {host}:{port}...")
        self.server = await asyncio.start_server(
            self.custom_handler, host, port
        )
        logger.info(f"[START] Asyncio server created successfully")

        logger.info(f"🚀 {self.protocol.upper()} proxy server STARTED on {host}:{port}")
        logger.info(f"[START] Server is now accepting connections")

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
    logger.info("[MAIN] Starting proxy server in standalone mode...")
    await setup_optimizations()

    host = os.getenv("PROXY_HOST", "0.0.0.0")
    port = int(os.getenv("PROXY_PORT", "1080"))
    protocol = os.getenv("PROXY_PROTOCOL", "shadowsocks")
    
    logger.info(f"[MAIN] Configuration: host={host}, port={port}, protocol={protocol}")

    if protocol.lower() != "shadowsocks":
        logger.error(f"Unknown protocol: {protocol}")
        raise ValueError("PROXY_PROTOCOL must be 'shadowsocks'")

    proxy = CustomProxyServer(protocol=protocol)

    shutdown_event = asyncio.Event()

    def handle_shutdown(sig, frame):
        logger.info(f"\n⏹️ Received signal {sig}, initiating shutdown...")
        shutdown_event.set()

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    server_task = asyncio.create_task(proxy.start(host, port))
    logger.info("[MAIN] Server task created")

    await shutdown_event.wait()
    logger.info("[MAIN] Shutdown event received")

    logger.info("⏳ Cancelling server task...")
    server_task.cancel()

    try:
        await server_task
    except asyncio.CancelledError:
        logger.info("✅ Server task cancelled")

    logger.info("🎉 Graceful shutdown complete")


if __name__ == "__main__":
    asyncio.run(main())
