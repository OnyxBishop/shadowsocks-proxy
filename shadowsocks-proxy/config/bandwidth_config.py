"""Bandwidth configuration constants"""


class BandwidthConfig:
    """Bandwidth configuration constants"""
    # Bandwidth in bytes/sec
    MIN_USER_RATE = 320 * 1024          # 320 KB/s = 2.5 Mbps (minimum for 720p)
    OPTIMAL_USER_RATE = 640 * 1024      # 640 KB/s = 5 Mbps (HD 1080p)
    MAX_USER_RATE = 2560 * 1024         # 2560 KB/s = 20 Mbps (4K)
    TOTAL_BANDWIDTH = 625 * 1024 * 1024 // 8  # 625 Mbps → bytes/sec
    RESERVED_BANDWIDTH = 50 * 1024 * 1024 // 8  # 50 Mbps for system

    # Connection limits
    MAX_CONNECTIONS_PER_USER = 12
    MAX_CONNECTIONS_PER_IP = 8
    MAX_TOTAL_CONNECTIONS = 5000

    # I/O buffer size
    BUFFER_SIZE = 256 * 1024  # 256 KB (optimal for streaming)
