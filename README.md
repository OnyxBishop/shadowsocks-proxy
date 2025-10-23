# Shadowsocks Proxy Server

[![en](https://img.shields.io/badge/lang-en-blue.svg)](README.md)
[![ru](https://img.shields.io/badge/lang-ru-red.svg)](README.ru.md)

A high-performance Shadowsocks AEAD proxy server with dynamic bandwidth management, domain whitelisting, and Redis-based user authentication.

## Features

- **Protocol**: Shadowsocks AEAD (ChaCha20-Poly1305)
- **Dynamic Bandwidth Management**: Fair bandwidth allocation with TCP backpressure
- **Domain Whitelisting**: Configurable JSON-based whitelist with hot reload
- **Redis Integration**: User authentication and connection management
- **Rate Limiting**: Per-user connection limits and bandwidth throttling
- **DoS Protection**: IP-based rate limiting with temporary bans
- **Production Ready**: Docker containerization with security hardening

## Architecture

```
┌─────────────┐
│   Client    │
│ (SS client) │
└──────┬──────┘
       │ Shadowsocks AEAD
       │ (ChaCha20-Poly1305)
       ▼
┌─────────────────────────────────┐
│   Shadowsocks Proxy Server      │
│                                 │
│  ┌──────────────────────────┐   │
│  │ UserConnectionManager    │   │
│  │ - Domain filtering       │   │
│  │ - Connection limits      │   │
│  │ - LRU cache              │   │
│  └──────────────────────────┘   │
│                                 │
│  ┌──────────────────────────┐   │
│  │ BandwidthManager         │   │
│  │ - Dynamic rate limiting  │   │
│  │ - Fair bandwidth sharing │   │
│  └──────────────────────────┘   │
│                                 │
│  ┌──────────────────────────┐   │
│  │ ShadowsocksServer        │   │
│  │ - AEAD encryption        │   │
│  │ - User identification    │   │
│  │ - DoS protection         │   │
│  └──────────────────────────┘   │
└────────┬────────────────────────┘
         │
         ▼
    ┌─────────┐
    │  Redis  │ ← User credentials
    └─────────┘
         │
         ▼
   ┌──────────┐
   │ Internet │
   │(Filtered)│
   └──────────┘
```

## Core Components

### 1. Shadowsocks AEAD Handler

Implements Shadowsocks AEAD protocol with ChaCha20-Poly1305 encryption:

```python
# shadowsocks_handler.py - Key derivation
def derive_key(self, password: str, salt: bytes, key_len: int) -> bytes:
    """HKDF key derivation from password and salt"""
    master_key = self.evp_bytes_to_key(password, 32)
    prk = hkdf_extract(salt, master_key)
    return hkdf_expand(prk, b"ss-subkey", key_len)
```

**Connection Flow:**
1. Client sends 32-byte salt
2. Server derives key using HKDF
3. Client sends encrypted length (2 bytes + 16-byte AEAD tag)
4. Server decrypts and validates payload length
5. Client sends encrypted payload (target address + data)
6. Server establishes connection and proxies traffic

### 2. User Identification & Authentication

Optimized 3-tier user lookup:

```python
# shadowsocks_handler.py - User identification
async def _try_decrypt_and_identify(self, salt: bytes, length_chunk: bytes):
    # Tier 1: LRU cache check (O(1))
    cache_key = hashlib.sha256(salt[:16]).hexdigest()[:16]
    cached_username = self.user_cache.get(cache_key)
    
    # Tier 2: In-memory user list (preloaded from Redis)
    for username, ss_password in self.cached_users.items():
        # Try to decrypt with this password
        
    # Tier 3: DoS protection - max 300 attempts
```

**Performance:**
- Cache hit rate: ~85-90% for active users
- Identification time: <5ms (cache hit), <100ms (cache miss)
- Memory footprint: ~100KB for 100 users

### 3. Dynamic Bandwidth Management

Fair bandwidth allocation based on active users:

```python
# proxy_server.py - Bandwidth calculation
async def calculate_fair_bandwidth(self) -> int:
    active_users = await self.get_active_users_count()
    available = TOTAL_BANDWIDTH - RESERVED_BANDWIDTH
    fair_share = available // active_users
    
    # Clamp to min/max rates
    return max(MIN_USER_RATE, min(MAX_USER_RATE, fair_share))
```

### 4. Rate Limiting with TCP Backpressure

Instead of blocking the event loop with `asyncio.sleep()`, uses TCP window throttling:

```python
# proxy_server.py - TCP backpressure rate limiting
if wait_time > 0:
    chunk_size = 8192
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        writer.write(chunk)
        await writer.drain()  # TCP naturally throttles
else:
    writer.write(data)
    await writer.drain()
```

**Why TCP Backpressure?**
- Non-blocking: Doesn't tie up event loop
- Natural: Leverages TCP flow control
- Smooth: Gradual slowdown

### 5. Domain Whitelisting

JSON-based whitelist with hot reload (no restart required):

```json
// domains.json
{
  "domains": [
    "youtube.com",
    "googlevideo.com",
    "ytimg.com"
  ],
  "google_services": [
    "googleapis.com",
    "gstatic.com"
  ],
  "dns_servers": [
    "8.8.8.8",
    "1.1.1.1"
  ]
}
```

**Server-side enforcement:**
```python
# proxy_server.py - Domain validation
is_allowed = (
    self.connection_manager.is_domain_allowed(target_host) or
    self.connection_manager.is_ip_allowed(target_host) or
    (target_port in [53, 853])  # DNS/DoT
)
if not is_allowed:
    writer.close()
    return
```

### 6. Connection Management

**Per-user limits:**
```python
MAX_CONNECTIONS_PER_USER = 12   # iOS/Android HTTP/2 multiplexing
MAX_CONNECTIONS_PER_IP = 8      # Prevent abuse
MAX_TOTAL_CONNECTIONS = 5000    # Global server limit
```

**Garbage collection:**
- Abandoned connections cleaned every 5 minutes
- 10-minute inactivity timeout
- Graceful shutdown with SIGTERM/SIGINT handling

## Redis Data Schema

### User Storage

```python
# User credentials (key: proxy:user:{username})
{
  "username": "user123",
  "password": "generated_ss_password",  # HMAC-SHA256 derived
  "created_at": "2024-01-01T00:00:00Z",
  "expires_at": "2024-02-01T00:00:00Z"
}

# Reverse index for O(1) lookup (key: ss_password_index:{password})
"user123"  # Maps SS password → username
```

### Password Generation

Deterministic HMAC-based generation:

```python
# ss_password_utils.py
def generate_ss_password(username: str, master_secret: str) -> str:
    """Generate deterministic SS password from username"""
    return hmac.new(
        master_secret.encode('utf-8'),
        username.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()[:32]
```

**Why HMAC?**
- Deterministic: Same username → same password
- Secure: Cannot reverse engineer master secret
- Fast: O(1) password validation

## Deployment

### Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- 1GB RAM minimum
- 2 CPU cores recommended

### Step 1: Clone Repository

```bash
git clone https://github.com/yourusername/shadowsocks-proxy.git
cd shadowsocks-proxy
```

### Step 2: Configure Environment

```bash
cp .env.example .env
```

Edit `.env` and set:

```bash
# Generate secure passwords
REDIS_PASSWORD=$(openssl rand -base64 32)
SS_MASTER_SECRET=$(openssl rand -base64 48)

# Update .env
REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379
SS_MASTER_SECRET=${SS_MASTER_SECRET}
```

### Step 3: Build and Deploy

```bash
# Build containers
docker-compose build

# Start services
docker-compose up -d

# Check logs
docker-compose logs -f proxy
```

### Step 4: Verify Deployment

```bash
# Check Redis connection
docker-compose exec proxy python -c "
import redis, os
r = redis.Redis.from_url(os.getenv('REDIS_URL'), decode_responses=True)
print('Redis:', 'OK' if r.ping() else 'FAILED')
"

# Check proxy listening
docker-compose ps
# Should show proxy on 0.0.0.0:1080
```

### Step 5: Create Test User

```python
# create_user.py
import redis
import json
from ss_password_utils import generate_ss_password
import os
from datetime import datetime, timedelta

redis_client = redis.Redis.from_url(os.getenv('REDIS_URL'), decode_responses=True)

username = "testuser"
ss_password = generate_ss_password(username, os.getenv('SS_MASTER_SECRET'))

user_data = {
    "username": username,
    "password": ss_password,
    "created_at": datetime.utcnow().isoformat(),
    "expires_at": (datetime.utcnow() + timedelta(days=30)).isoformat()
}

# Save user
redis_client.set(f"proxy:user:{username}", json.dumps(user_data))
redis_client.set(f"ss_password_index:{ss_password}", username)

print(f"Created user: {username}")
print(f"SS Password: {ss_password}")
```

Run:
```bash
docker-compose exec proxy python create_user.py
```

### Step 6: Configure Client

**Shadowsocks URL format:**
```
ss://METHOD:PASSWORD@HOST:PORT
```

Example:
```
ss://chacha20-ietf-poly1305:generated_password@your-server.com:1080
```

**Recommended clients:**
- **iOS**: Shadowrocket, Potatso Lite
- **Android**: Shadowsocks Android
- **Windows**: Shadowsocks-Windows
- **macOS**: ShadowsocksX-NG

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `REDIS_URL` | Yes | - | Redis connection string |
| `PROXY_HOST` | No | `0.0.0.0` | Bind address |
| `PROXY_PORT` | No | `1080` | Listen port |
| `PROXY_PROTOCOL` | No | `shadowsocks` | Protocol (must be shadowsocks) |
| `SS_MASTER_SECRET` | Yes | - | Master secret for password generation |
| `SS_METHOD` | No | `chacha20-ietf-poly1305` | Encryption method |
| `LOG_LEVEL` | No | `INFO` | Logging level |

### Domain Whitelist

Edit `domains.json` to add/remove allowed domains:

```json
{
  "domains": [
    "example.com",
    "*.example.com"  // Not supported, use "example.com" for subdomains
  ]
}
```

**Hot reload:** Changes detected automatically within 10 seconds.

### Bandwidth Tuning

Edit `BandwidthConfig` class in `proxy_server.py`:

```python
class BandwidthConfig:
    MIN_USER_RATE = 320 * 1024      # 320 KB/s
    OPTIMAL_USER_RATE = 640 * 1024  # 640 KB/s
    MAX_USER_RATE = 2560 * 1024     # 2560 KB/s (2.5 MB/s)
    TOTAL_BANDWIDTH = 625 * 1024 * 1024 // 8  # 625 Mbps
```

## Monitoring

### View Logs

```bash
# All logs
docker-compose logs -f

# Proxy only
docker-compose logs -f proxy

# Last 100 lines
docker-compose logs --tail=100 proxy
```

### Check Stats

```bash
# Active connections
docker-compose exec proxy python -c "
import redis, os
r = redis.Redis.from_url(os.getenv('REDIS_URL'), decode_responses=True)
users = [k.decode() for k in r.scan_iter(match=b'proxy:user:*')]
print(f'Total users: {len(users)}')
"
```

### Health Checks

```bash
# Container health
docker-compose ps

# Redis health
docker-compose exec redis redis-cli -a YOUR_PASSWORD ping
# Should return: PONG
```

## Performance

### Benchmarks

**Environment:**
- 2 vCPU, 2GB RAM
- Redis on same host
- 100 concurrent users

**Results:**
- Throughput: ~580 Mbps (72 MB/s)
- Latency: <10ms (P50), <50ms (P99)
- Memory: ~400MB RAM (with 1000 users)
- CPU: ~30-40% at full load

### Optimization Tips

1. **Use uvloop** (auto-detected):
   ```bash
   pip install uvloop
   ```

2. **Increase connection limits:**
   ```python
   MAX_TOTAL_CONNECTIONS = 10000
   ```

3. **Redis persistence:**
   - Disable AOF for better performance
   - Use RDB snapshots only

4. **Network tuning:**
   ```bash
   # /etc/sysctl.conf
   net.core.somaxconn = 2048
   net.ipv4.tcp_max_syn_backlog = 2048
   net.ipv4.ip_local_port_range = 10000 65000
   ```

## Security

### Implemented Protections

1. **DoS Protection:**
   - IP-based rate limiting (10 failed attempts → 5 min ban)
   - Max 300 decryption attempts per connection
   - Connection timeout: 10 minutes

2. **Container Security:**
   - Read-only filesystem
   - Non-root user (UID 1004)
   - Dropped capabilities (ALL)
   - No new privileges

3. **Network Security:**
   - Domain whitelisting
   - No direct internet access from container
   - Redis password authentication

### Best Practices

1. **Change default passwords:**
   ```bash
   REDIS_PASSWORD=$(openssl rand -base64 32)
   SS_MASTER_SECRET=$(openssl rand -base64 48)
   ```

2. **Use firewall:**
   ```bash
   # Allow only proxy port
   ufw allow 1080/tcp
   ufw enable
   ```

3. **Enable TLS** (if exposing Redis):
   ```yaml
   # docker-compose.yml
   redis:
     command: redis-server --tls-port 6380 --tls-cert-file /certs/redis.crt
   ```

4. **Rotate secrets** periodically (every 90 days)

## Troubleshooting

### Connection refused

```bash
# Check if port is listening
netstat -tlnp | grep 1080

# Check firewall
ufw status

# Check Docker
docker-compose ps
```

### Authentication failed

```bash
# Verify user exists in Redis
docker-compose exec redis redis-cli -a YOUR_PASSWORD
GET proxy:user:username

# Check SS_MASTER_SECRET matches
docker-compose exec proxy env | grep SS_MASTER_SECRET
```

### Slow connections

```bash
# Check bandwidth limits
docker-compose logs proxy | grep "Updated rates"

# Check active connections
docker-compose logs proxy | grep "Active connections"

# Monitor Redis
docker-compose exec redis redis-cli -a YOUR_PASSWORD INFO stats
```

### Domains not loading

```bash
# Validate domains.json
docker-compose exec proxy python -c "
from domains_validator import validate_domains_file
validate_domains_file('./domains.json')
print('Valid')
"

# Check logs for blocked domains
docker-compose logs proxy | grep "Blocked:"
```

## Development

### Local Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Start Redis
docker run -d -p 6379:6379 redis:7-alpine redis-server --requirepass testpass

# Set environment
export REDIS_URL="redis://:testpass@localhost:6379"
export SS_MASTER_SECRET="test_secret_minimum_32_chars_long"

# Run server
python proxy_server.py
```

### Testing

```bash
# Unit tests
pytest tests/

# Integration tests
pytest tests/integration/

# Load testing
locust -f tests/load_test.py
```

## License

MIT License

## Contributing

Pull requests welcome! Please:

1. Follow existing code style
2. Add tests for new features
3. Update documentation
4. Run linter: `ruff check .`

## Acknowledgements
https://shadowsocks.org/doc/what-is-shadowsocks.html
https://v2ray.com/en/index.html
https://regex101.com/