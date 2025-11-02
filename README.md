# Shadowsocks Proxy Server

[![en](https://img.shields.io/badge/lang-en-blue.svg)](README.md)
[![ru](https://img.shields.io/badge/lang-ru-red.svg)](README.ru.md)

A simple, unrestricted Shadowsocks AEAD proxy server for personal use with friends and family.

## Features

- **Protocol**: Shadowsocks AEAD (ChaCha20-Poly1305)
- **Simple Setup**: No database required, just set environment variables
- **No Restrictions**: No bandwidth limits, connection limits, or domain filtering
- **Docker Ready**: Easy deployment with Docker and docker-compose
- **Secure**: HMAC-based password generation from master secret
- **Telegram Bot**: Optional bot for easy user management and credential distribution

## Quick Start

### Prerequisites

- Docker 20.10+
- Docker Compose 2.0+

### Step 1: Clone Repository

```bash
git clone https://github.com/yourusername/shadowsocks-proxy.git
cd shadowsocks-proxy
```

### Step 2: Configure Environment

Create a `.env` file:

```bash
# Generate a secure master secret (minimum 32 characters)
SS_MASTER_SECRET=$(openssl rand -base64 48)
SS_USERNAME=your_username

echo "SS_MASTER_SECRET=${SS_MASTER_SECRET}" > .env
echo "SS_USERNAME=${SS_USERNAME}" >> .env
```

### Step 3: Start the Server

```bash
# Build and start
docker-compose up -d

# Check logs
docker-compose logs -f proxy
```

You should see:
```
Shadowsocks server initialized
SHADOWSOCKS proxy server started on 0.0.0.0:1080
```

### Step 4: Get Your Connection Details

The server will generate a deterministic password based on your username and master secret:

```python
# To calculate your password manually:
import hmac
import hashlib

username = "your_username"
master_secret = "your_master_secret_from_env"

ss_password = hmac.new(
    master_secret.encode('utf-8'),
    username.encode('utf-8'),
    hashlib.sha256
).hexdigest()[:32]

print(f"Your SS Password: {ss_password}")
```

### Step 5: Configure Client

**Connection details:**
- **Server**: your-server-ip
- **Port**: 1080
- **Password**: (generated from your username + master secret)
- **Encryption**: chacha20-ietf-poly1305

**Shadowsocks URL format:**
```
ss://chacha20-ietf-poly1305:YOUR_PASSWORD@your-server-ip:1080
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
| `SS_MASTER_SECRET` | Yes | - | Master secret for password generation (min 32 chars) |
| `SS_USERNAME` | No | `default_user` | Username for password generation |
| `PROXY_HOST` | No | `0.0.0.0` | Bind address |
| `PROXY_PORT` | No | `1080` | Listen port |
| `PROXY_PROTOCOL` | No | `shadowsocks` | Protocol (must be shadowsocks) |

## How It Works

1. **Password Generation**: The server generates a deterministic password using HMAC-SHA256:
   ```python
   password = HMAC-SHA256(master_secret, username)[:32]
   ```

2. **Client Connection**: When a client connects:
   - Sends a 32-byte salt
   - Sends encrypted request
   - Server derives key using salt and password
   - Server decrypts and proxies the connection

3. **No Restrictions**: All traffic is proxied without:
   - Bandwidth limits
   - Connection limits
   - Domain filtering
   - User authentication via database

## Security

### Password Security

- Use a strong master secret (minimum 32 characters)
- Generate it securely: `openssl rand -base64 48`
- Keep it secret and don't share it
- All your friends/family can use the same server with different usernames

### Network Security

1. **Use firewall:**
   ```bash
   # Allow only proxy port
   ufw allow 1080/tcp
   ufw enable
   ```

2. **Consider using a VPN or private network** for additional security

3. **Monitor your server** for unusual activity

## Deployment

### Production Deployment

```bash
# Start in detached mode
docker-compose up -d

# View logs
docker-compose logs -f proxy

# Restart server
docker-compose restart proxy

# Stop server
docker-compose down
```

### Resource Usage

- **Memory**: ~50-100MB under normal load
- **CPU**: Minimal (encryption is efficient)
- **Network**: Depends on your usage

## Troubleshooting

### Connection refused

```bash
# Check if port is listening
netstat -tlnp | grep 1080

# Check Docker
docker-compose ps

# Check logs
docker-compose logs proxy
```

### Authentication failed

1. Verify your SS_MASTER_SECRET is set correctly
2. Ensure you're using the correct username
3. Recalculate your password using the formula above
4. Check server logs for decryption errors

### Slow connections

This server has no bandwidth limits, so slow connections are usually due to:
- Your server's network speed
- Your ISP throttling
- Network congestion

## Development

### Local Setup

```bash
# Install dependencies
cd shadowsocks-proxy
pip install -r requirements.txt

# Set environment variables
export SS_MASTER_SECRET="test_secret_minimum_32_chars_long"
export SS_USERNAME="testuser"

# Run server
python proxy_server.py
```

## Multiple Users

### Option 1: Using Telegram Bot (Recommended)

1. Set up the Telegram bot (see `shadowsocks-proxy/bot/README.md`)
2. Users send `/start` to the bot
3. Bot automatically generates credentials and SS links
4. Users stored in `users.json`

### Option 2: Manual Configuration

To add more users (friends/family), they just need:

1. Your server IP and port (1080)
2. Their own unique username
3. The master secret (share securely)

Each username will generate a different password, but all use the same master secret.

**Example:**
- Alice: username="alice" → password=HMAC(secret, "alice")
- Bob: username="bob" → password=HMAC(secret, "bob")

## License

MIT License

## Acknowledgements

- [Shadowsocks Protocol Documentation](https://shadowsocks.org/doc/what-is-shadowsocks.html)