FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY proxy_server.py shadowsocks_handler.py start.sh ./

# Copy bot code (optional)
COPY bot/ ./bot/

# Make startup script executable
RUN chmod +x start.sh

# Create non-root user for security
RUN groupadd -g 1004 appgroup && \
    useradd -m -u 1004 -g appgroup -s /usr/sbin/nologin app && \
    chown -R app:appgroup /app

USER app

CMD ["./start.sh"]
