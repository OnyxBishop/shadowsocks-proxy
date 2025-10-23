FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY proxy_server.py shadowsocks_handler.py domains_validator.py ss_password_utils.py domains.json ./

# Copy new directory structure
COPY config/ ./config/
COPY entities/ ./entities/
COPY managers/ ./managers/

# Create non-root user for security
RUN groupadd -g 1004 appgroup && \
    useradd -m -u 1004 -g appgroup -s /usr/sbin/nologin app && \
    chown -R app:appgroup /app

USER app

CMD ["python", "-u", "proxy_server.py"]
