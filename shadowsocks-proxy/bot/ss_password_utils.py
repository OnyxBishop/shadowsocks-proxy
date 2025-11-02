"""
Утилиты для генерации Shadowsocks паролей
Единый источник истины для HMAC-based password generation
"""
import hmac
import hashlib
import os
import re
import secrets
import string
import logging
from datetime import timezone, datetime
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


def generate_credentials() -> str:
    """Generate unique username for new user"""
    timestamp = int(datetime.now(timezone.utc).timestamp())
    random_part = ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(6))
    username = f'Ramee_vpn_{timestamp}_{random_part}'

    # Валидация сгенерированного username
    if not validate_username(username):
        logger.error(f"Generated invalid username: {username}")
        raise ValueError("Failed to generate valid username")

    return username


def generate_ss_password(username: str, master_secret: Optional[str] = None) -> str:
    """
    Генерирует детерминированный SS пароль для username через HMAC-SHA256

    Args:
        username: Уникальный username пользователя
        master_secret: Мастер-пароль (по умолчанию берется из SS_MASTER_SECRET env)

    Returns:
        32-символьный hex-строка пароля

    Raises:
        ValueError: Если master_secret не задан
    """
    secret = master_secret or os.getenv('SS_MASTER_SECRET', '')

    if not secret:
        raise ValueError("SS_MASTER_SECRET is not set. Cannot generate SS password")

    return hmac.new(
        secret.encode('utf-8'),
        username.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()[:32]


def validate_username(username: str) -> bool:
    """
    Валидация username (MED-002)
    - Длина: 3-64 символа
    - Допустимые символы: a-z, A-Z, 0-9, underscore, тире
    """
    if not username or len(username) < 3 or len(username) > 64:
        return False
    # Разрешаем буквы, цифры, underscore, тире
    if not re.match(r'^[a-zA-Z0-9_\-]{3,64}$', username):
        return False
    return True
