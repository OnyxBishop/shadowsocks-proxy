"""
Утилиты для генерации Shadowsocks паролей
Единый источник истины для HMAC-based password generation
"""
import hmac
import hashlib
import os
from typing import Optional


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
