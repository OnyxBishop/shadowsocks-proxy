"""
Валидатор domains.json
Проверяет корректность структуры и содержимого whitelist доменов
"""
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class DomainsValidator:
    """Валидатор структуры domains.json"""

    REQUIRED_KEYS = ['domains', 'google_services', 'dns_servers']
    OPTIONAL_KEYS = ['description', 'version', 'comment']

    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Валидация отдельного домена"""
        if not isinstance(domain, str):
            return False
        if not domain or len(domain) > 255:
            return False
        # Базовая проверка: должен содержать точку и не начинаться с точки
        if '.' not in domain or domain.startswith('.'):
            return False
        return True

    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Валидация IP-адреса"""
        if not isinstance(ip, str):
            return False
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False

    def validate_structure(self, data: Dict) -> List[str]:
        """
        Проверка структуры JSON

        Returns:
            Список ошибок (пустой если всё ок)
        """
        errors = []

        # Проверка обязательных ключей
        for key in self.REQUIRED_KEYS:
            if key not in data:
                errors.append(f"Missing required key: {key}")
            elif not isinstance(data[key], list):
                errors.append(f"Key '{key}' must be a list")
            elif not data[key]:
                errors.append(f"Key '{key}' cannot be empty")

        # Проверка доменов
        if 'domains' in data and isinstance(data['domains'], list):
            for i, domain in enumerate(data['domains']):
                if not self.validate_domain(domain):
                    errors.append(f"Invalid domain at domains[{i}]: {domain}")

        # Проверка google_services
        if 'google_services' in data and isinstance(data['google_services'], list):
            for i, domain in enumerate(data['google_services']):
                if not self.validate_domain(domain):
                    errors.append(f"Invalid domain at google_services[{i}]: {domain}")

        # Проверка DNS серверов
        if 'dns_servers' in data and isinstance(data['dns_servers'], list):
            for i, server in enumerate(data['dns_servers']):
                # DNS сервер может быть IP или доменом
                if not (self.validate_ip(server) or self.validate_domain(server)):
                    errors.append(f"Invalid DNS server at dns_servers[{i}]: {server}")

        return errors

    def load_and_validate(self, path: str) -> Optional[Dict]:
        """
        Загрузка и валидация domains.json

        Raises:
            FileNotFoundError: Если файл не найден
            ValueError: Если JSON невалидный или структура некорректна
        """
        domains_path = Path(path)

        if not domains_path.exists():
            raise FileNotFoundError(f"domains.json not found at: {path}")

        try:
            with open(domains_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON syntax: {e}")

        errors = self.validate_structure(data)
        if errors:
            error_msg = "\n".join(f"  - {err}" for err in errors)
            raise ValueError(f"domains.json validation failed:\n{error_msg}")

        logger.info(f"domains.json validated successfully: {len(data['domains'])} domains, "
                    f"{len(data['google_services'])} google services, "
                    f"{len(data['dns_servers'])} DNS servers")

        return data


def validate_domains_file(path: str = "./domains.json") -> Dict:
    """
    Утилита для валидации domains.json при старте сервисов

    Args:
        path: Путь к domains.json

    Returns:
        Валидированный словарь с доменами

    Raises:
        FileNotFoundError, ValueError: При ошибке валидации
    """
    validator = DomainsValidator()
    return validator.load_and_validate(path)
