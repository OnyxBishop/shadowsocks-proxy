# Shadowsocks Прокси-Сервер

[![en](https://img.shields.io/badge/lang-en-blue.svg)](README.md)
[![ru](https://img.shields.io/badge/lang-ru-red.svg)](README.ru.md)

Высокопроизводительный Shadowsocks AEAD прокси-сервер с динамическим управлением пропускной способностью, белым списком доменов и аутентификацией пользователей через Redis.

## Возможности

- **Протокол**: Shadowsocks AEAD (ChaCha20-Poly1305)
- **Динамическое управление пропускной способностью**: Справедливое распределение bandwidth с TCP backpressure
- **Белый список доменов**: Настраиваемый whitelist на основе JSON с горячей перезагрузкой
- **Интеграция с Redis**: Аутентификация пользователей и управление соединениями
- **Rate Limiting**: Ограничения соединений и пропускной способности на пользователя
- **Защита от DoS**: Rate limiting по IP с временными блокировками
- **Production Ready**: Контейнеризация Docker с усиленной безопасностью

## Архитектура

```
┌─────────────┐
│   Клиент    │
│ (SS клиент) │
└──────┬──────┘
       │ Shadowsocks AEAD
       │ (ChaCha20-Poly1305)
       ▼
┌─────────────────────────────────┐
│   Shadowsocks Прокси-Сервер     │
│                                 │
│  ┌──────────────────────────┐   │
│  │ UserConnectionManager    │   │
│  │ - Фильтрация доменов     │   │
│  │ - Лимиты соединений      │   │
│  │ - LRU кэш                │   │
│  └──────────────────────────┘   │
│                                 │
│  ┌──────────────────────────┐   │
│  │ BandwidthManager         │   │
│  │ - Динамический rate limit│   │
│  │ - Справедливое распр-ние │   │
│  └──────────────────────────┘   │
│                                 │
│  ┌──────────────────────────┐   │
│  │ ShadowsocksServer        │   │
│  │ - AEAD шифрование        │   │
│  │ - Идентификация польз-лей│   │
│  │ - Защита от DoS          │   │
│  └──────────────────────────┘   │
└────────┬────────────────────────┘
         │
         ▼
    ┌─────────┐
    │  Redis  │ ← Учетные данные
    └─────────┘
         │
         ▼
   ┌──────────┐
   │ Интернет │
   │(Фильтр.) │
   └──────────┘
```

## Основные Компоненты

### 1. Shadowsocks AEAD Handler

Реализует протокол Shadowsocks AEAD с шифрованием ChaCha20-Poly1305:

```python
# shadowsocks_handler.py - Деривация ключа
def derive_key(self, password: str, salt: bytes, key_len: int) -> bytes:
    """HKDF деривация ключа из пароля и соли"""
    master_key = self.evp_bytes_to_key(password, 32)
    prk = hkdf_extract(salt, master_key)
    return hkdf_expand(prk, b"ss-subkey", key_len)
```

**Поток соединения:**
1. Клиент отправляет 32-байтовую соль
2. Сервер выводит ключ через HKDF
3. Клиент отправляет зашифрованную длину (2 байта + 16-байтовый AEAD tag)
4. Сервер расшифровывает и проверяет длину payload
5. Клиент отправляет зашифрованный payload (адрес назначения + данные)
6. Сервер устанавливает соединение и проксирует трафик

### 2. Идентификация и Аутентификация Пользователей

Оптимизированный 3-уровневый поиск пользователя:

```python
# shadowsocks_handler.py - Идентификация пользователя
async def _try_decrypt_and_identify(self, salt: bytes, length_chunk: bytes):
    # Уровень 1: Проверка LRU кэша (O(1))
    cache_key = hashlib.sha256(salt[:16]).hexdigest()[:16]
    cached_username = self.user_cache.get(cache_key)
    
    # Уровень 2: Список пользователей в памяти (предзагружен из Redis)
    for username, ss_password in self.cached_users.items():
        # Попытка расшифровки с этим паролем
        
    # Уровень 3: Защита от DoS - макс 300 попыток
```

**Производительность:**
- Cache hit rate: ~85-90% для активных пользователей
- Время идентификации: <5ms (cache hit), <100ms (cache miss)
- Использование памяти: ~100KB на 100 пользователей

### 3. Динамическое Управление Пропускной Способностью

Справедливое распределение bandwidth на основе активных пользователей:

```python
# proxy_server.py - Расчет bandwidth
async def calculate_fair_bandwidth(self) -> int:
    active_users = await self.get_active_users_count()
    available = TOTAL_BANDWIDTH - RESERVED_BANDWIDTH
    fair_share = available // active_users
    
    # Ограничение min/max
    return max(MIN_USER_RATE, min(MAX_USER_RATE, fair_share))
```

### 4. Rate Limiting с TCP Backpressure

Вместо блокировки event loop через `asyncio.sleep()`, используется throttling TCP окна:

```python
# proxy_server.py - TCP backpressure rate limiting
if wait_time > 0:
    chunk_size = 8192
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        writer.write(chunk)
        await writer.drain()  # TCP естественно замедляет
else:
    writer.write(data)
    await writer.drain()
```

**Зачем TCP Backpressure?**
- Неблокирующий: Не занимает event loop
- Естественный: Использует TCP flow control
- Плавный: Постепенное замедление

### 5. Белый Список Доменов

Whitelist на основе JSON с горячей перезагрузкой (без перезапуска):

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

**Проверка на стороне сервера:**
```python
# proxy_server.py - Валидация домена
is_allowed = (
    self.connection_manager.is_domain_allowed(target_host) or
    self.connection_manager.is_ip_allowed(target_host) or
    (target_port in [53, 853])  # DNS/DoT
)
if not is_allowed:
    writer.close()
    return
```

### 6. Управление Соединениями

**Лимиты на пользователя:**
```python
MAX_CONNECTIONS_PER_USER = 12   # iOS/Android HTTP/2 multiplexing
MAX_CONNECTIONS_PER_IP = 8      # Предотвращение злоупотреблений
MAX_TOTAL_CONNECTIONS = 5000    # Глобальный лимит сервера
```

**Сборка мусора:**
- Очистка заброшенных соединений каждые 5 минут
- Таймаут неактивности 10 минут
- Graceful shutdown с обработкой SIGTERM/SIGINT

## Схема Данных Redis

### Хранение Пользователей

```python
# Учетные данные (ключ: proxy:user:{username})
{
  "username": "user123",
  "password": "generated_ss_password",  # Сгенерирован через HMAC-SHA256
  "created_at": "2024-01-01T00:00:00Z",
  "expires_at": "2024-02-01T00:00:00Z"
}

# Обратный индекс для O(1) поиска (ключ: ss_password_index:{password})
"user123"  # Отображает SS пароль → username
```

### Генерация Паролей

Детерминированная генерация на основе HMAC:

```python
# ss_password_utils.py
def generate_ss_password(username: str, master_secret: str) -> str:
    """Генерирует детерминированный SS пароль из username"""
    return hmac.new(
        master_secret.encode('utf-8'),
        username.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()[:32]
```

**Зачем HMAC?**
- Детерминированный: Один username → один пароль
- Безопасный: Невозможно восстановить master secret
- Быстрый: O(1) валидация пароля

## Развертывание

### Требования

- Docker 20.10+
- Docker Compose 2.0+
- Минимум 1GB RAM
- Рекомендуется 2 ядра CPU

### Шаг 1: Клонирование Репозитория

```bash
git clone https://github.com/OnyxBishop/shadowsocks-proxy.git
cd shadowsocks-proxy
```

### Шаг 2: Настройка Окружения

```bash
cp .env.example .env
```

Отредактируйте `.env` и задайте:

```bash
# Генерация безопасных паролей
REDIS_PASSWORD=$(openssl rand -base64 32)
SS_MASTER_SECRET=$(openssl rand -base64 48)

# Обновите .env
REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379
SS_MASTER_SECRET=${SS_MASTER_SECRET}
```

### Шаг 3: Сборка и Развертывание

```bash
# Сборка контейнеров
docker-compose build

# Запуск сервисов
docker-compose up -d

# Просмотр логов
docker-compose logs -f proxy
```

### Шаг 4: Проверка Развертывания

``` bash
# Проверка работы прокси
docker-compose ps
# Должен показать proxy на 0.0.0.0:1080
```

### Шаг 5: Создание Тестового Пользователя

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

# Сохранение пользователя
redis_client.set(f"proxy:user:{username}", json.dumps(user_data))
redis_client.set(f"ss_password_index:{ss_password}", username)

print(f"Создан пользователь: {username}")
print(f"SS Пароль: {ss_password}")
```

Запуск:
```bash
docker-compose exec proxy python create_user.py
```

### Шаг 6: Настройка Клиента

**Формат Shadowsocks URL:**
```
ss://МЕТОД:ПАРОЛЬ@ХОСТ:ПОРТ
```

Пример:
```
ss://chacha20-ietf-poly1305:generated_password@your-server.com:1080
```

**Рекомендуемые клиенты:**
- **iOS**: Shadowrocket, Potatso Lite, V2Box, V2RayTun
- **Android**: Shadowsocks Android, V2RayTun, V2Box
- **Windows**: Shadowsocks-Windows, Hiddify
- **macOS**: ShadowsocksX-NG, V2RayTun

## Конфигурация

### Переменные Окружения

| Переменная | Обязательная | По умолчанию | Описание |
|-----------|--------------|--------------|----------|
| `REDIS_URL` | Да | - | Строка подключения Redis |
| `PROXY_HOST` | Нет | `0.0.0.0` | Адрес привязки |
| `PROXY_PORT` | Нет | `1080` | Порт прослушивания |
| `PROXY_PROTOCOL` | Нет | `shadowsocks` | Протокол (должен быть shadowsocks) |
| `SS_MASTER_SECRET` | Да | - | Мастер-секрет для генерации паролей |
| `SS_METHOD` | Нет | `chacha20-ietf-poly1305` | Метод шифрования |
| `LOG_LEVEL` | Нет | `INFO` | Уровень логирования |

### Белый Список Доменов

Отредактируйте `domains.json` для добавления/удаления разрешенных доменов:

```json
{
  "domains": [
    "example.com",
    "*.example.com"  // Не поддерживается, используйте "example.com" для поддоменов
  ]
}
```

**Горячая перезагрузка:** Изменения обнаруживаются автоматически в течение 10 секунд.

### Настройка Пропускной Способности

Отредактируйте класс `BandwidthConfig` в `proxy_server.py`:

```python
class BandwidthConfig:
    MIN_USER_RATE = 320 * 1024      # 320 КБ/с
    OPTIMAL_USER_RATE = 640 * 1024  # 640 КБ/с
    MAX_USER_RATE = 2560 * 1024     # 2560 КБ/с (2.5 МБ/с)
    TOTAL_BANDWIDTH = 625 * 1024 * 1024 // 8  # 625 Мбит/с
```

## Мониторинг

### Просмотр Логов

```bash
# Все логи
docker-compose logs -f

# Только прокси
docker-compose logs -f proxy

# Последние 100 строк
docker-compose logs --tail=100 proxy
```

### Проверка Статистики

```bash
# Активные соединения
docker-compose exec proxy python -c "
import redis, os
r = redis.Redis.from_url(os.getenv('REDIS_URL'), decode_responses=True)
users = [k.decode() for k in r.scan_iter(match=b'proxy:user:*')]
print(f'Всего пользователей: {len(users)}')
"
```

### Health Checks

```bash
# Состояние контейнеров
docker-compose ps

# Проверка Redis
docker-compose exec redis redis-cli -a YOUR_PASSWORD ping
# Должно вернуть: PONG
```

## Производительность

### Бенчмарки

**Окружение:**
- 2 vCPU, 2GB RAM
- Redis на том же хосте
- 100 одновременных пользователей

**Результаты:**
- Пропускная способность: ~580 Мбит/с (72 МБ/с)
- Задержка: <10ms (P50), <50ms (P99)
- Память: ~400MB RAM (при 1000 пользователей)
- CPU: ~30-40% при полной нагрузке

### Советы по Оптимизации

1. **Используйте uvloop** (определяется автоматически):
   ```bash
   pip install uvloop
   ```

2. **Увеличьте лимиты соединений:**
   ```python
   MAX_TOTAL_CONNECTIONS = 10000
   ```

3. **Настройка Redis:**
   - Отключите AOF для лучшей производительности
   - Используйте только RDB снапшоты

4. **Настройка сети:**
   ```bash
   # /etc/sysctl.conf
   net.core.somaxconn = 2048
   net.ipv4.tcp_max_syn_backlog = 2048
   net.ipv4.ip_local_port_range = 10000 65000
   ```

## Безопасность

### Реализованные Защиты

1. **Защита от DoS:**
   - Rate limiting по IP (10 неудачных попыток → бан на 5 мин)
   - Максимум 300 попыток расшифровки на соединение
   - Таймаут соединения: 10 минут

2. **Безопасность Контейнера:**
   - Файловая система только для чтения
   - Непривилегированный пользователь (UID 1004)
   - Сброшены capabilities (ALL)
   - Без новых привилегий

3. **Сетевая Безопасность:**
   - Белый список доменов
   - Нет прямого доступа в интернет из контейнера
   - Парольная аутентификация Redis

### Лучшие Практики

1. **Смените стандартные пароли:**
   ```bash
   REDIS_PASSWORD=$(openssl rand -base64 32)
   SS_MASTER_SECRET=$(openssl rand -base64 48)
   ```

2. **Используйте файрвол:**
   ```bash
   # Разрешите только порт прокси
   ufw allow 1080/tcp
   ufw enable
   ```

3. **Включите TLS** (если Redis открыт наружу):
   ```yaml
   # docker-compose.yml
   redis:
     command: redis-server --tls-port 6380 --tls-cert-file /certs/redis.crt
   ```

4. **Ротация секретов** периодически (каждые 90 дней)

## Устранение Неполадок

### Соединение отклонено

```bash
# Проверьте, прослушивается ли порт
netstat -tlnp | grep 1080

# Проверьте файрвол
ufw status

# Проверьте Docker
docker-compose ps
```

### Ошибка аутентификации

```bash
# Проверьте существование пользователя в Redis
docker-compose exec redis redis-cli -a YOUR_PASSWORD
GET proxy:user:username

# Проверьте соответствие SS_MASTER_SECRET
docker-compose exec proxy env | grep SS_MASTER_SECRET
```

### Медленные соединения

```bash
# Проверьте лимиты bandwidth
docker-compose logs proxy | grep "Updated rates"

# Проверьте активные соединения
docker-compose logs proxy | grep "Active connections"

# Мониторинг Redis
docker-compose exec redis redis-cli -a YOUR_PASSWORD INFO stats
```

### Домены не загружаются

```bash
# Валидация domains.json
docker-compose exec proxy python -c "
from domains_validator import validate_domains_file
validate_domains_file('./domains.json')
print('Valid')
"

# Проверьте логи на заблокированные домены
docker-compose logs proxy | grep "Blocked:"
```

## Разработка

### Локальная Настройка

```bash
# Установка зависимостей
pip install -r requirements.txt

# Запуск Redis
docker run -d -p 6379:6379 redis:7-alpine redis-server --requirepass testpass

# Настройка окружения
export REDIS_URL="redis://:testpass@localhost:6379"
export SS_MASTER_SECRET="test_secret_minimum_32_chars_long"

# Запуск сервера
python proxy_server.py
```

### Тестирование

```bash
# Unit тесты
pytest tests/

# Интеграционные тесты
pytest tests/integration/

# Нагрузочное тестирование
locust -f tests/load_test.py
```

## Лицензия

MIT License

## Вклад в Проект

Приветствуются pull request'ы! Пожалуйста:

1. Следуйте существующему стилю кода
2. Добавляйте тесты для новых функций
3. Обновляйте документацию
4. Запускайте линтер: `ruff check .`

## Полезные ссылки
1. https://shadowsocks.org/doc/what-is-shadowsocks.html
2. https://v2ray.com/ru/index.html
3. https://regex101.com/
