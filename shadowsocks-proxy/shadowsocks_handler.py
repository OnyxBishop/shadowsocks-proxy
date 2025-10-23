import asyncio
import hashlib
import hmac
import logging
import os
import time
import json
from typing import Optional, Dict, List, Tuple
from collections import OrderedDict

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from ss_password_utils import generate_ss_password

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class UserCache:
    """LRU cache for recently active users"""

    def __init__(self, max_size: int = 100):
        self.cache: OrderedDict[str, str] = OrderedDict()  # salt_hash -> username
        self.max_size = max_size
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Optional[str]:
        """Get username by key, updating LRU order"""
        if key in self.cache:
            self.hits += 1
            self.cache.move_to_end(key)
            return self.cache[key]
        self.misses += 1
        return None

    def put(self, key: str, username: str):
        """Add user to cache"""
        if key in self.cache:
            self.cache.move_to_end(key)
        else:
            self.cache[key] = username
            if len(self.cache) > self.max_size:
                self.cache.popitem(last=False)

    def get_stats(self) -> dict:
        """Cache efficiency statistics"""
        total = self.hits + self.misses
        hit_rate = (self.hits / total * 100) if total > 0 else 0
        return {
            'size': len(self.cache),
            'hits': self.hits,
            'misses': self.misses,
            'hit_rate': hit_rate
        }


class ShadowsocksServer:
    """Shadowsocks AEAD server with system integration"""

    def __init__(self, connection_manager, bandwidth_manager, buffer_size=65536):
        self.connection_manager = connection_manager
        self.bandwidth_manager = bandwidth_manager
        self.buffer_size = buffer_size

        # DoS protection: track failed attempts per IP
        self.failed_attempts = {}  # ip -> (timestamp, count)
        self.max_attempts_per_ip = 10
        self.ban_duration = 300  # 5 minutes ban

        # Optimization: cache + preloaded passwords
        self.user_cache = UserCache(max_size=100)
        self.cached_users: Dict[str, str] = {}  # username -> ss_password
        self.last_users_refresh = 0
        self.users_refresh_interval = 30  # Refresh every 30 seconds

        logger.info("Shadowsocks server initialized")

    @staticmethod
    def evp_bytes_to_key(password: str, key_len: int) -> bytes:
        m = []
        i = 0
        while len(b''.join(m)) < key_len:
            md5 = hashlib.md5()
            data = password.encode()
            if i > 0:
                data = m[i - 1] + data
            md5.update(data)
            m.append(md5.digest())
            i += 1
        return b''.join(m)[:key_len]

    def derive_key(self, password: str, salt: bytes, key_len: int) -> bytes:
        master_key = self.evp_bytes_to_key(password, 32)

        def hkdf_extract(salt, ikm):
            return hmac.new(salt, ikm, hashlib.sha1).digest()

        def hkdf_expand(prk, info, length):
            t = b""
            okm = b""
            i = 0
            while len(okm) < length:
                i += 1
                t = hmac.new(prk, t + info + bytes([i]), hashlib.sha1).digest()
                okm += t
            return okm[:length]

        prk = hkdf_extract(salt, master_key)
        return hkdf_expand(prk, b"ss-subkey", key_len)

    async def handle_connection(self, reader, writer):
        """Handle Shadowsocks connection"""
        peer_ip, peer_port = writer.get_extra_info("peername")
        connection_id = f"ss_{peer_ip}:{peer_port}_{time.time()}"
        username = None

        # DoS protection: check if IP is banned
        if peer_ip in self.failed_attempts:
            last_fail_time, fail_count = self.failed_attempts[peer_ip]
            if fail_count >= self.max_attempts_per_ip:
                time_since_ban = time.time() - last_fail_time
                if time_since_ban < self.ban_duration:
                    logger.warning(f"[SS] IP {peer_ip} is temporarily banned ({self.ban_duration - time_since_ban:.0f}s remaining)")
                    writer.close()
                    return
                else:
                    del self.failed_attempts[peer_ip]

        logger.info(f"[SS] New connection from {peer_ip}:{peer_port}")

        try:
            try:
                salt = await asyncio.wait_for(reader.readexactly(32), timeout=5)
            except (asyncio.IncompleteReadError, asyncio.TimeoutError) as e:
                logger.debug(f"[SS] Not a Shadowsocks connection from {peer_ip}: {e}")
                writer.close()
                return

            length_chunk = await reader.readexactly(18)
            username = await self._try_decrypt_and_identify(salt, length_chunk)

            if not username:
                logger.warning(f"[SS] Could not identify user from {peer_ip}")
                if peer_ip in self.failed_attempts:
                    _, count = self.failed_attempts[peer_ip]
                    self.failed_attempts[peer_ip] = (time.time(), count + 1)
                else:
                    self.failed_attempts[peer_ip] = (time.time(), 1)
                writer.close()
                return

            # Successful identification - reset failed attempts
            if peer_ip in self.failed_attempts:
                del self.failed_attempts[peer_ip]

            user_key = f"proxy:user:{username}"
            user_data = await self.connection_manager.redis.get(user_key)
            user_info = json.loads(user_data)
            ss_password = user_info['password']

            if not await self.connection_manager.can_connect(username, peer_ip, connection_id):
                logger.warning(f"[SS] Connection limit exceeded for {username}")
                writer.close()
                return

            key = self.derive_key(ss_password, salt, 32)
            aead = ChaCha20Poly1305(key)

            nonce = b'\x00' * 12
            payload_length_bytes = aead.decrypt(nonce, length_chunk, None)
            payload_length = int.from_bytes(payload_length_bytes, 'big')

            logger.info(f"[SS] {username} payload length: {payload_length}")

            if payload_length > 0x3FFF:
                logger.warning(f"[SS] Invalid payload length: {payload_length}")
                writer.close()
                return

            nonce = self._increment_nonce(nonce)
            payload_chunk = await reader.readexactly(payload_length + 16)
            payload = aead.decrypt(nonce, payload_chunk, None)

            # Parse destination address and extract initial data
            addr_type = payload[0]
            header_len = 0

            if addr_type == 1:  # IPv4
                target_host = '.'.join(str(b) for b in payload[1:5])
                target_port = int.from_bytes(payload[5:7], 'big')
                header_len = 7
            elif addr_type == 3:  # Domain
                domain_len = payload[1]
                target_host = payload[2:2 + domain_len].decode()
                target_port = int.from_bytes(payload[2 + domain_len:4 + domain_len], 'big')
                header_len = 1 + 1 + domain_len + 2
            elif addr_type == 4:  # IPv6
                target_host = ':'.join(f'{payload[i]:02x}{payload[i + 1]:02x}' for i in range(1, 17, 2))
                target_port = int.from_bytes(payload[17:19], 'big')
                header_len = 19
            else:
                writer.close()
                return

            initial_data = payload[header_len:] if len(payload) > header_len else b''

            logger.info(f"[SS] {username} -> {target_host}:{target_port} (initial data: {len(initial_data)} bytes)")

            # Check permissions (domains + IP + DNS ports)
            is_allowed = (
                self.connection_manager.is_domain_allowed(target_host) or
                self.connection_manager.is_ip_allowed(target_host) or
                (target_port in [53, 853] and target_host in ['1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4'])  # DNS/DoT
            )

            if not is_allowed:
                logger.debug(f"[SS] Blocked: {target_host}:{target_port} (not in whitelist)")
                writer.close()
                return

            try:
                remote_reader, remote_writer = await asyncio.open_connection(target_host, target_port)
                logger.info(f"[SS] {username}: connected to {target_host}:{target_port}")
            except Exception as e:
                logger.error(f"[SS] Connection failed to {target_host}:{target_port}: {e}")
                writer.close()
                return

            import os as os_module
            response_salt = os_module.urandom(32)
            response_key = self.derive_key(ss_password, response_salt, 32)
            response_aead = ChaCha20Poly1305(response_key)

            writer.write(response_salt)
            await writer.drain()
            logger.info(f"[SS] {username}: sent response salt, starting data transfer")

            # Send initial data (if any) to remote server
            if initial_data:
                logger.info(f"[SS] {username}: sending initial {len(initial_data)} bytes to {target_host}")
                remote_writer.write(initial_data)
                await remote_writer.drain()

            nonce_c2s = self._increment_nonce(nonce)
            nonce_s2c = b'\x00' * 12

            limiter = self.connection_manager.get_rate_limiter(username)

            results = await asyncio.gather(
                self._pipe_decrypt(reader, remote_writer, aead, nonce_c2s, limiter, username, "c2s"),
                self._pipe_encrypt(remote_reader, writer, response_aead, nonce_s2c, limiter, username, "s2c"),
                return_exceptions=True
            )

            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(f"[SS] {username}: pipe task {i} failed: {result}")

        except Exception as e:
            logger.error(f"[SS] Error: {e}", exc_info=True)
        finally:
            if username:
                await self.connection_manager.disconnect(username, peer_ip, connection_id)
            writer.close()

    def _increment_nonce(self, nonce: bytes) -> bytes:
        counter = int.from_bytes(nonce, 'little')
        counter += 1
        return counter.to_bytes(12, 'little')

    async def _refresh_users_cache(self):
        """Refresh user list from Redis (every 30 seconds)"""
        now = time.monotonic()
        if now - self.last_users_refresh < self.users_refresh_interval:
            return

        try:
            cursor = 0
            new_cache = {}

            while cursor != 0 or len(new_cache) == 0:
                cursor, keys = await self.connection_manager.redis.scan(
                    cursor, match=b"proxy:user:*", count=100
                )

                for key in keys:
                    username = key.decode().split(':')[-1]
                    user_data = await self.connection_manager.redis.get(key)

                    if user_data:
                        try:
                            user_info = json.loads(user_data)
                            ss_password = user_info.get('password', '')
                            if ss_password:
                                new_cache[username] = ss_password
                        except Exception:
                            continue

                if cursor == 0:
                    break

            self.cached_users = new_cache
            self.last_users_refresh = now
            logger.info(f"[SS] Refreshed user cache: {len(self.cached_users)} users")

        except Exception as e:
            logger.error(f"[SS] Failed to refresh users cache: {e}")

    async def _try_decrypt_and_identify(self, salt: bytes, length_chunk: bytes) -> Optional[str]:
        """
        OPTIMIZED user identification:
        1. Check LRU cache of recent active users (O(1))
        2. Iterate through preloaded password list from memory (no Redis requests)
        3. Update cache on success
        """
        await self._refresh_users_cache()

        if not self.cached_users:
            logger.warning("[SS] No users in cache, cannot identify")
            return None

        # Create key for LRU cache (first 16 bytes of salt)
        cache_key = hashlib.sha256(salt[:16]).hexdigest()[:16]

        # Check LRU cache
        cached_username = self.user_cache.get(cache_key)
        if cached_username and cached_username in self.cached_users:
            ss_password = self.cached_users[cached_username]
            try:
                key_derived = self.derive_key(ss_password, salt, 32)
                aead = ChaCha20Poly1305(key_derived)
                nonce = b'\x00' * 12
                decrypted = aead.decrypt(nonce, length_chunk, None)
                length = int.from_bytes(decrypted, 'big')

                if 0 < length <= 0x3FFF:
                    logger.info(f"[SS] ✅ Cache HIT: {cached_username}")
                    return cached_username
            except Exception:
                pass

        # Iterate all users from memory (no Redis requests)
        attempts = 0
        max_attempts = 300

        for username, ss_password in self.cached_users.items():
            if attempts >= max_attempts:
                logger.warning(f"[SS] Exceeded max attempts ({max_attempts}), aborting identification")
                return None

            attempts += 1

            try:
                key_derived = self.derive_key(ss_password, salt, 32)
                aead = ChaCha20Poly1305(key_derived)
                nonce = b'\x00' * 12
                decrypted = aead.decrypt(nonce, length_chunk, None)
                length = int.from_bytes(decrypted, 'big')

                if 0 < length <= 0x3FFF:
                    logger.info(f"[SS] ✅ Identified: {username} after {attempts} attempts (cache miss)")
                    self.user_cache.put(cache_key, username)

                    if (self.user_cache.hits + self.user_cache.misses) % 100 == 0:
                        stats = self.user_cache.get_stats()
                        logger.info(f"[SS] Cache stats: {stats['hit_rate']:.1f}% hit rate, {stats['size']} entries")

                    return username

            except Exception:
                continue

        logger.warning(f"[SS] Failed to identify user after {attempts} attempts")
        return None

    async def _pipe_decrypt(self, reader, writer, aead, nonce, limiter, username, direction):
        """Read encrypted data, decrypt and send as plaintext (c2s)"""
        try:
            total_bytes = 0
            packet_count = 0
            while not reader.at_eof():
                try:
                    encrypted_length = await asyncio.wait_for(reader.readexactly(18), timeout=300)
                except asyncio.IncompleteReadError as e:
                    logger.debug(f"[SS] {direction} {username}: IncompleteReadError on length: {e}")
                    break
                except asyncio.TimeoutError:
                    logger.debug(f"[SS] {direction} {username}: Timeout waiting for data after {packet_count} packets")
                    break

                length_bytes = aead.decrypt(nonce, encrypted_length, None)
                nonce = self._increment_nonce(nonce)

                payload_length = int.from_bytes(length_bytes, 'big')

                encrypted_payload = await reader.readexactly(payload_length + 16)
                data = aead.decrypt(nonce, encrypted_payload, None)
                nonce = self._increment_nonce(nonce)

                if not data:
                    break

                packet_count += 1
                total_bytes += len(data)
                logger.debug(f"[SS] {direction} {username}: packet #{packet_count}, decrypted {len(data)} bytes (total: {total_bytes})")

                await self.bandwidth_manager.track_usage(username, len(data))

                # TCP backpressure instead of asyncio.sleep()
                if limiter:
                    wait_time = await limiter.consume(len(data))
                    if wait_time > 0:
                        chunk_size = 8192
                        offset = 0
                        while offset < len(data):
                            chunk = data[offset:offset + chunk_size]
                            writer.write(chunk)
                            await writer.drain()
                            offset += chunk_size
                    else:
                        writer.write(data)
                        await writer.drain()
                else:
                    writer.write(data)
                    await writer.drain()

            logger.info(f"[SS] {direction} {username}: finished, total {total_bytes} bytes")

        except (ConnectionResetError, BrokenPipeError, EOFError) as e:
            logger.debug(f"[SS] {direction} {username}: connection closed - {type(e).__name__}")
        except Exception as e:
            logger.error(f"[SS] Pipe {direction} error: {e}", exc_info=True)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                logger.debug(f"[SS] Error closing writer in {direction}: {e}")

    async def _pipe_encrypt(self, reader, writer, aead, nonce, limiter, username, direction):
        try:
            total_bytes = 0
            max_payload_size = 0x3FFF  # 16383 bytes - max for Shadowsocks AEAD

            while not reader.at_eof():
                data = await asyncio.wait_for(reader.read(self.buffer_size), timeout=300)
                if not data:
                    break

                total_bytes += len(data)
                logger.debug(f"[SS] {direction} {username}: received {len(data)} bytes (total: {total_bytes})")

                await self.bandwidth_manager.track_usage(username, len(data))

                # Split large chunks into max_payload_size parts
                offset = 0
                packets_to_send = []
                while offset < len(data):
                    chunk = data[offset:offset + max_payload_size]

                    # CORRECT order: length first, then payload
                    length_bytes = len(chunk).to_bytes(2, 'big')
                    encrypted_length = aead.encrypt(nonce, length_bytes, None)
                    nonce = self._increment_nonce(nonce)

                    encrypted_payload = aead.encrypt(nonce, chunk, None)
                    nonce = self._increment_nonce(nonce)

                    packets_to_send.append(encrypted_length + encrypted_payload)
                    offset += len(chunk)

                # TCP backpressure instead of asyncio.sleep()
                if limiter:
                    wait_time = await limiter.consume(len(data))
                    if wait_time > 0:
                        for packet in packets_to_send:
                            writer.write(packet)
                            await writer.drain()
                    else:
                        for packet in packets_to_send:
                            writer.write(packet)
                        await writer.drain()
                else:
                    for packet in packets_to_send:
                        writer.write(packet)
                    await writer.drain()

            logger.info(f"[SS] {direction} {username}: finished, total {total_bytes} bytes")

        except (ConnectionResetError, BrokenPipeError, EOFError) as e:
            logger.debug(f"[SS] {direction} {username}: connection closed - {type(e).__name__}")
        except Exception as e:
            logger.error(f"[SS] Pipe {direction} error: {e}", exc_info=True)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                logger.debug(f"[SS] Error closing writer in {direction}: {e}")
