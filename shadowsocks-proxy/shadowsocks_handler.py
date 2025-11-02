import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional, Dict

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class ShadowsocksServer:
    """Pure Shadowsocks AEAD server without restrictions"""

    def __init__(self, buffer_size=65536):
        self.buffer_size = buffer_size
        # Get master secret from environment
        self.master_secret = os.getenv('SS_MASTER_SECRET', '')
        if not self.master_secret:
            raise ValueError("SS_MASTER_SECRET environment variable must be set")
        
        # Path to users.json
        self.users_file = Path(__file__).parent / "users.json"
        self.users_cache: Dict[str, str] = {}  # username -> ss_password
        self.last_cache_update = 0
        self.cache_ttl = 5  # Refresh every 5 seconds
        
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

    def generate_ss_password(self, username: str) -> str:
        """Generate deterministic SS password for username via HMAC-SHA256"""
        return hmac.new(
            self.master_secret.encode('utf-8'),
            username.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()[:32]
    
    def load_users_from_json(self) -> Dict[str, str]:
        """Load users from JSON file"""
        if not self.users_file.exists():
            # Fallback to environment variable mode
            username = os.getenv('SS_USERNAME', 'default_user')
            password = self.generate_ss_password(username)
            return {username: password}
        
        try:
            with open(self.users_file, 'r', encoding='utf-8') as f:
                users_data = json.load(f)
            
            # Convert to username -> password dict
            result = {}
            for user_id, user_info in users_data.items():
                username = user_info.get('username')
                ss_password = user_info.get('ss_password')
                if username and ss_password:
                    result[username] = ss_password
            
            logger.info(f"Loaded {len(result)} users from JSON")
            return result
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Failed to load users.json: {e}")
            # Fallback to environment variable mode
            username = os.getenv('SS_USERNAME', 'default_user')
            password = self.generate_ss_password(username)
            return {username: password}
    
    def refresh_users_cache(self):
        """Refresh users cache if TTL expired"""
        now = time.time()
        if now - self.last_cache_update > self.cache_ttl:
            self.users_cache = self.load_users_from_json()
            self.last_cache_update = now

    async def handle_connection(self, reader, writer):
        """Handle Shadowsocks connection"""
        peer_ip, peer_port = writer.get_extra_info("peername")

        logger.info(f"[SS] New connection from {peer_ip}:{peer_port}")

        try:
            try:
                salt = await asyncio.wait_for(reader.readexactly(32), timeout=5)
            except (asyncio.IncompleteReadError, asyncio.TimeoutError) as e:
                logger.debug(f"[SS] Not a Shadowsocks connection from {peer_ip}: {e}")
                writer.close()
                return

            length_chunk = await reader.readexactly(18)
            
            # Refresh users cache and try to identify user
            self.refresh_users_cache()
            
            username = None
            ss_password = None
            
            # Try to decrypt with each user's password
            for test_username, test_password in self.users_cache.items():
                try:
                    test_key = self.derive_key(test_password, salt, 32)
                    test_aead = ChaCha20Poly1305(test_key)
                    test_nonce = b'\x00' * 12
                    
                    # Try to decrypt length chunk
                    payload_length_bytes = test_aead.decrypt(test_nonce, length_chunk, None)
                    payload_length = int.from_bytes(payload_length_bytes, 'big')
                    
                    # Valid payload length range
                    if 0 < payload_length <= 0x3FFF:
                        username = test_username
                        ss_password = test_password
                        logger.info(f"[SS] Identified user: {username}")
                        break
                except Exception:
                    continue
            
            if not username or not ss_password:
                logger.warning(f"[SS] Could not identify user from {peer_ip}")
                writer.close()
                return

            key = self.derive_key(ss_password, salt, 32)
            aead = ChaCha20Poly1305(key)

            nonce = b'\x00' * 12
            # We already decrypted and validated this in the user identification step
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

            # Parse destination address
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
                logger.warning(f"[SS] Unknown address type: {addr_type}")
                writer.close()
                return

            initial_data = payload[header_len:] if len(payload) > header_len else b''

            logger.info(f"[SS] {username} -> {target_host}:{target_port} (initial data: {len(initial_data)} bytes)")

            try:
                remote_reader, remote_writer = await asyncio.open_connection(target_host, target_port)
                logger.info(f"[SS] {username}: connected to {target_host}:{target_port}")
            except Exception as e:
                logger.error(f"[SS] Connection failed to {target_host}:{target_port}: {e}")
                writer.close()
                return

            # Generate response salt
            response_salt = os.urandom(32)
            response_key = self.derive_key(ss_password, response_salt, 32)
            response_aead = ChaCha20Poly1305(response_key)

            writer.write(response_salt)
            await writer.drain()
            logger.info(f"[SS] {username}: sent response salt, starting data transfer")

            # Send initial data to remote server
            if initial_data:
                logger.info(f"[SS] {username}: sending initial {len(initial_data)} bytes to {target_host}")
                remote_writer.write(initial_data)
                await remote_writer.drain()

            nonce_c2s = self._increment_nonce(nonce)
            nonce_s2c = b'\x00' * 12

            results = await asyncio.gather(
                self._pipe_decrypt(reader, remote_writer, aead, nonce_c2s, username, "c2s"),
                self._pipe_encrypt(remote_reader, writer, response_aead, nonce_s2c, username, "s2c"),
                return_exceptions=True
            )

            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(f"[SS] {username}: pipe task {i} failed: {result}")

        except Exception as e:
            logger.error(f"[SS] Error: {e}", exc_info=True)
        finally:
            writer.close()

    def _increment_nonce(self, nonce: bytes) -> bytes:
        counter = int.from_bytes(nonce, 'little')
        counter += 1
        return counter.to_bytes(12, 'little')

    async def _pipe_decrypt(self, reader, writer, aead, nonce, username, direction):
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

    async def _pipe_encrypt(self, reader, writer, aead, nonce, username, direction):
        """Read plaintext data, encrypt and send (s2c)"""
        try:
            total_bytes = 0
            max_payload_size = 0x3FFF  # 16383 bytes - max for Shadowsocks AEAD

            while not reader.at_eof():
                data = await asyncio.wait_for(reader.read(self.buffer_size), timeout=300)
                if not data:
                    break

                total_bytes += len(data)
                logger.debug(f"[SS] {direction} {username}: received {len(data)} bytes (total: {total_bytes})")

                # Split large chunks into max_payload_size parts
                offset = 0
                while offset < len(data):
                    chunk = data[offset:offset + max_payload_size]

                    # Encrypt: length first, then payload
                    length_bytes = len(chunk).to_bytes(2, 'big')
                    encrypted_length = aead.encrypt(nonce, length_bytes, None)
                    nonce = self._increment_nonce(nonce)

                    encrypted_payload = aead.encrypt(nonce, chunk, None)
                    nonce = self._increment_nonce(nonce)

                    writer.write(encrypted_length + encrypted_payload)
                    offset += len(chunk)
                
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
