#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import socket
import struct
import hashlib
import hmac
import base64
import asyncio
import aiohttp
import logging
import ipaddress
import subprocess
from aiohttp import web

# 环境变量
UUID = os.environ.get('UUID', '7bd180e8-1142-4387-93f5-03e8d750a896')   # 节点UUID
NEZHA_SERVER = os.environ.get('NEZHA_SERVER', '')    # 哪吒v0填写格式: nezha.xxx.com  哪吒v1填写格式: nezha.xxx.com:8008
NEZHA_PORT = os.environ.get('NEZHA_PORT', '')        # 哪吒v1请留空，哪吒v0 agent端口
NEZHA_KEY = os.environ.get('NEZHA_KEY', '')          # 哪吒v0或v1密钥，哪吒面板后台命令里获取
DOMAIN = os.environ.get('DOMAIN', '')                # 项目分配的域名或反代后的域名,不包含https://前缀,例如: domain.xxx.com
SUB_PATH = os.environ.get('SUB_PATH', 'sub')         # 节点订阅token
NAME = os.environ.get('NAME', '')                    # 节点名称
WSPATH = os.environ.get('WSPATH', UUID[:8])          # 节点路径
PORT = int(os.environ.get('SERVER_PORT') or os.environ.get('PORT') or 3000)  # http和ws端口，默认自动优先获取容器分配的端口
AUTO_ACCESS = os.environ.get('AUTO_ACCESS', '').lower() == 'true' # 自动访问保活,默认关闭,true开启,false关闭,需同时填写DOMAIN变量
DEBUG = os.environ.get('DEBUG', '').lower() == 'true' # 保持默认,调试使用,true开启调试

# 全局变量
CurrentDomain = DOMAIN
CurrentPort = 443
Tls = 'tls'
ISP = ''

# dns server
DNS_SERVERS = ['8.8.4.4', '1.1.1.1']
BLOCKED_DOMAINS = [
    'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me',
    'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org'
]

# 日志级别
log_level = logging.DEBUG if DEBUG else logging.INFO
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# 禁用访问,连接等日志
logging.getLogger('aiohttp.access').setLevel(logging.WARNING)
logging.getLogger('aiohttp.server').setLevel(logging.WARNING)
logging.getLogger('aiohttp.client').setLevel(logging.WARNING)
logging.getLogger('aiohttp.internal').setLevel(logging.WARNING)
logging.getLogger('aiohttp.websocket').setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

def is_port_available(port, host='0.0.0.0'):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False

def find_available_port(start_port, max_attempts=100):
    for port in range(start_port, start_port + max_attempts):
        if is_port_available(port):
            return port
    return None

def is_blocked_domain(host: str) -> bool:
    if not host:
        return False
    host_lower = host.lower()
    return any(host_lower == blocked or host_lower.endswith('.' + blocked) 
              for blocked in BLOCKED_DOMAINS)

async def get_isp():
    global ISP
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get('https://api.ip.sb/geoip', 
                                 headers={'User-Agent': 'Mozilla/5.0'},
                                 timeout=3) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    ISP = f"{data.get('country_code', '')}-{data.get('isp', '')}".replace(' ', '_')
                    return
    except:
        pass
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get('http://ip-api.com/json',
                                 headers={'User-Agent': 'Mozilla/5.0'},
                                 timeout=3) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    ISP = f"{data.get('countryCode', '')}-{data.get('org', '')}".replace(' ', '_')
                    return
    except:
        pass
    
    ISP = 'Unknown'

async def get_ip():
    global CurrentDomain, Tls, CurrentPort
    if not DOMAIN or DOMAIN == 'your-domain.com':
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get('https://api-ipv4.ip.sb/ip', timeout=5) as resp:
                    if resp.status == 200:
                        ip = await resp.text()
                        CurrentDomain = ip.strip()
                        Tls = 'none'
                        CurrentPort = PORT
        except Exception as e:
            logger.error(f'Failed to get IP: {e}')
            CurrentDomain = 'change-your-domain.com'
            Tls = 'tls'
            CurrentPort = 443
    else:
        CurrentDomain = DOMAIN
        Tls = 'tls'
        CurrentPort = 443

async def resolve_host(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except:
        pass
    
    for dns_server in DNS_SERVERS:
        try:
            async with aiohttp.ClientSession() as session:
                url = f'https://dns.google/resolve?name={host}&type=A'
                async with session.get(url, timeout=5) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get('Status') == 0 and data.get('Answer'):
                            for answer in data['Answer']:
                                if answer.get('type') == 1:
                                    return answer.get('data')
        except:
            continue
    
    return host  # 如果解析失败，返回原始域名

SS_AEAD_METHOD = 'aes-128-gcm'
SS_AEAD_KEY_LEN = 16
SS_AEAD_SALT_LEN = 16
SS_AEAD_NONCE_LEN = 12
SS_AEAD_TAG_LEN = 16
SS_AEAD_MAX_CHUNK_SIZE = 0x3fff
SS_AEAD_INFO = b'ss-subkey'


class ShadowsocksProtocolError(Exception):
    pass


def parse_shadowsocks_address(data: bytes):
    if len(data) < 1:
        return None

    offset = 0
    atyp = data[offset]
    offset += 1

    if atyp == 1:  # IPv4
        if len(data) < offset + 4 + 2:
            return None
        host = '.'.join(str(b) for b in data[offset:offset+4])
        offset += 4
    elif atyp == 3:  # 域名
        if len(data) < offset + 1:
            return None
        host_len = data[offset]
        offset += 1
        if host_len == 0:
            raise ShadowsocksProtocolError('Invalid empty Shadowsocks host')
        if len(data) < offset + host_len + 2:
            return None
        try:
            host = data[offset:offset+host_len].decode()
        except UnicodeDecodeError as exc:
            raise ShadowsocksProtocolError('Invalid Shadowsocks host encoding') from exc
        offset += host_len
    elif atyp == 4:  # IPv6
        if len(data) < offset + 16 + 2:
            return None
        host = ':'.join(f'{(data[j] << 8) + data[j+1]:04x}' 
                      for j in range(offset, offset+16, 2))
        offset += 16
    else:
        raise ShadowsocksProtocolError('Invalid Shadowsocks address type')

    port = struct.unpack('!H', data[offset:offset+2])[0]
    offset += 2
    return host, port, offset


def evp_bytes_to_key(password: bytes, key_len: int) -> bytes:
    result = b''
    prev = b''
    while len(result) < key_len:
        prev = hashlib.md5(prev + password).digest()
        result += prev
    return result[:key_len]


def hkdf_sha1(salt: bytes, key: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, key, hashlib.sha1).digest()
    okm = b''
    prev = b''
    counter = 1
    while len(okm) < length:
        prev = hmac.new(prk, prev + info + bytes([counter]), hashlib.sha1).digest()
        okm += prev
        counter += 1
    return okm[:length]


AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

AES_RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
GCM_R = 0xe1000000000000000000000000000000


def aes_xtime(value: int) -> int:
    value <<= 1
    if value & 0x100:
        value ^= 0x11b
    return value & 0xff


class Aes128:
    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError('AES-128 key must be 16 bytes')
        self.round_keys = self.expand_key(key)

    @staticmethod
    def expand_key(key: bytes) -> list:
        expanded = list(key)
        rcon_iter = 1
        while len(expanded) < 176:
            temp = expanded[-4:]
            if len(expanded) % 16 == 0:
                temp = temp[1:] + temp[:1]
                temp = [AES_SBOX[b] for b in temp]
                temp[0] ^= AES_RCON[rcon_iter]
                rcon_iter += 1
            for value in temp:
                expanded.append(expanded[-16] ^ value)
        return expanded

    @staticmethod
    def add_round_key(state: list, round_key: list):
        for i in range(16):
            state[i] ^= round_key[i]

    @staticmethod
    def sub_bytes(state: list):
        for i, value in enumerate(state):
            state[i] = AES_SBOX[value]

    @staticmethod
    def shift_rows(state: list):
        state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
        state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
        state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]

    @staticmethod
    def mix_columns(state: list):
        for i in range(0, 16, 4):
            a0, a1, a2, a3 = state[i:i+4]
            t = a0 ^ a1 ^ a2 ^ a3
            state[i] ^= t ^ aes_xtime(a0 ^ a1)
            state[i+1] ^= t ^ aes_xtime(a1 ^ a2)
            state[i+2] ^= t ^ aes_xtime(a2 ^ a3)
            state[i+3] ^= t ^ aes_xtime(a3 ^ a0)

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError('AES block must be 16 bytes')
        state = list(block)
        self.add_round_key(state, self.round_keys[:16])

        for round_index in range(1, 10):
            self.sub_bytes(state)
            self.shift_rows(state)
            self.mix_columns(state)
            start = round_index * 16
            self.add_round_key(state, self.round_keys[start:start+16])

        self.sub_bytes(state)
        self.shift_rows(state)
        self.add_round_key(state, self.round_keys[160:176])
        return bytes(state)


def xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def inc32(counter: bytearray):
    value = (int.from_bytes(counter[12:16], 'big') + 1) & 0xffffffff
    counter[12:16] = value.to_bytes(4, 'big')


def gcm_mul(x: int, y: int) -> int:
    z = 0
    v = x
    for i in range(128):
        if (y >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ GCM_R
        else:
            v >>= 1
    return z


def ghash(h: int, aad: bytes, ciphertext: bytes) -> bytes:
    y = 0

    def update(block: bytes):
        nonlocal y
        y = gcm_mul(y ^ int.from_bytes(block, 'big'), h)

    for data in (aad, ciphertext):
        for offset in range(0, len(data), 16):
            block = data[offset:offset+16]
            if len(block) < 16:
                block += b'\x00' * (16 - len(block))
            update(block)

    update((len(aad) * 8).to_bytes(8, 'big') + (len(ciphertext) * 8).to_bytes(8, 'big'))
    return y.to_bytes(16, 'big')


class Aes128Gcm:
    def __init__(self, key: bytes):
        self.aes = Aes128(key)
        self.h = int.from_bytes(self.aes.encrypt_block(b'\x00' * 16), 'big')

    def gctr(self, initial_counter: bytes, data: bytes) -> bytes:
        if not data:
            return b''
        counter = bytearray(initial_counter)
        output = bytearray()
        for offset in range(0, len(data), 16):
            block = data[offset:offset+16]
            key_stream = self.aes.encrypt_block(bytes(counter))
            output.extend(xor_bytes(block, key_stream[:len(block)]))
            inc32(counter)
        return bytes(output)

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes = b'') -> bytes:
        if len(nonce) != 12:
            raise ValueError('AES-GCM nonce must be 12 bytes')
        j0 = nonce + b'\x00\x00\x00\x01'
        initial_counter = bytearray(j0)
        inc32(initial_counter)
        ciphertext = self.gctr(bytes(initial_counter), plaintext)
        tag_mask = self.aes.encrypt_block(j0)
        tag = xor_bytes(tag_mask, ghash(self.h, aad, ciphertext))
        return ciphertext + tag

    def decrypt(self, nonce: bytes, data: bytes, aad: bytes = b'') -> bytes:
        if len(data) < SS_AEAD_TAG_LEN:
            raise ValueError('Missing AES-GCM tag')
        ciphertext = data[:-SS_AEAD_TAG_LEN]
        tag = data[-SS_AEAD_TAG_LEN:]
        j0 = nonce + b'\x00\x00\x00\x01'
        expected_tag = xor_bytes(self.aes.encrypt_block(j0), ghash(self.h, aad, ciphertext))
        if not hmac.compare_digest(tag, expected_tag):
            raise ValueError('Invalid AES-GCM tag')
        initial_counter = bytearray(j0)
        inc32(initial_counter)
        return self.gctr(bytes(initial_counter), ciphertext)


def increment_shadowsocks_nonce(nonce: bytearray):
    for i in range(len(nonce)):
        nonce[i] = (nonce[i] + 1) & 0xff
        if nonce[i] != 0:
            break


class ShadowsocksAeadCrypto:
    def __init__(self, password: str):
        self.master_key = evp_bytes_to_key(password.encode(), SS_AEAD_KEY_LEN)

    def cipher_for_salt(self, salt: bytes) -> Aes128Gcm:
        if len(salt) != SS_AEAD_SALT_LEN:
            raise ShadowsocksProtocolError('Invalid Shadowsocks AEAD salt')
        subkey = hkdf_sha1(salt, self.master_key, SS_AEAD_INFO, SS_AEAD_KEY_LEN)
        return Aes128Gcm(subkey)


class ShadowsocksAeadDecoder:
    def __init__(self, password: str):
        self.crypto = ShadowsocksAeadCrypto(password)
        self.buffer = bytearray()
        self.cipher = None
        self.nonce = bytearray(SS_AEAD_NONCE_LEN)
        self.pending_len = None

    def feed(self, data: bytes):
        self.buffer.extend(data)

    def next_nonce(self) -> bytes:
        nonce = bytes(self.nonce)
        increment_shadowsocks_nonce(self.nonce)
        return nonce

    def next_chunk(self):
        if self.cipher is None:
            if len(self.buffer) < SS_AEAD_SALT_LEN:
                return None
            salt = bytes(self.buffer[:SS_AEAD_SALT_LEN])
            del self.buffer[:SS_AEAD_SALT_LEN]
            self.cipher = self.crypto.cipher_for_salt(salt)

        if self.pending_len is None:
            encrypted_len_size = 2 + SS_AEAD_TAG_LEN
            if len(self.buffer) < encrypted_len_size:
                return None
            encrypted_len = bytes(self.buffer[:encrypted_len_size])
            del self.buffer[:encrypted_len_size]
            try:
                length_bytes = self.cipher.decrypt(self.next_nonce(), encrypted_len)
            except ValueError as exc:
                raise ShadowsocksProtocolError('Invalid Shadowsocks AEAD length tag') from exc
            self.pending_len = struct.unpack('!H', length_bytes)[0]
            if self.pending_len > SS_AEAD_MAX_CHUNK_SIZE:
                raise ShadowsocksProtocolError('Invalid Shadowsocks AEAD chunk size')

        encrypted_payload_size = self.pending_len + SS_AEAD_TAG_LEN
        if len(self.buffer) < encrypted_payload_size:
            return None

        encrypted_payload = bytes(self.buffer[:encrypted_payload_size])
        del self.buffer[:encrypted_payload_size]
        try:
            payload = self.cipher.decrypt(self.next_nonce(), encrypted_payload)
        except ValueError as exc:
            raise ShadowsocksProtocolError('Invalid Shadowsocks AEAD payload tag') from exc
        self.pending_len = None
        return payload


class ShadowsocksAeadEncoder:
    def __init__(self, password: str):
        self.crypto = ShadowsocksAeadCrypto(password)
        self.salt = os.urandom(SS_AEAD_SALT_LEN)
        self.cipher = self.crypto.cipher_for_salt(self.salt)
        self.nonce = bytearray(SS_AEAD_NONCE_LEN)
        self.salt_sent = False

    def next_nonce(self) -> bytes:
        nonce = bytes(self.nonce)
        increment_shadowsocks_nonce(self.nonce)
        return nonce

    def encrypt(self, data: bytes) -> bytes:
        output = bytearray()
        if not self.salt_sent:
            output.extend(self.salt)
            self.salt_sent = True

        for offset in range(0, len(data), SS_AEAD_MAX_CHUNK_SIZE):
            chunk = data[offset:offset+SS_AEAD_MAX_CHUNK_SIZE]
            output.extend(self.cipher.encrypt(self.next_nonce(), struct.pack('!H', len(chunk))))
            output.extend(self.cipher.encrypt(self.next_nonce(), chunk))

        return bytes(output)


class ProxyHandler:
    def __init__(self, uuid: str, ss_password: str = None):
        self.uuid = uuid
        self.uuid_bytes = bytes.fromhex(uuid)
        self.ss_password = ss_password or uuid
        
    async def handle_vless(self, websocket, first_msg: bytes) -> bool:
        """处理VLS协议"""
        try:
            if len(first_msg) < 18 or first_msg[0] != 0:
                return False
            
            # 验证UUID
            if first_msg[1:17] != self.uuid_bytes:
                return False
            
            i = first_msg[17] + 19
            if i + 3 > len(first_msg):
                return False
            
            port = struct.unpack('!H', first_msg[i:i+2])[0]
            i += 2
            atyp = first_msg[i]
            i += 1
            
            # 解析地址
            host = ''
            if atyp == 1:  # IPv4
                if i + 4 > len(first_msg):
                    return False
                host = '.'.join(str(b) for b in first_msg[i:i+4])
                i += 4
            elif atyp == 2:  # 域名
                if i >= len(first_msg):
                    return False
                host_len = first_msg[i]
                i += 1
                if i + host_len > len(first_msg):
                    return False
                host = first_msg[i:i+host_len].decode()
                i += host_len
            elif atyp == 3:  # IPv6
                if i + 16 > len(first_msg):
                    return False
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}' 
                              for j in range(i, i+16, 2))
                i += 16
            else:
                return False
            
            if is_blocked_domain(host):
                await websocket.close()
                return False
            
            await websocket.send_bytes(bytes([0, 0]))
            
            resolved_host = await resolve_host(host)
            
            try:
                reader, writer = await asyncio.open_connection(resolved_host, port)
                
                # 发送剩余数据
                if i < len(first_msg):
                    writer.write(first_msg[i:])
                    await writer.drain()
                
                # 双向转发
                async def forward_ws_to_tcp():
                    try:
                        async for msg in websocket:
                            if msg.type == aiohttp.WSMsgType.BINARY:
                                writer.write(msg.data)
                                await writer.drain()
                    except:
                        pass
                    finally:
                        writer.close()
                        await writer.wait_closed()
                
                async def forward_tcp_to_ws():
                    try:
                        while True:
                            data = await reader.read(4096)
                            if not data:
                                break
                            await websocket.send_bytes(data)
                    except:
                        pass
                
                await asyncio.gather(
                    forward_ws_to_tcp(),
                    forward_tcp_to_ws()
                )
                
            except Exception as e:
                if DEBUG:
                    logger.error(f"Connection error: {e}")
            
            return True
            
        except Exception as e:
            if DEBUG:
                logger.error(f"VLESS handler error: {e}")
            return False
    
    async def handle_trojan(self, websocket, first_msg: bytes) -> bool:
        """处理Tro协议"""
        try:
            if len(first_msg) < 58:
                return False
            
            received_hash_bytes = first_msg[:56]
            
            # 验证密码 - 支持标准UUID和无短横线UUID
            hash_obj1 = hashlib.sha224()
            hash_obj1.update(self.uuid.encode())
            expected_hash_hex1 = hash_obj1.hexdigest()
            
            # 尝试使用标准UUID（带短横线）
            standard_uuid = UUID
            hash_obj2 = hashlib.sha224()
            hash_obj2.update(standard_uuid.encode())
            expected_hash_hex2 = hash_obj2.hexdigest()
            
            # 转换为hex字符串进行比较
            received_hash_hex = received_hash_bytes.decode('ascii', errors='ignore')
            
            # 检查是否匹配任一UUID格式
            if received_hash_hex != expected_hash_hex1 and received_hash_hex != expected_hash_hex2:
                return False
            
            offset = 56
            if first_msg[offset:offset+2] == b'\r\n':
                offset += 2
            
            cmd = first_msg[offset]
            if cmd != 1:
                return False
            offset += 1
            
            atyp = first_msg[offset]
            offset += 1
            
            # 解析地址
            host = ''
            if atyp == 1:  # IPv4
                host = '.'.join(str(b) for b in first_msg[offset:offset+4])
                offset += 4
            elif atyp == 3:  # 域名
                host_len = first_msg[offset]
                offset += 1
                host = first_msg[offset:offset+host_len].decode()
                offset += host_len
            elif atyp == 4:  # IPv6
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}' 
                              for j in range(offset, offset+16, 2))
                offset += 16
            else:
                return False
            
            port = struct.unpack('!H', first_msg[offset:offset+2])[0]
            offset += 2
            
            if first_msg[offset:offset+2] == b'\r\n':
                offset += 2
            
            if is_blocked_domain(host):
                await websocket.close()
                return False
            
            # 连接目标
            resolved_host = await resolve_host(host)
            
            try:
                reader, writer = await asyncio.open_connection(resolved_host, port)
                
                if offset < len(first_msg):
                    writer.write(first_msg[offset:])
                    await writer.drain()
                
                async def forward_ws_to_tcp():
                    try:
                        async for msg in websocket:
                            if msg.type == aiohttp.WSMsgType.BINARY:
                                writer.write(msg.data)
                                await writer.drain()
                    except:
                        pass
                    finally:
                        writer.close()
                        await writer.wait_closed()
                
                async def forward_tcp_to_ws():
                    try:
                        while True:
                            data = await reader.read(4096)
                            if not data:
                                break
                            await websocket.send_bytes(data)
                    except:
                        pass
                
                await asyncio.gather(
                    forward_ws_to_tcp(),
                    forward_tcp_to_ws()
                )
                
            except Exception as e:
                if DEBUG:
                    logger.error(f"Connection error: {e}")
            
            return True
            
        except Exception as e:
            if DEBUG:
                logger.error(f"Tro handler error: {e}")
            return False
    
    async def handle_shadowsocks_aes_128_gcm(self, websocket, first_msg: bytes) -> bool:
        """处理ss aes-128-gcm协议"""
        try:
            decoder = ShadowsocksAeadDecoder(self.ss_password)
            encoder = ShadowsocksAeadEncoder(self.ss_password)
            plaintext = bytearray()
            parsed = None
            decoder.feed(first_msg)

            while parsed is None:
                while True:
                    chunk = decoder.next_chunk()
                    if chunk is None:
                        break
                    plaintext.extend(chunk)
                    parsed = parse_shadowsocks_address(plaintext)
                    if parsed is not None:
                        break

                if parsed is not None:
                    break

                if len(plaintext) > SS_AEAD_MAX_CHUNK_SIZE:
                    raise ShadowsocksProtocolError('Shadowsocks address header is too large')

                msg = await asyncio.wait_for(websocket.receive(), timeout=5)
                if msg.type != aiohttp.WSMsgType.BINARY:
                    return False
                decoder.feed(msg.data)

            host, port, offset = parsed
            
            if is_blocked_domain(host):
                await websocket.close()
                return False
            
            # 连接目标
            resolved_host = await resolve_host(host)
            
            try:
                reader, writer = await asyncio.open_connection(resolved_host, port)
                
                wrote_initial = False
                if offset < len(plaintext):
                    writer.write(plaintext[offset:])
                    wrote_initial = True

                while True:
                    chunk = decoder.next_chunk()
                    if chunk is None:
                        break
                    if chunk:
                        writer.write(chunk)
                        wrote_initial = True

                if wrote_initial:
                    await writer.drain()
                
                async def forward_ws_to_tcp():
                    try:
                        async for msg in websocket:
                            if msg.type == aiohttp.WSMsgType.BINARY:
                                decoder.feed(msg.data)
                                wrote_data = False
                                while True:
                                    chunk = decoder.next_chunk()
                                    if chunk is None:
                                        break
                                    if chunk:
                                        writer.write(chunk)
                                        wrote_data = True
                                if wrote_data:
                                    await writer.drain()
                    except:
                        pass
                    finally:
                        writer.close()
                        await writer.wait_closed()
                
                async def forward_tcp_to_ws():
                    try:
                        while True:
                            data = await reader.read(4096)
                            if not data:
                                break
                            await websocket.send_bytes(encoder.encrypt(data))
                    except:
                        pass
                
                await asyncio.gather(
                    forward_ws_to_tcp(),
                    forward_tcp_to_ws()
                )
                
            except Exception as e:
                if DEBUG:
                    logger.error(f"Connection error: {e}")
            
            return True
            
        except (asyncio.TimeoutError, ShadowsocksProtocolError):
            return False
        except Exception as e:
            if DEBUG:
                logger.error(f"Shadowsocks aes-128-gcm handler error: {e}")
            return False

    async def handle_shadowsocks(self, websocket, first_msg: bytes) -> bool:
        """处理ss none协议，兼容旧链接"""
        try:
            parsed = parse_shadowsocks_address(first_msg)
            if parsed is None:
                return False
            host, port, offset = parsed

            if is_blocked_domain(host):
                await websocket.close()
                return False
            
            # 连接目标
            resolved_host = await resolve_host(host)
            
            try:
                reader, writer = await asyncio.open_connection(resolved_host, port)
                
                if offset < len(first_msg):
                    writer.write(first_msg[offset:])
                    await writer.drain()
                
                async def forward_ws_to_tcp():
                    try:
                        async for msg in websocket:
                            if msg.type == aiohttp.WSMsgType.BINARY:
                                writer.write(msg.data)
                                await writer.drain()
                    except:
                        pass
                    finally:
                        writer.close()
                        await writer.wait_closed()
                
                async def forward_tcp_to_ws():
                    try:
                        while True:
                            data = await reader.read(4096)
                            if not data:
                                break
                            await websocket.send_bytes(data)
                    except:
                        pass
                
                await asyncio.gather(
                    forward_ws_to_tcp(),
                    forward_tcp_to_ws()
                )
                
            except Exception as e:
                if DEBUG:
                    logger.error(f"Connection error: {e}")
            
            return True
            
        except ShadowsocksProtocolError:
            return False
        except Exception as e:
            if DEBUG:
                logger.error(f"Shadowsocks handler error: {e}")
            return False

async def websocket_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    CUUID = UUID.replace('-', '')
    path = request.path
    
    if f'/{WSPATH}' not in path:
        await ws.close()
        return ws
    
    proxy = ProxyHandler(CUUID, UUID)
    
    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=5)
        if first_msg.type != aiohttp.WSMsgType.BINARY:
            await ws.close()
            return ws
        
        msg_data = first_msg.data
        
        # 尝试VLS
        if len(msg_data) > 17 and msg_data[0] == 0:
            if await proxy.handle_vless(ws, msg_data):
                return ws
        
        # 尝试Tro
        if len(msg_data) >= 58:
            if await proxy.handle_trojan(ws, msg_data):
                return ws
        
        # 尝试ss aes-128-gcm
        tried_shadowsocks_aead = False
        if len(msg_data) > 0 and (
            len(msg_data) >= SS_AEAD_SALT_LEN + 2 + SS_AEAD_TAG_LEN or msg_data[0] not in (1, 3, 4)
        ):
            tried_shadowsocks_aead = True
            if await proxy.handle_shadowsocks_aes_128_gcm(ws, msg_data):
                return ws

        # 尝试ss none，兼容旧链接
        if len(msg_data) > 0 and msg_data[0] in (1, 3, 4):
            if await proxy.handle_shadowsocks(ws, msg_data):
                return ws

        if not tried_shadowsocks_aead:
            if await proxy.handle_shadowsocks_aes_128_gcm(ws, msg_data):
                return ws
        
        await ws.close()
        
    except asyncio.TimeoutError:
        await ws.close()
    except Exception as e:
        if DEBUG:
            logger.error(f"WebSocket handler error: {e}")
        await ws.close()
    
    return ws

async def http_handler(request):
    if request.path == '/':
        try:
            with open('index.html', 'r', encoding='utf-8') as f:
                content = f.read()
            return web.Response(text=content, content_type='text/html')
        except:
            return web.Response(text='Hello world!', content_type='text/html')
    
    elif request.path == f'/{SUB_PATH}':
        await get_isp()
        await get_ip()
        
        name_part = f"{NAME}-{ISP}" if NAME else ISP
        tls_param = 'tls' if Tls == 'tls' else 'none'
        ss_tls_param = 'tls;' if Tls == 'tls' else ''
        
        # 生成配置链接
        vless_url = f"vless://{UUID}@{CurrentDomain}:{CurrentPort}?encryption=none&security={tls_param}&sni={CurrentDomain}&fp=chrome&type=ws&host={CurrentDomain}&path=%2F{WSPATH}#{name_part}"
        trojan_url = f"trojan://{UUID}@{CurrentDomain}:{CurrentPort}?security={tls_param}&sni={CurrentDomain}&fp=chrome&type=ws&host={CurrentDomain}&path=%2F{WSPATH}#{name_part}"
        
        ss_method_password = base64.b64encode(f"{SS_AEAD_METHOD}:{UUID}".encode()).decode()
        ss_url = f"ss://{ss_method_password}@{CurrentDomain}:{CurrentPort}?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D{CurrentDomain};path%3D%2F{WSPATH};{ss_tls_param}sni%3D{CurrentDomain};skip-cert-verify%3Dtrue;mux%3D0#{name_part}"
        
        subscription = f"{vless_url}\n{trojan_url}\n{ss_url}"
        base64_content = base64.b64encode(subscription.encode()).decode()
        
        return web.Response(text=base64_content + '\n', content_type='text/plain')
    
    return web.Response(status=404, text='Not Found\n')

def get_download_url():
    import platform
    arch = platform.machine()
    
    if 'arm' in arch.lower() or 'aarch64' in arch.lower():
        if not NEZHA_PORT:
            return 'https://arm64.eooce.com/v1'
        else:
            return 'https://arm64.eooce.com/agent'
    else:
        if not NEZHA_PORT:
            return 'https://amd64.eooce.com/v1'
        else:
            return 'https://amd64.eooce.com/agent'

async def download_file():
    if not NEZHA_SERVER and not NEZHA_KEY:
        return
    
    try:
        url = get_download_url()
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                if resp.status == 200:
                    content = await resp.read()
                    with open('npm', 'wb') as f:
                        f.write(content)
                    os.chmod('npm', 0o755)
                    logger.info('✅ npm downloaded successfully')
    except Exception as e:
        logger.error(f'Download failed: {e}')

async def run_nezha():
    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
        if './npm' in result.stdout and '[n]pm' in result.stdout:
            logger.info('npm is already running, skip...')
            return
    except:
        pass
    
    # 等待文件下载完成
    await download_file()
    
    command = ''
    tls_ports = ['443', '8443', '2096', '2087', '2083', '2053']
    if NEZHA_SERVER and NEZHA_PORT and NEZHA_KEY:
        nezha_tls = '--tls' if NEZHA_PORT in tls_ports else ''
        command = f'nohup ./npm -s {NEZHA_SERVER}:{NEZHA_PORT} -p {NEZHA_KEY} {nezha_tls} --disable-auto-update --report-delay 4 --skip-conn --skip-procs >/dev/null 2>&1 &'
    elif NEZHA_SERVER and NEZHA_KEY:
        if not NEZHA_PORT:
            port = NEZHA_SERVER.split(':')[-1] if ':' in NEZHA_SERVER else ''
            nz_tls = 'true' if port in tls_ports else 'false'
            config = f"""client_secret: {NEZHA_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: true
ip_report_period: 1800
report_delay: 4
server: {NEZHA_SERVER}
skip_connection_count: true
skip_procs_count: true
temperature: false
tls: {nz_tls}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: {UUID}"""

            with open('config.yaml', 'w') as f:
                f.write(config)

        command = f'nohup ./npm -c config.yaml >/dev/null 2>&1 &'
    else:
        return
    
    try:
        subprocess.Popen(command, shell=True, executable='/bin/bash')
        logger.info('✅ nz started successfully')
    except Exception as e:
        logger.error(f'Error running nz: {e}')

async def add_access_task():
    if not AUTO_ACCESS or not DOMAIN:
        return
    
    full_url = f"https://{DOMAIN}/{SUB_PATH}"
    try:
        async with aiohttp.ClientSession() as session:
            await session.post("https://oooo.serv00.net/add-url",
                             json={"url": full_url},
                             headers={'Content-Type': 'application/json'})
        logger.info('Automatic Access Task added successfully')
    except:
        pass

def cleanup_files():
    for file in ['npm', 'config.yaml']:
        try:
            if os.path.exists(file):
                os.remove(file)
        except:
            pass

async def main():
    actual_port = PORT
    
    # 检查端口是否可用，如果不可用则查找可用端口
    if not is_port_available(actual_port):
        logger.warning(f"Port {actual_port} is already in use, finding available port...")
        new_port = find_available_port(actual_port + 1)
        if new_port:
            actual_port = new_port
            logger.info(f"Using port {actual_port} instead of {PORT}")
        else:
            logger.error("No available ports found")
            sys.exit(1)
    
    app = web.Application()
    
    # 路由
    app.router.add_get('/', http_handler)
    app.router.add_get(f'/{SUB_PATH}', http_handler)
    app.router.add_get(f'/{WSPATH}', websocket_handler)
    
    # 启动服务
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', actual_port)
    await site.start()
    logger.info(f"✅ server is running on port {actual_port}")
    asyncio.create_task(run_nezha())
    async def delayed_cleanup():
        await asyncio.sleep(180)
        cleanup_files()
    
    asyncio.create_task(delayed_cleanup())
    
    await add_access_task()
    
    try:
        await asyncio.Future()
    except KeyboardInterrupt:
        pass
    finally:
        await runner.cleanup()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped by user")
        cleanup_files()
