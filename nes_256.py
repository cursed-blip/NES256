"""
NES256 - educational AES-like block cipher + AE (toy)

Name: NES256 (New Encryption Standard 256) -- an experimental, educational
implementation modeled after AES design choices but with some modern twists:
- 256-bit master key
- 128-bit block size
- Round keys derived via HKDF (HMAC-SHA256) from master key + nonce
- 14 rounds (AES-256-like count)
- AES S-box and AES-style SubBytes/ShiftRows/MixColumns layers (SPN design)
- CTR mode for confidentiality + HMAC-SHA256 (encrypt-then-MAC) for integrity
- 16-byte random nonce per encryption

IMPORTANT WARNING
-----------------
This is a teaching/experimentation implementation ONLY. It is NOT a
cryptographically-audited algorithm and should NOT be used to protect real
secrets. Creating a secure block cipher is extremely difficult and requires
years of cryptanalysis and review. Do NOT claim this is "better than AES-256".
Use established, vetted primitives (e.g., AES-GCM via cryptography or libsodium)
for real security.

Files/Functions
----------------
- generate_key(): returns 32-byte key
- encrypt(plaintext, key, aad=b"") -> base64 token (nonce||ct||tag)
- decrypt(token_b64, key, aad=b"") -> plaintext bytes (raises on auth fail)

Feel free to tinker: change round counts, tweak linear layer, or swap MAC.

"""

from __future__ import annotations
import os
import hmac
import hashlib
import secrets
import base64
from typing import Tuple

# Parameters
BLOCK_SIZE = 16          # 128-bit block
KEY_SIZE = 32            # 256-bit master key
NONCE_SIZE = 16          # 128-bit nonce
MAC_SIZE = 32            # HMAC-SHA256 tag length
ROUNDS = 14              # AES-256 uses 14 rounds

# AES S-box (copied from standard AES tables) - used here for demonstration
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

# --- Utility: simple HKDF (HMAC-SHA256) used to expand master key into round keys ---

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def derive_round_keys(master_key: bytes, nonce: bytes) -> list[bytes]:
    """Derive (ROUNDS+1) 16-byte round keys using HKDF with nonce as salt."""
    if len(master_key) != KEY_SIZE:
        raise ValueError("master_key must be 32 bytes (256-bit)")
    prk = hkdf_extract(nonce, master_key)
    total = (ROUNDS + 1) * BLOCK_SIZE
    okm = hkdf_expand(prk, b"NES256 roundkeys", total)
    keys = [okm[i*16:(i+1)*16] for i in range(ROUNDS + 1)]
    return keys

# --- AES-like primitive layers ---

def sub_bytes(state: bytearray) -> None:
    for i in range(len(state)):
        state[i] = SBOX[state[i]]


def shift_rows(state: bytearray) -> None:
    # state is 16 bytes in column-major order like AES
    # rows: 0..3
    s = list(state)
    # Row 1 rotate left 1
    state[1]  = s[5]
    state[5]  = s[9]
    state[9]  = s[13]
    state[13] = s[1]
    # Row 2 rotate left 2
    state[2]  = s[10]
    state[6]  = s[14]
    state[10] = s[2]
    state[14] = s[6]
    # Row 3 rotate left 3
    state[3]  = s[15]
    state[7]  = s[3]
    state[11] = s[7]
    state[15] = s[11]


def xtime(a: int) -> int:
    return ((a << 1) & 0xff) ^ (0x1b if (a & 0x80) else 0x00)


def mix_single_column(a: list[int]) -> list[int]:
    r = [0,0,0,0]
    r[0] = (xtime(a[0]) ^ (xtime(a[1]) ^ a[1]) ^ a[2] ^ a[3]) & 0xff
    r[1] = (a[0] ^ xtime(a[1]) ^ (xtime(a[2]) ^ a[2]) ^ a[3]) & 0xff
    r[2] = (a[0] ^ a[1] ^ xtime(a[2]) ^ (xtime(a[3]) ^ a[3])) & 0xff
    r[3] = ((xtime(a[0]) ^ a[0]) ^ a[1] ^ a[2] ^ xtime(a[3])) & 0xff
    return r


def mix_columns(state: bytearray) -> None:
    for c in range(4):
        col = [state[c], state[4+c], state[8+c], state[12+c]]
        m = mix_single_column(col)
        state[c], state[4+c], state[8+c], state[12+c] = m


def add_round_key(state: bytearray, roundkey: bytes) -> None:
    for i in range(BLOCK_SIZE):
        state[i] ^= roundkey[i]

# --- Block encryption (single block) ---

def encrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("block must be 16 bytes")
    state = bytearray(block)
    add_round_key(state, round_keys[0])
    for r in range(1, ROUNDS):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[r])
    # final round
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[ROUNDS])
    return bytes(state)

# --- CTR mode and AE (Encrypt-then-MAC with HMAC-SHA256) ---

def _int_to_block(n: int) -> bytes:
    return n.to_bytes(16, 'big')


def ctr_keystream(master_key: bytes, nonce: bytes, length: int) -> bytes:
    round_keys = derive_round_keys(master_key, nonce)
    out = bytearray()
    counter = 0
    while len(out) < length:
        iv = bytearray(nonce)
        # XOR last 8 bytes with counter (simple counter placement)
        ctr_block = int.from_bytes(iv[8:], 'big') ^ counter
        iv[8:] = ctr_block.to_bytes(8, 'big')
        block = encrypt_block(bytes(iv), round_keys)
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def generate_key() -> bytes:
    return secrets.token_bytes(KEY_SIZE)


def encrypt(plaintext: bytes | str, key: bytes, aad: bytes = b"") -> str:
    """Encrypt with NES256-CTR + HMAC-SHA256 (encrypt-then-mac).
    Returns base64(nonce || ciphertext || tag)
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError('key must be bytes')
    if len(key) != KEY_SIZE:
        raise ValueError('key must be 32 bytes')

    nonce = secrets.token_bytes(NONCE_SIZE)
    ks = ctr_keystream(key, nonce, len(plaintext))
    ciphertext = bytes(a ^ b for a,b in zip(plaintext, ks))

    mac = hmac.new(key, nonce + aad + ciphertext, hashlib.sha256).digest()
    blob = nonce + ciphertext + mac
    return base64.b64encode(blob).decode('ascii')


def decrypt(token_b64: str, key: bytes, aad: bytes = b"") -> bytes:
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError('key must be bytes')
    try:
        blob = base64.b64decode(token_b64)
    except Exception as e:
        raise ValueError('invalid base64 token') from e
    if len(blob) < NONCE_SIZE + MAC_SIZE:
        raise ValueError('token too short')
    nonce = blob[:NONCE_SIZE]
    tag = blob[-MAC_SIZE:]
    ciphertext = blob[NONCE_SIZE:-MAC_SIZE]

    expected = hmac.new(key, nonce + aad + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        raise ValueError('authentication failed')

    ks = ctr_keystream(key, nonce, len(ciphertext))
    plaintext = bytes(a ^ b for a,b in zip(ciphertext, ks))
    return plaintext

# --- Demo when run as script ---
if __name__ == '__main__':
    print('NES256 demo (toy)')
    key = generate_key()
    print('Key (base64):', base64.b64encode(key).decode('ascii'))
    msg = 'Hello NES256 world! This is a test.'
    aad = b'metadata'
    token = encrypt(msg, key, aad=aad)
    print('Token:', token)
    pt = decrypt(token, key, aad=aad)
    print('Decrypted:', pt.decode('utf-8'))
    # tamper test
    try:
        bad = bytearray(base64.b64decode(token))
        if len(bad) > NONCE_SIZE + 2:
            bad[NONCE_SIZE+2] ^= 1
        decrypt(base64.b64encode(bad).decode('ascii'), key, aad=aad)
    except Exception as e:
        print('Tamper detected (expected):', e)
