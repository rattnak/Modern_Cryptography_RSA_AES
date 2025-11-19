"""
Pure-Python AES implementation (ECB mode, PKCS#7 padding).

Public API:
- encrypt(text: str, key: str, size: int) -> str  # returns hex ciphertext
- decrypt(ciphertext_hex: str, key: str, size: int) -> str  # returns plaintext

This implementation accepts `size` in {128,192,256}. If the provided
`key` string is not the required length, it is deterministically derived
by taking SHA-256 of the key string and truncating/expanding to needed bytes.
"""
from typing import List
import hashlib
import os


# AES S-box and inverse S-box
#
# AES uses a single 8-bit substitution box (S-box) for the SubBytes step.
# The S-box is the same for AES-128, AES-192 and AES-256 — it is not
# different per round or per key size. The S-box is constructed by taking
# the multiplicative inverse in GF(2^8) (with 0 mapped to 0) followed by
# an affine transformation. Many implementations hard-code the table for
# performance. We also compute the inverse S-box from this table below.
# The S-box is the same for all AES variants (128/192/256).
sbox = [
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

inv_sbox = [0] * 256
for i, v in enumerate(sbox):
    inv_sbox[v] = i


# Round constant
Rcon = [0x00,
        0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36,
        0x6C,0xD8,0xAB,0x4D,0x9A,0x2F,0x5E,0xBC,0x63,0xC6,
        0x97,0x35,0x6A,0xD4,0xB3,0x7D,0xFA,0xEF,0xC5,0x91]


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1) & 0xFF


def _mul(a: int, b: int) -> int:
    # multiply in GF(2^8)
    res = 0
    for i in range(8):
        if b & 1:
            res ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return res


def _sub_bytes(state: List[int]) -> None:
    for i in range(16):
        state[i] = sbox[state[i]]


def _inv_sub_bytes(state: List[int]) -> None:
    for i in range(16):
        state[i] = inv_sbox[state[i]]


def _shift_rows(state: List[int]) -> None:
    # state is column-major 4x4
    s = state.copy()
    # row 0
    state[0] = s[0]; state[4] = s[4]; state[8] = s[8]; state[12] = s[12]
    # row 1
    state[1] = s[5]; state[5] = s[9]; state[9] = s[13]; state[13] = s[1]
    # row 2
    state[2] = s[10]; state[6] = s[14]; state[10] = s[2]; state[14] = s[6]
    # row 3
    state[3] = s[15]; state[7] = s[3]; state[11] = s[7]; state[15] = s[11]


def _inv_shift_rows(state: List[int]) -> None:
    s = state.copy()
    state[0] = s[0]; state[4] = s[4]; state[8] = s[8]; state[12] = s[12]
    state[1] = s[13]; state[5] = s[1]; state[9] = s[5]; state[13] = s[9]
    state[2] = s[10]; state[6] = s[14]; state[10] = s[2]; state[14] = s[6]
    state[3] = s[7]; state[7] = s[11]; state[11] = s[15]; state[15] = s[3]


def _mix_columns(state: List[int]) -> None:
    for c in range(4):
        i = c * 4
        a0 = state[i]; a1 = state[i+1]; a2 = state[i+2]; a3 = state[i+3]
        state[i]   = (_mul(0x02, a0) ^ _mul(0x03, a1) ^ a2 ^ a3) & 0xFF
        state[i+1] = (a0 ^ _mul(0x02, a1) ^ _mul(0x03, a2) ^ a3) & 0xFF
        state[i+2] = (a0 ^ a1 ^ _mul(0x02, a2) ^ _mul(0x03, a3)) & 0xFF
        state[i+3] = (_mul(0x03, a0) ^ a1 ^ a2 ^ _mul(0x02, a3)) & 0xFF


def _inv_mix_columns(state: List[int]) -> None:
    for c in range(4):
        i = c * 4
        a0 = state[i]; a1 = state[i+1]; a2 = state[i+2]; a3 = state[i+3]
        state[i]   = (_mul(0x0e, a0) ^ _mul(0x0b, a1) ^ _mul(0x0d, a2) ^ _mul(0x09, a3)) & 0xFF
        state[i+1] = (_mul(0x09, a0) ^ _mul(0x0e, a1) ^ _mul(0x0b, a2) ^ _mul(0x0d, a3)) & 0xFF
        state[i+2] = (_mul(0x0d, a0) ^ _mul(0x09, a1) ^ _mul(0x0e, a2) ^ _mul(0x0b, a3)) & 0xFF
        state[i+3] = (_mul(0x0b, a0) ^ _mul(0x0d, a1) ^ _mul(0x09, a2) ^ _mul(0x0e, a3)) & 0xFF


def _add_round_key(state: List[int], round_key: List[int]) -> None:
    for i in range(16):
        state[i] ^= round_key[i]


def _bytes_to_state(block: bytes) -> List[int]:
    # convert 16-byte block to 16-element list (column-major)
    return [b for b in block]


def _state_to_bytes(state: List[int]) -> bytes:
    return bytes(state)


def _key_schedule(key_bytes: bytes, Nk: int, Nr: int) -> List[List[int]]:
    # Expand key_bytes into (Nr+1) round keys, each 16 bytes
    # Words are 4 bytes
    key_len = Nk * 4
    assert len(key_bytes) == key_len

    # initial words
    w = []
    for i in range(Nk):
        w.append([key_bytes[4*i], key_bytes[4*i+1], key_bytes[4*i+2], key_bytes[4*i+3]])

    def sub_word(word):
        return [sbox[b] for b in word]

    i = Nk
    while len(w) < 4 * (Nr + 1):
        temp = w[-1].copy()
        if i % Nk == 0:
            # rotate
            temp = temp[1:] + temp[:1]
            temp = sub_word(temp)
            temp[0] ^= Rcon[i // Nk]
        elif Nk > 6 and i % Nk == 4:
            temp = sub_word(temp)
        # xor with word Nk positions earlier
        w.append([ (temp[j] ^ w[-Nk][j]) & 0xFF for j in range(4) ])
        i += 1

    # Build round keys
    round_keys = []
    for r in range(Nr + 1):
        rk = []
        for j in range(4):
            rk.extend(w[r*4 + j])
        round_keys.append(rk)
    return round_keys


def _encrypt_block(block: bytes, round_keys: List[List[int]], Nr: int) -> bytes:
    state = _bytes_to_state(block)
    _add_round_key(state, round_keys[0])
    for rnd in range(1, Nr):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[rnd])
    # final round
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[Nr])
    return _state_to_bytes(state)


def _decrypt_block(block: bytes, round_keys: List[List[int]], Nr: int) -> bytes:
    state = _bytes_to_state(block)
    _add_round_key(state, round_keys[Nr])
    for rnd in range(Nr-1, 0, -1):
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, round_keys[rnd])
        _inv_mix_columns(state)
    _inv_shift_rows(state)
    _inv_sub_bytes(state)
    _add_round_key(state, round_keys[0])
    return _state_to_bytes(state)


def _pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    if pad_len == 0:
        pad_len = 16
    return data + bytes([pad_len]) * pad_len


def _unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]


def _derive_key_bytes(key: str, required_len: int) -> bytes:
    kb = key.encode('utf-8')
    if len(kb) == required_len:
        return kb
    # Deterministically derive by hashing and truncating/concatenating
    h = hashlib.sha256(kb).digest()
    if required_len <= len(h):
        return h[:required_len]
    # If longer (shouldn't happen for AES keys), repeat hashing
    out = bytearray()
    ctr = 0
    while len(out) < required_len:
        data = h + bytes([ctr])
        out.extend(hashlib.sha256(data).digest())
        ctr += 1
    return bytes(out[:required_len])


def encrypt(text: str, key: str, size: int) -> str:
    """Encrypt `text` with `key`. `size` is AES key size in bits (128/192/256).
    Returns ciphertext as a hex string.
    """
    if size not in (128, 192, 256):
        raise ValueError("Unsupported AES size. Choose 128, 192, or 256")
    Nk = {128:4, 192:6, 256:8}[size]
    Nr = Nk + 6
    key_bytes = _derive_key_bytes(key, Nk * 4)
    round_keys = _key_schedule(key_bytes, Nk, Nr)

    data = text.encode('utf-8')
    data = _pad(data)
    out = bytearray()
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        out_block = _encrypt_block(block, round_keys, Nr)
        out.extend(out_block)
    return out.hex()


def decrypt(ciphertext_hex: str, key: str, size: int) -> str:
    """Decrypt hex ciphertext using `key` and `size`. Returns plaintext string."""
    if size not in (128, 192, 256):
        raise ValueError("Unsupported AES size. Choose 128, 192, or 256")
    Nk = {128:4, 192:6, 256:8}[size]
    Nr = Nk + 6
    key_bytes = _derive_key_bytes(key, Nk * 4)
    round_keys = _key_schedule(key_bytes, Nk, Nr)

    try:
        data = bytes.fromhex(ciphertext_hex)
    except Exception:
        raise ValueError("Ciphertext must be a hex string")
    if len(data) % 16 != 0:
        raise ValueError("Invalid ciphertext length")
    out = bytearray()
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        out_block = _decrypt_block(block, round_keys, Nr)
        out.extend(out_block)
    try:
        out = _unpad(bytes(out))
    except ValueError:
        raise ValueError("Invalid padding or wrong key")
    return out.decode('utf-8', errors='replace')


def generate_key(size: int) -> str:
    """Generate a cryptographically secure random AES key.

    Args:
        size: key size in bits (128, 192, or 256)

    Returns:
        Hex-encoded key string (lowercase). Length: size/4 characters.

    Raises:
        ValueError: if unsupported size provided.
    """
    if size not in (128, 192, 256):
        raise ValueError("Unsupported AES size. Choose 128, 192, or 256")
    nbytes = size // 8
    key_bytes = os.urandom(nbytes)
    return key_bytes.hex()


if __name__ == '__main__':
    # quick self test
    pt = "Hello AES world!"
    k = "my secret key"
    c = encrypt(pt, k, 128)
    print('cipher hex:', c)
    p = decrypt(c, k, 128)
    print('plaintext:', p)
