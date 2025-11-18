
"""
rsa_system.py

Core RSA implementation used by the Flask API, unit tests, and (indirectly)
the React frontend.

Features:
- Number theory utilities (gcd, extended gcd, modular inverse)
- Probabilistic prime generation (Miller–Rabin)
- RSA keypair generation (with p, q, phi, e, d)
- Raw RSA encrypt / decrypt / sign / verify on integers
- Byte/hex helpers and RSA operations on bytes (for web text/hex modes)
- SHA-256 based signing/verification for messages (educational only)
- Fingerprint helper (SHA-1 of modulus)

NOTE: This is *raw* RSA (no padding like OAEP or PSS). It is suitable only
for teaching and demonstration, not for production cryptography.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Tuple, Optional


# ============================================================
# Math utilities
# ============================================================

class MathUtils:
    @staticmethod
    def gcd(a: int, b: int) -> int:
        """Compute greatest common divisor using Euclid's algorithm."""
        while b != 0:
            a, b = b, a % b
        return abs(a)

    @staticmethod
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        """
        Extended Euclidean algorithm.
        Returns (g, x, y) such that a*x + b*y = g = gcd(a, b).
        """
        if b == 0:
            return (a, 1, 0)
        g, x1, y1 = MathUtils.extended_gcd(b, a % b)
        return g, y1, x1 - (a // b) * y1

    @staticmethod
    def mod_inverse(a: int, m: int) -> int:
        """
        Compute modular inverse of a modulo m.
        Raises ValueError if gcd(a, m) != 1 (inverse does not exist).
        """
        g, x, _ = MathUtils.extended_gcd(a, m)
        if g != 1:
            raise ValueError("No modular inverse exists for given a mod m")
        return x % m


# ============================================================
# Prime generation
# ============================================================

class PrimeGenerator:
    """
    Prime generation and primality testing.

    Uses a small-prime trial division shortcut followed by a
    Miller–Rabin probabilistic test. Good enough for educational
    RSA key sizes used in this project (256–2048 bits).
    """

    _SMALL_PRIMES = [
        2, 3, 5, 7, 11, 13, 17, 19,
        23, 29, 31, 37, 41, 43, 47,
        53, 59, 61
    ]

    @staticmethod
    def is_prime(n: int, rounds: int = 16) -> bool:
        """Return True if n is probably prime, False otherwise."""
        if n < 2:
            return False

        # Quick check for small primes and even numbers
        for p in PrimeGenerator._SMALL_PRIMES:
            if n == p:
                return True
            if n % p == 0:
                return n == p

        # Write n-1 as 2^r * d
        d = n - 1
        r = 0
        while d % 2 == 0:
            r += 1
            d //= 2

        # Miller–Rabin tests
        for _ in range(rounds):
            a = secrets.randbelow(n - 3) + 2  # in [2, n-2]
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for __ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    @staticmethod
    def generate_prime(bits: int) -> int:
        """
        Generate a random prime with the given bit length.

        Ensures:
        - prime.bit_length() == bits
        - prime is odd (except the trivial 2, which we don't use here)
        """
        if bits < 2:
            raise ValueError("Bit length must be at least 2")

        while True:
            # Set MSB and LSB to ensure correct bit length and oddness
            candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
            if PrimeGenerator.is_prime(candidate):
                return candidate


# ============================================================
# Text <-> integer conversion (for tests)
# ============================================================

class TextConverter:
    """
    Convert between arbitrary UTF-8 text and big integers.
    Used in unit tests, and also available to callers that want
    to work directly in the "text -> int -> RSA -> int -> text" style.
    """

    @staticmethod
    def text_to_int(text: str) -> int:
        if text == "":
            return 0
        data = text.encode("utf-8")
        return int.from_bytes(data, byteorder="big", signed=False)

    @staticmethod
    def int_to_text(value: int) -> str:
        if value == 0:
            return ""
        if value < 0:
            raise ValueError("Cannot convert negative integers to text")
        length = (value.bit_length() + 7) // 8
        data = value.to_bytes(length, byteorder="big", signed=False)
        return data.decode("utf-8")


# ============================================================
# RSA core structures / helpers
# ============================================================

@dataclass
class RSAKeyPair:
    """
    RSA keypair container.

    e: public exponent
    d: private exponent
    n: modulus
    p, q: prime factors of n (optional but present for generated keys)
    """
    e: int
    d: int
    n: int
    p: Optional[int] = None
    q: Optional[int] = None

    def get_public_key(self) -> Tuple[int, int]:
        """Return (e, n) tuple."""
        return self.e, self.n

    def get_private_key(self) -> Tuple[int, int]:
        """Return (d, n) tuple."""
        return self.d, self.n


# ---- byte/hex helpers (for Flask API & React UI) ----

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big", signed=False)


def int_to_bytes(x: int) -> bytes:
    if x == 0:
        return b"\x00"
    length = (x.bit_length() + 7) // 8
    return x.to_bytes(length, "big", signed=False)


def text_to_bytes(text: str) -> bytes:
    return text.encode("utf-8")


def bytes_to_text(data: bytes) -> str:
    return data.decode("utf-8")


def hex_to_bytes(h: str) -> bytes:
    h = h.strip().lower()
    if h.startswith("0x"):
        h = h[2:]
    if h == "":
        return b""
    if len(h) % 2 == 1:
        h = "0" + h
    return bytes.fromhex(h)


def bytes_to_hex(b: bytes) -> str:
    return b.hex()


def fingerprint_from_modulus(n: int, length: int = 12) -> str:
    """
    Compute a short fingerprint of the modulus n for display purposes.
    Uses SHA-1 over the decimal string of n and returns first `length`
    hex characters in uppercase.
    """
    h = hashlib.sha1(str(n).encode("utf-8")).hexdigest()
    return h[:length].upper()


# ============================================================
# RSA operations
# ============================================================

class RSA:
    """
    Educational RSA implementation.

    - Raw RSA on integers (no padding)
    - Utilities for generating keypairs
    - Extra helpers for byte-level operations & CRT decrypt
    """

    # ---------- key generation ----------

    @staticmethod
    def generate_keypair(bits: int = 2048, e: int = 65537) -> RSAKeyPair:
        """
        Generate an RSA keypair.

        bits: modulus bit length (e.g., 256, 512, 1024, 2048)
        e: public exponent (must be odd and > 1, typically 65537)
        """
        if e <= 1 or e % 2 == 0:
            raise ValueError("Public exponent e must be an odd integer > 1")

        # Generate primes of roughly half the bit length each
        half_bits = bits // 2
        p = PrimeGenerator.generate_prime(half_bits)
        q = PrimeGenerator.generate_prime(half_bits)
        while q == p:
            q = PrimeGenerator.generate_prime(half_bits)

        n = p * q
        phi = (p - 1) * (q - 1)

        # Ensure gcd(e, phi) == 1
        if MathUtils.gcd(e, phi) != 1:
            # Extremely rare for chosen e=65537, but handle robustly
            return RSA.generate_keypair(bits=bits, e=e)

        d = MathUtils.mod_inverse(e, phi)

        return RSAKeyPair(e=e, d=d, n=n, p=p, q=q)

    # ---------- basic integer RSA (used by tests) ----------

    @staticmethod
    def encrypt(message: int, public_key: Tuple[int, int]) -> int:
        """
        Raw RSA encryption on integers.
        message must satisfy 0 <= message < n.
        """
        e, n = public_key
        if not (0 <= message < n):
            raise ValueError("Message integer must satisfy 0 <= m < n")
        return pow(message, e, n)

    @staticmethod
    def decrypt(ciphertext: int, private_key: Tuple[int, int]) -> int:
        """
        Raw RSA decryption on integers.
        ciphertext must satisfy 0 <= ciphertext < n.
        """
        d, n = private_key
        if not (0 <= ciphertext < n):
            raise ValueError("Ciphertext integer must satisfy 0 <= c < n")
        return pow(ciphertext, d, n)

    @staticmethod
    def sign(message_hash: int, private_key: Tuple[int, int]) -> int:
        """
        Raw RSA signing of an already-computed integer hash:

            signature = hash^d mod n

        This is the behavior expected by the existing unit tests.
        """
        d, n = private_key
        if not (0 <= message_hash < n):
            # For tests this should never happen; enforce for completeness
            raise ValueError("Hash integer must satisfy 0 <= h < n")
        return pow(message_hash, d, n)

    @staticmethod
    def verify(signature: int, public_key: Tuple[int, int]) -> int:
        """
        Raw RSA verification:

            recovered_hash = signature^e mod n

        Caller must compare recovered_hash to their expected hash.
        """
        e, n = public_key
        if not (0 <= signature < n):
            raise ValueError("Signature integer must satisfy 0 <= s < n")
        return pow(signature, e, n)

    # ---------- CRT decrypt on integers ----------

    @staticmethod
    def decrypt_crt(ciphertext: int, keypair: RSAKeyPair) -> int:
        """
        CRT-optimized decrypt using p, q, d from the keypair.
        Falls back to standard decrypt if p or q missing.
        """
        if keypair.p is None or keypair.q is None:
            # No CRT data – fall back
            return RSA.decrypt(ciphertext, keypair.get_private_key())

        p = keypair.p
        q = keypair.q
        d = keypair.d
        n = keypair.n

        if not (0 <= ciphertext < n):
            raise ValueError("Ciphertext integer must satisfy 0 <= c < n")

        dp = d % (p - 1)
        dq = d % (q - 1)
        q_inv = MathUtils.mod_inverse(q, p)

        m1 = pow(ciphertext, dp, p)
        m2 = pow(ciphertext, dq, q)
        h = (q_inv * (m1 - m2)) % p
        m = (m2 + h * q) % n
        return m

    # ---------- byte-level RSA helpers (for API) ----------

    @staticmethod
    def encrypt_bytes(message_bytes: bytes,
                      public_key: Tuple[int, int]) -> bytes:
        """Encrypt raw bytes with RSA (no padding)."""
        m_int = bytes_to_int(message_bytes)
        c_int = RSA.encrypt(m_int, public_key)
        return int_to_bytes(c_int)

    @staticmethod
    def decrypt_bytes(ciphertext_bytes: bytes,
                      private_key: Tuple[int, int]) -> bytes:
        """Decrypt raw bytes with RSA (no padding)."""
        c_int = bytes_to_int(ciphertext_bytes)
        m_int = RSA.decrypt(c_int, private_key)
        return int_to_bytes(m_int)

    @staticmethod
    def decrypt_bytes_crt(ciphertext_bytes: bytes,
                          keypair: RSAKeyPair) -> bytes:
        """CRT-optimized decrypt on bytes, when p and q are available."""
        c_int = bytes_to_int(ciphertext_bytes)
        m_int = RSA.decrypt_crt(c_int, keypair)
        return int_to_bytes(m_int)

    # ---------- SHA-256-based signing on bytes (for messages) ----------

    @staticmethod
    def sign_bytes(message_bytes: bytes,
                   private_key: Tuple[int, int]) -> bytes:
        """
        Sign SHA-256(message_bytes) with RSA private key.
        Educational only (no PKCS#1 v1.5 or PSS padding).
        """
        d, n = private_key
        h = hashlib.sha256(message_bytes).digest()
        h_int = bytes_to_int(h)
        if h_int >= n:
            # For realistic key sizes this won't happen, but keep the check
            raise ValueError("Modulus n is too small for SHA-256 hash integer.")
        s_int = pow(h_int, d, n)
        return int_to_bytes(s_int)

    @staticmethod
    def verify_bytes(message_bytes: bytes,
                     signature_bytes: bytes,
                     public_key: Tuple[int, int]) -> bool:
        """
        Verify SHA-256(message_bytes) against a raw-RSA signature.
        True if valid, False otherwise.
        """
        e, n = public_key
        h = hashlib.sha256(message_bytes).digest()
        h_int = bytes_to_int(h)
        s_int = bytes_to_int(signature_bytes)
        v_int = pow(s_int, e, n)
        return v_int == h_int
