
# flask_rsa.py
#
# RSA Cryptosystem Flask API - Integrated + Import Keys
# CSCI 663 - Introduction to Cryptography
#
# Educational implementation:
#   - Raw RSA (no OAEP/PSS or PSS padding)
#   - For classroom demos only, NOT for production use

import json
import secrets
import hashlib
from typing import Dict, Any

from flask import Flask, request, jsonify
from flask_cors import CORS

# ============================================================
# RSA Number Theory Utilities
# ============================================================

def egcd(a: int, b: int):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def inv_mod(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse for given a mod m")
    return x % m


def miller_rabin(n: int, k: int = 16) -> bool:
    """Probabilistic primality test."""
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return n == p

    d = n - 1
    r = 0
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
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


def gen_prime(bits: int) -> int:
    """Generate a random prime with the given bit-length."""
    while True:
        cand = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if miller_rabin(cand):
            return cand


# ============================================================
# RSA Core
# ============================================================

def rsa_keygen(bits: int = 1024, e: int = 65537) -> Dict[str, int]:
    """Generate RSA keypair (p, q, n, phi, e, d)."""
    half = bits // 2
    p = gen_prime(half)
    q = gen_prime(half)
    while q == p:
        q = gen_prime(half)
    n = p * q
    phi = (p - 1) * (q - 1)
    # rare case, regenerate if e divides phi
    if phi % e == 0:
        return rsa_keygen(bits, e)
    d = inv_mod(e, phi)
    return {"p": p, "q": q, "n": n, "phi": phi, "e": e, "d": d}


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big", signed=False)


def int_to_bytes(x: int) -> bytes:
    if x == 0:
        return b"\x00"
    length = (x.bit_length() + 7) // 8
    return x.to_bytes(length, "big", signed=False)


def text_to_bytes(text: str) -> bytes:
    return text.encode("utf-8")


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


# Raw RSA (no padding) ---------------------------------------

def rsa_encrypt_bytes(m_bytes: bytes, e: int, n: int) -> bytes:
    m_int = bytes_to_int(m_bytes)
    if not (0 <= m_int < n):
        raise ValueError("Plaintext integer must satisfy 0 ≤ m < n. Use larger key or shorter message.")
    c_int = pow(m_int, e, n)
    return int_to_bytes(c_int)


def rsa_decrypt_bytes(c_bytes: bytes, d: int, n: int) -> bytes:
    c_int = bytes_to_int(c_bytes)
    if not (0 <= c_int < n):
        raise ValueError("Ciphertext integer must satisfy 0 ≤ c < n.")
    m_int = pow(c_int, d, n)
    return int_to_bytes(m_int)


def rsa_sign_bytes(msg_bytes: bytes, d: int, n: int) -> bytes:
    """Sign SHA-256(message) with private exponent d."""
    h = hashlib.sha256(msg_bytes).digest()
    h_int = bytes_to_int(h)
    if h_int >= n:
        raise ValueError("n is too small for SHA-256 hash integer. Generate a larger key.")
    s_int = pow(h_int, d, n)
    return int_to_bytes(s_int)


def rsa_verify_bytes(msg_bytes: bytes, sig_bytes: bytes, e: int, n: int) -> bool:
    """Verify signature against SHA-256(message) with public exponent e."""
    h = hashlib.sha256(msg_bytes).digest()
    h_int = bytes_to_int(h)
    s_int = bytes_to_int(sig_bytes)
    v_int = pow(s_int, e, n)
    return v_int == h_int


# ============================================================
# Flask App + In-Memory Key Store
# ============================================================

app = Flask(__name__)
CORS(app)

# session_id -> {"public": {"n", "e"}, "private": {"n", "d"}, "raw": {...}}
KEY_STORE: Dict[str, Dict[str, Any]] = {}


def parse_int_or_hex(s: str) -> int:
    """Try to parse as decimal; if that fails, parse as hex."""
    s = s.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    try:
        return int(s, 10)
    except ValueError:
        # last attempt: treat as hex without 0x
        return int(s, 16)


# ============================================================
# Endpoints
# ============================================================

@app.route("/api/example", methods=["GET"])
def example():
    return jsonify({"success": True, "message": "RSA Flask API is running"}), 200


@app.route("/api/generate-keys", methods=["POST"])
def generate_keys():
    try:
        data = request.get_json(force=True)
        size = int(data.get("size", 1024))
        session_id = data.get("session_id")
        if not session_id:
            return jsonify({"success": False, "error": "session_id is required"}), 400

        # e fixed as 65537 (common choice)
        e = 65537
        key = rsa_keygen(bits=size, e=e)

        public_key = {"n": str(key["n"]), "e": str(key["e"])}
        private_key = {"n": str(key["n"]), "d": str(key["d"])}

        KEY_STORE[session_id] = {
            "public": public_key,
            "private": private_key,
            "raw": key,  # includes p, q, phi, etc. (not sent to front-end)
        }

        return jsonify({
            "success": True,
            "public_key": public_key,
            "private_key": private_key,
            "size": size
        }), 200

    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 500


@app.route("/api/get-keys", methods=["POST"])
def get_keys():
    try:
        data = request.get_json(force=True)
        session_id = data.get("session_id")
        if not session_id:
            return jsonify({"success": False, "error": "session_id is required"}), 400

        info = KEY_STORE.get(session_id)
        if not info:
            return jsonify({"success": False, "error": "No keys found for this session"}), 404

        return jsonify({
            "success": True,
            "public_key": info.get("public"),
            "private_key": info.get("private")
        }), 200

    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 500


# NEW: Import / Set Custom Keys ---------------------------------------

@app.route("/api/import-keys", methods=["POST"])
def import_keys():
    """
    Import an existing RSA keypair (or just public/private part) for a session.

    Expected JSON format:

      {
        "session_id": "session_123",
        "public_key": {
          "n": "1234567890...",
          "e": "65537"
        },
        "private_key": {
          "n": "1234567890...",
          "d": "987654321..."
        }
      }

    Notes:
      - public_key is optional
      - private_key is optional
      - if both provided, n must match
    """
    try:
        data = request.get_json(force=True)
        session_id = data.get("session_id")
        if not session_id:
            return jsonify({"success": False, "error": "session_id is required"}), 400

        public_data = data.get("public_key")
        private_data = data.get("private_key")

        if not public_data and not private_data:
            return jsonify({
                "success": False,
                "error": "At least one of public_key or private_key must be provided"
            }), 400

        store_entry: Dict[str, Any] = {}

        # Public key
        if public_data:
            try:
                n_pub = parse_int_or_hex(str(public_data["n"]))
                e_pub = parse_int_or_hex(str(public_data["e"]))
            except Exception:
                return jsonify({
                    "success": False,
                    "error": "Invalid public_key format. Expect strings n and e."
                }), 400

            store_entry["public"] = {"n": str(n_pub), "e": str(e_pub)}

        # Private key
        if private_data:
            try:
                n_priv = parse_int_or_hex(str(private_data["n"]))
                d_priv = parse_int_or_hex(str(private_data["d"]))
            except Exception:
                return jsonify({
                    "success": False,
                    "error": "Invalid private_key format. Expect strings n and d."
                }), 400

            store_entry["private"] = {"n": str(n_priv), "d": str(d_priv)}

        # Check n consistency if both parts present
        if "public" in store_entry and "private" in store_entry:
            if store_entry["public"]["n"] != store_entry["private"]["n"]:
                return jsonify({
                    "success": False,
                    "error": "Public and private key modulus n do not match"
                }), 400

        # Save / merge with existing
        existing = KEY_STORE.get(session_id, {})
        existing.update(store_entry)
        KEY_STORE[session_id] = existing

        return jsonify({
            "success": True,
            "message": "Keys imported successfully",
            "public_key": existing.get("public"),
            "private_key": existing.get("private")
        }), 200

    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 500


# Encrypt / Decrypt ---------------------------------------------------

@app.route("/api/encrypt", methods=["POST"])
def encrypt():
    try:
        data = request.get_json(force=True)
        session_id = data.get("session_id")
        message = data.get("message", "")

        if not session_id:
            return jsonify({"success": False, "error": "session_id is required"}), 400
        if not message:
            return jsonify({"success": False, "error": "message is required"}), 400

        info = KEY_STORE.get(session_id)
        if not info or "public" not in info:
            return jsonify({"success": False, "error": "No public key available for this session"}), 404

        pub = info["public"]
        n = int(pub["n"])
        e = int(pub["e"])

        m_bytes = text_to_bytes(message)
        c_bytes = rsa_encrypt_bytes(m_bytes, e, n)
        ciphertext_hex = bytes_to_hex(c_bytes)

        return jsonify({"success": True, "ciphertext": ciphertext_hex}), 200

    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 500


@app.route("/api/decrypt", methods=["POST"])
def decrypt():
    try:
        data = request.get_json(force=True)
        session_id = data.get("session_id")
        ciphertext = data.get("ciphertext", "")

        if not session_id:
            return jsonify({"success": False, "error": "session_id is required"}), 400
        if not ciphertext:
            return jsonify({"success": False, "error": "ciphertext is required"}), 400

        info = KEY_STORE.get(session_id)
        if not info or "private" not in info:
            return jsonify({"success": False, "error": "No private key available for this session"}), 404

        priv = info["private"]
        n = int(priv["n"])
        d = int(priv["d"])

        # Try as hex first; if that fails, treat as decimal integer
        c_bytes: bytes
        try:
            c_bytes = hex_to_bytes(ciphertext)
        except Exception:
            # if hex fails, interpret as decimal integer string
            c_int = parse_int_or_hex(ciphertext)
            c_bytes = int_to_bytes(c_int)

        m_bytes = rsa_decrypt_bytes(c_bytes, d, n)
        plaintext = m_bytes.decode("utf-8", errors="replace")

        return jsonify({"success": True, "plaintext": plaintext}), 200

    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 500


# Sign / Verify -------------------------------------------------------

@app.route("/api/sign", methods=["POST"])
def sign():
    try:
        data = request.get_json(force=True)
        session_id = data.get("session_id")
        message = data.get("message", "")

        if not session_id:
            return jsonify({"success": False, "error": "session_id is required"}), 400
        if not message:
            return jsonify({"success": False, "error": "message is required"}), 400

        info = KEY_STORE.get(session_id)
        if not info or "private" not in info:
            return jsonify({"success": False, "error": "No private key available for this session"}), 404

        priv = info["private"]
        n = int(priv["n"])
        d = int(priv["d"])

        m_bytes = text_to_bytes(message)
        sig_bytes = rsa_sign_bytes(m_bytes, d, n)
        sig_hex = bytes_to_hex(sig_bytes)

        return jsonify({"success": True, "signature": sig_hex}), 200

    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 500


@app.route("/api/verify", methods=["POST"])
def verify():
    try:
        data = request.get_json(force=True)
        session_id = data.get("session_id")
        message = data.get("message", "")
        signature = data.get("signature", "")

        if not session_id:
            return jsonify({"success": False, "error": "session_id is required"}), 400
        if not message:
            return jsonify({"success": False, "error": "message is required"}), 400
        if not signature:
            return jsonify({"success": False, "error": "signature is required"}), 400

        info = KEY_STORE.get(session_id)
        if not info or "public" not in info:
            return jsonify({"success": False, "error": "No public key available for this session"}), 404

        pub = info["public"]
        n = int(pub["n"])
        e = int(pub["e"])

        m_bytes = text_to_bytes(message)
        sig_bytes = hex_to_bytes(signature)

        valid = rsa_verify_bytes(m_bytes, sig_bytes, e, n)
        return jsonify({"success": True, "valid": bool(valid)}), 200

    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 500


# ============================================================
# Banner + Main
# ============================================================

def print_banner():
    banner = r"""
======================================================================
RSA Cryptosystem Flask API - Integrated Version (with Import Keys)
CSCI 663 - Introduction to Cryptography
======================================================================

API uses educational RSA (raw, no OAEP/PSS). Endpoints:

  POST /api/generate-keys   -> create keypair for session_id
  POST /api/get-keys        -> return stored keys for session_id
  POST /api/import-keys     -> import user-supplied public/private keys
  POST /api/encrypt         -> text -> ciphertext (hex)
  POST /api/decrypt         -> ciphertext (hex/dec) -> text
  POST /api/sign            -> sign SHA-256(message) with private key
  POST /api/verify          -> verify signature for message
  GET  /api/example         -> health check

Keys are stored per session_id in memory (KEY_STORE).
Press Ctrl+C to stop the server.
======================================================================
"""
    print(banner)


if __name__ == "__main__":
    print_banner()
    # Run on port 8080 to match the React frontend
    app.run(host="0.0.0.0", port=8080, debug=True)

