# AES Module

This folder contains a pure-Python AES implementation and a small
Flask REST API for basic symmetric-key operations used by the
project frontend.

Key points

- AES implementation: `aes/aes.py` — ECB mode, PKCS#7 padding
- Public API:
  - `encrypt(text: str, key: str, size: int) -> str` — returns ciphertext hex
  - `decrypt(ciphertext_hex: str, key: str, size: int) -> str` — returns plaintext
  - `generate_key(size: int) -> str` — generates a secure random key (hex)
- Supported key sizes: `128`, `192`, `256` (bits)

Security notes

- The AES implementation is educational and uses ECB mode (no IV) and
  does not provide authentication. Do NOT use this for production data.
- `generate_key` returns a hex string. For production use prefer an
  authenticated mode (GCM) and robust KDFs (PBKDF2/scrypt/Argon2) for
  passphrase-derived keys.

Flask API
The Flask app `flask_aes.py` exposes simple endpoints that the frontend
can call. By default the app runs on `127.0.0.1:8081` to avoid port
conflicts with the RSA service (which uses port `8080`).

Endpoints

- `GET /api/aes/health` — health check
- `POST /api/aes/generate-key` — body: `{"size": 128}`; returns `{ "key": "...hex..." }`
- `POST /api/aes/encrypt` — body: `{"message": "...", "key": "...", "size": 128}`; returns `{ "ciphertext": "...hex..." }`
- `POST /api/aes/decrypt` — body: `{"ciphertext": "...hex...", "key": "...", "size": 128}`; returns `{ "plaintext": "..." }`

Quick start (Python)

```bash
# from repo root
python -m venv venv
source venv/bin/activate   # or 'venv\Scripts\activate' on Windows
pip install flask flask-cors
python aes/flask_aes.py
```

Test with curl (example)

```bash
curl http://127.0.0.1:8081/api/aes/health

# generate key
curl -X POST http://127.0.0.1:8081/api/aes/generate-key -H "Content-Type: application/json" -d '{"size": 128}'

# encrypt
curl -X POST http://127.0.0.1:8081/api/aes/encrypt -H "Content-Type: application/json" -d '{"message":"hello","key":"<HEX_KEY>","size":128}'

# decrypt
curl -X POST http://127.0.0.1:8081/api/aes/decrypt -H "Content-Type: application/json" -d '{"ciphertext":"<CIPHER_HEX>","key":"<HEX_KEY>","size":128}'
```

Integration with frontend

- Point the frontend AES-related requests to `http://127.0.0.1:8081/api/aes/...`.
- If you host both RSA and AES services on the same origin, update
  the frontend routes accordingly. The Flask app enables CORS for
  the frontend.

Files

- `aes.py` — AES implementation and helpers
- `flask_aes.py` — Flask REST API for AES operations
- `test_aes.py` — unit tests for AES functions
