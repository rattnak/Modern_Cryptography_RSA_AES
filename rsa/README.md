# RSA Cryptosystem Implementation

This is an RSA encryption implementation based on the
[Understanding Cryptography: From Established Symmetric and Asymmetric Ciphers to Post-Quantum Algorithms](https://learn.lajevardi.id.ir/Cryptography/Refrence/2.pdf) textbook.
It includes both a Python library, Flask REST API integration, and performance benchmarking tools for encryption, decryption, and digital signatures.


---

## How to Run Tests

### Core RSA Tests (no installation needed)

```bash
cd rsa
python3 test_rsa.py
```

You should see: `46 tests passed`

### API Integration Tests

API tests are now located in the `api/` directory at the project root:

```bash
# From project root, with virtual environment activated
source venv/bin/activate
python3 -m pytest api/test_flask_api.py -v
```

Total: 46 core tests + 26 API integration tests = 72 tests, all passing.

---

## How to Start the Server

The unified Flask server (handling both RSA and AES) is now located in the `api/` directory at the project root:

```bash
# From project root
source venv/bin/activate
python3 api/app.py
```

Or use the convenient startup script:
```bash
# From project root - starts both backend and frontend
./start_all.sh
```

Server runs on `http://localhost:8080`

Test it:
```bash
curl http://localhost:8080/api/health
```

---

## What's Implemented

### RSA Core Functions

**Key Generation:**
- Generate two distinct prime numbers (p, q) using Miller-Rabin primality test
- Calculate n = p × q
- Calculate φ(n) = (p-1)(q-1)
- Choose public exponent e where gcd(e, φ(n)) = 1
- Calculate private exponent d = e⁻¹ mod φ(n)

**Encryption/Decryption:**
- Encrypt: c = m^e mod n
- Decrypt: m = c^d mod n

**Digital Signatures:**
- Sign: signature = hash(message)^d mod n
- Verify: hash(message) == signature^e mod n
- Uses SHA-256 for hashing

**Mathematical Functions:**
- Miller-Rabin primality testing
- Extended Euclidean Algorithm for modular inverse
- Fast modular exponentiation
- GCD calculation

**Supported Key Sizes:**
- 256 bits (testing)
- 512 bits (demos)
- 1024 bits
- 2048 bits

**Additional Features:**
- Key import/export functionality
- Flexible input parsing (decimal/hexadecimal)
- Session management for API keys
- Comprehensive error handling
- Performance benchmarking tools

---

## Python Usage

### Simple API

```python
from rsa import generate_keypair, encrypt, decrypt, sign, verify

# Generate keys
keys = generate_keypair(512)

# Encrypt
ciphertext = encrypt("Hello!", keys['public_key'], keys['size'])

# Decrypt
plaintext = decrypt(ciphertext, keys['private_key'], keys['size'])

# Sign
sig = sign("Document", keys['private_key'], keys['size'])

# Verify
is_valid = verify("Document", sig['signature'], sig['message_hash'],
                   keys['public_key'], keys['size'])
```

### Object-Oriented API

```python
from rsa_system import RSA, TextConverter

# Generate keys
keypair = RSA.generate_keypair(bits=512)
public_key = keypair.get_public_key()
private_key = keypair.get_private_key()

# Encrypt
message = 12345
ciphertext = RSA.encrypt(message, public_key)
decrypted = RSA.decrypt(ciphertext, private_key)
```

---

## Flask API Endpoints

The RSA API is now integrated into the unified server at `api/app.py`. All endpoints use `http://localhost:8080/api/`

### GET /api/health
Check if server is running.

```bash
curl http://localhost:8080/api/health
```

### POST /api/generate-keys
Generate RSA key pair.

```bash
curl -X POST http://localhost:8080/api/generate-keys \
  -H "Content-Type: application/json" \
  -d '{"size": 512, "session_id": "test"}'
```

### POST /api/encrypt
Encrypt a message.

```bash
curl -X POST http://localhost:8080/api/encrypt \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello!", "session_id": "test"}'
```

### POST /api/decrypt
Decrypt a message.

```bash
curl -X POST http://localhost:8080/api/decrypt \
  -H "Content-Type: application/json" \
  -d '{"ciphertext": "YOUR_CIPHERTEXT", "session_id": "test"}'
```

### POST /api/sign
Sign a message.

```bash
curl -X POST http://localhost:8080/api/sign \
  -H "Content-Type: application/json" \
  -d '{"message": "Document", "session_id": "test"}'
```

### POST /api/verify
Verify a signature.

```bash
curl -X POST http://localhost:8080/api/verify \
  -H "Content-Type: application/json" \
  -d '{"message": "Document", "signature": "SIG", "message_hash": "HASH", "session_id": "test"}'
```

### POST /api/import-keys
Import existing RSA keys.

```bash
curl -X POST http://localhost:8080/api/import-keys \
  -H "Content-Type: application/json" \
  -d '{"public_key": {...}, "private_key": {...}, "session_id": "test"}'
```

### POST /api/get-keys
Retrieve current session keys.

```bash
curl -X POST http://localhost:8080/api/get-keys \
  -H "Content-Type: application/json" \
  -d '{"session_id": "test"}'
```

---

## Files

**Core Implementation:**
- `__init__.py` - Package initialization and exports
- `rsa.py` - Simple function-based API wrapper
- `rsa_system.py` - Object-oriented RSA implementation
- `test_rsa.py` - 46 comprehensive unit tests

**Legacy Flask API:**
- `flask_rsa.py` - Standalone RSA server (now integrated into `api/app.py`)

**Performance Benchmarking:**
- `benchmark_rsa.py` - Command-line benchmarking tool
- `benchmark_with_graph.py` - Visual benchmarking with matplotlib graphs

**Note:** API server and tests have been moved to the `api/` directory at project root for unified RSA+AES handling.

---

## Testing Coverage

**46 Core RSA Tests (test_rsa.py):**
- Mathematical functions (GCD, modular inverse, etc.)
- Prime number generation (Miller-Rabin primality test)
- Key pair generation for multiple key sizes
- Encryption/decryption operations
- Text conversion and encoding
- Edge cases and error handling
- Integration tests

**26 API Integration Tests (api/test_flask_api.py):**
- Health check endpoint
- Key generation with various sizes
- Encryption/decryption workflows
- Digital signatures and verification
- Error handling and validation
- Session management
- Unicode and special character support
- Key import/export functionality

**Performance Benchmarking:**
- Execution time measurements for all key sizes
- Graphical performance analysis
- Comparison across different operations

---

## Performance Benchmarking

Run performance tests to measure RSA operations across different key sizes:

**Text-based benchmark:**
```bash
cd rsa
python3 benchmark_rsa.py
```

**Visual benchmark with graphs:**
```bash
# From project root
python3 rsa/benchmark_with_graph.py
```

This generates matplotlib graphs showing:
- Key generation times
- Encryption performance
- Decryption performance
- Comparison across 256, 512, 1024, and 2048-bit keys

---

## Troubleshooting

**Flask not installed:**
```bash
# From project root
source venv/bin/activate
pip install flask flask-cors matplotlib numpy
```

**Port 8080 in use:**
Edit `api/app.py` and change the port number.

**Virtual environment not found:**
```bash
# From project root
python3 -m venv venv
source venv/bin/activate
```

**Core tests fail:**
Make sure you're in the `rsa` directory when running `test_rsa.py`.

**API tests fail:**
Make sure you're in the project root and the virtual environment is activated.

**Import errors:**
The `rsa` module now uses `__init__.py`. Make sure to import from the project root or install as a package.

---

## Important Notes

This is an educational implementation. It uses textbook RSA without OAEP padding. Do not use in production.

For production use:
- Use established libraries (`cryptography`, `PyCryptodome`)
- Use minimum 2048-bit keys
- Use OAEP padding for encryption
- Use PSS for signatures

---

## Textbook Compliance

Implementation follows [Understanding Cryptography: From Established Symmetric and Asymmetric Ciphers to Post-Quantum Algorithms](https://learn.lajevardi.id.ir/Cryptography/Refrence/2.pdf) textbook:

- Key generation algorithm (5 steps) - Complete
- Miller-Rabin primality test - Implemented
- Extended Euclidean Algorithm - Implemented
- RSA encryption (c = m^e mod n) - Implemented
- RSA decryption (m = c^d mod n) - Implemented
- Digital signatures with SHA-256 - Implemented

---

## Quick Commands

```bash
# Run core RSA tests
cd rsa
python3 test_rsa.py

# Setup environment (from project root)
python3 -m venv venv
source venv/bin/activate
pip install flask flask-cors matplotlib numpy

# Install frontend dependencies
npm install

# Start everything (easiest)
./start_all.sh

# Or manually start backend and frontend
python3 api/app.py          # Terminal 1
npm run dev                 # Terminal 2

# Run API integration tests
python3 -m pytest api/test_flask_api.py -v

# Run performance benchmarks
python3 rsa/benchmark_rsa.py              # Text output
python3 rsa/benchmark_with_graph.py       # With graphs

# Test server
curl http://localhost:8080/api/health
```

---

## Integration with Project

This RSA implementation is part of a larger cryptography project that includes:

- **AES Implementation** (`aes/` directory)
- **Unified REST API** (`api/app.py` - handles both RSA and AES)
- **React Frontend** (`src/` directory with Vite + Tailwind)
- **Comprehensive Documentation** (see main [README.md](../README.md))

For complete project setup and usage, refer to the main README at the project root.