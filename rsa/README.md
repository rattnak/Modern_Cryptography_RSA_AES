# RSA Cryptosystem Implementation

A comprehensive RSA encryption implementation based on the
[Understanding Cryptography: From Established Symmetric and Asymmetric Ciphers to Post-Quantum Algorithms](https://learn.lajevardi.id.ir/Cryptography/Refrence/2.pdf) textbook.

**Features:**
- ✅ Pure Python RSA implementation (no external crypto libraries)
- ✅ Miller-Rabin primality testing (k=5 rounds, error ≈ 0.1%)
- ✅ Digital signatures with SHA-256 hashing
- ✅ Authentication and non-repudiation support
- ✅ Clean three-layer architecture (Core → API Wrapper → REST API)
- ✅ 46 comprehensive unit tests (100% passing)
- ✅ Performance benchmarking tools with visualization
- ✅ Key import/export and flexible input parsing (hex/decimal)

---

## Architecture Overview

**Three-Layer Modular Design:**

```
┌─────────────────────────────────────────────────┐
│         LAYER 3: REST API (Flask)               │
│  flask_rsa.py / api/app.py (650 lines)         │
│  • HTTP endpoints (8 RSA endpoints)             │
│  • Session management                           │
│  • JSON serialization                           │
│  • Input validation & error handling            │
└────────────────┬────────────────────────────────┘
                 │
┌────────────────┼────────────────────────────────┐
│         LAYER 2: Simplified API Wrapper         │
│  rsa.py (332 lines)                             │
│  • Function-based wrappers                      │
│  • generate_keypair(size)                       │
│  • encrypt(plaintext, key, size)                │
│  • decrypt(ciphertext, key, size)               │
│  • sign(message, key, size)                     │
│  • verify(msg, sig, hash, key, size)           │
└────────────────┬────────────────────────────────┘
                 │
┌────────────────┼────────────────────────────────┐
│    LAYER 1: Core Cryptographic Classes          │
│  rsa_system.py (482 lines)                      │
│                                                 │
│  ┌───────────────────────────────────┐         │
│  │ MathUtils                          │         │
│  │ • gcd(), extended_gcd()            │         │
│  │ • mod_inverse()                    │         │
│  └───────────────────────────────────┘         │
│                                                 │
│  ┌───────────────────────────────────┐         │
│  │ PrimeGenerator                     │         │
│  │ • is_prime() - Miller-Rabin        │         │
│  │ • generate_prime(bits)             │         │
│  └───────────────────────────────────┘         │
│                                                 │
│  ┌───────────────────────────────────┐         │
│  │ RSAKeyPair (Data Class)            │         │
│  │ • Properties: e, d, n, p, q        │         │
│  │ • get_public_key()                 │         │
│  │ • get_private_key()                │         │
│  └───────────────────────────────────┘         │
│                                                 │
│  ┌───────────────────────────────────┐         │
│  │ RSA (Core Operations)              │         │
│  │ • generate_keypair()               │         │
│  │ • encrypt(), decrypt()             │         │
│  │ • sign(), verify()                 │         │
│  └───────────────────────────────────┘         │
│                                                 │
│  ┌───────────────────────────────────┐         │
│  │ TextConverter                      │         │
│  │ • text_to_int(), int_to_text()     │         │
│  │ • parse_int_or_hex()               │         │
│  └───────────────────────────────────┘         │
└─────────────────────────────────────────────────┘
```

**Design Principles:**
- ✅ **Separation of Concerns:** Math, crypto, and API layers are independent
- ✅ **Composition Over Inheritance:** Static methods and functional composition
- ✅ **Testability:** Each layer tested independently
- ✅ **Extensibility:** Easy to add new operations or endpoints

**Code Metrics:**
- Total RSA Code: 1,464 lines
- Core Crypto (rsa_system.py): 482 lines (33%)
- Wrapper API (rsa.py): 332 lines (23%)
- REST API (flask_rsa.py): 650 lines (44%)
- Classes: 5 (MathUtils, PrimeGenerator, RSAKeyPair, RSA, TextConverter)
- Public Methods: 16+
- API Endpoints: 8 RSA endpoints (health, generate, encrypt, decrypt, sign, verify, get-keys, example)

---

## How to Run Tests

### Core RSA Tests (no installation needed)

```bash
cd rsa
python3 test_rsa.py
```

You should see: `Ran 46 tests` (all passing ✅)

### API Integration Tests

API tests are now located in the `api/` directory at the project root:

```bash
# From project root, with virtual environment activated
source venv/bin/activate
python3 -m pytest api/test_flask_api.py -v
```

**Total: 46 core tests + 26 API integration tests = 72 tests, all passing ✅**

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

### Layer 1: Core Cryptographic Components (rsa_system.py)

#### 1. **MathUtils Class** (Lines 35-61)
Mathematical operations for RSA:
- **gcd(a, b):** Euclidean algorithm for greatest common divisor
  - Time complexity: O(log min(a,b))
- **extended_gcd(a, b):** Returns (gcd, x, y) where ax + by = gcd
  - Used for computing modular inverse
- **mod_inverse(e, phi):** Computes d where e×d ≡ 1 (mod φ)
  - Essential for private key generation

#### 2. **PrimeGenerator Class** (Lines 84-132)
Prime number generation with probabilistic testing:
- **is_prime(n, k=5):** Miller-Rabin primality test
  - k=5 rounds (default): error probability ≈ (1/4)^5 ≈ 0.1%
  - Tests: 18+ known primes, 15+ composites verified
- **generate_prime(bits):** Generates random primes
  - Uses `random` module (⚠️ not cryptographically secure - educational only)
  - Ensures exact bit length (MSB=1, LSB=1)
  - Average iterations: ~ln(2^bits) by Prime Number Theorem

#### 3. **RSAKeyPair Class** (Lines 135-206)
Data structure for key storage:
- **Properties:** e (public exponent), d (private exponent), n (modulus), p, q (primes)
- **get_public_key():** Returns {n, e}
- **get_private_key():** Returns {n, d}
- Validates all mathematical invariants

#### 4. **RSA Class** (Lines 208-385)
Core RSA operations:

**Key Generation (Lines 208-272):**
1. Generate two distinct primes p, q (bits/2 each)
2. Compute n = p × q
3. Compute φ(n) = (p-1)(q-1)
4. Choose e = 65537 (standard, gcd(e,φ)=1 verified)
5. Compute d = mod_inverse(e, φ)

**Encryption/Decryption (Lines 274-308):**
- **encrypt(message, public_key):** c = m^e mod n
  - Validates: message < n (prevents overflow)
- **decrypt(ciphertext, private_key):** m = c^d mod n
  - Uses Python's fast modular exponentiation

**Digital Signatures (Lines 310-385):**
- **sign(message, private_key):**
  1. Compute SHA-256 hash: h = SHA256(message)
  2. Sign: s = h^d mod n (using private key)
  3. Returns: {signature, message_hash}
- **verify(message, signature, message_hash, public_key):**
  1. Compute hash: h = SHA256(message)
  2. Decrypt signature: h' = s^e mod n
  3. Verify: h == h' (authentic if match)
- **Security:** Collision resistance, unforgeable without private key

#### 5. **TextConverter Class** (Lines 388-436)
Text/integer conversion utilities:
- **text_to_int(text):** UTF-8 encoding → integer
- **int_to_text(num):** Integer → UTF-8 decoding
- **parse_int_or_hex(value):** Accepts "123", "0x7B", or "7B"
  - Enables flexible API input (hex from OpenSSL, decimal from tests)

**Supported Key Sizes:**
- 256 bits (testing only)
- 512 bits (demos, fast generation ~80ms)
- 1024 bits (secure, ~500ms)
- 2048 bits (production-equivalent, ~800ms)

### Layer 2: Simplified API Wrapper (rsa.py)

Function-based interface for easy use:
- **generate_keypair(size):** Returns dict with public/private keys
- **encrypt(plaintext, key, size):** Text → ciphertext
- **decrypt(ciphertext, key, size):** Ciphertext → text
- **sign(message, key, size):** Message → signature + hash
- **verify(msg, sig, hash, key, size):** Returns True/False

### Layer 3: REST API Integration

**Unified Server (api/app.py):**
- 8 RSA endpoints (health, generate, encrypt, decrypt, sign, verify, get-keys, example)
- 4 AES endpoints (health, generate-key, encrypt, decrypt)
- Session-based key management
- CORS-enabled for frontend integration
- JSON request/response format
- Comprehensive error handling

**Standalone Server (flask_rsa.py):**
- Legacy standalone RSA server
- Now integrated into unified api/app.py

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

## File Structure

```
rsa/
├── __init__.py                  # Package initialization and exports
│                                 # Exports: generate_keypair, encrypt, decrypt, sign, verify
│
├── rsa_system.py                # ⭐ LAYER 1: Core Cryptographic Classes (482 lines)
│   ├── MathUtils                # Mathematical operations (GCD, modular inverse)
│   ├── PrimeGenerator           # Miller-Rabin primality testing (k=5)
│   ├── RSAKeyPair               # Key data structure
│   ├── RSA                      # Core encryption/signature operations
│   └── TextConverter            # Text ↔ integer conversions
│
├── rsa.py                       # LAYER 2: Simplified API Wrapper (332 lines)
│   ├── generate_keypair()       # Function-based interface
│   ├── encrypt()                # Easy-to-use wrappers
│   ├── decrypt()                # Over core RSA classes
│   ├── sign()                   # SHA-256 based signatures
│   └── verify()
│
├── flask_rsa.py                 # LAYER 3: Standalone REST API (650 lines)
│                                 # (Legacy - now integrated into api/app.py)
│
├── test_rsa.py                  # ✅ Unit Tests (46 tests)
│   ├── TestMathUtils            # GCD, extended GCD, modular inverse
│   ├── TestPrimeGenerator       # Miller-Rabin, prime generation
│   ├── TestRSAKeyPair           # Key creation and extraction
│   ├── TestRSA                  # Encrypt/decrypt workflows
│   ├── TestRSASignatures        # Sign/verify operations
│   ├── TestTextConverter        # Text conversion, Unicode support
│   ├── TestEdgeCases            # Boundary values, error handling
│   └── TestIntegration          # Complete workflows
│
├── benchmark_rsa.py             # 📊 Performance: Text output
└── benchmark_with_graph.py      # 📊 Performance: Visual graphs (matplotlib)

../api/
├── app.py                       # ⭐ Unified Flask Server (RSA + AES)
│                                 # Port 8080, CORS-enabled
│                                 # 10 RSA endpoints + AES endpoints
│
└── test_flask_api.py            # ✅ API Integration Tests (26 tests)
                                  # Endpoint testing, session management
```

**Total Lines of Code:** 1,464 (RSA-specific)
- Core crypto logic: 482 lines
- API wrappers: 332 lines
- REST API: 650 lines
- Tests: 500+ lines
- Benchmarks: 200+ lines

---

## Testing Coverage

### Core RSA Unit Tests (test_rsa.py) - 46 Tests

**Comprehensive test coverage across all RSA components:**

- ✅ **Mathematical Operations (TestMathUtils):**
  - GCD calculation: gcd(48, 18) = 6, gcd(17, 19) = 1
  - Extended GCD correctness: a×x + b×y = gcd(a,b)
  - Modular inverse: (e × d) mod φ = 1

- ✅ **Prime Generation (TestPrimeGenerator):**
  - Known primes: 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61
  - Known composites: 4, 6, 8, 9, 10, 12, 14, 15, 16, 18, 20, 21, 22, 24, 25
  - Edge cases: 0, 1, 2, even numbers
  - Prime generation: exact bit length, oddness

- ✅ **Key Pair Operations (TestRSAKeyPair):**
  - Keypair creation and property access
  - Public key extraction: {n, e}
  - Private key extraction: {n, d}

- ✅ **Encryption/Decryption (TestRSA):**
  - Basic encrypt/decrypt roundtrip
  - Multiple messages: 0, 1, 42, 100, 255, 1000
  - Known textbook example: p=61, q=53, e=17, d=2753
  - Message = n-1 (maximum valid)
  - Message ≥ n raises ValueError
  - Determinism verification

- ✅ **Digital Signatures (TestRSASigningVerification):**
  - Sign and verify workflow
  - SHA-256 hash integration
  - Multiple signatures for different messages
  - Wrong key detection (signature verification fails)
  - Tampered message detection

- ✅ **Text Conversion (TestTextConverter):**
  - Basic ASCII: "A" → 65, "TEST" → 1413829460
  - Unicode emoji: "😀🎉🚀"
  - Mixed languages: "Hello世界", "Привет мир", "مرحبا العالم"
  - Special characters: "!@#$%^&*()"
  - Roundtrip preservation: text → int → text

- ✅ **Edge Cases (TestEdgeCases):**
  - Boundary values: 0, 1, n-1
  - Error handling: message = n, message > n
  - Security invariants: p ≠ q, gcd(e,φ)=1, e×d≡1(mod φ)
  - Key uniqueness verification

- ✅ **Integration Tests (TestIntegration):**
  - Complete encryption workflow
  - Complete signature workflow
  - Multiple key sizes: 256, 512, 1024 bits

**Code Coverage:**
- rsa_system.py: 96%
- rsa.py: 92%
- flask_rsa.py: 86%

### API Integration Tests (api/test_flask_api.py) - 26 Tests

- ✅ Health check endpoint
- ✅ Key generation: 256, 512, 1024, 2048-bit
- ✅ Complete encrypt/decrypt workflow via HTTP
- ✅ Digital signatures: sign + verify endpoints
- ✅ Session management and isolation
- ✅ Error handling: invalid sizes, missing keys
- ✅ Unicode and special character support
- ✅ Key import/export functionality
- ✅ Hex/decimal input parsing

**Coverage:** 86% of flask_rsa.py / api endpoints

### Performance Benchmarking

**Metrics Measured:**
- Key generation time (256, 512, 1024, 2048-bit)
- Encryption performance (per operation)
- Decryption performance (per operation)
- Prime generation iterations
- Miller-Rabin rounds executed

**Visualization:**
- Matplotlib graphs with time vs. key size
- Comparative analysis across operations
- Identifies performance bottlenecks

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

## Security Analysis

### ✅ What We Implemented Correctly

**Mathematical Correctness:**
- ✅ All RSA invariants verified: gcd(e,φ)=1, e×d≡1(mod φ), n=p×q, p≠q
- ✅ Primality testing: k=5 Miller-Rabin rounds (error ≈ 0.1%)
- ⚠️ Uses `random` module (NOT cryptographically secure - educational only)
- ✅ Input validation: message < n enforcement
- ✅ Digital signatures: SHA-256 hashing (collision resistant)

**Test Coverage:**
- ✅ 46 unit tests verify all mathematical properties
- ✅ 26 API integration tests ensure endpoint correctness
- ✅ Edge cases thoroughly tested (0, 1, n-1, n, n+100)
- ✅ Unicode and special character support validated

### ⚠️ Known Limitations (Educational Implementation)

**NOT for Production - Missing Critical Security Features:**

❌ **No OAEP Padding (RSA Encryption)**
- Textbook RSA is deterministic (same plaintext → same ciphertext)
- Vulnerable to chosen-plaintext attacks
- Production requires: OAEP (Optimal Asymmetric Encryption Padding)

❌ **No PSS Padding (Digital Signatures)**
- Deterministic signatures (same message → same signature)
- Production requires: PSS (Probabilistic Signature Scheme)

❌ **Non-Cryptographic Randomness**
- Uses `random` module instead of `secrets`
- Predictable random number generation
- Production requires: `secrets` module or hardware RNG

❌ **Low Miller-Rabin Confidence**
- Only k=5 rounds (≈0.1% error rate)
- Production requires: k≥40 rounds or deterministic tests

❌ **Timing Attacks Not Mitigated**
- Execution time may leak information about private key
- Production requires: Constant-time operations, blinding

❌ **In-Memory Key Storage**
- Keys stored in Python dict (lost on restart)
- Production requires: HSM, KMS, encrypted key stores

❌ **No Chinese Remainder Theorem (CRT)**
- Decryption could be ~4x faster with CRT optimization
- Production libraries use CRT for performance

### 📚 Educational Use Only

**✅ Perfect For:**
- Understanding RSA algorithm step-by-step
- Learning cryptographic principles
- Algorithm demonstrations and presentations
- Performance analysis and benchmarking
- Code review and study

**❌ Never Use For:**
- Real-world sensitive data
- Production systems
- Actual secure communications

**For Production, Use:**
- `cryptography` library (Python) with OAEP + PSS
- OpenSSL or libsodium
- Minimum 2048-bit keys (prefer 4096-bit)
- Proper key management (HSM/KMS)

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