# CSCI 663 - Cryptography Project
## Group B

Implementation of cryptographic algorithms based on the [Understanding Cryptography: From Established Symmetric and Asymmetric Ciphers to Post-Quantum Algorithms](https://learn.lajevardi.id.ir/Cryptography/Refrence/2.pdf) textbook.

---

## Quick Navigation

**Jump to:**
- [RSA Implementation](#rsa-implementation) - Asymmetric encryption (Complete)
- [AES Implementation](#aes-implementation) - Symmetric encryption (In Progress)
- [Project Status](#project-status)
- [Textbook Compliance](#textbook-compliance)
- [Quick Commands](#quick-commands-reference)

---

## Project Structure

```
.
├── rsa/          # RSA implementation (asymmetric encryption)
└── aes/          # AES implementation (symmetric encryption) [IN PROGRESS]
```

---

# RSA Implementation

RSA encryption implementation with Python library and Flask REST API for encryption, decryption, and digital signatures.

## Quick Start - RSA

### Run RSA Tests (no installation needed)

```bash
cd rsa
python3 test_rsa.py
```

Expected: `46 tests passed`

### Run RSA Flask API

```bash
cd rsa

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install flask flask-cors

# Run tests
python test_rsa.py         # 46 tests
python test_flask_api.py   # 21 tests

# Start server
python flask_rsa.py
```

Server runs on `http://localhost:8080`

Test: `curl http://localhost:8080/api/health`

---

## RSA Implementation Details

### Core Functions

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

### RSA Python Usage

```python
from rsa import generate_keypair, encrypt, decrypt, sign, verify

# Generate keys
keys = generate_keypair(512)

# Encrypt/Decrypt
ciphertext = encrypt("Hello!", keys['public_key'], keys['size'])
plaintext = decrypt(ciphertext, keys['private_key'], keys['size'])

# Sign/Verify
sig = sign("Document", keys['private_key'], keys['size'])
is_valid = verify("Document", sig['signature'], sig['message_hash'],
                   keys['public_key'], keys['size'])
```

### RSA Flask API Endpoints

All endpoints: `http://localhost:8080/api/`

**GET /api/health** - Check server status

**POST /api/generate-keys** - Generate RSA key pair
```bash
curl -X POST http://localhost:8080/api/generate-keys \
  -H "Content-Type: application/json" \
  -d '{"size": 512, "session_id": "test"}'
```

**POST /api/encrypt** - Encrypt message
```bash
curl -X POST http://localhost:8080/api/encrypt \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello!", "session_id": "test"}'
```

**POST /api/decrypt** - Decrypt message
```bash
curl -X POST http://localhost:8080/api/decrypt \
  -H "Content-Type: application/json" \
  -d '{"ciphertext": "YOUR_CIPHERTEXT", "session_id": "test"}'
```

**POST /api/sign** - Sign message
```bash
curl -X POST http://localhost:8080/api/sign \
  -H "Content-Type: application/json" \
  -d '{"message": "Document", "session_id": "test"}'
```

**POST /api/verify** - Verify signature
```bash
curl -X POST http://localhost:8080/api/verify \
  -H "Content-Type: application/json" \
  -d '{"message": "Document", "signature": "SIG", "message_hash": "HASH", "session_id": "test"}'
```

### RSA Files

- `rsa.py` - Simple function-based API
- `rsa_system.py` - Object-oriented RSA implementation
- `test_rsa.py` - 46 unit tests
- `flask_rsa.py` - REST API server
- `test_flask_api.py` - 21 API tests
- `requirements.txt` - Dependencies

### RSA Testing Coverage

**46 Core Tests:**
- Mathematical functions
- Prime generation
- Key generation
- Encryption/decryption
- Text conversion
- Edge cases
- Integration tests

**21 API Tests:**
- Health check
- Key generation
- Encryption/decryption
- Digital signatures
- Error handling
- Session management
- Unicode support

---

# AES Implementation

[IN PROGRESS]

AES (Advanced Encryption Standard) symmetric encryption implementation.

## Quick Start - AES

```bash
cd aes
# Instructions will be added once implementation is complete
```

## AES Implementation Details

### Planned Features

**Modes of Operation:**
- ECB (Electronic Codebook)
- CBC (Cipher Block Chaining)
- CTR (Counter Mode)
- [Other modes TBD]

**Key Sizes:**
- 128 bits
- 192 bits
- 256 bits

**Core Operations:**
- SubBytes transformation
- ShiftRows transformation
- MixColumns transformation
- AddRoundKey transformation
- Key expansion

### AES Python Usage

```python
# Example usage (will be updated once implemented)
from aes import encrypt, decrypt, generate_key

# Generate key
key = generate_key(128)

# Encrypt/Decrypt
ciphertext = encrypt("Hello!", key, mode='CBC')
plaintext = decrypt(ciphertext, key, mode='CBC')
```

### AES Files

```
aes/
├── aes.py              # [TBD] Core AES implementation
├── aes_modes.py        # [TBD] Modes of operation
├── test_aes.py         # [TBD] Unit tests
└── requirements.txt    # [TBD] Dependencies
```

---

## Textbook Compliance

Both implementations follow [Understanding Cryptography: From Established Symmetric and Asymmetric Ciphers to Post-Quantum Algorithms](https://learn.lajevardi.id.ir/Cryptography/Refrence/2.pdf) textbook.

### RSA (Chapter 7) - Complete
- Key generation algorithm (5 steps)
- Miller-Rabin primality test
- Extended Euclidean Algorithm
- RSA encryption (c = m^e mod n)
- RSA decryption (m = c^d mod n)
- Digital signatures with SHA-256

### AES (Chapter 4) - In Progress
- Round transformations
- Key expansion
- Multiple modes of operation
- Multiple key sizes

---

## Installation

### RSA Setup

```bash
cd rsa
python3 -m venv venv
source venv/bin/activate
pip install flask flask-cors
```

### AES Setup

```bash
cd aes
# Instructions will be added
```

---

## Testing

### Run All RSA Tests

```bash
cd rsa
python3 test_rsa.py         # 46 core tests
python test_flask_api.py    # 21 API tests
```

### Run All AES Tests

```bash
cd aes
# Instructions will be added
```

---

## Important Notes

These are educational implementations based on the textbook. Not for production use.

**Security Warnings:**
- RSA uses textbook implementation without OAEP padding
- AES implementation for educational purposes only

**For Production:**
- Use established libraries (`cryptography`, `PyCryptodome`)
- Use proper padding schemes (OAEP for RSA, PKCS7 for AES)
- Use minimum 2048-bit keys for RSA
- Use minimum 128-bit keys for AES

---

## Troubleshooting

**Virtual environment not found:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Dependencies not installed:**
```bash
pip install -r requirements.txt
```

**Tests fail:**
Make sure you're in the correct directory (`rsa/` or `aes/`).

**Port already in use (RSA Flask):**
Edit `flask_rsa.py` line 431, change port number.

---

## Project Status

| Component | Status | Tests | Completion |
|-----------|--------|-------|------------|
| RSA Core | Complete | 46/46 pass | 100% |
| RSA Flask API | Complete | 21/21 pass | 100% |
| AES Core |  In Progress | TBD | 0% |
| AES Modes |  In Progress | TBD | 0% |

---

## Contributors

CSCI 663 - Group B
- RSA Implementation: Chanrattnak Mong, Ronald Targbeh
- AES Implementation: Derek Oum, Monyvann Men - In Progress

---

## Quick Commands Reference

```bash
# RSA
cd rsa
python3 test_rsa.py              # Test core RSA
python test_flask_api.py         # Test API
python flask_rsa.py              # Start server

# AES (coming soon)
cd aes
# Commands will be added
```