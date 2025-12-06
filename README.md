# RSA & AES Cryptography Implementation

**CSCI 663 - Introduction to Cryptography**
**Group B - Final Project**

A comprehensive web application demonstrating both RSA (asymmetric) and AES (symmetric) cryptographic algorithms with a clean, educational interface. Built entirely in Python with a React frontend.

---

## Project Overview

This project implements **RSA** and **AES** cryptographic algorithms from scratch in pure Python, providing both a REST API and an interactive web interface for encryption, decryption, and digital signatures.

### Key Features

**Complete RSA Implementation**
- Asymmetric encryption/decryption
- Digital signatures with verification
- Key sizes: 256, 512, 1024, 2048-bit
- Pure Python implementation (no external crypto libraries)
- Key import/export functionality
- Flexible input parsing (decimal/hexadecimal)

**Complete AES Implementation**
- Symmetric encryption/decryption
- Supports AES-128, AES-192, AES-256
- ECB mode with PKCS#7 padding
- Pure Python implementation
- Custom S-box, ShiftRows, MixColumns

**Unified REST API**
- Single Flask server handles both RSA and AES
- CORS-enabled for frontend integration
- Session management for RSA keys
- JSON-based request/response

**Interactive Web Interface**
- React-based UI with Tailwind CSS
- Real-time encryption/decryption
- Algorithm switching (RSA ↔ AES)
- Key generation buttons
- Copy-to-clipboard functionality

---

## Performance Benchmarks

**Measured on Apple Silicon (M-series) / Intel Mac**

### RSA Performance

| Key Size | Generation Time | Encryption | Decryption |
|----------|----------------|------------|------------|
| 256-bit | ~30ms | 0.01ms | 0.5ms |
| 512-bit | ~80ms | 0.02ms | 2ms |
| 1024-bit | ~500ms | 0.03ms | 5ms |
| 2048-bit | ~800ms | 0.1ms | 20ms |

### AES Performance

| Key Size | Encryption | Decryption |
|----------|------------|------------|
| 128-bit | ~0.5ms | ~0.5ms |
| 192-bit | ~0.6ms | ~0.6ms |
| 256-bit | ~0.7ms | ~0.7ms |

**Note:** Pure Python implementation is 5-10x slower than C-based libraries (OpenSSL), but excellent for educational purposes.

---

## Project Structure

```
CSCI663-GroupB-CryptographyProject/
│
├── api/                           # Unified Backend Server
│   ├── app.py                     # ⭐ Main Flask server (RSA + AES)
│   ├── requirements.txt           # Python dependencies
│   └── test_flask_api.py          # API integration tests (26 tests)
│
├── rsa/                           # RSA Implementation
│   ├── __init__.py                # Package exports
│   ├── rsa.py                     # Simplified API wrapper
│   ├── rsa_system.py              # Core RSA algorithms
│   ├── test_rsa.py                # Unit tests (46 tests)
│   ├── flask_rsa.py               # Legacy standalone server
│   ├── benchmark_rsa.py           # Text-based performance benchmarks
│   ├── benchmark_with_graph.py    # Visual benchmarking with matplotlib
│   └── README.md                  # RSA-specific documentation
│
├── aes/                           # AES Implementation
│   ├── __init__.py                # Package exports
│   ├── aes.py                     # AES algorithm implementation
│   ├── test_aes.py                # Unit tests
│   └── flask_aes.py               # (Standalone server - optional)
│
├── src/                           # React Frontend
│   ├── App.jsx                    # Main React component
│   ├── main.jsx                   # Entry point
│   └── index.css                  # Tailwind CSS
│
├── venv/                          # Python Virtual Environment
│   └── ...                        # Flask, Flask-CORS, matplotlib, etc.
│
├── Startup Scripts
│   ├── start_all.sh               # 🎯 Run both backend + frontend
│   ├── run.sh                     # Alternative startup
│   └── start_server.sh            # Backend only
│
├── Documentation
│   ├── README.md                  # This file
│   ├── QUICK_START.md             # Quick reference
│   ├── START_PROJECT.md           # Complete startup guide
│   ├── PROJECT_STRUCTURE.md       # Architecture details
│   ├── RUN_BENCHMARK.md           # Performance testing guide
│   ├── FLASK_SERVER_GUIDE.md      # Server troubleshooting
│   ├── NAK_PRESENTATION_SLIDES.md # Presentation content
│   └── PERFORMANCE_SLIDES.md      # Performance analysis
│
├── Configuration
│   ├── package.json               # Node.js dependencies
│   ├── vite.config.js             # Vite configuration
│   ├── tailwind.config.js         # Tailwind CSS config
│   └── .gitignore                 # Git ignore rules
│
└── Startup Scripts
    └── start_all.sh               # 🎯 Run both backend + frontend (executable)
```

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.13+** (with venv)
- **Node.js 18+** (with npm)
- **macOS, Linux, or Windows**

### Installation

```bash
# 1. Clone/navigate to project directory
cd CSCI663-GroupB-CryptographyProject

# 2. Create Python virtual environment (if not exists)
python3 -m venv venv

# 3. Activate virtual environment
source venv/bin/activate  # macOS/Linux
# or
venv\Scripts\activate     # Windows

# 4. Install Python dependencies
pip install flask flask-cors matplotlib numpy

# 5. Install Node.js dependencies
npm install
```

### Running the Application

**Easiest Way (Recommended):**
```bash
# Make the script executable (first time only)
chmod +x start_all.sh

# Run everything
./start_all.sh
```

**Manual Way (Two Terminals):**

Terminal 1 - Backend:
```bash
source venv/bin/activate
python3 api/app.py
```

Terminal 2 - Frontend:
```bash
npm run dev
```

**Then open:** http://localhost:5173

---

## 🎮 Usage Guide

### RSA Encryption/Decryption

1. Open http://localhost:5173
2. Select **RSA** tab
3. Click **Generate Keys** (choose 512 or 1024-bit for demos)
4. Enter a message in the text box
5. Click **Encrypt** → See ciphertext
6. Click **Decrypt** → Original message restored

### Digital Signatures

1. Generate RSA keys (if not already done)
2. Enter a message
3. Click **Sign Message**
4. Copy the signature
5. Click **Verify Signature** → Shows "Valid" or "Invalid"

### AES Encryption/Decryption

1. Select **AES** tab
2. Click **Generate Key** (128, 192, or 256-bit)
3. Enter plaintext message
4. Click **Encrypt** → See hex ciphertext
5. Click **Decrypt** → Original message restored

---

## 🔌 API Endpoints

### RSA Endpoints (Port 8080)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check |
| `POST` | `/api/generate-keys` | Generate RSA keypair |
| `POST` | `/api/encrypt` | Encrypt message with RSA |
| `POST` | `/api/decrypt` | Decrypt ciphertext with RSA |
| `POST` | `/api/sign` | Create digital signature |
| `POST` | `/api/verify` | Verify signature |
| `POST` | `/api/import-keys` | Import external keys |
| `POST` | `/api/get-keys` | Retrieve session keys |

### AES Endpoints (Port 8080)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/aes/health` | Health check |
| `POST` | `/api/aes/generate-key` | Generate AES key |
| `POST` | `/api/aes/encrypt` | Encrypt with AES |
| `POST` | `/api/aes/decrypt` | Decrypt with AES |

### Example API Calls

**Generate RSA Keys:**
```bash
curl -X POST http://localhost:8080/api/generate-keys \
  -H "Content-Type: application/json" \
  -d '{"size": 512, "session_id": "demo"}'
```

**Encrypt with RSA:**
```bash
curl -X POST http://localhost:8080/api/encrypt \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello World", "session_id": "demo"}'
```

**Generate AES Key:**
```bash
curl -X POST http://localhost:8080/api/aes/generate-key \
  -H "Content-Type: application/json" \
  -d '{"size": 128}'
```

---

## 🧪 Testing

### Run All Tests

```bash
# RSA unit tests (46 tests)
python3 -m pytest rsa/test_rsa.py -v

# AES unit tests
python3 -m pytest aes/test_aes.py -v

# API integration tests (26 tests)
python3 -m pytest api/test_flask_api.py -v
```

### Test Coverage

- **RSA Module:** 46 unit tests across 8 test classes
  - Mathematical operations (GCD, modular inverse)
  - Prime generation (Miller-Rabin)
  - Encryption/decryption workflows
  - Digital signatures
- **AES Module:** Comprehensive unit tests
  - Key expansion
  - SubBytes, ShiftRows, MixColumns
  - Encryption/decryption
- **API Integration:** 26 endpoint tests
  - RSA and AES endpoints
  - Session management
  - Error handling
- **Total:** 72+ tests

### Performance Benchmarking

**Text Output:**
```bash
python3 rsa/benchmark_rsa.py
```

**With Visual Graphs:**
```bash
python3 rsa/benchmark_with_graph.py
```

This generates matplotlib graphs showing performance metrics across different key sizes.

See [RUN_BENCHMARK.md](RUN_BENCHMARK.md) for detailed instructions.

---

## 🔐 Security Implementation

### What's Implemented ✅

**RSA:**
- ✅ Prime number generation (Miller-Rabin primality test)
- ✅ Modular arithmetic (Extended Euclidean Algorithm)
- ✅ Public/Private key generation
- ✅ Encryption with public key
- ✅ Decryption with private key
- ✅ Digital signatures (SHA-256 hash)
- ✅ Signature verification
- ✅ Flexible input parsing (hex/decimal)

**AES:**
- ✅ Key expansion
- ✅ SubBytes (S-box substitution)
- ✅ ShiftRows transformation
- ✅ MixColumns (Galois Field multiplication)
- ✅ AddRoundKey (XOR operation)
- ✅ PKCS#7 padding
- ✅ Variable rounds (10/12/14 based on key size)

### Known Limitations ⚠️

**Educational Implementation - NOT for Production:**

- ❌ No OAEP padding (RSA uses textbook encryption)
- ❌ No PSS padding (digital signatures)
- ❌ ECB mode only (AES - no CBC/CTR/GCM)
- ❌ No initialization vector (IV)
- ❌ Vulnerable to timing attacks
- ❌ No constant-time operations
- ❌ Single-threaded (no parallelization)
- ❌ No Chinese Remainder Theorem optimization

**For Production Use:**
- Use `cryptography` library (Python)
- Use OpenSSL or libsodium
- Implement proper key management
- Use authenticated encryption (GCM)
- Add proper error handling

---

## 📚 Implementation Details

### RSA Algorithm (rsa/rsa_system.py)

**Key Components:**

1. **Prime Generation** (Lines 84-186)
   - Miller-Rabin primality test
   - Configurable bit length
   - Random prime generation

2. **Modular Arithmetic** (Lines 32-82)
   - Extended Euclidean Algorithm
   - Modular inverse calculation
   - GCD computation

3. **Key Generation** (Lines 208-272)
   - Generate two large primes (p, q)
   - Compute n = p × q
   - Choose e = 65537 (public exponent)
   - Calculate d = e⁻¹ mod φ(n) (private exponent)

4. **Encryption/Decryption** (Lines 274-308)
   - Encryption: c = m^e mod n
   - Decryption: m = c^d mod n
   - Modular exponentiation

5. **Digital Signatures** (Lines 310-385)
   - SHA-256 hashing
   - Sign: s = hash(m)^d mod n
   - Verify: hash(m) == s^e mod n

### AES Algorithm (aes/aes.py)

**Key Components:**

1. **S-Box Substitution** (Lines 26-82)
   - Pre-computed S-box table
   - Inverse S-box for decryption

2. **Key Expansion** (Lines 140-176)
   - Expands key to round keys
   - Uses Rcon (round constants)
   - SubWord transformation

3. **Core Transformations** (Lines 75-124)
   - SubBytes: Byte substitution
   - ShiftRows: Row permutation
   - MixColumns: Galois Field operations
   - AddRoundKey: XOR with round key

4. **Encryption/Decryption** (Lines 178-288)
   - Variable rounds (10/12/14)
   - PKCS#7 padding/unpadding
   - ECB mode operation

---

## 🎓 Educational Value

### Learning Outcomes

✅ **Understand Cryptographic Principles:**
- Asymmetric vs Symmetric encryption
- Public-key cryptography concepts
- Key generation and management
- Digital signatures and verification

✅ **Mathematical Foundations:**
- Modular arithmetic
- Prime number generation
- Galois Field operations
- Euler's totient function

✅ **Practical Implementation:**
- Algorithm design patterns
- API development (REST)
- Frontend-backend integration
- Testing and benchmarking

### Use Cases

- ✅ Cryptography course projects
- ✅ Security concept demonstrations
- ✅ Algorithm visualization
- ✅ Performance analysis
- ✅ Code review and learning

---

## 🛠️ Tech Stack

### Backend
- **Language:** Python 3.13+
- **Framework:** Flask 3.0.0
- **CORS:** Flask-CORS 4.0.0
- **Testing:** pytest
- **Visualization:** matplotlib, numpy

### Frontend
- **Framework:** React 18.3.1
- **Build Tool:** Vite 5.4.2
- **Styling:** Tailwind CSS 3.4.1
- **HTTP Client:** Fetch API

### Development Tools
- **Package Manager:** npm, pip
- **Virtual Environment:** venv
- **Version Control:** Git

---

## 📖 Documentation

Comprehensive documentation available:

- **[QUICK_START.md](QUICK_START.md)** - Get running in 2 minutes
- **[START_PROJECT.md](START_PROJECT.md)** - Complete setup guide
- **[PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md)** - Architecture details
- **[RUN_BENCHMARK.md](RUN_BENCHMARK.md)** - Performance testing
- **[FLASK_SERVER_GUIDE.md](FLASK_SERVER_GUIDE.md)** - API troubleshooting
- **[NAK_PRESENTATION_SLIDES.md](NAK_PRESENTATION_SLIDES.md)** - Presentation content
- **[PERFORMANCE_SLIDES.md](PERFORMANCE_SLIDES.md)** - Benchmark analysis

---

## 🤝 Contributing

This is an educational project for CSCI 663.

**Group Members:**
- Implementation: RSA algorithms, Flask API, testing
- Implementation: AES algorithms, frontend integration
- Documentation: Technical writing, presentation slides

---

## ⚠️ Disclaimer

**This is an educational implementation for learning purposes only.**

**DO NOT use in production systems.** Use established cryptographic libraries:
- Python: `cryptography`, `PyCryptodome`
- OpenSSL
- libsodium

---

## 📝 License

Educational project for academic purposes.
CSCI 663 - Introduction to Cryptography

---

## 🎯 Summary

**To run the complete project:**

```bash
# First time setup
chmod +x start_all.sh

# Start everything
./start_all.sh
```

**Then open:** http://localhost:5173

**Features:**
- ✅ RSA encryption/decryption (256, 512, 1024, 2048-bit)
- ✅ AES encryption/decryption (128, 192, 256-bit)
- ✅ Digital signatures with verification
- ✅ Key import/export functionality
- ✅ Flexible input parsing (hex/decimal)
- ✅ REST API (port 8080)
- ✅ Interactive web UI (port 5173)
- ✅ 72+ unit tests (46 RSA + 26 API)
- ✅ Performance benchmarks with visual graphs

**Perfect for:**
- 🎓 Learning cryptography concepts
- 📊 Algorithm demonstrations
- 🔬 Performance analysis and benchmarking
- 💻 Code review and study
- 🎯 Educational presentations

**Quick Commands:**
```bash
# Run all tests
python3 rsa/test_rsa.py                    # 46 core RSA tests
python3 -m pytest api/test_flask_api.py -v # 26 API tests
python3 -m pytest aes/test_aes.py -v       # AES tests

# Run benchmarks
python3 rsa/benchmark_rsa.py               # Text output
python3 rsa/benchmark_with_graph.py        # Visual graphs

# Start services individually
python3 api/app.py                         # Backend only
npm run dev                                # Frontend only
```

---

**Made with 🔐 for CSCI 663 - Introduction to Cryptography**
