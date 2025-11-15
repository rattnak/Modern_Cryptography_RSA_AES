# Cryptography Demo

A web application demonstrating AES and RSA cryptographic techniques with a clean, minimal interface.

## Features

### AES (Advanced Encryption Standard)
- Symmetric encryption algorithm
- Supports AES-128, AES-192, and AES-256
- Custom Python implementation
- Variable rounds: 10, 12, or 14 based on key size
- Includes SubBytes, ShiftRows, MixColumns transformations
- PKCS7 padding

### RSA (Rivest-Shamir-Adleman)
- Asymmetric encryption algorithm
- Frontend UI ready
- Backend implementation pending
- Key sizes: 1024, 2048, 4096-bit

## Tech Stack

### Frontend
- React 18.3.1
- Vite 5.4.2
- Tailwind CSS 3.4.1

### Backend
- Python 3.13.7
- Flask 3.0.0
- Flask-CORS 4.0.0

## Project Structure
```
project-aes/
├── backend/
│   ├── aes_crypto.py      # Custom AES implementation
│   ├── app.py             # Flask API server
│   └── requirements.txt   # Python dependencies
├── src/
│   ├── App.jsx            # Main React component
│   ├── main.jsx           # React entry point
│   └── index.css          # Tailwind styles
├── index.html
├── package.json
└── vite.config.js
```

## Installation

### Backend Setup

1. Create virtual environment:
python -m venv .venv

2. Activate virtual environment:
.venv\Scripts\Activate.ps1

3. Install dependencies:
cd backend
pip install -r requirements.txt

### Frontend Setup

1. Install dependencies:
npm install

## Running the Application

### Start Backend Server

cd backend
python app.py

Server runs on http://localhost:5000

### Start Frontend Development Server

npm run dev

Application runs on http://localhost:5173

## Usage

### AES Encryption/Decryption

1. Select AES tab
2. Choose mode (Encrypt or Decrypt)
3. Select key size (128, 192, or 256-bit)
4. Enter encryption key
5. Enter plaintext or ciphertext
6. Click Encrypt or Decrypt
7. View and copy output

### Key Sizes

- AES-128: 16 bytes, 10 rounds
- AES-192: 24 bytes, 12 rounds
- AES-256: 32 bytes, 14 rounds

## API Endpoints

### Encrypt
POST /api/encrypt

Content-Type: application/json

```
{
  "plaintext": "text to encrypt",
  "key": "encryption key",
  "keySize": 128
}
```

### Decrypt
POST /api/decrypt

Content-Type: application/json


```
{
  "ciphertext": "hex string",
  "key": "encryption key",
  "keySize": 128
}
```
### Health Check
GET /api/health

## Implementation Details

### AES Algorithm Components

- S-Box and Inverse S-Box for byte substitution
- Galois Field multiplication for MixColumns
- Key expansion with Rcon (round constants)
- AddRoundKey XOR operation
- Variable rounds based on key length

### Security Notes

This is an educational implementation. For production use:
- Use established cryptographic libraries
- Implement proper key management
- Add initialization vectors (IV)
- Consider authenticated encryption modes

## Development

### Build for Production
```
npm run build
```
### Preview Production Build

```
npm run preview
```

## License

Educational project for demonstrating cryptographic techniques.
