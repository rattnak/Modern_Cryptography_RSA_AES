"""
Flask REST API with simplified function signatures:
- encrypt(plaintext, key, size)
- decrypt(ciphertext, key, size)
- sign(message, key, size)
- verify(message, signature, hash, key, size)
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from rsa import generate_keypair, encrypt, decrypt, sign, verify

app = Flask(__name__)
CORS(app)  # Enable CORS for React frontend

# Store keypairs in memory (session management)
keypairs = {}


@app.route('/api/health', methods=['GET'])
def health_check():
    # Health check endpoint.
    return jsonify({
        'status': 'ok',
        'message': 'RSA API is running',
        'version': '2.0 - Simplified API'
    })


@app.route('/api/generate-keys', methods=['POST'])
def api_generate_keys():
    """
    Generate RSA key pair.
    
    Request JSON:
    {
        "size": 512,
        "session_id": "unique_id"
    }
    
    Response JSON:
    {
        "success": true,
        "public_key": {"e": int, "n": str},
        "private_key": {"d": str, "n": str},
        "size": 512
    }
    """
    try:
        data = request.get_json()
        size = int(data.get('size', 512))
        session_id = data.get('session_id', 'default')
        
        # Validate size
        if size not in [256, 512, 1024, 2048]:
            return jsonify({
                'success': False,
                'error': 'Invalid key size. Choose from: 256, 512, 1024, 2048'
            }), 400
        
        # Generate keypair using simplified API
        keys = generate_keypair(size)
        
        # Store keypair
        keypairs[session_id] = keys
        
        # Return keys (convert large numbers to strings for JSON)
        return jsonify({
            'success': True,
            'public_key': {
                'e': keys['public_key']['e'],
                'n': str(keys['public_key']['n'])
            },
            'private_key': {
                'd': str(keys['private_key']['d']),
                'n': str(keys['private_key']['n'])
            },
            'size': keys['size']
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    """
    Encrypt a message using simplified API.
    
    Request JSON:
    {
        "message": "Hello World",
        "session_id": "unique_id"
    }
    
    Response JSON:
    {
        "success": true,
        "ciphertext": "12345...",
        "original_message": "Hello World"
    }
    """
    try:
        data = request.get_json()
        message = data.get('message', '')
        session_id = data.get('session_id', 'default')
        
        if not message:
            return jsonify({
                'success': False,
                'error': 'Message cannot be empty'
            }), 400
        
        # Get keypair
        if session_id not in keypairs:
            return jsonify({
                'success': False,
                'error': 'No keys found. Please generate keys first.'
            }), 400
        
        keys = keypairs[session_id]
        
        # Encrypt using simplified API: encrypt(plaintext, key, size)
        ciphertext = encrypt(message, keys['public_key'], keys['size'])
        
        return jsonify({
            'success': True,
            'ciphertext': ciphertext,
            'original_message': message
        })
        
    except ValueError as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    """
    Decrypt a ciphertext using simplified API.
    
    Request JSON:
    {
        "ciphertext": "12345...",
        "session_id": "unique_id"
    }
    
    Response JSON:
    {
        "success": true,
        "plaintext": "Hello World",
        "original_ciphertext": "12345..."
    }
    """
    try:
        data = request.get_json()
        ciphertext = data.get('ciphertext', '')
        session_id = data.get('session_id', 'default')
        
        if not ciphertext:
            return jsonify({
                'success': False,
                'error': 'Ciphertext cannot be empty'
            }), 400
        
        # Get keypair
        if session_id not in keypairs:
            return jsonify({
                'success': False,
                'error': 'No keys found. Please generate keys first.'
            }), 400
        
        keys = keypairs[session_id]
        
        # Decrypt using simplified API: decrypt(ciphertext, key, size)
        plaintext = decrypt(ciphertext, keys['private_key'], keys['size'])
        
        return jsonify({
            'success': True,
            'plaintext': plaintext,
            'original_ciphertext': ciphertext
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/sign', methods=['POST'])
def api_sign():
    """
    Sign a message using simplified API.
    
    Request JSON:
    {
        "message": "Hello World",
        "session_id": "unique_id"
    }
    
    Response JSON:
    {
        "success": true,
        "signature": "...",
        "message_hash": "...",
        "original_message": "Hello World"
    }
    """
    try:
        data = request.get_json()
        message = data.get('message', '')
        session_id = data.get('session_id', 'default')
        
        if not message:
            return jsonify({
                'success': False,
                'error': 'Message cannot be empty'
            }), 400
        
        # Get keypair
        if session_id not in keypairs:
            return jsonify({
                'success': False,
                'error': 'No keys found. Please generate keys first.'
            }), 400
        
        keys = keypairs[session_id]
        
        # Sign using simplified API: sign(message, key, size)
        signature_data = sign(message, keys['private_key'], keys['size'])
        
        return jsonify({
            'success': True,
            'signature': signature_data['signature'],
            'message_hash': signature_data['message_hash'],
            'original_message': message
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/verify', methods=['POST'])
def api_verify():
    """
    Verify a signature using simplified API.
    
    Request JSON:
    {
        "message": "Hello World",
        "signature": "...",
        "message_hash": "...",
        "session_id": "unique_id"
    }
    
    Response JSON:
    {
        "success": true,
        "valid": true,
        "message": "Signature is valid!"
    }
    """
    try:
        data = request.get_json()
        message = data.get('message', '')
        signature = data.get('signature', '')
        message_hash = data.get('message_hash', '')
        session_id = data.get('session_id', 'default')
        
        if not all([message, signature, message_hash]):
            return jsonify({
                'success': False,
                'error': 'Missing required fields: message, signature, or message_hash'
            }), 400
        
        # Get keypair
        if session_id not in keypairs:
            return jsonify({
                'success': False,
                'error': 'No keys found. Please generate keys first.'
            }), 400
        
        keys = keypairs[session_id]
        
        # Verify using simplified API: verify(message, signature, hash, key, size)
        is_valid = verify(
            message,
            signature,
            message_hash,
            keys['public_key'],
            keys['size']
        )
        
        return jsonify({
            'success': True,
            'valid': is_valid,
            'message': 'Signature is valid!' if is_valid else 'Signature is INVALID!'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/get-keys', methods=['POST'])
def api_get_keys():
    """
    Get current keys for a session.
    
    Request JSON:
    {
        "session_id": "unique_id"
    }
    
    Response JSON:
    {
        "success": true,
        "has_keys": true,
        "public_key": {...},
        "private_key": {...},
        "size": 512
    }
    """
    try:
        data = request.get_json()
        session_id = data.get('session_id', 'default')
        
        if session_id not in keypairs:
            return jsonify({
                'success': True,
                'has_keys': False
            })
        
        keys = keypairs[session_id]
        
        return jsonify({
            'success': True,
            'has_keys': True,
            'public_key': {
                'e': keys['public_key']['e'],
                'n': str(keys['public_key']['n'])
            },
            'private_key': {
                'd': str(keys['private_key']['d']),
                'n': str(keys['private_key']['n'])
            },
            'size': keys['size']
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/example', methods=['GET'])
def api_example():
    """
    Show example of how to use the simplified API.
    
    Returns example code snippets.
    """
    example = {
        'description': 'RSA Simplified API Examples',
        'examples': [
            {
                'operation': 'Generate Keys',
                'code': 'keys = generate_keypair(512)'
            },
            {
                'operation': 'Encrypt',
                'code': 'ciphertext = encrypt("Hello", keys["public_key"], keys["size"])'
            },
            {
                'operation': 'Decrypt',
                'code': 'plaintext = decrypt(ciphertext, keys["private_key"], keys["size"])'
            },
            {
                'operation': 'Sign',
                'code': 'sig = sign("Message", keys["private_key"], keys["size"])'
            },
            {
                'operation': 'Verify',
                'code': 'is_valid = verify(message, sig["signature"], sig["message_hash"], keys["public_key"], keys["size"])'
            }
        ]
    }
    return jsonify(example)


if __name__ == '__main__':
    print("=" * 70)
    print("RSA Cryptosystem Flask API - Simplified Version")
    print("CSCI 663 - Introduction to Cryptography")
    print("=" * 70)
    print("\nAPI uses simplified function signatures:")
    print("  • encrypt(plaintext, key, size)")
    print("  • decrypt(ciphertext, key, size)")
    print("  • sign(message, key, size)")
    print("  • verify(message, signature, hash, key, size)")
    print("\nStarting server on http://localhost:5000")
    print("\nAPI Endpoints:")
    print("  POST /api/generate-keys")
    print("  POST /api/encrypt")
    print("  POST /api/decrypt")
    print("  POST /api/sign")
    print("  POST /api/verify")
    print("  POST /api/get-keys")
    print("  GET  /api/example")
    print("\nPress Ctrl+C to stop the server") #Basic instruction.
    print("=" * 70)

    # Using port 8080 to avoid macOS firewall issues
    app.run(debug=True, host='127.0.0.1', port=8080)