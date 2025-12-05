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
import os, sys
# Ensure the project root (parent of this `rsa` folder) is on sys.path so
# the sibling `aes` package can be imported when this script is executed
# directly (e.g. `python rsa/flask_rsa.py`).
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from aes import generate_key as aes_generate_key, encrypt as aes_encrypt, decrypt as aes_decrypt

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

    Supports flexible input formats:
    - Decimal integer strings: "12345678..."
    - Hexadecimal strings: "0xabcdef..." or "abcdef..."

    Request JSON:
    {
        "ciphertext": "12345...",  # decimal or hex format
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
        from rsa_system import TextConverter

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

        # Try flexible parsing for ciphertext (decimal or hex)
        # The decrypt function in rsa.py expects string ciphertext,
        # but we can pre-process to handle hex format
        try:
            # Check if it looks like hex (contains a-f or 0x prefix)
            if '0x' in ciphertext.lower() or any(c in ciphertext.lower() for c in 'abcdef'):
                # Parse as hex and convert back to decimal string for decrypt function
                parsed_int = TextConverter.parse_int_or_hex(ciphertext)
                ciphertext_for_decrypt = str(parsed_int)
            else:
                ciphertext_for_decrypt = ciphertext
        except ValueError:
            # If parsing fails, use original ciphertext
            ciphertext_for_decrypt = ciphertext

        # Decrypt using simplified API: decrypt(ciphertext, key, size)
        plaintext = decrypt(ciphertext_for_decrypt, keys['private_key'], keys['size'])

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


@app.route('/api/aes/health', methods=['GET'])
def aes_health_check():
    # Simple AES health endpoint
    return jsonify({
        'status': 'ok',
        'message': 'AES endpoints are available under /api/aes/*',
        'version': '1.0'
    })


@app.route('/api/aes/generate-key', methods=['POST'])
def api_aes_generate_key():
    try:
        data = request.get_json() or {}
        size = int(data.get('size', 128))
        if size not in (128, 192, 256):
            return jsonify({'success': False, 'error': 'Invalid size. Choose 128,192,256'}), 400
        key_hex = aes_generate_key(size)
        return jsonify({'success': True, 'key': key_hex, 'size': size})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/aes/encrypt', methods=['POST'])
def api_aes_encrypt():
    try:
        data = request.get_json() or {}
        message = data.get('message', '')
        key = data.get('key', '')
        size = int(data.get('size', 128))

        if not message:
            return jsonify({'success': False, 'error': 'Message cannot be empty'}), 400
        if not key:
            return jsonify({'success': False, 'error': 'Key required'}), 400
        if size not in (128, 192, 256):
            return jsonify({'success': False, 'error': 'Invalid size. Choose 128,192,256'}), 400

        ciphertext = aes_encrypt(message, key, size)
        return jsonify({'success': True, 'ciphertext': ciphertext, 'original_message': message})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/aes/decrypt', methods=['POST'])
def api_aes_decrypt():
    try:
        data = request.get_json() or {}
        ciphertext = data.get('ciphertext', '')
        key = data.get('key', '')
        size = int(data.get('size', 128))

        if not ciphertext:
            return jsonify({'success': False, 'error': 'Ciphertext cannot be empty'}), 400
        if not key:
            return jsonify({'success': False, 'error': 'Key required'}), 400
        if size not in (128, 192, 256):
            return jsonify({'success': False, 'error': 'Invalid size. Choose 128,192,256'}), 400

        plaintext = aes_decrypt(ciphertext, key, size)
        return jsonify({'success': True, 'plaintext': plaintext, 'original_ciphertext': ciphertext})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


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


@app.route('/api/import-keys', methods=['POST'])
def api_import_keys():
    """
    Import/upload existing RSA keypair for a session.

    This allows users to use their own pre-generated keys or keys
    from external sources, making the system more flexible for
    educational demonstrations and testing.

    Request JSON:
    {
        "session_id": "unique_id",
        "public_key": {
            "n": "123456...",  # decimal or hex string
            "e": "65537"       # decimal or hex string
        },
        "private_key": {
            "n": "123456...",  # decimal or hex string
            "d": "987654..."   # decimal or hex string
        },
        "size": 512  # optional, bit size
    }

    Note: At least one of public_key or private_key must be provided.
          If both provided, modulus 'n' must match.

    Response JSON:
    {
        "success": true,
        "message": "Keys imported successfully",
        "public_key": {...},
        "private_key": {...}
    }
    """
    try:
        from rsa_system import TextConverter

        data = request.get_json()
        session_id = data.get('session_id', 'default')
        public_data = data.get('public_key')
        private_data = data.get('private_key')
        size = data.get('size', 1024)  # default size

        if not public_data and not private_data:
            return jsonify({
                'success': False,
                'error': 'At least one of public_key or private_key must be provided'
            }), 400

        # Build keypair structure
        imported_keys = {'size': size}

        # Parse public key
        if public_data:
            try:
                n_pub = TextConverter.parse_int_or_hex(str(public_data['n']))
                e_pub = TextConverter.parse_int_or_hex(str(public_data['e']))
                imported_keys['public_key'] = {'n': n_pub, 'e': e_pub}
            except (KeyError, ValueError) as e:
                return jsonify({
                    'success': False,
                    'error': f'Invalid public_key format: {str(e)}'
                }), 400

        # Parse private key
        if private_data:
            try:
                n_priv = TextConverter.parse_int_or_hex(str(private_data['n']))
                d_priv = TextConverter.parse_int_or_hex(str(private_data['d']))
                imported_keys['private_key'] = {'n': n_priv, 'd': d_priv}
            except (KeyError, ValueError) as e:
                return jsonify({
                    'success': False,
                    'error': f'Invalid private_key format: {str(e)}'
                }), 400

        # Validate that n matches if both keys provided
        if 'public_key' in imported_keys and 'private_key' in imported_keys:
            if imported_keys['public_key']['n'] != imported_keys['private_key']['n']:
                return jsonify({
                    'success': False,
                    'error': 'Public and private key modulus (n) do not match'
                }), 400

        # Store the imported keys
        keypairs[session_id] = imported_keys

        # Prepare response
        response = {
            'success': True,
            'message': 'Keys imported successfully'
        }

        if 'public_key' in imported_keys:
            response['public_key'] = {
                'e': imported_keys['public_key']['e'],
                'n': str(imported_keys['public_key']['n'])
            }

        if 'private_key' in imported_keys:
            response['private_key'] = {
                'd': str(imported_keys['private_key']['d']),
                'n': str(imported_keys['private_key']['n'])
            }

        return jsonify(response)

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error importing keys: {str(e)}'
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
            },
            {
                'operation': 'Import Keys',
                'code': 'import_keys(session_id, public_key, private_key)'
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
    print("")
    print("AES Endpoints (same process):")
    print("  GET  /api/aes/health")
    print("  POST /api/aes/generate-key")
    print("  POST /api/aes/encrypt")
    print("  POST /api/aes/decrypt")
    print("\nPress Ctrl+C to stop the server") #Basic instruction.
    print("=" * 70)

    # Using port 8080 to avoid macOS firewall issues
    app.run(debug=True, host='127.0.0.1', port=8080)