"""
Flask REST API for AES operations (generate-key, encrypt, decrypt).

This mirrors the RSA Flask API style used in `rsa/flask_rsa.py`, but
keeps endpoints scoped to `/api/aes/*` and runs on port 8081 by default
to avoid conflicts with the RSA server.
"""
from flask import Flask, request, jsonify
from flask_cors import CORS
from aes import generate_key, encrypt, decrypt

app = Flask(__name__)
CORS(app)


@app.route('/api/aes/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'ok',
        'message': 'AES API is running',
        'version': '1.0'
    })


@app.route('/api/aes/generate-key', methods=['POST'])
def api_generate_key():
    try:
        data = request.get_json() or {}
        size = int(data.get('size', 128))
        if size not in (128, 192, 256):
            return jsonify({'success': False, 'error': 'Invalid size. Choose 128,192,256'}), 400
        key_hex = generate_key(size)
        return jsonify({'success': True, 'key': key_hex, 'size': size})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/aes/encrypt', methods=['POST'])
def api_encrypt():
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

        ciphertext = encrypt(message, key, size)
        return jsonify({'success': True, 'ciphertext': ciphertext, 'original_message': message})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/aes/decrypt', methods=['POST'])
def api_decrypt():
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

        plaintext = decrypt(ciphertext, key, size)
        return jsonify({'success': True, 'plaintext': plaintext, 'original_ciphertext': ciphertext})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    print('=' * 70)
    print('AES Flask API')
    print('Running on http://127.0.0.1:8081')
    print('=' * 70)
    app.run(debug=True, host='127.0.0.1', port=8081)
