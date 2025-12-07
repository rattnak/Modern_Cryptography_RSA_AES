import random
import hashlib
import warnings
from typing import Tuple, Dict


class MathUtils:
    # Mathematical utility functions for RSA.
    
    @staticmethod
    def gcd(a: int, b: int) -> int:
        # Compute GCD using Euclidean algorithm.
        while b != 0:
            a, b = b, a % b
        return a
    
    @staticmethod
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        # Extended Euclidean Algorithm for modular inverse.
        if b == 0:
            return a, 1, 0
        else:
            gcd_val, x1, y1 = MathUtils.extended_gcd(b, a % b)
            x = y1
            y = x1 - (a // b) * y1
            return gcd_val, x, y
    
    @staticmethod
    def mod_inverse(e: int, phi: int) -> int:
        # Compute modular multiplicative inverse.
        gcd_val, x, y = MathUtils.extended_gcd(e, phi)
        if gcd_val != 1:
            raise ValueError("Modular inverse does not exist")
        return x % phi


class PrimeGenerator:
    # Prime number generation and testing.
    
    @staticmethod
    def is_prime(n: int, k: int = 5) -> bool:
        # Miller-Rabin primality test.
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        # Write n-1 as 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        # Witness loop
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
            
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        
        return True
    
    @staticmethod
    def generate_prime(bits: int) -> int:
        # Generate a random prime number with specified bit length.
        while True:
            num = random.getrandbits(bits)
            num |= (1 << bits - 1) | 1
            if PrimeGenerator.is_prime(num):
                return num


def generate_keypair(size: int = 1024) -> Dict:
    """
    Generate RSA public and private key pair.
    
    Args:
        size: Bit length for the modulus n (256, 512, 1024, or 2048)
    
    Returns:
        Dictionary containing:
        {
            'public_key': {'e': int, 'n': int},
            'private_key': {'d': int, 'n': int},
            'size': int
        }
    
    Example:
        >>> keys = generate_keypair(512)
        >>> keys['size']
        512
    """
    # Generate two distinct primes
    p = PrimeGenerator.generate_prime(size // 2)
    q = PrimeGenerator.generate_prime(size // 2)
    
    while p == q:
        q = PrimeGenerator.generate_prime(size // 2)
    
    # Compute n and phi
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Choose e
    e = 65537
    if MathUtils.gcd(e, phi) != 1:
        e = 3
        while MathUtils.gcd(e, phi) != 1:
            e += 2
    
    # Compute d
    d = MathUtils.mod_inverse(e, phi)
    
    return {
        'public_key': {'e': e, 'n': n},
        'private_key': {'d': d, 'n': n},
        'size': size
    }


def encrypt(plaintext: str, key: Dict, size: int) -> str:
    """
    Encrypt a plaintext message using RSA public key.

    WARNING: This is textbook RSA without padding (OAEP).
    For production use, implement OAEP padding as recommended in
    "Understanding Cryptography" textbook.

    Args:
        plaintext: String message to encrypt
        key: Dictionary with 'e' and 'n' keys (public key)
        size: Key size in bits

    Returns:
        Encrypted ciphertext as string representation of integer

    Example:
        >>> keys = generate_keypair(512)
        >>> ciphertext = encrypt("Hello", keys['public_key'], keys['size'])
        >>> isinstance(ciphertext, str)
        True
    """
    # Warn about lack of padding
    warnings.warn(
        "Using textbook RSA without OAEP padding. Not secure for production use.",
        UserWarning
    )

    # Convert text to integer
    message_int = int.from_bytes(plaintext.encode('utf-8'), byteorder='big')

    # Check if message is too large
    if message_int >= key['n']:
        raise ValueError(f"Message too large for {size}-bit key. Use larger key or shorter message.")

    # Encrypt: c = m^e mod n
    e = key['e']
    n = key['n']
    ciphertext_int = pow(message_int, e, n)

    return str(ciphertext_int)


def decrypt(ciphertext: str, key: Dict, size: int) -> str:
    """
    Decrypt a ciphertext using RSA private key.
    
    Args:
        ciphertext: String representation of encrypted integer
        key: Dictionary with 'd' and 'n' keys (private key)
        size: Key size in bits
    
    Returns:
        Decrypted plaintext message as string
    
    Example:
        >>> keys = generate_keypair(512)
        >>> ct = encrypt("Hello", keys['public_key'], keys['size'])
        >>> pt = decrypt(ct, keys['private_key'], keys['size'])
        >>> pt
        'Hello'
    """
    # Convert ciphertext string to integer
    ciphertext_int = int(ciphertext)
    
    # Decrypt: m = c^d mod n
    d = key['d']
    n = key['n']
    message_int = pow(ciphertext_int, d, n)
    
    # Convert integer back to text
    num_bytes = (message_int.bit_length() + 7) // 8
    plaintext = message_int.to_bytes(num_bytes, byteorder='big').decode('utf-8')
    
    return plaintext


def sign(message: str, key: Dict, size: int) -> Dict:
    """
    Sign a message using RSA private key.
    
    Args:
        message: String message to sign
        key: Dictionary with 'd' and 'n' keys (private key)
        size: Key size in bits
    
    Returns:
        Dictionary containing:
        {
            'signature': str (integer as string),
            'message_hash': str (integer as string)
        }
    
    Example:
        >>> keys = generate_keypair(512)
        >>> sig = sign("Hello", keys['private_key'], keys['size'])
        >>> 'signature' in sig
        True
    """
    # Create SHA-256 hash (cryptographically secure)
    hash_obj = hashlib.sha256(message.encode('utf-8'))
    hash_bytes = hash_obj.digest()
    message_hash = int.from_bytes(hash_bytes, byteorder='big')

    # Ensure hash fits within modulus
    d = key['d']
    n = key['n']
    if message_hash >= n:
        # Truncate hash to fit (alternative: use larger key)
        message_hash = message_hash % n

    # Sign: s = h(m)^d mod n
    signature = pow(message_hash, d, n)

    return {
        'signature': str(signature),
        'message_hash': str(message_hash)
    }


def verify(message: str, signature: str, message_hash: str, key: Dict, size: int) -> bool:
    """
    Verify a digital signature using RSA public key.

    Args:
        message: Original message
        signature: Signature as string (integer)
        message_hash: Expected hash as string (integer)
        key: Dictionary with 'e' and 'n' keys (public key)
        size: Key size in bits

    Returns:
        True if signature is valid, False otherwise

    Example:
        >>> keys = generate_keypair(512)
        >>> sig = sign("Hello", keys['private_key'], keys['size'])
        >>> verify("Hello", sig['signature'], sig['message_hash'], keys['public_key'], keys['size'])
        True
    """
    # Compute hash of the current message
    hash_obj = hashlib.sha256(message.encode('utf-8'))
    hash_bytes = hash_obj.digest()
    computed_hash = int.from_bytes(hash_bytes, byteorder='big')

    # Ensure hash fits within modulus (same truncation as in sign)
    n = key['n']
    if computed_hash >= n:
        computed_hash = computed_hash % n

    # Convert signature string to integer
    signature_int = int(signature)

    # Recover the hash from the signature: h = s^e mod n
    e = key['e']
    recovered_hash = pow(signature_int, e, n)

    # Signature is valid if the recovered hash matches the computed hash of the message
    return recovered_hash == computed_hash


# Example usage
if __name__ == "__main__":
    
    # Generate keys
    print("Generating 512-bit RSA keys...")
    keys = generate_keypair(512)
    
    print(f"✓ Keys generated!")
    print(f"  Public key (e): {keys['public_key']['e']}")
    print(f"  Key size: {keys['size']} bits")
    print()
    
    # Test encryption/decryption
    print("=" * 70)
    print("Testing Encryption/Decryption")
    print("=" * 70)
    
    message = "Hello, RSA!"
    print(f"Original message: '{message}'")
    
    # Encrypt using the simplified API
    ciphertext = encrypt(message, keys['public_key'], keys['size'])
    print(f"Encrypted: {ciphertext[:50]}...")
    
    # Decrypt using the simplified API
    plaintext = decrypt(ciphertext, keys['private_key'], keys['size'])
    print(f"Decrypted: '{plaintext}'")
    print(f"✓ Success: {message == plaintext}")
    print()
    
    # Test digital signatures
    print("=" * 70)
    print("Testing Digital Signatures")
    print("=" * 70)
    
    message = "Important document"
    print(f"Message to sign: '{message}'")
    
    # Sign using the simplified API
    signature_data = sign(message, keys['private_key'], keys['size'])
    print(f"Signature: {signature_data['signature'][:50]}...")
    
    # Verify using the simplified API
    is_valid = verify(
        message,
        signature_data['signature'],
        signature_data['message_hash'],
        keys['public_key'],
        keys['size']
    )
    print(f"✓ Signature valid: {is_valid}")