import random
from typing import Tuple, Optional


class MathUtils:
    # Mathematical utility functions for RSA implementation.

    
    @staticmethod
    def gcd(a: int, b: int) -> int:
        """
        Compute the Greatest Common Divisor using Euclidean algorithm.
        
        Args:
            a: First integer
            b: Second integer
        
        Returns:
            GCD of a and b
            
        Example:
            >>> MathUtils.gcd(48, 18)
            6
        """
        while b != 0:
            a, b = b, a % b
        return a
    
    @staticmethod
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        """
        Extended Euclidean Algorithm.
        Returns gcd(a,b) and coefficients x, y such that ax + by = gcd(a,b)
        
        This is crucial for finding the modular inverse in RSA.
        
        Args:
            a: First integer
            b: Second integer
        
        Returns:
            Tuple (gcd, x, y) where ax + by = gcd
            
        Example:
            >>> g, x, y = MathUtils.extended_gcd(17, 3120)
            >>> g
            1
        """
        if b == 0:
            return a, 1, 0
        else:
            gcd_val, x1, y1 = MathUtils.extended_gcd(b, a % b)
            x = y1
            y = x1 - (a // b) * y1
            return gcd_val, x, y
    
    @staticmethod
    def mod_inverse(e: int, phi: int) -> int:
        """
        Compute the modular multiplicative inverse of e modulo phi.
        This finds d such that (e * d) ≡ 1 (mod phi)
        
        Args:
            e: The public exponent
            phi: Euler's totient function φ(n)
        
        Returns:
            d: The private exponent (modular inverse of e)
            
        Raises:
            ValueError: If modular inverse does not exist
            
        Example:
            >>> MathUtils.mod_inverse(17, 3120)
            2753
        """
        gcd_val, x, y = MathUtils.extended_gcd(e, phi)
        
        if gcd_val != 1:
            raise ValueError("Modular inverse does not exist")
        
        return x % phi


class PrimeGenerator:
    # Prime number generation and testing utilities.
    @staticmethod
    def is_prime(n: int, k: int = 5) -> bool:
        """
        Miller-Rabin primality test.
        Tests whether n is probably prime with k rounds of testing.
        
        The textbook discusses the importance of using probabilistic 
        primality tests for large numbers as deterministic tests are too slow.
        
        Args:
            n: Number to test for primality
            k: Number of rounds (higher = more accurate)
        
        Returns:
            True if n is probably prime, False if composite
            
        Example:
            >>> PrimeGenerator.is_prime(61)
            True
            >>> PrimeGenerator.is_prime(100)
            False
        """
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
        """
        Generate a random prime number with specified bit length.
        
        For security, the textbook recommends large primes.
        Common sizes are 1024, 2048, or 4096 bits for n.
        
        Args:
            bits: Bit length of the prime
        
        Returns:
            A prime number with the specified bit length
            
        Example:
            >>> p = PrimeGenerator.generate_prime(16)
            >>> PrimeGenerator.is_prime(p)
            True
        """
        while True:
            num = random.getrandbits(bits)
            num |= (1 << bits - 1) | 1
            
            if PrimeGenerator.is_prime(num):
                return num


class RSAKeyPair:
    """
    Represents an RSA key pair (public and private keys).
  
    """
    
    def __init__(self, e: int, d: int, n: int, p: Optional[int] = None, q: Optional[int] = None):
        """
        Initialize RSA key pair.
        
        Args:
            e: Public exponent
            d: Private exponent
            n: Modulus
            p: First prime (optional, for optimization)
            q: Second prime (optional, for optimization)
        """
        self.e = e  # Public exponent
        self.d = d  # Private exponent
        self.n = n  # Modulus
        self.p = p  # First prime (kept for CRT optimization)
        self.q = q  # Second prime (kept for CRT optimization)
    
    def get_public_key(self) -> Tuple[int, int]:
        """Return public key as tuple (e, n)."""
        return (self.e, self.n)
    
    def get_private_key(self) -> Tuple[int, int]:
        """Return private key as tuple (d, n)."""
        return (self.d, self.n)
    
    def __str__(self) -> str:
        """String representation of key pair."""
        return f"RSA Key Pair:\n  Public: (e={self.e}, n={self.n})\n  Private: (d={self.d}, n={self.n})"


class RSA:
    # Main RSA implementation class.
    
    # Implements the RSA cryptosystem following the algorithm from our textbook (Understanding Cryptography).
    
    @staticmethod
    def generate_keypair(bits: int = 1024, verbose: bool = False) -> RSAKeyPair:
        """
        Generate RSA public and private key pair.
        
        Algorithm from "Understanding Cryptography":
        1. Choose two large primes p and q
        2. Compute n = p * q
        3. Compute φ(n) = (p-1)(q-1)
        4. Choose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
        5. Compute d such that d*e ≡ 1 (mod φ(n))
        
        Args:
            bits: Bit length for the modulus n
            verbose: Print generation steps if True
        
        Returns:
            RSAKeyPair object containing public and private keys
            
        Example:
            >>> rsa = RSA()
            >>> keypair = rsa.generate_keypair(bits=256)
            >>> isinstance(keypair, RSAKeyPair)
            True
        """
        if verbose:
            print(f"Generating RSA keys with {bits}-bit modulus...")
        
        # Step 1: Generate two distinct primes p and q
        if verbose:
            print("Step 1: Generating primes p and q...")
        p = PrimeGenerator.generate_prime(bits // 2)
        q = PrimeGenerator.generate_prime(bits // 2)
        
        while p == q:
            q = PrimeGenerator.generate_prime(bits // 2)
        
        # Step 2: Compute n = p * q
        n = p * q
        if verbose:
            print(f"Step 2: n = p × q = {n}")
        
        # Step 3: Compute Euler's totient φ(n) = (p-1)(q-1)
        phi = (p - 1) * (q - 1)
        if verbose:
            print(f"Step 3: φ(n) = {phi}")
        
        # Step 4: Choose e (public exponent)
        # 65537 is preferred for security reasons
        e = 65537
        
        if MathUtils.gcd(e, phi) != 1:
            e = 3
            while MathUtils.gcd(e, phi) != 1:
                e += 2
        
        if verbose:
            print(f"Step 4: e = {e}")
        
        # Step 5: Compute d (private exponent)
        d = MathUtils.mod_inverse(e, phi)
        if verbose:
            print(f"Step 5: d = {d}")
            print("Key generation complete!")
        
        return RSAKeyPair(e, d, n, p, q)
    
    @staticmethod
    def encrypt(message: int, public_key: Tuple[int, int]) -> int:
        """
        Encrypt a message using RSA public key.
        
        Encryption: c = m^e mod n
        
        Args:
            message: Integer message (must be < n)
            public_key: Tuple (e, n)
        
        Returns:
            Encrypted ciphertext as integer
            
        Raises:
            ValueError: If message >= n
            
        Example:
            >>> keypair = RSA.generate_keypair(bits=256)
            >>> public_key = keypair.get_public_key()
            >>> ciphertext = RSA.encrypt(42, public_key)
            >>> isinstance(ciphertext, int)
            True
        """
        e, n = public_key
        
        if message >= n:
            raise ValueError("Message too large for key size")
        
        return pow(message, e, n)
    
    @staticmethod
    def decrypt(ciphertext: int, private_key: Tuple[int, int]) -> int:
        """
        Decrypt a ciphertext using RSA private key.
        
        Decryption: m = c^d mod n
        
        Args:
            ciphertext: Integer ciphertext
            private_key: Tuple (d, n)
        
        Returns:
            Decrypted message as integer
            
        Example:
            >>> keypair = RSA.generate_keypair(bits=256)
            >>> public_key = keypair.get_public_key()
            >>> private_key = keypair.get_private_key()
            >>> message = 42
            >>> ciphertext = RSA.encrypt(message, public_key)
            >>> decrypted = RSA.decrypt(ciphertext, private_key)
            >>> message == decrypted
            True
        """
        d, n = private_key
        return pow(ciphertext, d, n)
    
    @staticmethod
    def sign(message_hash: int, private_key: Tuple[int, int]) -> int:
        """
        Sign a message hash using private key.
        
        Signing: s = h(m)^d mod n
        
        Args:
            message_hash: Hash of the message to sign
            private_key: Tuple (d, n)
        
        Returns:
            Digital signature
        """
        return RSA.decrypt(message_hash, private_key)
    
    @staticmethod
    def verify(signature: int, public_key: Tuple[int, int]) -> int:
        """
        Verify a signature using public key.
        
        Verification: h(m) = s^e mod n
        
        Args:
            signature: Digital signature
            public_key: Tuple (e, n)
        
        Returns:
            Recovered message hash
        """
        return RSA.encrypt(signature, public_key)


class TextConverter:
    # Utility class for converting between text and integers.

    
    @staticmethod
    def text_to_int(text: str) -> int:
        """
        Convert text string to integer for RSA encryption.
        
        Args:
            text: String message
        
        Returns:
            Integer representation
        """
        return int.from_bytes(text.encode('utf-8'), byteorder='big')
    
    @staticmethod
    def int_to_text(number: int) -> str:
        """
        Convert integer back to text string after RSA decryption.
        
        Args:
            number: Integer representation
        
        Returns:
            Original text string
        """
        num_bytes = (number.bit_length() + 7) // 8
        return number.to_bytes(num_bytes, byteorder='big').decode('utf-8')


# Example usage
if __name__ == "__main__":
    print("=" * 70)
    print("RSA Cryptosystem Implementation")
    print("CSCI 663 - Introduction to Cryptography")
    print("=" * 70)
    print()
    
    # Generate keys
    print("Generating RSA key pair (512-bit for demo)...")
    keypair = RSA.generate_keypair(bits=512, verbose=True)
    
    public_key = keypair.get_public_key()
    private_key = keypair.get_private_key()
    
    print("\n" + "=" * 70)
    print("Testing Encryption and Decryption")
    print("=" * 70)
    
    # Test numeric message
    message = 42
    print(f"\nOriginal message: {message}")
    
    ciphertext = RSA.encrypt(message, public_key)
    print(f"Encrypted: {ciphertext}")
    
    decrypted = RSA.decrypt(ciphertext, private_key)
    print(f"Decrypted: {decrypted}")
    print(f"Success: {message == decrypted}")
    
    # Test text message
    print("\n" + "=" * 70)
    print("Testing with Text Message")
    print("=" * 70)
    
    text = "HELLO"
    print(f"\nOriginal text: {text}")
    
    message_int = TextConverter.text_to_int(text)
    ciphertext = RSA.encrypt(message_int, public_key)
    decrypted_int = RSA.decrypt(ciphertext, private_key)
    decrypted_text = TextConverter.int_to_text(decrypted_int)
    
    print(f"Decrypted text: {decrypted_text}")
    print(f"Success: {text == decrypted_text}")