import unittest
import sys
from rsa_system import MathUtils, PrimeGenerator, RSA, RSAKeyPair, TextConverter


class TestMathUtils(unittest.TestCase):
    # Test cases for MathUtils class.

    def test_gcd_basic(self):
        # Test GCD with basic inputs.
        self.assertEqual(MathUtils.gcd(48, 18), 6)
        self.assertEqual(MathUtils.gcd(17, 3120), 1)
        self.assertEqual(MathUtils.gcd(100, 50), 50)
    
    def test_gcd_coprime(self):
        # Test GCD with coprime numbers.
        self.assertEqual(MathUtils.gcd(13, 17), 1)
        self.assertEqual(MathUtils.gcd(65537, 3120), 1)
    
    def test_extended_gcd(self):
        # Test Extended Euclidean Algorithm.
        a, b = 17, 3120
        gcd_val, x, y = MathUtils.extended_gcd(a, b)
        
        self.assertEqual(gcd_val, 1)
        self.assertEqual(a * x + b * y, gcd_val)
    
    def test_mod_inverse(self):
        # Test modular inverse calculation.
        e = 17
        phi = 3120
        d = MathUtils.mod_inverse(e, phi)
        
        self.assertEqual((e * d) % phi, 1)
    
    def test_mod_inverse_no_inverse(self):
        # Test modular inverse when it doesn't exist.
        with self.assertRaises(ValueError):
            MathUtils.mod_inverse(10, 20)  # gcd(10, 20) = 10 != 1


class TestPrimeGenerator(unittest.TestCase):
    # Test cases for PrimeGenerator class.

    
    def test_is_prime_known_primes(self):
        # Test primality of known prime numbers.
        primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61]
        for p in primes:
            self.assertTrue(PrimeGenerator.is_prime(p), f"{p} should be prime")
    
    def test_is_prime_known_composites(self):
        # Test primality of known composite numbers.
        composites = [4, 6, 8, 9, 10, 12, 14, 15, 16, 18, 20, 21, 22, 24, 25]
        for c in composites:
            self.assertFalse(PrimeGenerator.is_prime(c), f"{c} should be composite")
    
    def test_is_prime_edge_cases(self):
        # Test edge cases for primality testing.
        self.assertFalse(PrimeGenerator.is_prime(0))
        self.assertFalse(PrimeGenerator.is_prime(1))
        self.assertTrue(PrimeGenerator.is_prime(2))
    
    def test_generate_prime_bit_length(self):
        # Test that generated primes have correct bit length.
        for bits in [8, 16, 32]:
            prime = PrimeGenerator.generate_prime(bits)
            self.assertTrue(PrimeGenerator.is_prime(prime))
            self.assertTrue(prime.bit_length() == bits, 
                          f"Prime should have {bits} bits, has {prime.bit_length()}")
    
    def test_generate_prime_is_odd(self):
        # Test that generated primes are odd (except 2).
        for _ in range(10):
            prime = PrimeGenerator.generate_prime(16)
            self.assertTrue(prime % 2 == 1 or prime == 2)


class TestRSAKeyPair(unittest.TestCase):
    # Test cases for RSAKeyPair class.
    def test_keypair_creation(self):
        # Test RSA key pair creation.
        e, d, n = 17, 2753, 3233
        keypair = RSAKeyPair(e, d, n)
        
        self.assertEqual(keypair.e, e)
        self.assertEqual(keypair.d, d)
        self.assertEqual(keypair.n, n)
    
    def test_get_public_key(self):
        # Test getting public key.
        e, d, n = 17, 2753, 3233
        keypair = RSAKeyPair(e, d, n)
        
        public_key = keypair.get_public_key()
        self.assertEqual(public_key, (e, n))
    
    def test_get_private_key(self):
        # Test getting private key.
        e, d, n = 17, 2753, 3233
        keypair = RSAKeyPair(e, d, n)
        
        private_key = keypair.get_private_key()
        self.assertEqual(private_key, (d, n))


class TestRSA(unittest.TestCase):
    # Test cases for RSA class.
    
    def setUp(self):
        # Set up test fixtures.
        # Generate a small key pair for testing
        self.keypair = RSA.generate_keypair(bits=256)
        self.public_key = self.keypair.get_public_key()
        self.private_key = self.keypair.get_private_key()
    
    def test_generate_keypair(self):
        # Test RSA key pair generation.
        keypair = RSA.generate_keypair(bits=256)
        
        self.assertIsInstance(keypair, RSAKeyPair)
        self.assertIsNotNone(keypair.e)
        self.assertIsNotNone(keypair.d)
        self.assertIsNotNone(keypair.n)
    
    def test_encrypt_decrypt_basic(self):
        # Test basic encryption and decryption.
        message = 42
        
        ciphertext = RSA.encrypt(message, self.public_key)
        decrypted = RSA.decrypt(ciphertext, self.private_key)
        
        self.assertEqual(message, decrypted)
    
    def test_encrypt_decrypt_multiple_messages(self):
        # Test encryption/decryption with multiple messages.
        messages = [1, 100, 1000, 12345, 99999]
        
        for message in messages:
            ciphertext = RSA.encrypt(message, self.public_key)
            decrypted = RSA.decrypt(ciphertext, self.private_key)
            self.assertEqual(message, decrypted, f"Failed for message {message}")
    
    def test_encrypt_message_too_large(self):
        # Test that encrypting message >= n raises error.
        e, n = self.public_key
        message = n + 1
        
        with self.assertRaises(ValueError):
            RSA.encrypt(message, self.public_key)
    
    def test_sign_verify(self):
        # Test digital signature creation and verification.
        message_hash = 12345
        
        signature = RSA.sign(message_hash, self.private_key)
        recovered_hash = RSA.verify(signature, self.public_key)
        
        self.assertEqual(message_hash, recovered_hash)
    
    def test_sign_verify_multiple(self):
        # Test signing and verifying multiple messages.
        hashes = [100, 1000, 54321, 98765]
        
        for msg_hash in hashes:
            signature = RSA.sign(msg_hash, self.private_key)
            recovered = RSA.verify(signature, self.public_key)
            self.assertEqual(msg_hash, recovered)
    
    def test_encryption_deterministic(self):
        # Test that RSA encryption is deterministic (same input = same output).
        message = 12345
        
        c1 = RSA.encrypt(message, self.public_key)
        c2 = RSA.encrypt(message, self.public_key)
        
        self.assertEqual(c1, c2)
    
    def test_known_example(self):
        # Test with known small example from textbook.
        # Example: p=61, q=53, e=17, d=2753, n=3233
        keypair = RSAKeyPair(e=17, d=2753, n=3233, p=61, q=53)
        public_key = keypair.get_public_key()
        private_key = keypair.get_private_key()
        
        message = 42
        expected_ciphertext = pow(42, 17, 3233)  # = 2557
        
        ciphertext = RSA.encrypt(message, public_key)
        self.assertEqual(ciphertext, expected_ciphertext)
        
        decrypted = RSA.decrypt(ciphertext, private_key)
        self.assertEqual(decrypted, message)


class TestTextConverter(unittest.TestCase):
    
    # Test cases for TextConverter class.
    
    def test_text_to_int_basic(self):
        # Test converting text to integer.
        text = "HELLO"
        num = TextConverter.text_to_int(text)
        
        self.assertIsInstance(num, int)
        self.assertGreater(num, 0)
    
    def test_int_to_text_basic(self):
        # Test converting integer back to text.
        text = "HELLO"
        num = TextConverter.text_to_int(text)
        recovered = TextConverter.int_to_text(num)
        
        self.assertEqual(text, recovered)
    
    def test_text_to_int_to_text_various(self):
        # Test text conversion with various strings.
        test_strings = ["A", "TEST", "Hello World", "12345", "RSA!"]
        
        for text in test_strings:
            num = TextConverter.text_to_int(text)
            recovered = TextConverter.int_to_text(num)
            self.assertEqual(text, recovered, f"Failed for: {text}")
    
    def test_text_encryption_decryption(self):
        # Test encrypting and decrypting text messages.
        keypair = RSA.generate_keypair(bits=256)
        public_key = keypair.get_public_key()
        private_key = keypair.get_private_key()
        
        text = "RSA"
        message_int = TextConverter.text_to_int(text)
        
        ciphertext = RSA.encrypt(message_int, public_key)
        decrypted_int = RSA.decrypt(ciphertext, private_key)
        decrypted_text = TextConverter.int_to_text(decrypted_int)
        
        self.assertEqual(text, decrypted_text)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions."""

    def setUp(self):
        """Set up test fixtures."""
        self.keypair = RSA.generate_keypair(bits=256)
        self.public_key = self.keypair.get_public_key()
        self.private_key = self.keypair.get_private_key()

    def test_encrypt_zero(self):
        """Test encrypting zero."""
        message = 0
        ciphertext = RSA.encrypt(message, self.public_key)
        decrypted = RSA.decrypt(ciphertext, self.private_key)
        self.assertEqual(message, decrypted)

    def test_encrypt_one(self):
        """Test encrypting one."""
        message = 1
        ciphertext = RSA.encrypt(message, self.public_key)
        decrypted = RSA.decrypt(ciphertext, self.private_key)
        self.assertEqual(message, decrypted)

    def test_encrypt_n_minus_one(self):
        """Test encrypting n-1 (maximum valid value)."""
        e, n = self.public_key
        message = n - 1
        ciphertext = RSA.encrypt(message, self.public_key)
        decrypted = RSA.decrypt(ciphertext, self.private_key)
        self.assertEqual(message, decrypted)

    def test_encrypt_message_equals_n_raises_error(self):
        """Test that encrypting message == n raises ValueError."""
        e, n = self.public_key
        message = n
        with self.assertRaises(ValueError):
            RSA.encrypt(message, self.public_key)

    def test_encrypt_message_greater_than_n_raises_error(self):
        """Test that encrypting message > n raises ValueError."""
        e, n = self.public_key
        message = n + 100
        with self.assertRaises(ValueError):
            RSA.encrypt(message, self.public_key)

    def test_p_not_equal_q(self):
        """Test that generated p and q are distinct."""
        for _ in range(5):
            keypair = RSA.generate_keypair(bits=256)
            self.assertIsNotNone(keypair.p)
            self.assertIsNotNone(keypair.q)
            self.assertNotEqual(keypair.p, keypair.q)

    def test_public_exponent_coprime_to_phi(self):
        """Test that e and phi(n) are coprime."""
        keypair = RSA.generate_keypair(bits=256)
        e = keypair.e
        phi = (keypair.p - 1) * (keypair.q - 1)
        gcd = MathUtils.gcd(e, phi)
        self.assertEqual(gcd, 1)

    def test_private_key_correctness(self):
        """Test that d*e ≡ 1 (mod phi(n))."""
        keypair = RSA.generate_keypair(bits=256)
        e = keypair.e
        d = keypair.d
        phi = (keypair.p - 1) * (keypair.q - 1)
        self.assertEqual((e * d) % phi, 1)

    def test_n_equals_p_times_q(self):
        """Test that n = p * q."""
        keypair = RSA.generate_keypair(bits=256)
        self.assertEqual(keypair.n, keypair.p * keypair.q)

    def test_large_message_encryption(self):
        """Test encrypting a large message (but still < n)."""
        e, n = self.public_key
        # Use a large message close to but less than n
        message = n // 2
        ciphertext = RSA.encrypt(message, self.public_key)
        decrypted = RSA.decrypt(ciphertext, self.private_key)
        self.assertEqual(message, decrypted)

    def test_signature_verification_with_wrong_key(self):
        """Test that signature verification fails with wrong public key."""
        # Sign with one key pair
        message_hash = 12345
        signature = RSA.sign(message_hash, self.private_key)

        # Try to verify with different key pair
        other_keypair = RSA.generate_keypair(bits=256)
        other_public_key = other_keypair.get_public_key()
        recovered_hash = RSA.verify(signature, other_public_key)

        # Should not match original hash
        self.assertNotEqual(recovered_hash, message_hash)

    def test_key_generation_reproducibility(self):
        """Test that key generation produces unique keys each time."""
        keypair1 = RSA.generate_keypair(bits=256)
        keypair2 = RSA.generate_keypair(bits=256)

        # Keys should be different
        self.assertNotEqual(keypair1.n, keypair2.n)
        self.assertNotEqual(keypair1.d, keypair2.d)


class TestTextConverterEdgeCases(unittest.TestCase):
    """Test edge cases for TextConverter."""

    def test_empty_string(self):
        """Test converting empty string."""
        text = ""
        num = TextConverter.text_to_int(text)
        self.assertEqual(num, 0)

    def test_single_character(self):
        """Test converting single character."""
        text = "A"
        num = TextConverter.text_to_int(text)
        recovered = TextConverter.int_to_text(num)
        self.assertEqual(text, recovered)

    def test_special_characters(self):
        """Test converting special characters."""
        text = "!@#$%^&*()"
        num = TextConverter.text_to_int(text)
        recovered = TextConverter.int_to_text(num)
        self.assertEqual(text, recovered)

    def test_newlines_and_tabs(self):
        """Test converting text with newlines and tabs."""
        text = "Hello\nWorld\t!"
        num = TextConverter.text_to_int(text)
        recovered = TextConverter.int_to_text(num)
        self.assertEqual(text, recovered)

    def test_unicode_emoji(self):
        """Test converting Unicode emoji."""
        text = "😀🎉🚀"
        num = TextConverter.text_to_int(text)
        recovered = TextConverter.int_to_text(num)
        self.assertEqual(text, recovered)

    def test_mixed_unicode(self):
        """Test converting mixed Unicode text."""
        text = "Hello 世界 Привет مرحبا"
        num = TextConverter.text_to_int(text)
        recovered = TextConverter.int_to_text(num)
        self.assertEqual(text, recovered)


class TestIntegration(unittest.TestCase):
    # Integration tests for complete RSA workflow.
    def test_complete_encryption_workflow(self):
        # Test complete encryption workflow from key generation to decryption.
        # Generate keys
        keypair = RSA.generate_keypair(bits=512)
        public_key = keypair.get_public_key()
        private_key = keypair.get_private_key()
        
        # Encrypt message
        message = 123456789
        ciphertext = RSA.encrypt(message, public_key)
        
        # Decrypt message
        decrypted = RSA.decrypt(ciphertext, private_key)
        
        # Verify
        self.assertEqual(message, decrypted)
    
    def test_complete_signature_workflow(self):
        # Test complete digital signature workflow.
        # Generate keys
        keypair = RSA.generate_keypair(bits=512)
        public_key = keypair.get_public_key()
        private_key = keypair.get_private_key()
        
        # Sign message hash
        message_hash = 987654321
        signature = RSA.sign(message_hash, private_key)
        
        # Verify signature
        recovered_hash = RSA.verify(signature, public_key)
        
        # Verify
        self.assertEqual(message_hash, recovered_hash)
    
    def test_different_key_sizes(self):
        # Test RSA with different key sizes.
        key_sizes = [256, 512]
        
        for bits in key_sizes:
            keypair = RSA.generate_keypair(bits=bits)
            public_key = keypair.get_public_key()
            private_key = keypair.get_private_key()
            
            message = 12345
            ciphertext = RSA.encrypt(message, public_key)
            decrypted = RSA.decrypt(ciphertext, private_key)
            
            self.assertEqual(message, decrypted, f"Failed for {bits}-bit keys")


def run_tests():
    # Run all unit tests and display results.
    print("=" * 70)
    print("RSA Cryptosystem Unit Tests")
    print("CSCI 663 - Introduction to Cryptography")
    print("=" * 70)
    print()
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test cases
    suite.addTests(loader.loadTestsFromTestCase(TestMathUtils))
    suite.addTests(loader.loadTestsFromTestCase(TestPrimeGenerator))
    suite.addTests(loader.loadTestsFromTestCase(TestRSAKeyPair))
    suite.addTests(loader.loadTestsFromTestCase(TestRSA))
    suite.addTests(loader.loadTestsFromTestCase(TestTextConverter))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))
    suite.addTests(loader.loadTestsFromTestCase(TestTextConverterEdgeCases))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 70)
    print("Test Summary")
    print("=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)