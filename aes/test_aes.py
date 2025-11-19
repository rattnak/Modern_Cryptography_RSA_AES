import unittest
import sys
from aes import encrypt, decrypt, generate_key


class TestAESBasic(unittest.TestCase):
    """Basic AES unit tests for encrypt/decrypt across key sizes.

    These tests exercise the public API:
      - encrypt(text, key, size) -> hex string
      - decrypt(hex, key, size) -> plaintext string

    Tests are written in the project's unittest style and include
    edge cases for empty strings, long inputs, invalid inputs, and
    consistency checks across key sizes (128, 192, 256).
    """

    def test_encrypt_decrypt_all_sizes(self):
        """Round-trip encryption/decryption for all supported AES sizes."""
        sizes = [128, 192, 256]
        plaintext = "The quick brown fox jumps over the lazy dog"
        for size in sizes:
            key = f"test-key-{size}"
            ciphertext = encrypt(plaintext, key, size)
            # ciphertext must be a non-empty hex string
            self.assertIsInstance(ciphertext, str)
            self.assertGreater(len(ciphertext), 0)

            recovered = decrypt(ciphertext, key, size)
            self.assertEqual(plaintext, recovered)

    def test_empty_string(self):
        """Encrypting and decrypting an empty string should round-trip."""
        plaintext = ""
        key = "empty-key"
        ciphertext = encrypt(plaintext, key, 128)
        self.assertIsInstance(ciphertext, str)

        recovered = decrypt(ciphertext, key, 128)
        self.assertEqual(plaintext, recovered)

    def test_long_text(self):
        """Encrypt a long message (multi-block) and verify round-trip."""
        plaintext = "A" * 4096  # many blocks
        key = "long-key-example"
        ciphertext = encrypt(plaintext, key, 256)
        recovered = decrypt(ciphertext, key, 256)
        self.assertEqual(plaintext, recovered)

    def test_invalid_ciphertext_raises(self):
        """Decrypting a non-hex string should raise a ValueError."""
        key = "some-key"
        with self.assertRaises(ValueError):
            decrypt("not-a-hex-string!!", key, 128)

    def test_invalid_size_raises(self):
        """Using an unsupported AES size should raise a ValueError."""
        with self.assertRaises(ValueError):
            encrypt("hello", "k", 100)
        with self.assertRaises(ValueError):
            decrypt("00", "k", 100)

    def test_different_keys_produce_different_ciphertext(self):
        """Different keys should (very likely) produce different ciphertexts."""
        plaintext = "Deterministic test text"
        c1 = encrypt(plaintext, "key-one", 128)
        c2 = encrypt(plaintext, "key-two", 128)
        self.assertNotEqual(c1, c2)

    def test_encryption_is_deterministic(self):
        """Repeated encryption with same inputs should be deterministic (ECB)."""
        plaintext = "Repeatable text"
        key = "same-key"
        c1 = encrypt(plaintext, key, 192)
        c2 = encrypt(plaintext, key, 192)
        self.assertEqual(c1, c2)

    def test_generate_key_lengths_and_usage(self):
        """Test that generated keys have correct lengths and work for encrypt/decrypt."""
        sizes = [128, 192, 256]
        plaintext = "Key gen test message"
        for size in sizes:
            key_hex = generate_key(size)
            # hex length should be size/4 characters (4 bits per hex digit)
            expected_hex_len = size // 4
            self.assertIsInstance(key_hex, str)
            self.assertEqual(len(key_hex), expected_hex_len)

            # Use generated key (hex) directly — our AES accepts string keys,
            # so pass the raw hex string; ensure round-trip works.
            ciphertext = encrypt(plaintext, key_hex, size)
            recovered = decrypt(ciphertext, key_hex, size)
            self.assertEqual(plaintext, recovered)


def run_tests():
    """Run the AES unit tests and print a small summary."""
    print("=" * 70)
    print("AES Unit Tests")
    print("CSCI 663 - AES Implementation Tests")
    print("=" * 70)
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestAESBasic)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 70)
    print("Test Summary")
    print("=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")

    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
