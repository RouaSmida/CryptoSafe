"""
test_crypto.py - Unit tests for CryptoSafe cryptographic functions.

Tests cover:
- AES-256-GCM encrypt/decrypt round-trip
- Wrong-password detection
- Corrupted ciphertext detection
- SHA-256 hashing correctness
- Invalid file format detection
"""

import sys
import os

# Make sure the backend package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import pytest
from crypto import decrypt_data, encrypt_data, hash_data, MAGIC


# ---------------------------------------------------------------------------
# encrypt_data / decrypt_data
# ---------------------------------------------------------------------------

class TestEncryptDecrypt:
    """Round-trip and error-path tests for AES-256-GCM functions."""

    def test_roundtrip_text_file(self):
        """Encrypt then decrypt a text payload and get the original back."""
        plaintext = b"Hello, CryptoSafe!"
        password = "s3cur3P@ssw0rd"
        encrypted = encrypt_data(plaintext, password)
        assert decrypt_data(encrypted, password) == plaintext

    def test_roundtrip_binary_file(self):
        """Encrypt then decrypt binary data (simulates an image or PDF)."""
        plaintext = bytes(range(256)) * 100  # 25.6 kB of binary data
        password = "binary_key_test"
        encrypted = encrypt_data(plaintext, password)
        assert decrypt_data(encrypted, password) == plaintext

    def test_encrypted_output_starts_with_magic(self):
        """Encrypted blob must begin with the CSAFE1 magic header."""
        encrypted = encrypt_data(b"data", "pw")
        assert encrypted.startswith(MAGIC)

    def test_encrypted_output_differs_from_plaintext(self):
        """Ciphertext must not equal the original plaintext."""
        plaintext = b"sensitive data"
        encrypted = encrypt_data(plaintext, "pw")
        assert encrypted != plaintext

    def test_two_encryptions_produce_different_ciphertexts(self):
        """Each encryption call uses a fresh random salt and nonce."""
        plaintext = b"same data"
        password = "same password"
        enc1 = encrypt_data(plaintext, password)
        enc2 = encrypt_data(plaintext, password)
        assert enc1 != enc2

    def test_wrong_password_raises_value_error(self):
        """Decryption with the wrong password must raise ValueError."""
        encrypted = encrypt_data(b"secret", "correct_password")
        with pytest.raises(ValueError, match="Decryption failed"):
            decrypt_data(encrypted, "wrong_password")

    def test_corrupted_ciphertext_raises_value_error(self):
        """Bit-flipping the ciphertext must cause GCM tag verification to fail."""
        encrypted = bytearray(encrypt_data(b"data", "pw"))
        # Flip a byte in the ciphertext area (after magic + salt + nonce = 34 bytes)
        encrypted[34] ^= 0xFF
        with pytest.raises(ValueError):
            decrypt_data(bytes(encrypted), "pw")

    def test_truncated_file_raises_value_error(self):
        """A file that is too short must be rejected."""
        with pytest.raises(ValueError, match="too short"):
            decrypt_data(b"tiny", "pw")

    def test_missing_magic_raises_value_error(self):
        """A file without the magic header must be rejected."""
        # Create valid-length but wrong-magic data
        fake = b"\x00" * 100
        with pytest.raises(ValueError, match="Not a valid CryptoSafe"):
            decrypt_data(fake, "pw")

    def test_empty_plaintext_roundtrip(self):
        """An empty file can be encrypted and decrypted back to empty bytes."""
        encrypted = encrypt_data(b"", "pw")
        assert decrypt_data(encrypted, "pw") == b""

    def test_unicode_password(self):
        """Passwords with non-ASCII characters should work correctly."""
        plaintext = b"unicode password test"
        password = "pässwörд123"
        encrypted = encrypt_data(plaintext, password)
        assert decrypt_data(encrypted, password) == plaintext


# ---------------------------------------------------------------------------
# hash_data
# ---------------------------------------------------------------------------

class TestHashData:
    """Tests for the SHA-256 hashing function."""

    def test_known_hash(self):
        """SHA-256 of the empty string is a well-known constant."""
        empty_hash = hash_data(b"")
        assert empty_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_hello_world_hash(self):
        """SHA-256('Hello, World!') must match the known value."""
        result = hash_data(b"Hello, World!")
        assert result == "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"

    def test_hash_is_64_hex_chars(self):
        """SHA-256 digest must always be 64 lowercase hex characters."""
        digest = hash_data(b"test data")
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    def test_different_data_different_hash(self):
        """Different inputs must produce different digests."""
        assert hash_data(b"abc") != hash_data(b"abd")

    def test_same_data_same_hash(self):
        """Hashing is deterministic: same input always yields same output."""
        data = b"consistent data"
        assert hash_data(data) == hash_data(data)
