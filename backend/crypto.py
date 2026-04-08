"""
crypto.py - Core cryptographic operations for CryptoSafe.

Provides AES-256-GCM encryption/decryption and SHA-256 file hashing.
Key derivation uses PBKDF2-HMAC-SHA256 with a random salt.
"""

import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# File format constants
MAGIC = b"CSAFE1"   # 6-byte magic header to identify CryptoSafe files
SALT_LEN = 16       # 128-bit salt for PBKDF2
NONCE_LEN = 12      # 96-bit nonce for AES-GCM (NIST recommended)
KDF_ITERATIONS = 200_000  # PBKDF2 iteration count (OWASP 2023 recommendation)


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from a password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_data(data: bytes, password: str) -> bytes:
    """
    Encrypt raw bytes using AES-256-GCM.

    File format (bytes):
        MAGIC (6) | SALT (16) | NONCE (12) | CIPHERTEXT+TAG (variable)

    AES-GCM authentication tag (16 bytes) is appended to the ciphertext
    automatically by the cryptography library.

    Args:
        data:     Plaintext bytes to encrypt.
        password: User-supplied password for key derivation.

    Returns:
        Encrypted bytes in CryptoSafe format.
    """
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(password, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)  # includes 16-byte GCM tag

    return MAGIC + salt + nonce + ciphertext


def decrypt_data(data: bytes, password: str) -> bytes:
    """
    Decrypt bytes that were encrypted with encrypt_data().

    Args:
        data:     Encrypted bytes in CryptoSafe format.
        password: Password used during encryption.

    Returns:
        Original plaintext bytes.

    Raises:
        ValueError: If the file format is invalid or the password is wrong.
    """
    header_len = len(MAGIC) + SALT_LEN + NONCE_LEN  # 34 bytes

    if len(data) < header_len + 16:  # at least one block + GCM tag
        raise ValueError("File is too short or not a valid CryptoSafe file.")

    if not data.startswith(MAGIC):
        raise ValueError("Not a valid CryptoSafe encrypted file.")

    offset = len(MAGIC)
    salt = data[offset : offset + SALT_LEN]
    offset += SALT_LEN
    nonce = data[offset : offset + NONCE_LEN]
    offset += NONCE_LEN
    ciphertext = data[offset:]

    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise ValueError("Decryption failed: incorrect password or corrupted file.")


def hash_data(data: bytes) -> str:
    """
    Compute the SHA-256 digest of the given bytes.

    Args:
        data: File bytes to hash.

    Returns:
        Lowercase hexadecimal SHA-256 digest string (64 characters).
    """
    return hashlib.sha256(data).hexdigest()
