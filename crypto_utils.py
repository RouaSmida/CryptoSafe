import os
import struct
from hashlib import sha256

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


MAGIC = b"CSF1"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
# Project baseline follows OWASP PBKDF2-HMAC-SHA256 guidance (2025-era recommendation).
# Revisit periodically and increase as practical for current hardware.
PBKDF2_ITERATIONS = 390000


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_file_content(file_name: str, content: bytes, password: str) -> bytes:
    if not password:
        raise ValueError("Password is required.")

    safe_name = os.path.basename(file_name or "file")
    name_bytes = safe_name.encode("utf-8")
    if len(name_bytes) > 65535:
        raise ValueError("File name is too long.")

    payload = struct.pack(">H", len(name_bytes)) + name_bytes + content
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = _derive_key(password, salt)

    encrypted_payload = AESGCM(key).encrypt(nonce, payload, None)
    return MAGIC + salt + nonce + encrypted_payload


def decrypt_file_content(encrypted_blob: bytes, password: str) -> tuple[str, bytes]:
    if not password:
        raise ValueError("Password is required.")
    if len(encrypted_blob) < len(MAGIC) + SALT_SIZE + NONCE_SIZE + 16:
        raise ValueError("Encrypted file is invalid or corrupted.")
    if not encrypted_blob.startswith(MAGIC):
        raise ValueError("Unsupported encrypted file format.")

    offset = len(MAGIC)
    salt = encrypted_blob[offset : offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = encrypted_blob[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext = encrypted_blob[offset:]

    key = _derive_key(password, salt)
    try:
        payload = AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Decryption failed. Wrong password or corrupted file.")

    if len(payload) < 2:
        raise ValueError("Decrypted payload is invalid.")

    name_length = struct.unpack(">H", payload[:2])[0]
    name_end = 2 + name_length
    if len(payload) < name_end:
        raise ValueError("Decrypted payload is incomplete.")

    file_name = payload[2:name_end].decode("utf-8", errors="replace") or "decrypted_file"
    file_content = payload[name_end:]
    return os.path.basename(file_name), file_content


def sha256_hash(content: bytes) -> str:
    return sha256(content).hexdigest()
