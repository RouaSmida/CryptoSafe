import os
import struct
from hashlib import sha256

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


MAGIC_V1 = b"CSF1"  # Legacy format: PBKDF2-HMAC-SHA256
MAGIC_V2 = b"CSF2"  # Current format: Argon2id
MAGIC = MAGIC_V1
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
MIN_ENCRYPTED_BLOB_SIZE = len(MAGIC_V1) + SALT_SIZE + NONCE_SIZE + 16
# Project baseline follows OWASP PBKDF2-HMAC-SHA256 guidance (2025-era recommendation).
# Revisit periodically and increase as practical for current hardware.
PBKDF2_ITERATIONS = 390000
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST_KIB = 65536  # 64 MiB
ARGON2_PARALLELISM = 2
SUPPORTED_MAGICS = (MAGIC_V1, MAGIC_V2)
DEFAULT_KDF_MODE = "argon2id"


def is_supported_encrypted_blob(blob: bytes) -> bool:
    return len(blob) >= MIN_ENCRYPTED_BLOB_SIZE and blob[:4] in SUPPORTED_MAGICS


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def _derive_key_argon2id(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )


def encrypt_file_content(
    file_name: str, content: bytes, password: str, kdf_mode: str = DEFAULT_KDF_MODE
) -> bytes:
    if not password:
        raise ValueError("Password is required.")
    if kdf_mode not in {"argon2id", "pbkdf2"}:
        raise ValueError("Unsupported KDF mode.")

    safe_name = os.path.basename(file_name or "file")
    name_bytes = safe_name.encode("utf-8")
    if len(name_bytes) > 65535:
        raise ValueError("File name is too long.")

    payload = struct.pack(">H", len(name_bytes)) + name_bytes + content
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    if kdf_mode == "argon2id":
        key = _derive_key_argon2id(password, salt)
        magic = MAGIC_V2
    else:
        key = _derive_key(password, salt)
        magic = MAGIC_V1

    encrypted_payload = AESGCM(key).encrypt(nonce, payload, None)
    return magic + salt + nonce + encrypted_payload


def decrypt_file_content(encrypted_blob: bytes, password: str) -> tuple[str, bytes]:
    if not password:
        raise ValueError("Password is required.")
    if len(encrypted_blob) < MIN_ENCRYPTED_BLOB_SIZE:
        raise ValueError("Encrypted file is invalid or corrupted.")
    magic = encrypted_blob[:4]
    if magic not in SUPPORTED_MAGICS:
        raise ValueError("Unsupported encrypted file format.")

    offset = len(magic)
    salt = encrypted_blob[offset : offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = encrypted_blob[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext = encrypted_blob[offset:]

    if magic == MAGIC_V2:
        key = _derive_key_argon2id(password, salt)
    else:
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

    try:
        file_name = payload[2:name_end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Decrypted file name is invalid or corrupted.") from exc
    file_name = file_name or "decrypted_file"
    file_content = payload[name_end:]
    return os.path.basename(file_name), file_content


def sha256_hash(content: bytes) -> str:
    return sha256(content).hexdigest()
