from crypto_utils import MAGIC_V1, MAGIC_V2, decrypt_file_content, encrypt_file_content


def test_encrypt_decrypt_roundtrip_preserves_name_and_bytes():
    original_name = "report.final.v1.pdf"
    original_data = b"hello from cryptosafe"
    password = "Str0ng!Password#2026"

    encrypted = encrypt_file_content(original_name, original_data, password)
    out_name, out_data = decrypt_file_content(encrypted, password)

    assert out_name == original_name
    assert out_data == original_data
    assert encrypted.startswith(MAGIC_V2)


def test_decrypt_wrong_password_raises_value_error():
    encrypted = encrypt_file_content("image.png", b"binary", "Val1d!Password")

    try:
        decrypt_file_content(encrypted, "Wrong!Password")
        assert False, "Expected ValueError for wrong password"
    except ValueError:
        assert True


def test_legacy_pbkdf2_blob_still_decrypts():
    encrypted = encrypt_file_content(
        "legacy.txt", b"legacy-data", "Val1d!Password", kdf_mode="pbkdf2"
    )

    out_name, out_data = decrypt_file_content(encrypted, "Val1d!Password")
    assert encrypted.startswith(MAGIC_V1)
    assert out_name == "legacy.txt"
    assert out_data == b"legacy-data"


def test_tampered_ciphertext_is_rejected():
    encrypted = encrypt_file_content("report.txt", b"very secret", "Val1d!Password")
    tampered = bytearray(encrypted)
    tampered[-1] ^= 0x01

    try:
        decrypt_file_content(bytes(tampered), "Val1d!Password")
        assert False, "Expected ValueError for tampered ciphertext"
    except ValueError:
        assert True
