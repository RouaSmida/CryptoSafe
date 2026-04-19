from crypto_utils import decrypt_file_content, encrypt_file_content


def test_encrypt_decrypt_roundtrip_preserves_name_and_bytes():
    original_name = "report.final.v1.pdf"
    original_data = b"hello from cryptosafe"
    password = "Str0ng!Password#2026"

    encrypted = encrypt_file_content(original_name, original_data, password)
    out_name, out_data = decrypt_file_content(encrypted, password)

    assert out_name == original_name
    assert out_data == original_data


def test_decrypt_wrong_password_raises_value_error():
    encrypted = encrypt_file_content("image.png", b"binary", "Val1d!Password")

    try:
        decrypt_file_content(encrypted, "Wrong!Password")
        assert False, "Expected ValueError for wrong password"
    except ValueError:
        assert True
