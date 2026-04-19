from io import BytesIO

from app import app


def _multipart(file_name: str, data: bytes, password: str):
    return {
        "password": password,
        "file": (BytesIO(data), file_name),
    }


def test_health_endpoint_reports_limits():
    client = app.test_client()
    response = client.get("/api/health")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert "rateLimit" in payload


def test_encrypt_rejects_weak_password():
    client = app.test_client()
    response = client.post(
        "/api/encrypt",
        data=_multipart("notes.txt", b"abc", "weakpass"),
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    payload = response.get_json()
    assert "Password" in payload["error"]


def test_encrypt_then_decrypt_roundtrip_via_api():
    client = app.test_client()

    enc_response = client.post(
        "/api/encrypt",
        data=_multipart("notes.txt", b"hello file", "Str0ng!Password#2026"),
        content_type="multipart/form-data",
    )
    assert enc_response.status_code == 200

    encrypted_bytes = enc_response.data
    dec_response = client.post(
        "/api/decrypt",
        data={
            "password": "Str0ng!Password#2026",
            "file": (BytesIO(encrypted_bytes), "notes.txt.enc"),
        },
        content_type="multipart/form-data",
    )

    assert dec_response.status_code == 200
    assert dec_response.data == b"hello file"
    content_disposition = dec_response.headers.get("Content-Disposition", "")
    assert "notes.txt" in content_disposition


def test_verify_hash_match_and_mismatch():
    client = app.test_client()

    ok = client.post(
        "/api/verify-hash",
        data={
            "expectedHash": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            "file": (BytesIO(b"hello"), "hello.txt"),
        },
        content_type="multipart/form-data",
    )
    assert ok.status_code == 200
    assert ok.get_json()["matches"] is True

    bad = client.post(
        "/api/verify-hash",
        data={
            "expectedHash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "file": (BytesIO(b"hello"), "hello.txt"),
        },
        content_type="multipart/form-data",
    )
    assert bad.status_code == 200
    assert bad.get_json()["matches"] is False


def test_api_responses_include_security_headers():
    client = app.test_client()
    response = client.get("/api/health")

    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("Cache-Control") == "no-store"
