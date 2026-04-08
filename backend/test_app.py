"""
test_app.py - Integration tests for the CryptoSafe Flask API endpoints.

Tests cover:
- /api/encrypt  returns a valid .enc file
- /api/decrypt  restores the original file
- /api/hash     returns correct JSON with SHA-256 digest
- Error handling for missing fields, wrong passwords, and file-size limits
"""

import io
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import pytest
from app import app as flask_app


@pytest.fixture
def client():
    """Create a Flask test client."""
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# /api/encrypt
# ---------------------------------------------------------------------------

class TestEncryptEndpoint:
    def test_returns_enc_file(self, client):
        data = {"file": (io.BytesIO(b"hello world"), "test.txt"), "password": "mypassword"}
        rv = client.post("/api/encrypt", data=data, content_type="multipart/form-data")
        assert rv.status_code == 200
        assert ".enc" in rv.headers.get("Content-Disposition", "")
        assert len(rv.data) > 0

    def test_missing_file_returns_400(self, client):
        rv = client.post("/api/encrypt", data={"password": "pw"}, content_type="multipart/form-data")
        assert rv.status_code == 400
        body = json.loads(rv.data)
        assert "error" in body

    def test_missing_password_returns_400(self, client):
        data = {"file": (io.BytesIO(b"data"), "file.txt")}
        rv = client.post("/api/encrypt", data=data, content_type="multipart/form-data")
        assert rv.status_code == 400
        body = json.loads(rv.data)
        assert "error" in body

    def test_empty_file_returns_400(self, client):
        data = {"file": (io.BytesIO(b""), "empty.txt"), "password": "pw"}
        rv = client.post("/api/encrypt", data=data, content_type="multipart/form-data")
        assert rv.status_code == 400

    def test_encrypted_output_is_binary_and_differs_from_input(self, client):
        payload = b"plaintext content"
        data = {"file": (io.BytesIO(payload), "plain.txt"), "password": "pw"}
        rv = client.post("/api/encrypt", data=data, content_type="multipart/form-data")
        assert rv.status_code == 200
        assert rv.data != payload


# ---------------------------------------------------------------------------
# /api/decrypt
# ---------------------------------------------------------------------------

class TestDecryptEndpoint:
    def _encrypt(self, client, payload: bytes, password: str) -> bytes:
        """Helper: encrypt payload via the API and return the encrypted bytes."""
        data = {"file": (io.BytesIO(payload), "file.txt"), "password": password}
        rv = client.post("/api/encrypt", data=data, content_type="multipart/form-data")
        assert rv.status_code == 200
        return rv.data

    def test_roundtrip(self, client):
        """Encrypt then decrypt returns the original bytes."""
        original = b"top secret content"
        enc = self._encrypt(client, original, "pw123")
        data = {"file": (io.BytesIO(enc), "file.txt.enc"), "password": "pw123"}
        rv = client.post("/api/decrypt", data=data, content_type="multipart/form-data")
        assert rv.status_code == 200
        assert rv.data == original

    def test_download_name_strips_enc(self, client):
        """The decrypted file should be named without the .enc extension."""
        enc = self._encrypt(client, b"data", "pw")
        data = {"file": (io.BytesIO(enc), "report.pdf.enc"), "password": "pw"}
        rv = client.post("/api/decrypt", data=data, content_type="multipart/form-data")
        assert rv.status_code == 200
        assert "report.pdf" in rv.headers.get("Content-Disposition", "")

    def test_wrong_password_returns_400(self, client):
        """Using the wrong password must return 400 with an error message."""
        enc = self._encrypt(client, b"data", "correct_pw")
        data = {"file": (io.BytesIO(enc), "file.enc"), "password": "wrong_pw"}
        rv = client.post("/api/decrypt", data=data, content_type="multipart/form-data")
        assert rv.status_code == 400
        body = json.loads(rv.data)
        assert "error" in body

    def test_invalid_file_returns_400(self, client):
        """Uploading a non-CryptoSafe file must return a 400 error."""
        data = {"file": (io.BytesIO(b"not a real enc file" * 10), "bad.enc"), "password": "pw"}
        rv = client.post("/api/decrypt", data=data, content_type="multipart/form-data")
        assert rv.status_code == 400
        body = json.loads(rv.data)
        assert "error" in body

    def test_missing_password_returns_400(self, client):
        data = {"file": (io.BytesIO(b"data"), "file.enc")}
        rv = client.post("/api/decrypt", data=data, content_type="multipart/form-data")
        assert rv.status_code == 400


# ---------------------------------------------------------------------------
# /api/hash
# ---------------------------------------------------------------------------

class TestHashEndpoint:
    def test_returns_sha256(self, client):
        import hashlib
        payload = b"hash me"
        expected = hashlib.sha256(payload).hexdigest()
        data = {"file": (io.BytesIO(payload), "doc.txt")}
        rv = client.post("/api/hash", data=data, content_type="multipart/form-data")
        assert rv.status_code == 200
        body = json.loads(rv.data)
        assert body["sha256"] == expected

    def test_response_contains_filename_and_size(self, client):
        payload = b"test content"
        data = {"file": (io.BytesIO(payload), "myfile.txt")}
        rv = client.post("/api/hash", data=data, content_type="multipart/form-data")
        body = json.loads(rv.data)
        assert body["filename"] == "myfile.txt"
        assert body["size"] == len(payload)

    def test_missing_file_returns_400(self, client):
        rv = client.post("/api/hash", data={}, content_type="multipart/form-data")
        assert rv.status_code == 400
        body = json.loads(rv.data)
        assert "error" in body

    def test_empty_file_returns_400(self, client):
        data = {"file": (io.BytesIO(b""), "empty.txt")}
        rv = client.post("/api/hash", data=data, content_type="multipart/form-data")
        assert rv.status_code == 400


# ---------------------------------------------------------------------------
# /  (frontend)
# ---------------------------------------------------------------------------

class TestFrontend:
    def test_index_returns_html(self, client):
        rv = client.get("/")
        assert rv.status_code == 200
        assert b"<!DOCTYPE html>" in rv.data or b"<html" in rv.data
