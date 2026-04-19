from io import BytesIO
from pathlib import Path
import re
import threading
import time
from collections import defaultdict, deque

from flask import Flask, jsonify, render_template, request, send_file

from crypto_utils import (
    DEFAULT_KDF_MODE,
    MAGIC_V1,
    MAGIC_V2,
    decrypt_file_content,
    encrypt_file_content,
    is_supported_encrypted_blob,
    sha256_hash,
)


BASE_DIR = Path(__file__).resolve().parent
MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB
RATE_LIMIT_WINDOW_SEC = 60
RATE_LIMIT_MAX_REQUESTS = 20
RATE_LIMITED_ENDPOINTS = {"encrypt", "decrypt", "verify_hash"}

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE

_rate_buckets: dict[str, deque[float]] = defaultdict(deque)
_rate_lock = threading.Lock()


def _client_ip() -> str:
    # Respect forwarded IP when behind a reverse proxy.
    forwarded = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    return forwarded or request.remote_addr or "unknown"


def _rate_limit_exceeded(client_id: str) -> tuple[bool, int]:
    now = time.time()
    with _rate_lock:
        bucket = _rate_buckets[client_id]
        while bucket and (now - bucket[0]) > RATE_LIMIT_WINDOW_SEC:
            bucket.popleft()

        if len(bucket) >= RATE_LIMIT_MAX_REQUESTS:
            retry_after = max(1, int(RATE_LIMIT_WINDOW_SEC - (now - bucket[0])))
            return True, retry_after

        bucket.append(now)
        return False, 0


def _get_file_bytes(field_name: str = "file"):
    uploaded = request.files.get(field_name)
    if uploaded is None or uploaded.filename == "":
        return None, None, "Please upload a file."

    # Keep the original client filename (basename only) so decrypted downloads
    # preserve the expected extension/type more reliably.
    filename = Path(uploaded.filename).name.strip() or "file"
    data = uploaded.read()
    if not data:
        return None, None, "Uploaded file is empty."
    return filename, data, None


def _validate_encryption_password(password: str) -> str | None:
    if len(password) < 12:
        return "Password must be at least 12 characters long."
    if not re.search(r"[A-Z]", password):
        return "Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must include at least one lowercase letter."
    if not re.search(r"\d", password):
        return "Password must include at least one number."
    if not re.search(r"[^A-Za-z0-9]", password):
        return "Password must include at least one symbol."
    if len(password) > 256:
        return "Password is too long. Maximum length is 256 characters."
    return None


@app.before_request
def enforce_rate_limit():
    if request.endpoint not in RATE_LIMITED_ENDPOINTS:
        return None

    client_id = f"{_client_ip()}:{request.endpoint}"
    blocked, retry_after = _rate_limit_exceeded(client_id)
    if blocked:
        return (
            jsonify(
                {
                    "error": "Too many requests. Please wait and try again.",
                    "retryAfterSec": retry_after,
                }
            ),
            429,
        )
    return None


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; object-src 'none'; frame-ancestors 'none'; "
        "base-uri 'self'; form-action 'self'"
    )
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/health")
def api_health():
    return jsonify(
        {
            "status": "ok",
            "service": "CryptoSafe",
            "maxUploadBytes": MAX_FILE_SIZE,
            "cryptoFormat": {
                "default": MAGIC_V2.decode("ascii"),
                "legacySupported": [MAGIC_V1.decode("ascii")],
                "defaultKdf": DEFAULT_KDF_MODE,
            },
            "rateLimit": {
                "windowSec": RATE_LIMIT_WINDOW_SEC,
                "maxRequests": RATE_LIMIT_MAX_REQUESTS,
                "appliesTo": sorted(RATE_LIMITED_ENDPOINTS),
            },
        }
    )


@app.post("/api/encrypt")
def encrypt():
    password = (request.form.get("password") or "").strip()
    file_name, data, error = _get_file_bytes()
    if error:
        return jsonify({"error": error}), 400

    password_error = _validate_encryption_password(password)
    if password_error:
        return jsonify({"error": password_error}), 400

    try:
        encrypted_blob = encrypt_file_content(file_name, data, password)
    except ValueError:
        return jsonify({"error": "Encryption failed. Ensure the password and file name are valid."}), 400

    output_name = f"{file_name}.enc"
    return send_file(
        BytesIO(encrypted_blob),
        as_attachment=True,
        download_name=output_name,
        mimetype="application/octet-stream",
    )


@app.post("/api/decrypt")
def decrypt():
    password = (request.form.get("password") or "").strip()
    _, encrypted_blob, error = _get_file_bytes()
    if error:
        return jsonify({"error": error}), 400
    if not is_supported_encrypted_blob(encrypted_blob):
        return jsonify({"error": "Encrypted file is invalid or corrupted."}), 400

    try:
        original_name, original_data = decrypt_file_content(encrypted_blob, password)
    except ValueError:
        return jsonify({"error": "Decryption failed. Wrong password or corrupted file."}), 400

    return send_file(
        BytesIO(original_data),
        as_attachment=True,
        download_name=original_name,
        mimetype="application/octet-stream",
    )


@app.post("/api/hash")
def hash_file():
    file_name, data, error = _get_file_bytes()
    if error:
        return jsonify({"error": error}), 400

    return jsonify(
        {
            "fileName": file_name,
            "size": len(data),
            "sha256": sha256_hash(data),
        }
    )


@app.post("/api/verify-hash")
def verify_hash():
    file_name, data, error = _get_file_bytes()
    if error:
        return jsonify({"error": error}), 400

    expected = (request.form.get("expectedHash") or "").strip().lower()
    if not expected:
        return jsonify({"error": "Expected SHA-256 hash is required."}), 400
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        return jsonify({"error": "Expected hash must be a valid 64-character SHA-256 hex string."}), 400

    actual = sha256_hash(data)
    return jsonify(
        {
            "fileName": file_name,
            "size": len(data),
            "expected": expected,
            "actual": actual,
            "matches": actual == expected,
        }
    )


@app.errorhandler(413)
def file_too_large(_):
    return jsonify({"error": "File is too large. Maximum size is 25 MB."}), 413


@app.errorhandler(Exception)
def handle_unexpected_error(exc):
    # Preserve JSON shape for API clients while keeping full server-side logs.
    app.logger.exception("Unhandled server error", exc_info=exc)
    if request.path.startswith("/api/"):
        return jsonify({"error": "Internal server error."}), 500
    return "Internal server error.", 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
