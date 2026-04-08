"""
app.py - Flask backend for CryptoSafe.

Endpoints:
    POST /api/encrypt  - Encrypt an uploaded file
    POST /api/decrypt  - Decrypt an uploaded .enc file
    POST /api/hash     - SHA-256 hash an uploaded file
    GET  /             - Serve the frontend
"""

import os

from flask import Flask, jsonify, render_template, request, send_file
from flask_cors import CORS
from io import BytesIO
from werkzeug.utils import secure_filename

from crypto import decrypt_data, encrypt_data, hash_data

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB upload limit

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "..", "frontend"),
    static_folder=os.path.join(os.path.dirname(__file__), "..", "frontend"),
    static_url_path="",
)
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE

CORS(app)  # allow cross-origin requests during local development


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _get_file_and_password():
    """
    Extract the uploaded file and password from the current request.

    Returns:
        (file_bytes, filename, password) tuple.

    Raises:
        ValueError: If required fields are missing or the file is empty.
    """
    if "file" not in request.files:
        raise ValueError("No file provided.")

    uploaded = request.files["file"]
    if not uploaded.filename:
        raise ValueError("No file selected.")

    password = (request.form.get("password") or "").strip()
    if not password:
        raise ValueError("Password is required.")

    file_bytes = uploaded.read()
    if len(file_bytes) == 0:
        raise ValueError("Uploaded file is empty.")

    return file_bytes, secure_filename(uploaded.filename), password


def _get_file():
    """
    Extract the uploaded file from the current request (no password needed).

    Returns:
        (file_bytes, filename) tuple.

    Raises:
        ValueError: If no file is provided or it is empty.
    """
    if "file" not in request.files:
        raise ValueError("No file provided.")

    uploaded = request.files["file"]
    if not uploaded.filename:
        raise ValueError("No file selected.")

    file_bytes = uploaded.read()
    if len(file_bytes) == 0:
        raise ValueError("Uploaded file is empty.")

    return file_bytes, secure_filename(uploaded.filename)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Serve the single-page frontend application."""
    return render_template("index.html")


@app.route("/api/encrypt", methods=["POST"])
def encrypt_endpoint():
    """
    Encrypt an uploaded file with AES-256-GCM.

    Form fields:
        file     - The file to encrypt (multipart/form-data)
        password - Encryption password

    Returns:
        The encrypted file as an attachment (<original_name>.enc).
    """
    try:
        file_bytes, filename, password = _get_file_and_password()
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    try:
        encrypted = encrypt_data(file_bytes, password)
    except Exception:  # pragma: no cover
        return jsonify({"error": "Encryption failed due to an internal error."}), 500

    return send_file(
        BytesIO(encrypted),
        as_attachment=True,
        download_name=f"{filename}.enc",
        mimetype="application/octet-stream",
    )


@app.route("/api/decrypt", methods=["POST"])
def decrypt_endpoint():
    """
    Decrypt a previously encrypted CryptoSafe file.

    Form fields:
        file     - The .enc file to decrypt (multipart/form-data)
        password - Decryption password (must match encryption password)

    Returns:
        The decrypted file as an attachment (original filename with .enc removed).
    """
    try:
        file_bytes, filename, password = _get_file_and_password()
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    try:
        decrypted = decrypt_data(file_bytes, password)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:  # pragma: no cover
        return jsonify({"error": "Decryption failed due to an internal error."}), 500

    # Strip the .enc extension from the download name when present
    download_name = filename[:-4] if filename.lower().endswith(".enc") else filename

    return send_file(
        BytesIO(decrypted),
        as_attachment=True,
        download_name=download_name,
        mimetype="application/octet-stream",
    )


@app.route("/api/hash", methods=["POST"])
def hash_endpoint():
    """
    Compute the SHA-256 hash of an uploaded file.

    Form fields:
        file - The file to hash (multipart/form-data)

    Returns:
        JSON  { "filename": str, "size": int, "sha256": str }
    """
    try:
        file_bytes, filename = _get_file()
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    digest = hash_data(file_bytes)
    return jsonify({
        "filename": filename,
        "size": len(file_bytes),
        "sha256": digest,
    })


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(413)
def too_large(_e):
    """Handle files that exceed the 50 MB limit."""
    return jsonify({"error": "File too large. Maximum allowed size is 50 MB."}), 413


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Debug mode is disabled for production; enable only for local development.
    app.run(host="0.0.0.0", port=5000, debug=False)
