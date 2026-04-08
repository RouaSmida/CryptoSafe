from io import BytesIO
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file
from werkzeug.utils import secure_filename

from crypto_utils import decrypt_file_content, encrypt_file_content, sha256_hash


BASE_DIR = Path(__file__).resolve().parent
MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE


def _get_file_bytes(field_name: str = "file"):
    uploaded = request.files.get(field_name)
    if uploaded is None or uploaded.filename == "":
        return None, None, "Please upload a file."

    filename = secure_filename(uploaded.filename) or "file"
    data = uploaded.read()
    if not data:
        return None, None, "Uploaded file is empty."
    return filename, data, None


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/encrypt")
def encrypt():
    password = (request.form.get("password") or "").strip()
    file_name, data, error = _get_file_bytes()
    if error:
        return jsonify({"error": error}), 400

    try:
        encrypted_blob = encrypt_file_content(file_name, data, password)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

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

    try:
        original_name, original_data = decrypt_file_content(encrypted_blob, password)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

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


@app.errorhandler(413)
def file_too_large(_):
    return jsonify({"error": "File is too large. Maximum size is 25 MB."}), 413


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
