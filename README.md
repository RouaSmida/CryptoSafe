# CryptoSafe

A cybersecurity web application for **file encryption, decryption, and hashing**,
built as a university project.

---

## Table of Contents

1. [Features](#features)
2. [Tech Stack](#tech-stack)
3. [Project Structure](#project-structure)
4. [How to Run](#how-to-run)
5. [Security Explanation](#security-explanation)
6. [API Reference](#api-reference)

---

## Features

| Feature | Details |
|---|---|
| **File Encryption** | AES-256-GCM authenticated encryption with PBKDF2-HMAC-SHA256 key derivation |
| **File Decryption** | Restores the original file; rejects wrong passwords and corrupt data |
| **SHA-256 Hashing** | Generates a 64-character hex digest; click to copy |
| **Drag & Drop Upload** | Supports any file type up to 50 MB |
| **Password Strength Meter** | Real-time visual indicator |
| **Dark / Light Mode** | Preference persisted in `localStorage` |
| **Progress Indicator** | Animated bar during server processing |
| **No Persistent Storage** | Files are processed in-memory and never written to disk |

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | HTML5, CSS3 (custom properties), Vanilla JavaScript (ES2020) |
| **Backend** | Python 3.11+, [Flask](https://flask.palletsprojects.com/) |
| **Encryption** | [`cryptography`](https://cryptography.io/) – AES-256-GCM |
| **Key Derivation** | PBKDF2-HMAC-SHA256 (200 000 iterations, 128-bit salt) |
| **Hashing** | Python `hashlib` – SHA-256 |
| **Tests** | `pytest` |

---

## Project Structure

```
CryptoSafe/
├── backend/
│   ├── app.py          # Flask application & REST endpoints
│   ├── crypto.py       # AES-256-GCM encrypt/decrypt & SHA-256 hash
│   ├── test_crypto.py  # Unit tests for cryptographic functions
│   └── test_app.py     # Integration tests for API endpoints
├── frontend/
│   ├── index.html      # Single-page application
│   ├── css/
│   │   └── style.css   # Responsive, dark/light-mode styles
│   └── js/
│       └── app.js      # Frontend logic (tabs, drag-drop, API calls)
├── requirements.txt    # Python dependencies
└── README.md
```

---

## How to Run

### Prerequisites

- Python 3.11 or later
- `pip`

### 1 – Install dependencies

```bash
pip install -r requirements.txt
```

### 2 – Start the server

```bash
cd backend
python app.py
```

The application will be available at **http://localhost:5000**.

### 3 – Run the tests

```bash
cd backend
pytest -v
```

---

## Security Explanation

### AES-256-GCM (Symmetric Encryption)

**AES (Advanced Encryption Standard)** is the gold-standard symmetric cipher
endorsed by NIST. This project uses:

| Parameter | Value | Reason |
|---|---|---|
| Key size | 256 bits | Maximum AES key length, resistant to brute-force |
| Mode | GCM (Galois/Counter Mode) | Provides *authenticated* encryption: tampering is detected |
| Nonce | 96 bits (random) | NIST-recommended size for GCM; never reused |

If the wrong password or a corrupted file is supplied, the GCM authentication
tag check fails immediately and a `ValueError` is raised — **no partial
plaintext is ever returned**.

### Key Derivation – PBKDF2-HMAC-SHA256

User passwords are transformed into cryptographic keys using
**PBKDF2 (Password-Based Key Derivation Function 2)**:

- A fresh **128-bit random salt** is generated for every encryption.
  This means two encryptions of the same file with the same password produce
  **completely different ciphertexts** (preventing rainbow-table attacks).
- **200 000 iterations** of HMAC-SHA256 make brute-force guessing expensive.
- The derived key is **never stored**; it is computed on-the-fly during
  decryption.

### SHA-256 Hashing

**SHA-256** is a one-way cryptographic hash function from the SHA-2 family.
A 256-bit (64 hex character) digest uniquely identifies file contents —
even a 1-bit change in the file produces a completely different hash.
Use cases: integrity verification, detecting tampering, checksums.

### Additional Security Measures

- Files are processed entirely **in memory** (via `BytesIO`) and are **never
  written to disk**.
- Uploaded file names are sanitised with `werkzeug.utils.secure_filename`.
- Upload size is capped at **50 MB** to prevent denial-of-service attacks.
- Passwords are sent via `multipart/form-data` (HTTPS in production) and are
  **never logged or persisted**.

---

## API Reference

All endpoints accept `multipart/form-data` POST requests.

### `POST /api/encrypt`

| Field | Type | Description |
|---|---|---|
| `file` | File | Any file (max 50 MB) |
| `password` | string | Encryption password |

**Response:** `application/octet-stream` – encrypted file (`<name>.enc`)

---

### `POST /api/decrypt`

| Field | Type | Description |
|---|---|---|
| `file` | File | A `.enc` file produced by CryptoSafe |
| `password` | string | The original encryption password |

**Response:** `application/octet-stream` – restored original file

---

### `POST /api/hash`

| Field | Type | Description |
|---|---|---|
| `file` | File | Any file (max 50 MB) |

**Response (JSON):**
```json
{
  "filename": "document.pdf",
  "size": 204800,
  "sha256": "a3f5...b7c9"
}
```
