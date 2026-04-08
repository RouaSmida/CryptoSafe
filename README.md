# CryptoSafe

CryptoSafe is a university-ready cybersecurity web application for:

- File encryption (AES-256, password-based)
- File decryption (with correct password)
- File hashing (SHA-256)

It is built with:

- **Backend:** Python + Flask
- **Frontend:** HTML, CSS, JavaScript
- **Crypto library:** `cryptography`

---

## Features

- Upload any file type (text, pdf, images, binaries)
- Encrypt files to `.enc` output with secure random salt/nonce
- Decrypt `.enc` files back to original content and filename
- Generate SHA-256 hash of uploaded files
- Copy hash to clipboard
- Drag-and-drop upload support
- Clear success/error messages
- No permanent file storage on the server

---

## Security Concepts Used

### 1) Symmetric Encryption (AES-256)
- Uses **AES-GCM** authenticated encryption from `cryptography`.
- Key is derived from user password using **PBKDF2-HMAC-SHA256** with:
  - random 16-byte salt
  - high iteration count
  - 32-byte key (256-bit)
- Each encryption uses a fresh random 12-byte nonce.

### 2) Hashing (SHA-256)
- Uses Python `hashlib.sha256` to generate a one-way digest.
- Useful for integrity checks and digital fingerprinting.

### 3) Secure File Handling
- Files are processed in-memory and returned immediately.
- No plaintext passwords/keys are stored.
- Input validation is applied for missing files/password and malformed encrypted data.

---

## Project Structure

```text
CryptoSafe/
├── app.py
├── crypto_utils.py
├── requirements.txt
├── templates/
│   └── index.html
└── static/
    ├── styles.css
    └── app.js
```

---

## How to Run

1. **Clone and enter project**
   ```bash
   git clone <your-repo-url>
   cd CryptoSafe
   ```

2. **Create virtual environment (recommended)**
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the app**
   ```bash
   python app.py
   ```

5. Open in browser:
   ```text
   http://127.0.0.1:5000
   ```

---

## API Endpoints

- `GET /` → UI page
- `POST /api/encrypt` → returns encrypted file
- `POST /api/decrypt` → returns decrypted file
- `POST /api/hash` → returns SHA-256 JSON

---

## Notes for University Submission

- Demonstrates practical cryptography usage (AES-256 + key derivation).
- Demonstrates hashing and integrity principles.
- Demonstrates secure file processing workflow in web apps.
- Code is modular (`crypto_utils.py`) and frontend/backend are separated.
