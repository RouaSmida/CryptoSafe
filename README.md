# CryptoSafe

CryptoSafe is a university-ready cybersecurity web application for:

- File encryption (AES-256, password-based, Argon2id by default)
- File decryption (with correct password)
- File hashing (SHA-256)

It is built with:

- **Backend:** Python + Flask
- **Frontend:** HTML, CSS, JavaScript
- **Crypto libraries:** `cryptography` + `argon2-cffi`

---

## Features

- Upload any file type (text, pdf, images, binaries)
- Encrypt files to `.enc` output with secure random salt/nonce
- Decrypt `.enc` files back to original content and filename
- Generate SHA-256 hash of uploaded files
- Verify file integrity by comparing SHA-256 with an expected hash
- Copy hash to clipboard
- Drag-and-drop upload support
- Password strength meter in UI
- Encryption password policy (12+ chars, upper/lower/number/symbol)
- API rate limiting on sensitive actions (encrypt/decrypt/verify)
- Security hardening headers on all responses
- Health endpoint for readiness checks
- Clear success/error messages
- No permanent file storage on the server

---

## Security Concepts Used

### 1) Symmetric Encryption (AES-256)
- Uses **AES-GCM** authenticated encryption from `cryptography`.
- Key is derived from user password using **Argon2id** in the current `CSF2` format.
- Decryption remains backward compatible with legacy `CSF1` payloads that used **PBKDF2-HMAC-SHA256**.
- Per-file random values include:
  - random 16-byte salt
   - random 12-byte nonce
  - 32-byte key (256-bit)

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
   On Windows PowerShell:
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```
   On Windows CMD:
   ```cmd
   .venv\Scripts\activate.bat
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

6. Run tests (recommended before release):
   ```bash
   pytest -q
   ```

---

## API Endpoints

- `GET /` → UI page
- `GET /api/health` → service health + limits
- `POST /api/encrypt` → returns encrypted file
- `POST /api/decrypt` → returns decrypted file
- `POST /api/hash` → returns SHA-256 JSON
- `POST /api/verify-hash` → verifies SHA-256 against expected hash

---

## Notes for University Submission

- Demonstrates practical cryptography usage (AES-256 + modern password KDF).
- Demonstrates hashing and integrity principles.
- Demonstrates secure file processing workflow in web apps.
- Code is modular (`crypto_utils.py`) and frontend/backend are separated.
