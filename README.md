# ZeroVault — Zero-Trust Password Manager

A client-server password manager built with **Python (Flask)** and **vanilla HTML/CSS/JavaScript**. The server is treated as an untrusted party — it never sees your passwords, your master password, or your encryption key.

---

## How It Works

```
Your Master Password
        │
        ▼
  PBKDF2 (600,000 iter, SHA-256)
        │
        ▼
   512 raw bits
   ┌────────────────────────────────────────────┐
   │ First 256 bits  │  Last 256 bits           │
   │  AES-256-GCM    │  Auth Key                │
   │  Encryption Key │  (sent to server)        │
   │  (stays in      │  Server stores only      │
   │   browser)      │  SHA-256(auth_key)       │
   └────────────────────────────────────────────┘
```

- All **encryption and decryption happen in your browser** using the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).
- The server stores only **opaque ciphertext** it cannot read.
- A complete server-side database breach exposes nothing useful.

---

## Security Design

| Property | Implementation |
|---|---|
| **Encryption** | AES-256-GCM (authenticated encryption with integrity protection) |
| **Key derivation** | PBKDF2 — 600,000 iterations, SHA-256, 256-bit random salt |
| **Per-entry IV** | Unique 96-bit random IV generated for every saved entry |
| **Auth split** | 512 derived bits split: enc key (browser-only) + auth key (server) |
| **Server storage** | Stores `SHA-256(auth_key)` only — never the master password or enc key |
| **Timing safety** | `hmac.compare_digest` for auth; deterministic dummy salt for unknown users |
| **Session tokens** | `secrets.token_hex(32)` — 64 hex chars, 8-hour expiry |
| **No CDNs** | Zero external requests — the entire frontend is three self-contained files |
| **Non-extractable key** | AES key imported with `extractable: false` — XSS cannot read key bytes |

---

## Features

- **Register / Login** with a master password (never transmitted)
- **Add passwords** — site, username, password, optional notes
- **List all passwords** in a clean card layout
- **Search** — instant client-side filtering (no server round-trip)
- **Reveal / Hide** individual passwords
- **Copy to clipboard** with one click
- **Edit** existing entries (re-encrypted with a fresh IV on save)
- **Delete** entries with confirmation
- **Password generator** — cryptographically random, 20-character default
- **Password strength meter** on registration

---

## Project Structure

```
Password-Manger/
├── backend/
│   ├── app.py            # Flask REST API + SQLite database
│   └── requirements.txt  # Python dependencies
└── frontend/
    ├── index.html        # Single-page app shell
    ├── style.css         # Dark theme UI
    └── app.js            # Crypto engine + API client + UI logic
```

---

## Getting Started

### Prerequisites

- Python 3.11+
- A modern browser (Chrome, Firefox, Safari, Edge)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/Grit-and-Gem/Password-Manger.git
cd Password-Manger

# 2. Install Python dependencies
cd backend
pip install -r requirements.txt

# 3. Start the server
python app.py
```

The server starts at `http://127.0.0.1:5000` and also serves the frontend.

Open `http://127.0.0.1:5000` in your browser.

> **Note:** The Web Crypto API requires a [secure context](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts) (HTTPS or `localhost`). Opening `index.html` directly via `file://` will not work.

---

## API Reference

All `/api/*` routes return JSON. Authenticated routes require an `Authorization: Bearer <token>` header.

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/register` | No | Create account (`username`, `salt`, `auth_verifier`) |
| `POST` | `/api/login/salt` | No | Fetch salt for key derivation (`username`) |
| `POST` | `/api/login` | No | Authenticate (`username`, `auth_key`) → `token` |
| `POST` | `/api/logout` | Yes | Invalidate session token |
| `GET` | `/api/vault` | Yes | List all encrypted entries |
| `POST` | `/api/vault` | Yes | Save a new encrypted entry |
| `PUT` | `/api/vault/<id>` | Yes | Update an encrypted entry |
| `DELETE` | `/api/vault/<id>` | Yes | Delete an entry |

---

## What the Server Never Sees

- Your **master password**
- Your **AES encryption key**
- The **plaintext** of any password, site name, username, or note
- The **raw auth key** (only its SHA-256 hash is stored)

Verify this yourself: inspect the Network tab in DevTools while adding a password. The request body will contain only a random-looking base64 ciphertext blob.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask, SQLite (`sqlite3` stdlib) |
| Frontend | HTML5, CSS3, Vanilla JavaScript (ES2022) |
| Crypto | Web Crypto API — `AES-GCM`, `PBKDF2`, `SHA-256` |
| Auth | HMAC-safe token sessions |
