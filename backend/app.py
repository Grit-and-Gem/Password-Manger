"""
Zero-Trust Password Manager - Backend API
==========================================
Zero-trust model: The server NEVER sees plaintext passwords or the encryption key.
All encryption/decryption happens client-side using AES-256-GCM via the Web Crypto API.

Auth flow:
  1. Client derives 512 bits from PBKDF2(masterPassword, salt, 600000 iterations).
  2. First 256 bits  -> AES-256-GCM encryption key  (stays in browser, never sent)
  3. Last  256 bits  -> auth key                     (sent here for login)
  4. Server stores   SHA-256(auth_key) as the verifier (never stores raw auth key)
"""

import hashlib
import hmac
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "..", "frontend")
DB_PATH    = os.path.join(BASE_DIR, "vault.db")

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")
CORS(app, supports_credentials=True)


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                username     TEXT    UNIQUE NOT NULL,
                salt         TEXT    NOT NULL,
                auth_verifier TEXT   NOT NULL,
                created_at   TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token      TEXT    PRIMARY KEY,
                user_id    INTEGER NOT NULL,
                expires_at TEXT    NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS vault_entries (
                id             TEXT    PRIMARY KEY,
                user_id        INTEGER NOT NULL,
                encrypted_data TEXT    NOT NULL,
                created_at     TEXT    NOT NULL,
                updated_at     TEXT    NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
        conn.commit()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def utc_future(hours: int = 8) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def get_session_user(token: str | None) -> int | None:
    """Return user_id for a valid, non-expired session token, else None."""
    if not token:
        return None
    with get_db() as conn:
        row = conn.execute(
            "SELECT user_id FROM sessions WHERE token = ? AND expires_at > ?",
            (token, utc_now()),
        ).fetchone()
    return row["user_id"] if row else None


def bearer_token(req) -> str:
    return req.headers.get("Authorization", "").removeprefix("Bearer ").strip()


# ---------------------------------------------------------------------------
# Static routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


# ---------------------------------------------------------------------------
# API: Registration
# ---------------------------------------------------------------------------
@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username      = data.get("username", "").strip().lower()
    salt          = data.get("salt", "")           # hex, client-generated
    auth_verifier = data.get("auth_verifier", "")  # hex, derived auth key

    # --- validation ---
    if not username or not salt or not auth_verifier:
        return jsonify({"error": "Missing required fields"}), 400
    if not (3 <= len(username) <= 50):
        return jsonify({"error": "Username must be 3–50 characters"}), 400
    if len(salt) != 64:         # 32 bytes = 64 hex chars
        return jsonify({"error": "Invalid salt"}), 400
    if len(auth_verifier) != 64:
        return jsonify({"error": "Invalid auth_verifier"}), 400

    # Double-hash for defence-in-depth: store SHA-256(auth_verifier)
    stored_verifier = hashlib.sha256(bytes.fromhex(auth_verifier)).hexdigest()

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, salt, auth_verifier, created_at) VALUES (?,?,?,?)",
                (username, salt, stored_verifier, utc_now()),
            )
            conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409

    return jsonify({"message": "Account created"}), 201


# ---------------------------------------------------------------------------
# API: Get salt (step 1 of login – needed before key derivation)
# ---------------------------------------------------------------------------
@app.route("/api/login/salt", methods=["POST"])
def login_salt():
    data     = request.get_json(silent=True) or {}
    username = data.get("username", "").strip().lower()

    with get_db() as conn:
        row = conn.execute(
            "SELECT salt FROM users WHERE username = ?", (username,)
        ).fetchone()

    if row:
        return jsonify({"salt": row["salt"]})

    # Return a deterministic dummy salt to prevent user-enumeration timing attacks.
    dummy = hashlib.sha256(f"dummy-salt-{username}".encode()).hexdigest()
    return jsonify({"salt": dummy})


# ---------------------------------------------------------------------------
# API: Login
# ---------------------------------------------------------------------------
@app.route("/api/login", methods=["POST"])
def login():
    data     = request.get_json(silent=True) or {}
    username = data.get("username", "").strip().lower()
    auth_key = data.get("auth_key", "")   # hex string from client

    with get_db() as conn:
        row = conn.execute(
            "SELECT id, auth_verifier FROM users WHERE username = ?", (username,)
        ).fetchone()

    # Compute hash even when user not found → constant-time response
    try:
        actual_hash = hashlib.sha256(bytes.fromhex(auth_key)).hexdigest()
    except (ValueError, Exception):
        actual_hash = ""

    if not row or not hmac.compare_digest(row["auth_verifier"], actual_hash):
        return jsonify({"error": "Invalid credentials"}), 401

    # Issue session token
    token   = secrets.token_hex(32)
    expires = utc_future(8)

    with get_db() as conn:
        # Prune stale sessions for this user
        conn.execute(
            "DELETE FROM sessions WHERE user_id = ? AND expires_at < ?",
            (row["id"], utc_now()),
        )
        conn.execute(
            "INSERT INTO sessions (token, user_id, expires_at) VALUES (?,?,?)",
            (token, row["id"], expires),
        )
        conn.commit()

    return jsonify({"token": token})


# ---------------------------------------------------------------------------
# API: Logout
# ---------------------------------------------------------------------------
@app.route("/api/logout", methods=["POST"])
def logout():
    token = bearer_token(request)
    if token:
        with get_db() as conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
    return jsonify({"message": "Logged out"})


# ---------------------------------------------------------------------------
# API: Vault – list all encrypted entries
# ---------------------------------------------------------------------------
@app.route("/api/vault", methods=["GET"])
def vault_list():
    user_id = get_session_user(bearer_token(request))
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    with get_db() as conn:
        rows = conn.execute(
            """SELECT id, encrypted_data, created_at, updated_at
               FROM vault_entries
               WHERE user_id = ?
               ORDER BY updated_at DESC""",
            (user_id,),
        ).fetchall()

    return jsonify({"entries": [dict(r) for r in rows]})


# ---------------------------------------------------------------------------
# API: Vault – add entry
# ---------------------------------------------------------------------------
@app.route("/api/vault", methods=["POST"])
def vault_add():
    user_id = get_session_user(bearer_token(request))
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    data           = request.get_json(silent=True) or {}
    encrypted_data = data.get("encrypted_data", "")
    if not encrypted_data:
        return jsonify({"error": "Missing encrypted_data"}), 400

    entry_id = secrets.token_hex(16)
    now      = utc_now()

    with get_db() as conn:
        conn.execute(
            "INSERT INTO vault_entries (id, user_id, encrypted_data, created_at, updated_at) VALUES (?,?,?,?,?)",
            (entry_id, user_id, encrypted_data, now, now),
        )
        conn.commit()

    return jsonify({"id": entry_id}), 201


# ---------------------------------------------------------------------------
# API: Vault – update entry
# ---------------------------------------------------------------------------
@app.route("/api/vault/<entry_id>", methods=["PUT"])
def vault_update(entry_id: str):
    user_id = get_session_user(bearer_token(request))
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    data           = request.get_json(silent=True) or {}
    encrypted_data = data.get("encrypted_data", "")
    if not encrypted_data:
        return jsonify({"error": "Missing encrypted_data"}), 400

    with get_db() as conn:
        cur = conn.execute(
            "UPDATE vault_entries SET encrypted_data = ?, updated_at = ? WHERE id = ? AND user_id = ?",
            (encrypted_data, utc_now(), entry_id, user_id),
        )
        conn.commit()

    if cur.rowcount == 0:
        return jsonify({"error": "Entry not found"}), 404

    return jsonify({"message": "Updated"})


# ---------------------------------------------------------------------------
# API: Vault – delete entry
# ---------------------------------------------------------------------------
@app.route("/api/vault/<entry_id>", methods=["DELETE"])
def vault_delete(entry_id: str):
    user_id = get_session_user(bearer_token(request))
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    with get_db() as conn:
        cur = conn.execute(
            "DELETE FROM vault_entries WHERE id = ? AND user_id = ?",
            (entry_id, user_id),
        )
        conn.commit()

    if cur.rowcount == 0:
        return jsonify({"error": "Entry not found"}), 404

    return jsonify({"message": "Deleted"})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    print("  Zero-Trust Vault API  →  http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
