#!/usr/bin/env python3
"""
Chimera-Sponge demo server (fallback design):
- Flask server with endpoints: /register, /login, /handshake, /message/send, /message/get
- Uses Argon2id (raw) + server pepper to store verifier
- Uses X25519 ephemeral DH + HKDF to produce symmetric keys for AEAD

Run: CHIMERA_PEPPER must be set in environment before starting.
"""
import os
import json
import sqlite3
import secrets
import time
from base64 import b64encode, b64decode
from typing import Optional

from flask import Flask, request, jsonify, g
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

# Argon2 low-level
from argon2.low_level import hash_secret_raw, Type

# Configuration
DB_PATH = "users.db"
SESSION_TTL = 3600  # seconds
SERVER_PEPER_ENV = "CHIMERA_PEPPER"

app = Flask(__name__)

# In-memory sessions: token -> {username, root_key(bytes), expires_at, server_esk_bytes}
SESSIONS = {}

# Ensure pepper present
PEPPER = os.environ.get(SERVER_PEPER_ENV)
if not PEPPER:
    raise RuntimeError(f"Environment variable {SERVER_PEPER_ENV} must be set to a secret pepper")
PEPPER = PEPPER.encode()

# --- Database helpers ---

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    c = db.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            salt BLOB NOT NULL,
            verifier BLOB NOT NULL,
            argon_params TEXT NOT NULL
        )
    ''')
    db.commit()
    db.close()

# --- Crypto helpers ---

def argon2id_derive(password: bytes, salt: bytes, time_cost=3, memory_kib=65536, parallelism=4, hash_len=32) -> bytes:
    """Return raw bytes from Argon2id (low-level binding)."""
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_kib,
        parallelism=parallelism,
        hash_len=hash_len,
        type=Type.ID,
    )


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def hkdf_expand(shared: bytes, info: bytes = b'chimera-root', length: int = 32) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
    return hkdf.derive(shared)

# --- User operations ---

@app.route('/register', methods=['POST'])
def register():
    """Register a new user.
    JSON body: {"username": str, "password": str}
    Returns: success or error
    """
    data = request.get_json(force=True)
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400

    db = get_db()
    c = db.cursor()
    # check exists
    c.execute('SELECT username FROM users WHERE username=?', (username,))
    if c.fetchone():
        return jsonify({'error': 'user exists'}), 400

    salt = secrets.token_bytes(16)
    # Argon2 params (server chooses safe defaults)
    argon_params = {'time': 3, 'memory_kib': 64*1024, 'parallelism': 4}
    k_client = argon2id_derive(password.encode(), salt, **argon_params)
    # Store verifier = HMAC(pepper, k_client)
    verifier = hmac_sha256(PEPPER, k_client)

    c.execute('INSERT INTO users(username, salt, verifier, argon_params) VALUES (?, ?, ?, ?)',
              (username, salt, verifier, json.dumps(argon_params)))
    db.commit()

    return jsonify({'ok': True})


@app.route('/login', methods=['POST'])
def login():
    """Login with username & password. Returns a temporary token and server ephemeral public key to proceed handshake.
    JSON body: {"username": str, "password": str, "client_epk": base64}
    Steps:
      - verify password-derived key against verifier
      - create server ephemeral X25519 -> server_esk, server_epk
      - compute ss = X25519(server_esk, client_epk)
      - combine ss || k_client to create root_key
      - create session token and return {token, server_epk_b64}
    """
    data = request.get_json(force=True)
    username = data.get('username')
    password = data.get('password')
    client_epk_b64 = data.get('client_epk')
    if not username or not password or not client_epk_b64:
        return jsonify({'error': 'username, password, client_epk required'}), 400

    db = get_db()
    c = db.cursor()
    c.execute('SELECT salt, verifier, argon_params FROM users WHERE username=?', (username,))
    row = c.fetchone()
    if not row:
        return jsonify({'error': 'invalid credentials'}), 403

    salt = row['salt']
    verifier = row['verifier']
    argon_params = json.loads(row['argon_params'])

    # derive k_client using same params
    k_client = argon2id_derive(password.encode(), salt, **argon_params)
    # compute verifier candidate
    verifier_candidate = hmac_sha256(PEPPER, k_client)
    # constant-time compare
    if not secrets.compare_digest(verifier_candidate, verifier):
        return jsonify({'error': 'invalid credentials'}), 403

    # parse client epk
    try:
        client_epk_bytes = b64decode(client_epk_b64)
        client_epk = X25519PublicKey.from_public_bytes(client_epk_bytes)
    except Exception:
        return jsonify({'error': 'invalid client_epk'}), 400

    # server ephemeral
    server_esk = X25519PrivateKey.generate()
    server_epk = server_esk.public_key()
    server_epk_bytes = server_epk.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

    # compute shared secret
    ss = server_esk.exchange(client_epk)
    # combine with k_client
    combined = ss + k_client
    root_key = hkdf_expand(combined, info=b'chimera-root-v2', length=32)

    # create session token
    token = b64encode(secrets.token_bytes(24)).decode()
    expires_at = time.time() + SESSION_TTL
    SESSIONS[token] = {
        'username': username,
        'root_key': root_key,
        'expires_at': expires_at,
        # store server private key bytes so server can re-derive if needed per-session (demo only)
        'server_esk_bytes': server_esk.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
    }

    return jsonify({'token': token, 'server_epk': b64encode(server_epk_bytes).decode(), 'expires_at': int(expires_at)})


def get_session_from_header():
    auth = request.headers.get('Authorization')
    if not auth or not auth.lower().startswith('bearer '):
        return None
    token = auth.split(' ', 1)[1].strip()
    session = SESSIONS.get(token)
    if not session:
        return None
    if session['expires_at'] < time.time():
        del SESSIONS[token]
        return None
    return session


@app.route('/message/send', methods=['POST'])
def message_send():
    """Send an encrypted message to server-stored inbox (demo). Requires Authorization: Bearer <token>
    JSON: {"ciphertext": base64, "nonce": base64}
    Server will store ciphertext in memory per user (simple inbox).
    """
    session = get_session_from_header()
    if not session:
        return jsonify({'error': 'unauthenticated'}), 403

    data = request.get_json(force=True)
    ciphertext_b64 = data.get('ciphertext')
    nonce_b64 = data.get('nonce')
    if not ciphertext_b64 or not nonce_b64:
        return jsonify({'error': 'ciphertext and nonce required'}), 400

    # simple inbox storage in session
    inbox = session.setdefault('inbox', [])
    inbox.append({'ciphertext': ciphertext_b64, 'nonce': nonce_b64, 'ts': int(time.time())})
    return jsonify({'ok': True})


@app.route('/message/get', methods=['GET'])
def message_get():
    session = get_session_from_header()
    if not session:
        return jsonify({'error': 'unauthenticated'}), 403
    inbox = session.get('inbox', [])
    return jsonify({'messages': inbox})


if __name__ == '__main__':
    init_db()
    print('Starting Chimera-Sponge demo server on http://127.0.0.1:5000')
    print('Make sure to run behind TLS in production and set CHIMERA_PEPPER in env')
    app.run(host='127.0.0.1', port=5000, debug=True)
