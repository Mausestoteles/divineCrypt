#!/usr/bin/env python3
"""
Chimera-Sponge demo server (Divine Flare edition):
- Flask server with endpoints: /register, /login, /handshake/send, /handshake/poll,
  /message/send, /message/get
- Uses scrypt (high cost) + server pepper to store verifier
- Uses X25519 ephemeral DH + HKDF to produce symmetric keys for AEAD

Run: CHIMERA_PEPPER must be set in environment before starting.
"""
import os
import json
import sqlite3
import secrets
import time
import hashlib
from base64 import b64encode, b64decode
from typing import Optional
from flask import Flask, request, jsonify, g
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

# Configuration
DB_PATH = "users.db"
SESSION_TTL = 3600  # seconds
SERVER_PEPER_ENV = "CHIMERA_PEPPER"
DIVINE_FLARE = "🔥 Divine Flare engaged"

# Scrypt presets ordered from most to least demanding.
SCRYPT_PRESETS = [
    {'n': 2 ** 18, 'r': 8, 'p': 1, 'length': 64},
    {'n': 2 ** 17, 'r': 8, 'p': 1, 'length': 64},
    {'n': 2 ** 16, 'r': 8, 'p': 1, 'length': 64},
    {'n': 2 ** 15, 'r': 8, 'p': 1, 'length': 64},
    {'n': 2 ** 14, 'r': 8, 'p': 1, 'length': 64},
]

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

    # Detect previous schema (Argon2 based) and rebuild if necessary
    c.execute("PRAGMA table_info(users)")
    columns = [row[1] for row in c.fetchall()]
    if columns and 'scrypt_params' not in columns:
        c.execute('DROP TABLE IF EXISTS users')

    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            salt BLOB NOT NULL,
            verifier BLOB NOT NULL,
            scrypt_params TEXT NOT NULL
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            ciphertext BLOB NOT NULL,
            nonce BLOB NOT NULL,
            aad BLOB,
            ts INTEGER NOT NULL
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS handshakes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            payload BLOB NOT NULL,
            ts INTEGER NOT NULL
        )
    ''')

    c.execute('CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient, ts DESC)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_handshakes_recipient ON handshakes(recipient, ts DESC)')

    db.commit()
    db.close()

# --- Crypto helpers ---

def scrypt_derive(password: bytes, salt: bytes, n: int = 2 ** 18, r: int = 8, p: int = 1, length: int = 64) -> bytes:
    """Return raw bytes from scrypt with hardened parameters."""
    return hashlib.scrypt(password=password, salt=salt, n=n, r=r, p=p, dklen=length)


def scrypt_with_fallback(password: bytes, salt: bytes, preferred: Optional[dict] = None):
    """Try deriving with preferred params, falling back to lighter presets.

    Returns (derived_key, params_used, preset_index).
    """

    candidates = []
    if preferred:
        candidates.append(preferred)
    candidates.extend(p for p in SCRYPT_PRESETS if p not in candidates)

    last_error = None
    for idx, params in enumerate(candidates):
        try:
            return scrypt_derive(password, salt, **params), params, idx
        except (ValueError, MemoryError) as exc:
            last_error = exc
            continue

    raise ValueError('scrypt derivation failed for all parameter presets') from last_error


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
    salt_b64 = data.get('salt')
    if not username or not password:
        return jsonify({'error': 'username and password required', 'divine_flare': DIVINE_FLARE}), 400

    db = get_db()
    c = db.cursor()
    # check exists
    c.execute('SELECT username FROM users WHERE username=?', (username,))
    if c.fetchone():
        return jsonify({'error': 'user exists', 'divine_flare': DIVINE_FLARE}), 400

    if salt_b64:
        try:
            salt = b64decode(salt_b64)
        except Exception:
            return jsonify({'error': 'invalid salt encoding', 'divine_flare': DIVINE_FLARE}), 400
        if len(salt) < 16:
            return jsonify({'error': 'salt too short', 'divine_flare': DIVINE_FLARE}), 400
    else:
        salt = secrets.token_bytes(32)

    # scrypt params (server chooses hardened defaults)
    preferred_params = SCRYPT_PRESETS[0]
    try:
        k_client, scrypt_params, preset_index = scrypt_with_fallback(password.encode(), salt, preferred=preferred_params)
    except ValueError:
        return jsonify({'error': 'scrypt derivation failed — please retry later', 'divine_flare': DIVINE_FLARE}), 500

    if preset_index > 0:
        print(f"{DIVINE_FLARE} Scrypt fallback activated for {username}: using n={scrypt_params['n']}, r={scrypt_params['r']}, p={scrypt_params['p']}")

    # Store verifier = HMAC(pepper, k_client)
    verifier = hmac_sha256(PEPPER, k_client)

    c.execute('INSERT INTO users(username, salt, verifier, scrypt_params) VALUES (?, ?, ?, ?)',
              (username, salt, verifier, json.dumps(scrypt_params)))
    db.commit()

    return jsonify({'ok': True, 'salt': b64encode(salt).decode(), 'params': scrypt_params, 'divine_flare': DIVINE_FLARE})


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
        return jsonify({'error': 'username, password, client_epk required', 'divine_flare': DIVINE_FLARE}), 400

    db = get_db()
    c = db.cursor()
    c.execute('SELECT salt, verifier, scrypt_params FROM users WHERE username=?', (username,))
    row = c.fetchone()
    if not row:
        return jsonify({'error': 'invalid credentials', 'divine_flare': DIVINE_FLARE}), 403

    salt = row['salt']
    verifier = row['verifier']
    scrypt_params = json.loads(row['scrypt_params'])

    # derive k_client using same params
    k_client = scrypt_derive(password.encode(), salt, **scrypt_params)
    # compute verifier candidate
    verifier_candidate = hmac_sha256(PEPPER, k_client)
    # constant-time compare
    if not secrets.compare_digest(verifier_candidate, verifier):
        return jsonify({'error': 'invalid credentials', 'divine_flare': DIVINE_FLARE}), 403

    # parse client epk
    try:
        client_epk_bytes = b64decode(client_epk_b64)
        client_epk = X25519PublicKey.from_public_bytes(client_epk_bytes)
    except Exception:
        return jsonify({'error': 'invalid client_epk', 'divine_flare': DIVINE_FLARE}), 400

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

    return jsonify({'token': token,
                    'server_epk': b64encode(server_epk_bytes).decode(),
                    'expires_at': int(expires_at),
                    'params': scrypt_params,
                    'divine_flare': DIVINE_FLARE})


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
    """Send an encrypted message to a peer via the server relay.
    Requires Authorization: Bearer <token>
    JSON: {"recipient": str, "ciphertext": base64, "nonce": base64, "aad": base64?}
    Server stores ciphertext in persistent inbox for the recipient.
    """
    session = get_session_from_header()
    if not session:
        return jsonify({'error': 'unauthenticated', 'divine_flare': DIVINE_FLARE}), 403

    data = request.get_json(force=True)
    recipient = data.get('recipient')
    ciphertext_b64 = data.get('ciphertext')
    nonce_b64 = data.get('nonce')
    aad_b64 = data.get('aad')
    if not recipient or not ciphertext_b64 or not nonce_b64:
        return jsonify({'error': 'recipient, ciphertext and nonce required', 'divine_flare': DIVINE_FLARE}), 400

    db = get_db()
    c = db.cursor()
    c.execute('SELECT 1 FROM users WHERE username=?', (recipient,))
    if not c.fetchone():
        return jsonify({'error': 'recipient not found', 'divine_flare': DIVINE_FLARE}), 404

    ts = int(time.time())
    c.execute('INSERT INTO messages(sender, recipient, ciphertext, nonce, aad, ts) VALUES (?, ?, ?, ?, ?, ?)',
              (session['username'], recipient, ciphertext_b64, nonce_b64, aad_b64, ts))
    db.commit()

    return jsonify({'ok': True, 'ts': ts, 'divine_flare': DIVINE_FLARE})


@app.route('/message/get', methods=['GET'])
def message_get():
    session = get_session_from_header()
    if not session:
        return jsonify({'error': 'unauthenticated', 'divine_flare': DIVINE_FLARE}), 403

    after_id = request.args.get('after_id', type=int)
    limit = min(request.args.get('limit', 50, type=int), 200)

    db = get_db()
    c = db.cursor()
    if after_id:
        c.execute('SELECT id, sender, ciphertext, nonce, aad, ts FROM messages WHERE recipient=? AND id>? ORDER BY id ASC LIMIT ?',
                  (session['username'], after_id, limit))
    else:
        c.execute('SELECT id, sender, ciphertext, nonce, aad, ts FROM messages WHERE recipient=? ORDER BY id ASC LIMIT ?',
                  (session['username'], limit))
    rows = c.fetchall()
    messages = [
        {
            'id': row['id'],
            'sender': row['sender'],
            'ciphertext': row['ciphertext'],
            'nonce': row['nonce'],
            'aad': row['aad'],
            'ts': row['ts'],
        }
        for row in rows
    ]

    return jsonify({'messages': messages, 'divine_flare': DIVINE_FLARE})


@app.route('/handshake/send', methods=['POST'])
def handshake_send():
    """Store a handshake payload addressed to another user."""
    session = get_session_from_header()
    if not session:
        return jsonify({'error': 'unauthenticated', 'divine_flare': DIVINE_FLARE}), 403

    data = request.get_json(force=True)
    recipient = data.get('recipient')
    payload_b64 = data.get('payload')
    if not recipient or not payload_b64:
        return jsonify({'error': 'recipient and payload required', 'divine_flare': DIVINE_FLARE}), 400

    try:
        payload = b64decode(payload_b64)
    except Exception:
        return jsonify({'error': 'invalid payload encoding', 'divine_flare': DIVINE_FLARE}), 400

    db = get_db()
    c = db.cursor()
    c.execute('SELECT 1 FROM users WHERE username=?', (recipient,))
    if not c.fetchone():
        return jsonify({'error': 'recipient not found', 'divine_flare': DIVINE_FLARE}), 404

    ts = int(time.time())
    c.execute('INSERT INTO handshakes(sender, recipient, payload, ts) VALUES (?, ?, ?, ?)',
              (session['username'], recipient, payload, ts))
    handshake_id = c.lastrowid
    db.commit()

    return jsonify({'ok': True, 'handshake_id': handshake_id, 'ts': ts, 'divine_flare': DIVINE_FLARE})


@app.route('/handshake/poll', methods=['GET'])
def handshake_poll():
    session = get_session_from_header()
    if not session:
        return jsonify({'error': 'unauthenticated', 'divine_flare': DIVINE_FLARE}), 403

    after_id = request.args.get('after_id', type=int)
    consume = request.args.get('consume', '0') in {'1', 'true', 'True'}
    limit = min(request.args.get('limit', 50, type=int), 200)

    db = get_db()
    c = db.cursor()
    if after_id:
        c.execute('SELECT id, sender, payload, ts FROM handshakes WHERE recipient=? AND id>? ORDER BY id ASC LIMIT ?',
                  (session['username'], after_id, limit))
    else:
        c.execute('SELECT id, sender, payload, ts FROM handshakes WHERE recipient=? ORDER BY id ASC LIMIT ?',
                  (session['username'], limit))
    rows = c.fetchall()
    handshakes = [
        {
            'id': row['id'],
            'sender': row['sender'],
            'payload': b64encode(row['payload']).decode(),
            'ts': row['ts'],
        }
        for row in rows
    ]

    if consume and rows:
        ids = [row['id'] for row in rows]
        c.execute('DELETE FROM handshakes WHERE id IN ({})'.format(','.join('?' for _ in ids)), ids)
        db.commit()

    return jsonify({'handshakes': handshakes, 'divine_flare': DIVINE_FLARE})


if __name__ == '__main__':
    init_db()
    print('Starting Chimera-Sponge demo server on http://127.0.0.1:5000')
    print('Make sure to run behind TLS in production and set CHIMERA_PEPPER in env — Divine Flare active!')
    app.run(host='127.0.0.1', port=5000, debug=True)
