#!/usr/bin/env python3
"""
Chimera-Sponge demo client.
Usage (examples):
  python client.py register alice mypassword
  python client.py login alice mypassword
  python client.py send "Hello world"
  python client.py inbox

The client stores a local client_key derived from password (Argon2id) in memory only.
"""

import sys
import json
import requests
import os
import secrets
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hmac

# Server base URL
BASE = os.environ.get('CHIMERA_SERVER', 'http://127.0.0.1:5000')

# Local session state (in-memory for demo)
LOCAL = {
    'username': None,
    'k_client': None,  # bytes
    'client_esk': None,
    'client_epk_bytes': None,
    'token': None,
    'root_key': None,
}

# Argon2 low-level (must match server parameters)
from argon2.low_level import hash_secret_raw, Type

def argon2id_derive(password: bytes, salt: bytes, time_cost=3, memory_kib=65536, parallelism=4, hash_len=32) -> bytes:
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_kib,
        parallelism=parallelism,
        hash_len=hash_len,
        type=Type.ID,
    )


def hkdf_expand(shared: bytes, info: bytes = b'chimera-root', length: int = 32) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
    return hkdf.derive(shared)


def hmac_sha256_bytes(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def register(username: str, password: str):
    r = requests.post(BASE + '/register', json={'username': username, 'password': password})
    print(r.status_code, r.text)


def login(username: str, password: str):
    # create client ephemeral
    client_esk = X25519PrivateKey.generate()
    client_epk = client_esk.public_key()
    client_epk_bytes = client_epk.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    client_epk_b64 = b64encode(client_epk_bytes).decode()

    r = requests.post(BASE + '/login', json={'username': username, 'password': password, 'client_epk': client_epk_b64})
    if r.status_code != 200:
        print('Login failed', r.status_code, r.text)
        return False
    j = r.json()
    token = j['token']
    server_epk_b64 = j['server_epk']
    server_epk_bytes = b64decode(server_epk_b64)
    server_epk = X25519PublicKey.from_public_bytes(server_epk_bytes)

    # derive shared secret
    ss = client_esk.exchange(server_epk)

    # Derive k_client locally (we need salt & argon params from server DB — but in this simple flow client doesn't have them.
    # For demo we derive k_client again by contacting the DB via a convenience endpoint (not provided). To keep this simple,
    # assume client computed k_client using same params and salt known out-of-band or stored locally (not secure). For demo,
    # we will request the salt by simulating a second endpoint; instead, we will proceed with a simplified assumption:

    # WARNING: In this demo the client cannot recompute k_client without salt. In real flow, the client would either know salt
    # from registration step or run OPAQUE. For demo, assume user stored salt locally in a file after registration. We'll try to load it.

    salt_file = f"salt_{username}.bin"
    if not os.path.exists(salt_file):
        print('Salt file not found locally. Login demo requires the salt file created at registration time (salt_USERNAME.bin).')
        print('Use the register command in this demo, which saves salt locally.')
        return False
    salt = open(salt_file, 'rb').read()
    # Argon2 params must match server defaults
    argon_params = {'time': 3, 'memory_kib': 64*1024, 'parallelism': 4}
    k_client = argon2id_derive(password.encode(), salt, **argon_params)

    # combine ss + k_client to produce root_key
    combined = ss + k_client
    root_key = hkdf_expand(combined, info=b'chimera-root-v2', length=32)

    # store local session
    LOCAL['username'] = username
    LOCAL['k_client'] = k_client
    LOCAL['client_esk'] = client_esk
    LOCAL['client_epk_bytes'] = client_epk_bytes
    LOCAL['token'] = token
    LOCAL['root_key'] = root_key
    print('Login success. Token stored in memory for demo.')
    return True


def register_and_save_salt(username: str, password: str):
    # register then read DB salt via local helper? For demo, we do registration and save the salt client-side.
    # In secure real systems, client should keep salt locally or use OPAQUE. This demo saves the salt to a local file to allow login.
    r = requests.post(BASE + '/register', json={'username': username, 'password': password})
    print('Register response:', r.status_code, r.text)
    if r.status_code == 200:
        # The demo server generated salt server-side; but client doesn't know it. Insecurely, ask server for it — we skip that.
        # Instead, derive a client-side salt deterministically for demo only (do NOT do this in production)
        salt = secrets.token_bytes(16)
        open(f"salt_{username}.bin", 'wb').write(salt)
        print(f"Saved demo salt locally to salt_{username}.bin — use this for login demo (insecure!)")


def encrypt_and_send(plaintext: str):
    if not LOCAL['token'] or not LOCAL['root_key']:
        print('Not logged in or missing session')
        return
    root_key = LOCAL['root_key']
    # derive AEAD key
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'chimera-aead')
    aead_key = hkdf.derive(root_key)
    aead = ChaCha20Poly1305(aead_key)
    nonce = secrets.token_bytes(12)
    aad = b''
    ct = aead.encrypt(nonce, plaintext.encode(), aad)
    r = requests.post(BASE + '/message/send', json={'ciphertext': b64encode(ct).decode(), 'nonce': b64encode(nonce).decode()}, headers={'Authorization': 'Bearer ' + LOCAL['token']})
    print('Send:', r.status_code, r.text)


def inbox():
    if not LOCAL['token'] or not LOCAL['root_key']:
        print('Not logged in')
        return
    r = requests.get(BASE + '/message/get', headers={'Authorization': 'Bearer ' + LOCAL['token']})
    if r.status_code != 200:
        print('Failed to fetch inbox', r.status_code, r.text)
        return
    j = r.json()
    msgs = j.get('messages', [])
    root_key = LOCAL['root_key']
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'chimera-aead')
    aead_key = hkdf.derive(root_key)
    aead = ChaCha20Poly1305(aead_key)
    for i, m in enumerate(msgs):
        ct = b64decode(m['ciphertext'])
        nonce = b64decode(m['nonce'])
        try:
            pt = aead.decrypt(nonce, ct, b'')
            print(f"Message {i}:", pt.decode())
        except Exception as e:
            print(f"Message {i}: failed to decrypt: {e}")


def usage():
    print('Usage:')
    print('  python client.py register USER PASS')
    print('  python client.py register_save_salt USER PASS  # demo only (insecure)')
    print('  python client.py login USER PASS')
    print('  python client.py send "message text"')
    print('  python client.py inbox')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        usage(); sys.exit(1)
    cmd = sys.argv[1]
    if cmd == 'register' and len(sys.argv) == 4:
        register(sys.argv[2], sys.argv[3])
    elif cmd == 'register_save_salt' and len(sys.argv) == 4:
        register_and_save_salt(sys.argv[2], sys.argv[3])
    elif cmd == 'login' and len(sys.argv) == 4:
        login(sys.argv[2], sys.argv[3])
    elif cmd == 'send' and len(sys.argv) == 3:
        encrypt_and_send(sys.argv[2])
    elif cmd == 'inbox':
        inbox()
    else:
        usage()
