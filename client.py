#!/usr/bin/env python3
"""
Chimera-Sponge demo client.
Usage (examples):
  python client.py register alice mypassword
  python client.py register_save_salt alice mypassword
  python client.py login alice mypassword
  python client.py handshake_offer bob
  python client.py handshake_poll
  python client.py handshake_accept HANDSHAKE_ID
  python client.py send bob "Hello world"
  python client.py inbox

The client stores a local client_key derived from password (scrypt) in memory only.
"""

import sys
import os
import secrets
import hashlib
import json
from typing import Optional, Dict
import requests
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hmac

# Server base URL
BASE = os.environ.get('CHIMERA_SERVER', 'http://127.0.0.1:5000')

# Divine Flare banner
DIVINE_FLARE = "🔥 Divine Flare engaged"

# Local session state (in-memory for demo)
LOCAL = {
    'username': None,
    'k_client': None,  # bytes
    'client_esk': None,
    'client_epk_bytes': None,
    'token': None,
    'root_key': None,
    'handshake_offers': {},  # handshake_id -> private key
    'handshake_cache': {},   # handshake_id -> decoded payload
    'peer_chat_keys': {},    # peer username -> bytes
}

def scrypt_derive(password: bytes, salt: bytes, n: int = 2 ** 18, r: int = 8, p: int = 1, length: int = 64) -> bytes:
    return hashlib.scrypt(password=password, salt=salt, n=n, r=r, p=p, dklen=length)


def hkdf_expand(shared: bytes, info: bytes = b'chimera-root', length: int = 32) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
    return hkdf.derive(shared)


def hmac_sha256_bytes(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def ensure_logged_in() -> bool:
    if not LOCAL['token'] or not LOCAL['root_key']:
        print(f"{DIVINE_FLARE} Not logged in. Run the login command first.")
        return False
    return True


def auth_headers() -> Dict[str, str]:
    if not LOCAL['token']:
        raise RuntimeError('No session token available')
    return {'Authorization': 'Bearer ' + LOCAL['token']}


def register(username: str, password: str, salt: Optional[bytes] = None):
    payload = {'username': username, 'password': password}
    if salt is not None:
        payload['salt'] = b64encode(salt).decode()
    r = requests.post(BASE + '/register', json=payload)
    try:
        j = r.json()
    except ValueError:
        print(f"Register request failed {r.status_code}: {r.text}")
        return None

    if r.status_code != 200:
        print(f"{DIVINE_FLARE} Register failed {r.status_code}: {j}")
        return None

    print(f"{DIVINE_FLARE} Registered {username}. Server salt (base64): {j.get('salt')}")
    return j


def login(username: str, password: str):
    # create client ephemeral
    client_esk = X25519PrivateKey.generate()
    client_epk = client_esk.public_key()
    client_epk_bytes = client_epk.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    client_epk_b64 = b64encode(client_epk_bytes).decode()

    r = requests.post(BASE + '/login', json={'username': username, 'password': password, 'client_epk': client_epk_b64})
    if r.status_code != 200:
        print(f"{DIVINE_FLARE} Login failed {r.status_code}: {r.text}")
        return False
    j = r.json()
    token = j['token']
    server_epk_b64 = j['server_epk']
    server_epk_bytes = b64decode(server_epk_b64)
    server_epk = X25519PublicKey.from_public_bytes(server_epk_bytes)

    # derive shared secret
    ss = client_esk.exchange(server_epk)

    salt_file = f"salt_{username}.bin"
    if not os.path.exists(salt_file):
        print(f"{DIVINE_FLARE} Salt file {salt_file} not found. Run register_save_salt first to capture the server salt.")
        return False
    salt = open(salt_file, 'rb').read()

    params_path = f"scrypt_{username}.json"
    if os.path.exists(params_path):
        with open(params_path, 'r', encoding='utf-8') as fh:
            scrypt_params = json.load(fh)
    else:
        # fallback to server defaults
        scrypt_params = {'n': 2 ** 18, 'r': 8, 'p': 1, 'length': 64}

    k_client = scrypt_derive(password.encode(), salt, **scrypt_params)

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
    LOCAL['handshake_offers'].clear()
    LOCAL['handshake_cache'].clear()
    LOCAL['peer_chat_keys'].clear()
    print(f"{DIVINE_FLARE} Login success. Token stored in memory for demo.")
    return True


def register_and_save_salt(username: str, password: str):
    response = register(username, password)
    if not response:
        return
    salt_b64 = response.get('salt')
    params = response.get('params')
    if not salt_b64:
        print(f"{DIVINE_FLARE} Server did not return a salt payload.")
        return
    salt = b64decode(salt_b64)
    salt_path = f"salt_{username}.bin"
    with open(salt_path, 'wb') as fh:
        fh.write(salt)
    print(f"{DIVINE_FLARE} Saved salt to {salt_path}. Keep it secret!")
    if params:
        params_path = f"scrypt_{username}.json"
        with open(params_path, 'w', encoding='utf-8') as fh:
            json.dump(params, fh)
        print(f"{DIVINE_FLARE} Stored scrypt parameters to {params_path}.")


def encrypt_and_send(recipient: str, plaintext: str):
    if not ensure_logged_in():
        return
    chat_secret = LOCAL['peer_chat_keys'].get(recipient)
    if not chat_secret:
        print(f"{DIVINE_FLARE} No chat key for {recipient}. Run handshake_offer and have them accept.")
        return
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=b'chimera-aead-' + recipient.encode())
    aead_key = hkdf.derive(chat_secret)
    aead = ChaCha20Poly1305(aead_key)
    nonce = secrets.token_bytes(12)
    aad = DIVINE_FLARE.encode()
    ct = aead.encrypt(nonce, plaintext.encode(), aad)
    payload = {
        'recipient': recipient,
        'ciphertext': b64encode(ct).decode(),
        'nonce': b64encode(nonce).decode(),
        'aad': b64encode(aad).decode(),
    }
    r = requests.post(BASE + '/message/send', json=payload, headers=auth_headers())
    if r.status_code == 200:
        print(f"{DIVINE_FLARE} Sent message to {recipient}.")
    else:
        print(f"{DIVINE_FLARE} Send failed {r.status_code}: {r.text}")


def handshake_offer(recipient: str):
    if not ensure_logged_in():
        return
    offer_priv = X25519PrivateKey.generate()
    offer_pub = offer_priv.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                                     format=serialization.PublicFormat.Raw)
    payload = {
        'type': 'offer',
        'ephemeral_pub': b64encode(offer_pub).decode(),
        'divine_flare': DIVINE_FLARE,
    }
    payload_b64 = b64encode(json.dumps(payload).encode()).decode()
    r = requests.post(BASE + '/handshake/send', json={'recipient': recipient, 'payload': payload_b64},
                      headers=auth_headers())
    if r.status_code != 200:
        print(f"{DIVINE_FLARE} Handshake offer failed {r.status_code}: {r.text}")
        return
    try:
        response_json = r.json()
    except ValueError:
        print(f"{DIVINE_FLARE} Unexpected handshake response: {r.text}")
        return
    handshake_id = response_json.get('handshake_id')
    if handshake_id is None:
        print(f"{DIVINE_FLARE} Handshake offer response missing id: {response_json}")
        return
    LOCAL['handshake_offers'][handshake_id] = offer_priv
    LOCAL['handshake_cache'][handshake_id] = {
        'id': handshake_id,
        'recipient': recipient,
        'decoded': payload,
    }
    print(f"{DIVINE_FLARE} Sent handshake offer {handshake_id} to {recipient}.")


def handshake_poll(consume: bool = True):
    if not ensure_logged_in():
        return
    params = {'consume': '1' if consume else '0'}
    r = requests.get(BASE + '/handshake/poll', params=params, headers=auth_headers())
    if r.status_code != 200:
        print(f"{DIVINE_FLARE} Handshake poll failed {r.status_code}: {r.text}")
        return
    try:
        body = r.json()
    except ValueError:
        print(f"{DIVINE_FLARE} Invalid handshake poll response: {r.text}")
        return
    entries = body.get('handshakes', [])
    if not entries:
        print(f"{DIVINE_FLARE} No handshake messages waiting.")
        return
    for entry in entries:
        handshake_id = entry.get('id')
        if handshake_id is None:
            print(f"{DIVINE_FLARE} Encountered handshake entry without id: {entry}")
            continue
        payload_b64 = entry.get('payload')
        decoded_payload = None
        if payload_b64:
            try:
                payload_bytes = b64decode(payload_b64)
                decoded_payload = json.loads(payload_bytes.decode())
            except Exception:
                decoded_payload = {'raw': payload_b64}
        entry['decoded'] = decoded_payload
        LOCAL['handshake_cache'][handshake_id] = entry
        sender = entry.get('sender', '<unknown>')
        if not decoded_payload:
            print(f"{DIVINE_FLARE} Handshake {handshake_id} from {sender}: unable to parse payload.")
            continue
        payload_type = decoded_payload.get('type')
        if payload_type == 'offer':
            print(f"{DIVINE_FLARE} Handshake offer {handshake_id} from {sender}. Run handshake_accept {handshake_id} to respond.")
        elif payload_type == 'accept':
            offer_id = decoded_payload.get('offer_id')
            remote_epk_b64 = decoded_payload.get('ephemeral_pub')
            if offer_id in LOCAL['handshake_offers'] and remote_epk_b64:
                offer_priv = LOCAL['handshake_offers'].pop(offer_id)
                remote_pub = X25519PublicKey.from_public_bytes(b64decode(remote_epk_b64))
                shared = offer_priv.exchange(remote_pub)
                peer_key = hkdf_expand(shared, info=b'chimera-divine-chat', length=32)
                LOCAL['peer_chat_keys'][sender] = peer_key
                print(f"{DIVINE_FLARE} Handshake with {sender} completed. Chat key ready.")
            else:
                print(f"{DIVINE_FLARE} Received accept for unknown offer {offer_id} from {sender}.")
        else:
            print(f"{DIVINE_FLARE} Handshake {handshake_id} from {sender}: {decoded_payload}.")


def handshake_accept(handshake_id_raw: str):
    if not ensure_logged_in():
        return
    try:
        handshake_id = int(handshake_id_raw)
    except ValueError:
        print(f"{DIVINE_FLARE} Invalid handshake id {handshake_id_raw}.")
        return
    entry = LOCAL['handshake_cache'].get(handshake_id)
    if not entry:
        print(f"{DIVINE_FLARE} Handshake {handshake_id} not cached. Run handshake_poll first.")
        return
    payload = entry.get('decoded')
    if not payload or payload.get('type') != 'offer':
        print(f"{DIVINE_FLARE} Handshake {handshake_id} is not an offer.")
        return
    remote_epk_b64 = payload.get('ephemeral_pub')
    if not remote_epk_b64:
        print(f"{DIVINE_FLARE} Offer {handshake_id} missing ephemeral key.")
        return
    remote_pub = X25519PublicKey.from_public_bytes(b64decode(remote_epk_b64))
    priv = X25519PrivateKey.generate()
    shared = priv.exchange(remote_pub)
    peer_key = hkdf_expand(shared, info=b'chimera-divine-chat', length=32)
    sender = entry.get('sender', '<unknown>')
    if sender == '<unknown>':
        print(f"{DIVINE_FLARE} Cannot respond to handshake without sender metadata.")
        return
    LOCAL['peer_chat_keys'][sender] = peer_key
    response_payload = {
        'type': 'accept',
        'offer_id': handshake_id,
        'ephemeral_pub': b64encode(priv.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                                                 format=serialization.PublicFormat.Raw)).decode(),
        'divine_flare': DIVINE_FLARE,
    }
    response_b64 = b64encode(json.dumps(response_payload).encode()).decode()
    r = requests.post(BASE + '/handshake/send', json={'recipient': sender, 'payload': response_b64},
                      headers=auth_headers())
    if r.status_code == 200:
        print(f"{DIVINE_FLARE} Accepted handshake {handshake_id} from {sender}. Chat key established.")
    else:
        print(f"{DIVINE_FLARE} Failed to send handshake acceptance: {r.status_code} {r.text}")
def inbox():
    if not ensure_logged_in():
        return
    r = requests.get(BASE + '/message/get', headers=auth_headers())
    if r.status_code != 200:
        print(f"{DIVINE_FLARE} Failed to fetch inbox {r.status_code}: {r.text}")
        return
    j = r.json()
    msgs = j.get('messages', [])
    if not msgs:
        print(f"{DIVINE_FLARE} Inbox empty.")
        return
    for m in msgs:
        sender = m.get('sender', '<unknown>')
        message_id = m.get('id')
        chat_secret = LOCAL['peer_chat_keys'].get(sender)
        if not chat_secret:
            print(f"{DIVINE_FLARE} Missing chat key for {sender}. Unable to decrypt message {message_id}.")
            continue
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                   info=b'chimera-aead-' + sender.encode())
        aead_key = hkdf.derive(chat_secret)
        aead = ChaCha20Poly1305(aead_key)
        ct = b64decode(m['ciphertext'])
        nonce = b64decode(m['nonce'])
        aad_b64 = m.get('aad')
        aad = b64decode(aad_b64) if aad_b64 else b''
        try:
            plaintext = aead.decrypt(nonce, ct, aad)
            print(f"{DIVINE_FLARE} Message {message_id} from {sender}: {plaintext.decode(errors='replace')}")
        except Exception as exc:
            print(f"{DIVINE_FLARE} Failed to decrypt message {message_id} from {sender}: {exc}")


def usage():
    print('Usage:')
    print('  python client.py register USER PASS')
    print('  python client.py register_save_salt USER PASS  # stores salt locally (demo)')
    print('  python client.py login USER PASS')
    print('  python client.py handshake_offer RECIPIENT')
    print('  python client.py handshake_poll [keep]')
    print('  python client.py handshake_accept HANDSHAKE_ID')
    print('  python client.py send RECIPIENT "message text"')
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
    elif cmd == 'handshake_offer' and len(sys.argv) == 3:
        handshake_offer(sys.argv[2])
    elif cmd == 'handshake_poll':
        consume = True
        if len(sys.argv) == 3 and sys.argv[2].lower() == 'keep':
            consume = False
        handshake_poll(consume=consume)
    elif cmd == 'handshake_accept' and len(sys.argv) == 3:
        handshake_accept(sys.argv[2])
    elif cmd == 'send' and len(sys.argv) >= 4:
        recipient = sys.argv[2]
        message = ' '.join(sys.argv[3:])
        encrypt_and_send(recipient, message)
    elif cmd == 'inbox':
        inbox()
    else:
        usage()
