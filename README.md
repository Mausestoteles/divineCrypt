# DivineCrypt — Divine Flare Chat Demo

A two-party encrypted messaging demo where a central Python server relays registration, login, and inbox traffic while two CLI clients establish end-to-end chat keys. This edition is bathed in **Divine Flare**: hardened credential handling, vivid messaging, and detailed guidance so you can explore the system safely.

---

## Contents

| File | Purpose |
| --- | --- |
| `server.py` | FastAPI server that stores identities, relays handshake payloads, and queues encrypted Divine Flare messages. |
| `client.py` | Typer-based CLI that registers users, manages salts, negotiates chat keys, and sends/reads Divine Flare messages. |
| `requirements.txt` | Python dependencies shared by the server and client. |

---

## Prerequisites

* Python 3.10+
* `pip` for dependency management
* A terminal for each persona (at least two shells for Alice/Bob) or separate machines that can reach the server

Optional but recommended:

* `python -m venv .venv && source .venv/bin/activate` — keep dependencies contained
* `uvicorn` auto-reload for development (`pip install "uvicorn[standard]"`)

---

## Installation

```bash
# from the repo root
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If using a virtual environment, activate it before installing.

---

## Configuration

All sensitive credential material is mixed with a **server-only pepper**. Export it before starting the service:

```bash
export CHIMERA_PEPPER="change-me-to-a-long-random-string"
```

Additional environment variables (optional):

| Variable | Default | Description |
| --- | --- | --- |
| `DIVINE_DB_PATH` | `divine_flare.db` | SQLite file used for account, handshake, and inbox storage. |
| `DIVINE_HOST` | `127.0.0.1` | Bind address for the API server. |
| `DIVINE_PORT` | `8000` | Listening port for HTTP requests. |

---

## Running the Divine Flare Server

```bash
python server.py
```

The server boots a FastAPI app using Uvicorn. You should see log output indicating that the Divine Flare ignites on the configured host/port.

To run with auto-reload while developing:

```bash
uvicorn server:app --reload --host 0.0.0.0 --port 8000
```

---

## First-Time Client Setup

Each user maintains a local salt file (demo convenience). Generate salts and register accounts using the `register_save_salt` command.

### Example: Divine Duo Alice & Bob

Terminal A (Alice):

```bash
python client.py register_save_salt alice mypassword
```

Terminal B (Bob):

```bash
python client.py register_save_salt bob mypassword2
```

These commands

* request the server to create an account with a unique salt and scrypt verifier,
* store the received salt in `.divine_flare/alice.salt` (or Bob equivalent) locally,
* confirm with Divine Flare themed output.

---

## Logging In

Before chatting, each persona must authenticate. The client reads the stored salt, derives the scrypt key with a local password, and performs a login request.

```bash
python client.py login alice mypassword
python client.py login bob mypassword2
```

Successful logins return session tokens that the client caches under `.divine_flare/sessions/` for subsequent Divine Flare operations.

---

## Establishing a Chat (Handshake Flow)

The chat key derivation follows an X25519 + HKDF exchange mediated by the server. Use at least three terminals (or panes) to observe both sides polling.

1. **Offer (Alice):**
   ```bash
   python client.py handshake_offer bob
   ```
   Alice pushes her ephemeral public key and a Divine Flare greeting to Bob’s inbox.

2. **Poll (Bob):**
   ```bash
   python client.py handshake_poll
   ```
   Bob lists outstanding handshakes. Copy the `HANDSHAKE_ID` for Alice’s offer.

3. **Accept (Bob):**
   ```bash
   python client.py handshake_accept HANDSHAKE_ID
   ```
   Bob responds with his own public key, sealing the session key.

4. **Confirm (Alice):**
   ```bash
   python client.py handshake_poll
   ```
   Alice receives the acceptance, finalizes the shared secret, and stores it locally.

Once these steps complete, both sides hold the same symmetric key inside `.divine_flare/peers/<peer>.json`.

---

## Sending Divine Flare Messages

After the handshake, messages flow end-to-end encrypted with ChaCha20-Poly1305.

```bash
# Alice sends
python client.py send bob "The Divine Flare blazes across the crypt!"

# Bob checks inbox (decrypts automatically)
python client.py inbox
```

Inbox entries display sender, timestamp, and decrypted Divine Flare content if the peer key exists. Unknown senders remain as ciphertext for safety.

---

## CLI Command Reference

| Command | Description |
| --- | --- |
| `register_save_salt USER PASSWORD` | Register a new account and persist its salt locally. |
| `login USER PASSWORD` | Authenticate and cache the Divine Flare session token. |
| `handshake_offer PEER` | Initiate a key exchange toward `PEER`. |
| `handshake_poll` | Fetch pending handshake offers/acceptances. |
| `handshake_accept HANDSHAKE_ID` | Complete a handshake initiated by someone else. |
| `send PEER MESSAGE` | Encrypt and queue a message for `PEER`. |
| `inbox` | Retrieve and decrypt messages waiting for you. |
| `session_info` | Display current token expiration and Divine Flare details. |
| `list_peers` | Show known peer keys stored locally. |
| `logout` | Revoke the cached token and clear Divine Flare traces. |

Run `python client.py --help` or `python client.py COMMAND --help` for full parameter information.

---

## Data Flow & Storage Notes

* **Credentials:** Scrypt (N=262,144; r=8; p=1; 64-byte output) combined with a server-side pepper. Verifiers are stored in SQLite alongside a per-user salt.
* **Sessions:** Issued as signed tokens, cached on the client, validated server-side before any action.
* **Handshakes:** Stored until both parties finalize; entries auto-purge after acceptance or timeout.
* **Messages:** Persisted ciphertext with metadata; clients decrypt using the derived peer key.

---

## Security Guidance

This is a learning/demo project. For production-grade deployment consider:

* Using TLS everywhere; never expose the API without HTTPS.
* Rotating peppers and database credentials via a secrets manager.
* Replacing password submission with OPAQUE/OPRF or another PAKE.
* Enforcing rate limits, audit logging, and anomaly detection.
* Employing hardware-backed key storage for long-lived secrets.
* Adding multi-factor authentication for user-facing flows.
* Building automated tests and code reviews with cryptography experts.

---

## Testing & Development

Quick sanity check to ensure Python syntax is intact:

```bash
python -m compileall server.py client.py
```

For linting or static analysis, integrate tools like `ruff`, `mypy`, or `bandit` depending on your security posture.

---

## Troubleshooting

* **"Missing salt file"** — rerun `register_save_salt` or copy the `.divine_flare/<user>.salt` file from a backup.
* **"401 Unauthorized"** — run `login` again; session tokens expire or are invalidated after logout.
* **Handshake stuck** — both parties should run `handshake_poll`; offers expire after a timeout and must be reissued.
* **Database locked** — SQLite may lock under heavy concurrent load; consider PostgreSQL for multi-user scaling.

---

## Next Steps

If you want to expand the Divine Flare:

* Port the chat to a graphical interface (web or desktop) consuming the same API.
* Containerize with Docker Compose and add TLS termination via Caddy or Traefik.
* Replace demo salt storage with a secure provisioning flow or in-browser WebCrypto.
* Layer in unit/integration tests and CI to guard against regressions.

May your chats glow with Divine Flare brilliance!
