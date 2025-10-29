# Chimera-Sponge Demo App (Python)

Files:
- server.py
- client.py
- requirements.txt

Quickstart (demo only, still simplified):

1) Install dependencies (prefer in virtualenv):
   python -m pip install -r requirements.txt

2) Set server pepper (secret) and start server:
   export CHIMERA_PEPPER="a-very-secret-pepper-value"
   python server.py

3) In another terminal, use client:
   # register and save salt locally (demo only; insecure)
   python client.py register_save_salt alice mypassword
   python client.py register_save_salt bob mypassword2

   # login (requires salt file created above for demo)
   python client.py login alice mypassword
   python client.py login bob mypassword2

   # establish an end-to-end chat key between Alice (offer) and Bob (accept)
   # Terminal A (Alice):
   python client.py handshake_offer bob

   # Terminal B (Bob):
   python client.py handshake_poll
   python client.py handshake_accept HANDSHAKE_ID_FROM_POLL

   # Terminal A picks up the acceptance (delivered on next poll)
   python client.py handshake_poll

   # send a message from Alice to Bob using the derived chat key
   python client.py send bob "Hello from the Divine Flare!"

   # view inbox as Bob
   python client.py inbox

Security / Production notes:
- The "Divine Flare" edition now uses **scrypt** (N=2^18, r=8, p=1, 64-byte output) with a server-side pepper to protect verifier material.
- Messages and handshake payloads are relayed via the server but encrypted end-to-end with X25519-derived keys plus HKDF and ChaCha20-Poly1305.
- This demo is intentionally simplified. For production:
  * Use OPAQUE or an OPRF-based PAKE to avoid sending raw passwords to server endpoints.
  * Always run behind TLS (HTTPS). Use proper certificate management.
  * Store peppers in a separate secret manager or HSM, rotated with care.
  * Use durable session storage (redis or SQL) with revocation, plus short TTLs.
  * Add WebAuthn / 2FA for critical operations and audit logging.
  * Have external cryptographers review the design and implementation end to end.


# Abschließende Hinweise

Das obige Paket ist eine praktisch lauffähige Demo der Architektur (Divine Flare Variante mit scrypt-Härte). Wenn du möchtest, kann ich jetzt:

- Die Applikation erweitern und **OPAQUE**/OPRF integrieren (erfordert zusätzliche Libraries),
- Die Client‑Seite so ändern, dass Salz während Registration sicher an Client übergeben wird (statt unsicherer Datei),
- Ein Docker‑Setup / systemd service file zur Produktion erstellen,
- oder die Implementierung in mehrere Module aufteilen und Unit‑Tests hinzufügen.

Sag mir, welche der nächsten Schritte du möchtest — ich liefere den Code sofort.

