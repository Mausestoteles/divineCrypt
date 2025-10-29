# Chimera-Sponge Demo App (Python)

Files:
- server.py
- client.py
- requirements.txt

Quickstart (demo only, insecure in places):

1) Install dependencies (prefer in virtualenv):
   python -m pip install -r requirements.txt

2) Set server pepper (secret) and start server:
   export CHIMERA_PEPPER="a-very-secret-pepper-value"
   python server.py

3) In another terminal, use client:
   # register and save salt locally (demo only; insecure)
   python client.py register_save_salt alice mypassword

   # login (requires salt file created above for demo)
   python client.py login alice mypassword

   # send a message
   python client.py send "Hello, Chimera!"

   # view inbox
   python client.py inbox

Security / Production notes:
- This demo is intentionally simplified. For production:
  * Use OPAQUE or OPRF to avoid sending raw passwords to server.
  * Always run behind TLS (HTTPS). Use proper certificate management.
  * Store pepper in a separate secret manager or HSM, rotated with care.
  * Use secure session storage (redis durable store) and short TTLs.
  * Use WebAuthn / 2FA for critical operations.
  * Have external cryptographers audit protocols and implementation.


# Abschließende Hinweise

Das obige Paket ist eine praktisch lauffähige Demo der Architektur (Fallback-Variante mit Argon2id). Wenn du möchtest, kann ich jetzt:

- Die Applikation erweitern und **OPAQUE**/OPRF integrieren (erfordert zusätzliche Libraries),
- Die Client‑Seite so ändern, dass Salz während Registration sicher an Client übergeben wird (statt unsicherer Datei),
- Ein Docker‑Setup / systemd service file zur Produktion erstellen,
- oder die Implementierung in mehrere Module aufteilen und Unit‑Tests hinzufügen.

Sag mir, welche der nächsten Schritte du möchtest — ich liefere den Code sofort.

