# aes-gcm-chat

A terminal-based encrypted chat application implementing AES-256-GCM authenticated encryption with SHA3-256 password verification. Built as a mandatory assignment for Applied Cryptography.

## How it works

The client generates a random 256-bit AES key and transmits it to the server over UDP. Both parties then verify they share the same pre-arranged password using SHA3-256 hashes before any messages are exchanged. All subsequent messages are encrypted with AES-256-GCM, using a fresh 96-bit random nonce per message — providing both confidentiality and integrity.

```
Client                              Server
  |                                   |
  |-- TCP connect ------------------>|
  |-- AES-256 key (UDP) ------------>|
  |-- b'\x01' + SHA3-256(password) ->|
  |                                   | (verify password hash)
  |<----------- encrypted chat ------>|
```

## Cryptographic primitives

- **AES-256-GCM** — authenticated encryption, 96-bit random nonce per message
- **SHA3-256** — pre-shared password verification
- Key transport over UDP (out-of-band relative to the TCP chat channel)

## Usage

Start the server:
```bash
python server.py
```

Connect with the client (defaults to localhost):
```bash
python client.py
# or specify a host:
python client.py 192.168.1.x
```

Both parties enter the same pre-arranged password. The session starts once the password hashes match.

## Requirements

```bash
pip install cryptography
```

## Notes

Key exchange is intentionally simple — the AES key is sent in plaintext over UDP as part of the assignment scope. A production implementation would use a proper key exchange protocol such as Diffie-Hellman or X25519.
