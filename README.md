# Kaleidoscope (KScope) MVP

Secure experimental VPN protocol with:
- Ed25519 identity auth
- X25519 key exchange (PFS)
- ChaCha20-Poly1305 encryption
- Token-based anti-probing gate
- JSON policy system
- Minimal control-plane bootstrap API

## Install
pip install cryptography

## Generate keys
python3 -m tools.gen_keys

## Generate PSK
python3 -m tools.gen_psk

Insert output into policy.json

## Run server
python3 -m server.main --policy policy.json

## Run client
python3 -m client.main --policy policy.json
