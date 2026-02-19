from __future__ import annotations
import os
import struct
import hmac
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def load_ed25519_private(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_ed25519_public(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def save_ed25519_private(key, path: str):
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ))


def save_ed25519_public(key, path: str):
    with open(path, "wb") as f:
        f.write(key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))


def sign_ed25519(priv, msg: bytes) -> bytes:
    return priv.sign(msg)


def verify_ed25519(pub, msg: bytes, sig: bytes):
    pub.verify(sig, msg)


def x25519_keypair():
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    )
    return priv, pub


def x25519_shared(priv, peer_pub):
    peer = x25519.X25519PublicKey.from_public_bytes(peer_pub)
    return priv.exchange(peer)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, digestmod="sha256").digest()


@dataclass
class SessionKeys:
    key: bytes


def derive_session(shared_secret: bytes, client_rnd: bytes, server_rnd: bytes):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(client_rnd)
    digest.update(server_rnd)
    salt = digest.finalize()
    key = hkdf_sha256(shared_secret, salt, b"kscope-v1")
    return SessionKeys(key)


def frame_encrypt(keys: SessionKeys, plaintext: bytes) -> bytes:
    aead = ChaCha20Poly1305(keys.key)
    nonce = os.urandom(12)
    ct = aead.encrypt(nonce, plaintext, None)
    return struct.pack("!I", len(ct)) + nonce + ct


def frame_decrypt(keys: SessionKeys, frame: bytes) -> bytes:
    (length,) = struct.unpack("!I", frame[:4])
    nonce = frame[4:16]
    ct = frame[16:]
    aead = ChaCha20Poly1305(keys.key)
    return aead.decrypt(nonce, ct, None)


def recv_encrypted_frame(sock):
    header = sock.recv(4)
    if not header:
        raise ConnectionError("closed")
    (length,) = struct.unpack("!I", header)
    body = sock.recv(12 + length)
    return header + body
