from __future__ import annotations
import os
import struct

VERSION = 1
OBFS_NONE = 0

MSG_CLIENT_HELLO = 1
MSG_SERVER_HELLO = 2
MSG_DATA = 3

MAX_HANDSHAKE = 64 * 1024
MAX_FRAME = 4 * 1024 * 1024


def recv_exact(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed")
        buf.extend(chunk)
    return bytes(buf)


def send_msg(sock, mtype: int, payload: bytes) -> None:
    header = struct.pack("!BI", mtype, len(payload))
    sock.sendall(header + payload)


def recv_msg(sock) -> tuple[int, bytes]:
    header = recv_exact(sock, 5)
    mtype, length = struct.unpack("!BI", header)
    if length > MAX_HANDSHAKE:
        raise ValueError("handshake too large")
    payload = recv_exact(sock, length)
    return mtype, payload


def pack_hello(version: int, obfs_mode: int, epoch_window: int,
               rnd: bytes, token: bytes, eph_pub: bytes, signature: bytes) -> bytes:
    return (
        struct.pack("!BBI", version, obfs_mode, epoch_window) +
        struct.pack("!H", len(rnd)) + rnd +
        struct.pack("!H", len(token)) + token +
        eph_pub + signature
    )


def unpack_hello(data: bytes):
    version, obfs_mode, epoch_window = struct.unpack("!BBI", data[:6])
    off = 6

    (rnd_len,) = struct.unpack("!H", data[off:off+2])
    off += 2
    rnd = data[off:off+rnd_len]
    off += rnd_len

    (tok_len,) = struct.unpack("!H", data[off:off+2])
    off += 2
    token = data[off:off+tok_len]
    off += tok_len

    eph_pub = data[off:off+32]
    off += 32
    sig = data[off:off+64]

    return version, obfs_mode, epoch_window, rnd, token, eph_pub, sig


def hello_to_sign(version: int, obfs_mode: int, epoch_window: int,
                  rnd: bytes, token: bytes, eph_pub: bytes) -> bytes:
    return (
        struct.pack("!BBI", version, obfs_mode, epoch_window) +
        struct.pack("!H", len(rnd)) + rnd +
        struct.pack("!H", len(token)) + token +
        eph_pub
    )


def new_random(n: int = 32) -> bytes:
    return os.urandom(n)
