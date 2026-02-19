import socket
import argparse
import base64
import time
import struct

from common.protocol import *
from common.crypto import *
from common.policy import load_policy


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="192.168.38.127")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--client-priv", default="keys/client_ed25519_priv.pem")
    parser.add_argument("--server-pub", default="keys/server_ed25519_pub.pem")
    parser.add_argument("--policy", default="policy.json")
    args = parser.parse_args()

    policy = load_policy(args.policy)
    psk = base64.b64decode(policy.psk_b64)

    sock = socket.socket()
    sock.connect((args.host, args.port))

    epoch_window = int(time.time()) // policy.epoch_seconds

    c_rnd = new_random(32)
    token = hmac_sha256(psk, c_rnd + struct.pack("!I", epoch_window))[:16]

    c_eph_priv, c_eph_pub = x25519_keypair()
    client_priv = load_ed25519_private(args.client_priv)

    c_sig = sign_ed25519(client_priv,
                         hello_to_sign(VERSION, OBFS_NONE, epoch_window,
                                       c_rnd, token, c_eph_pub))

    send_msg(sock, MSG_CLIENT_HELLO,
             pack_hello(VERSION, OBFS_NONE, epoch_window,
                        c_rnd, token, c_eph_pub, c_sig))

    mtype, payload = recv_msg(sock)
    ver, obfs, epoch_window, s_rnd, token, s_eph_pub, s_sig = unpack_hello(payload)

    server_pub = load_ed25519_public(args.server_pub)
    verify_ed25519(server_pub,
                   hello_to_sign(ver, obfs, epoch_window, s_rnd, token, s_eph_pub),
                   s_sig)

    shared = x25519_shared(c_eph_priv, s_eph_pub)
    keys = derive_session(shared, c_rnd, s_rnd)

    print("Session established")

    sock.sendall(frame_encrypt(keys, b"ping"))
    frame = recv_encrypted_frame(sock)
    print(frame_decrypt(keys, frame))


if __name__ == "__main__":
    main()
