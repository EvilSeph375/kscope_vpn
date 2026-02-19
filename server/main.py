import socket
import threading
import argparse
import base64
import time
import struct

from common.protocol import *
from common.crypto import *
from common.policy import load_policy


def silent_fail(conn):
    try:
        conn.close()
    except:
        pass


def handle_client(conn, addr, args):
    try:
        policy = load_policy(args.policy)
        psk = base64.b64decode(policy.psk_b64)

        mtype, payload = recv_msg(conn)
        if mtype != MSG_CLIENT_HELLO:
            return silent_fail(conn)

        ver, obfs, epoch_window, c_rnd, token, c_eph_pub, c_sig = unpack_hello(payload)

        # token verify with time-drift tolerance (+/- 1 window)
ok = False
for w in (epoch_window - 1, epoch_window, epoch_window + 1):
    expected = hmac_sha256(psk, c_rnd + struct.pack("!I", w))[:16]
    if token == expected:
        ok = True
        epoch_window = w  # normalize to accepted window
        break

if not ok:
    # В проде — тихий дроп. Для отладки можно печатать причину:
    if getattr(args, "debug", False):
        print(f"[server] token mismatch from {addr}")
    return silent_fail(conn)


        client_pub = load_ed25519_public(args.client_pub)
        verify_ed25519(client_pub,
                       hello_to_sign(ver, obfs, epoch_window, c_rnd, token, c_eph_pub),
                       c_sig)

        s_rnd = new_random(32)
        s_eph_priv, s_eph_pub = x25519_keypair()

        server_priv = load_ed25519_private(args.server_priv)
        s_sig = sign_ed25519(server_priv,
                             hello_to_sign(VERSION, obfs, epoch_window, s_rnd, token, s_eph_pub))

        send_msg(conn, MSG_SERVER_HELLO,
                 pack_hello(VERSION, obfs, epoch_window, s_rnd, token, s_eph_pub, s_sig))

        shared = x25519_shared(s_eph_priv, c_eph_pub)
        keys = derive_session(shared, c_rnd, s_rnd)

        print(f"[server] session established {addr}")

        while True:
            frame = recv_encrypted_frame(conn)
            pt = frame_decrypt(keys, frame)
            print("[server] got:", pt)
            conn.sendall(frame_encrypt(keys, b"echo: " + pt))

    except Exception as e:
        print("error:", e)
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--server-priv", default="keys/server_ed25519_priv.pem")
    parser.add_argument("--client-pub", default="keys/client_ed25519_pub.pem")
    parser.add_argument("--policy", default="policy.json")
    parser.add_argument("--debug", action="store_true")
 
    args = parser.parse_args()

    s = socket.socket()
    s.bind((args.listen, args.port))
    s.listen(128)

    print("Server listening")

    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client,
                         args=(conn, addr, args),
                         daemon=True).start()


if __name__ == "__main__":
    main()
