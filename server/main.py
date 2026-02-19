import socket
import threading
import argparse
import base64
import struct

from common.protocol import (
    VERSION,
    MSG_CLIENT_HELLO,
    MSG_SERVER_HELLO,
    send_msg,
    recv_msg,
    unpack_hello,
    pack_hello,
    hello_to_sign,
    new_random,
)

from common.crypto import (
    load_ed25519_private,
    load_ed25519_public,
    sign_ed25519,
    verify_ed25519,
    x25519_keypair,
    x25519_shared,
    derive_session,
    recv_encrypted_frame,
    frame_decrypt,
    frame_encrypt,
    hmac_sha256,
)

from common.policy import load_policy


def silent_fail(conn: socket.socket) -> None:
    try:
        conn.close()
    except Exception:
        pass


def handle_client(conn: socket.socket, addr, args) -> None:
    try:
        policy = load_policy(args.policy)
        psk = base64.b64decode(policy.psk_b64)

        # ---- receive client hello ----
        mtype, payload = recv_msg(conn)
        if mtype != MSG_CLIENT_HELLO:
            return silent_fail(conn)

        ver, obfs, epoch_window, c_rnd, token, c_eph_pub, c_sig = unpack_hello(payload)

        # ---- token verify with +/-1 window tolerance ----
        ok = False
        for w in (epoch_window - 1, epoch_window, epoch_window + 1):
            expected = hmac_sha256(psk, c_rnd + struct.pack("!I", w))[:16]
            if token == expected:
                ok = True
                epoch_window = w  # normalize to accepted window
                break

        if not ok:
            if args.debug:
                print(f"[server] token mismatch from {addr}")
            return silent_fail(conn)

        # ---- verify client signature ----
        client_pub = load_ed25519_public(args.client_pub)
        verify_ed25519(
            client_pub,
            hello_to_sign(ver, obfs, epoch_window, c_rnd, token, c_eph_pub),
            c_sig,
        )

        # ---- prepare server hello ----
        s_rnd = new_random(32)
        s_eph_priv, s_eph_pub = x25519_keypair()

        server_priv = load_ed25519_private(args.server_priv)
        s_sig = sign_ed25519(
            server_priv,
            hello_to_sign(VERSION, obfs, epoch_window, s_rnd, token, s_eph_pub),
        )

        send_msg(
            conn,
            MSG_SERVER_HELLO,
            pack_hello(VERSION, obfs, epoch_window, s_rnd, token, s_eph_pub, s_sig),
        )

        # ---- derive session keys ----
        shared = x25519_shared(s_eph_priv, c_eph_pub)
        keys = derive_session(shared, c_rnd, s_rnd)

        print(f"[server] session established {addr}")

        # ---- encrypted echo loop ----
        while True:
            try:
                frame = recv_encrypted_frame(conn)
            except ConnectionError:
                if args.debug:
                    print(f"[server] client {addr} disconnected")
                break

            pt = frame_decrypt(keys, frame)
            if args.debug:
                print("[server] got:", pt)

            conn.sendall(frame_encrypt(keys, b"echo: " + pt))

    except Exception as e:
        if args.debug:
            print(f"[server] error with {addr}: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--server-priv", default="keys/server_ed25519_priv.pem")
    parser.add_argument("--client-pub", default="keys/client_ed25519_pub.pem")
    parser.add_argument("--policy", default="policy.json")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((args.listen, args.port))
    s.listen(128)

    print("Server listening")

    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr, args), daemon=True).start()


if __name__ == "__main__":
    main()
