import socket
import threading
import argparse
import os

from common.protocol import *
from common.crypto import *
from common.policy import load_policy
from common.tun import create_tun


def handle_client(conn, addr, args):
    policy = load_policy(args.policy)
    psk = base64.b64decode(policy.psk_b64)

    # === handshake ===
    mtype, payload = recv_msg(conn)
    ver, obfs, epoch_window, c_rnd, token, c_eph_pub, c_sig = unpack_hello(payload)

    client_pub = load_ed25519_public(args.client_pub)
    verify_ed25519(client_pub,
                   hello_to_sign(ver, obfs, epoch_window, c_rnd, token, c_eph_pub),
                   c_sig)

    s_rnd = new_random(32)
    s_eph_priv, s_eph_pub = x25519_keypair()
    server_priv = load_ed25519_private(args.server_priv)

    s_sig = sign_ed25519(server_priv,
                         hello_to_sign(VERSION, obfs, epoch_window,
                                       s_rnd, token, s_eph_pub))

    send_msg(conn, MSG_SERVER_HELLO,
             pack_hello(VERSION, obfs, epoch_window,
                        s_rnd, token, s_eph_pub, s_sig))

    shared = x25519_shared(s_eph_priv, c_eph_pub)
    keys = derive_session(shared, c_rnd, s_rnd)

    print("Tunnel established")

    tun = create_tun("ks0")

    os.system("ip addr add 10.10.0.1/24 dev ks0")
    os.system("ip link set ks0 up")

    def tun_to_sock():
        while True:
            packet = os.read(tun, 2000)
            conn.sendall(frame_encrypt(keys, packet))

    threading.Thread(target=tun_to_sock, daemon=True).start()

    while True:
        frame = recv_encrypted_frame(conn)
        packet = frame_decrypt(keys, frame)
        os.write(tun, packet)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--server-priv", default="keys/server_ed25519_priv.pem")
    parser.add_argument("--client-pub", default="keys/client_ed25519_pub.pem")
    parser.add_argument("--policy", default="policy.json")
    args = parser.parse_args()

    s = socket.socket()
    s.bind((args.listen, args.port))
    s.listen(1)

    print("TUN server listening")

    conn, addr = s.accept()
    handle_client(conn, addr, args)


if __name__ == "__main__":
    main()
