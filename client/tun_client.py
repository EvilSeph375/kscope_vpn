import socket
import argparse
import os
import base64
import time
import struct
import threading
import subprocess
import json
import signal
from pathlib import Path

from common.protocol import *
from common.crypto import *
from common.policy import load_policy
from common.tun import create_tun

STATE_PATH = Path("/tmp/kscope_client_state.json")
RESOLV_PATH = Path("/etc/resolv.conf")
RESOLV_BAK = Path("/tmp/kscope_resolv.conf.bak")


def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def ip_route_show() -> str:
    return run(["ip", "route"]).stdout


def parse_default_route(route_text: str) -> dict:
    for line in route_text.splitlines():
        if line.startswith("default "):
            parts = line.split()
            out = {}
            if "via" in parts:
                out["via"] = parts[parts.index("via") + 1]
            if "dev" in parts:
                out["dev"] = parts[parts.index("dev") + 1]
            return out
    return {}


def save_state(state: dict) -> None:
    STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")


def load_state() -> dict | None:
    if not STATE_PATH.exists():
        return None
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return None


def set_dns_temporarily(dns_servers: list[str], enable: bool, debug: bool) -> None:
    if not enable:
        return

    try:
        if RESOLV_PATH.exists() and not RESOLV_BAK.exists():
            RESOLV_BAK.write_bytes(RESOLV_PATH.read_bytes())

        content = "\n".join([f"nameserver {ip}" for ip in dns_servers]) + "\n"
        run(["bash", "-lc", f"cat > {RESOLV_PATH} <<'EOF'\n{content}EOF"], check=True)
        if debug:
            print(f"[client] DNS set to {dns_servers}")
    except Exception as e:
        if debug:
            print(f"[client] DNS set failed: {e}")


def restore_dns(debug: bool) -> None:
    try:
        if RESOLV_BAK.exists():
            run(["bash", "-lc", f"cat {RESOLV_BAK} > {RESOLV_PATH}"], check=True)
            RESOLV_BAK.unlink(missing_ok=True)
            if debug:
                print("[client] DNS restored")
    except Exception as e:
        if debug:
            print(f"[client] DNS restore failed: {e}")


def add_bypass_routes(subnet: str, gw_ip: str, out_dev: str, src_ip: str | None, debug: bool) -> None:
    cmd = ["ip", "route", "replace", subnet, "dev", out_dev]
    if src_ip:
        cmd += ["src", src_ip]
    run(cmd, check=True)

    run(["ip", "route", "replace", gw_ip, "dev", out_dev], check=True)

    if debug:
        print(f"[client] bypass routes set: {subnet} via dev {out_dev} (src {src_ip}), gw {gw_ip} dev {out_dev}")


def set_default_via_vpn(vpn_gw: str, vpn_dev: str, debug: bool) -> None:
    run(["ip", "route", "replace", "default", "via", vpn_gw, "dev", vpn_dev], check=True)
    if debug:
        print(f"[client] default route -> {vpn_gw} dev {vpn_dev}")


def restore_default_route(original: dict, debug: bool) -> None:
    if not original:
        return

    if "via" in original and "dev" in original:
        run(["ip", "route", "replace", "default", "via", original["via"], "dev", original["dev"]], check=True)
        if debug:
            print(f"[client] default restored: via {original['via']} dev {original['dev']}")
    elif "dev" in original:
        run(["ip", "route", "replace", "default", "dev", original["dev"]], check=True)
        if debug:
            print(f"[client] default restored: dev {original['dev']}")


def cleanup_routes(state: dict, debug: bool) -> None:
    restore_default_route(state.get("default_route", {}), debug=debug)

    if debug:
        print("[client] routing cleanup done")

    try:
        STATE_PATH.unlink(missing_ok=True)
    except Exception:
        pass


def ask_server_host() -> str:
    while True:
        host = input("Введите IP сервера: ").strip()
        if host:
            return host
        print("IP сервера не может быть пустым.")


class StopFlag:
    stop = False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=None, help="IP сервера; если не указан, будет запрошен при запуске")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--client-priv", default="keys/client_ed25519_priv.pem")
    parser.add_argument("--server-pub", default="keys/server_ed25519_pub.pem")
    parser.add_argument("--policy", default="policy.json")

    parser.add_argument("--vpn-subnet", default="10.10.0.0/24")
    parser.add_argument("--vpn-client-ip", default="10.10.0.2/24")
    parser.add_argument("--vpn-server-ip", default="10.10.0.1")

    parser.add_argument("--set-default", action="store_true")
    parser.add_argument("--bypass-subnet", default="192.168.137.0/24")
    parser.add_argument("--bypass-gw", default="192.168.137.2")
    parser.add_argument("--bypass-dev", default="ens37")
    parser.add_argument("--bypass-src", default="192.168.137.130")
    parser.add_argument("--manage-dns", action="store_true")
    parser.add_argument("--dns", default="1.1.1.1,8.8.8.8")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--restore", action="store_true")

    args = parser.parse_args()

    if args.restore:
        st = load_state()
        if st:
            cleanup_routes(st, debug=args.debug)
            restore_dns(debug=args.debug)
            print("[client] restored and exit")
        else:
            print("[client] no saved state to restore")
        return

    if not args.host:
        args.host = ask_server_host()

    original_routes = ip_route_show()
    original_default = parse_default_route(original_routes)

    state = {
        "default_route": original_default,
        "dns_managed": bool(args.manage_dns),
    }
    save_state(state)

    stop_flag = StopFlag()

    def request_stop(signum=None, frame=None):
        stop_flag.stop = True

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    try:
        policy = load_policy(args.policy)
        psk = base64.b64decode(policy.psk_b64)

        sock = socket.socket()
        sock.connect((args.host, args.port))

        epoch_window = int(time.time()) // policy.epoch_seconds
        c_rnd = new_random(32)
        token = hmac_sha256(psk, c_rnd + struct.pack("!I", epoch_window))[:16]

        c_eph_priv, c_eph_pub = x25519_keypair()
        client_priv = load_ed25519_private(args.client_priv)

        c_sig = sign_ed25519(
            client_priv,
            hello_to_sign(VERSION, OBFS_NONE, epoch_window, c_rnd, token, c_eph_pub),
        )

        send_msg(
            sock,
            MSG_CLIENT_HELLO,
            pack_hello(VERSION, OBFS_NONE, epoch_window, c_rnd, token, c_eph_pub, c_sig),
        )

        mtype, payload = recv_msg(sock)
        if mtype != MSG_SERVER_HELLO:
            raise RuntimeError("expected server hello")

        ver, obfs, epoch_window, s_rnd, srv_token, s_eph_pub, s_sig = unpack_hello(payload)

        server_pub = load_ed25519_public(args.server_pub)
        verify_ed25519(
            server_pub,
            hello_to_sign(ver, obfs, epoch_window, s_rnd, srv_token, s_eph_pub),
            s_sig,
        )

        shared = x25519_shared(c_eph_priv, s_eph_pub)
        keys = derive_session(shared, c_rnd, s_rnd)

        tun = create_tun("ks0")
        run(["ip", "addr", "add", args.vpn_client_ip, "dev", "ks0"], check=False)
        run(["ip", "link", "set", "ks0", "up"], check=True)

        print("Tunnel established (ks0 up)")

        if args.set_default:
            bypass_src = args.bypass_src.strip() if args.bypass_src.strip() else None
            add_bypass_routes(args.bypass_subnet, args.bypass_gw, args.bypass_dev, bypass_src, debug=args.debug)

            if args.manage_dns:
                dns_servers = [x.strip() for x in args.dns.split(",") if x.strip()]
                set_dns_temporarily(dns_servers, enable=True, debug=args.debug)

            set_default_via_vpn(args.vpn_server_ip, "ks0", debug=args.debug)

        def tun_to_sock():
            while not stop_flag.stop:
                try:
                    pkt = os.read(tun, 2000)
                except Exception:
                    break
                try:
                    sock.sendall(frame_encrypt(keys, pkt))
                except Exception:
                    break

        t = threading.Thread(target=tun_to_sock, daemon=True)
        t.start()

        while not stop_flag.stop:
            try:
                frame = recv_encrypted_frame(sock)
            except Exception:
                break
            try:
                pkt = frame_decrypt(keys, frame)
                os.write(tun, pkt)
            except Exception:
                break

    finally:
        st = load_state() or state
        try:
            cleanup_routes(st, debug=args.debug)
        except Exception:
            pass
        try:
            restore_dns(debug=args.debug)
        except Exception:
            pass
        try:
            os.close(tun)  # type: ignore[name-defined]
        except Exception:
            pass
        try:
            sock.close()  # type: ignore[name-defined]
        except Exception:
            pass
        print("[client] stopped and restored routing")


if __name__ == "__main__":
    main()
