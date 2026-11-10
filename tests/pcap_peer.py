"""Run 'server' and 'client SERVER_IP' on separate Ethernet peers in a test network."""
import argparse
import contextlib
import os
import socket
import subprocess
import threading

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("role", choices=("server", "client"))
parser.add_argument("binary")
parser.add_argument("server_ip")
parser.add_argument("--device")
args = parser.parse_args()
if "UDP2RAW_KEY" not in os.environ:
    parser.error("set UDP2RAW_KEY to the same test key on both peers")
remote = f"{args.server_ip}:34396"


def server():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as echo:
        echo.bind(("127.0.0.1", 0))
        def loop():
            while True:
                data, peer = echo.recvfrom(65535)
                echo.sendto(data, peer)
        threading.Thread(target=loop, daemon=True).start()
        subprocess.run([args.binary, "-s", "-l", remote, "-r",
                        f"127.0.0.1:{echo.getsockname()[1]}", "-a"], check=True)


def client():
    for mode, options in [
        ("udp", ["--pcap-send", "--no-pcap-mutex"]),
        ("icmp", ["--pcap-send"]),
        ("faketcp", ["--pcap-send", "--no-pcap-mutex"]),
        ("easy-faketcp", ["--pcap-send"]),
        ("udp", []),
    ]:
        if args.device:
            options.extend(["--dev", args.device])
        with contextlib.ExitStack() as stack:
            proc = subprocess.Popen([args.binary, "-c", "-l", "127.0.0.1:33339", "-r",
                                     remote, "--raw-mode", mode, *options])
            stack.callback(proc.wait, 5)
            stack.callback(proc.terminate)
            sock = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            sock.settimeout(.25)
            for _ in range(60):
                payload = os.urandom(601)
                sock.sendto(payload, ("127.0.0.1", 33339))
                try:
                    if sock.recv(2000) == payload:
                        break
                except socket.timeout:
                    if proc.poll() is not None:
                        raise RuntimeError("pcap client exited")
            else:
                raise AssertionError(f"no echo on {mode} {options}")
        print("PASS pcap over Ethernet", mode, options, flush=True)


if args.role == "server":
    server()
else:
    client()
