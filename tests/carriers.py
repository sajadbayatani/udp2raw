"""Exercise optional carriers with real sockets in an isolated Linux namespace.

Usage: python3 tests/carriers.py SERVER_BINARY
"""
import contextlib
import os
import socket
import subprocess
import sys
import threading
import time

from failover import blocked

SERVER = sys.argv[1]
KEY = os.urandom(32).hex()


def addr(ip, port):
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def proc(stack, exe, args):
    p = subprocess.Popen([exe, *args], env={**os.environ, "UDP2RAW_KEY": KEY})
    def stop():
        p.terminate()
        p.wait(timeout=5)
    stack.callback(stop)
    return p


def case(ip, mode, server_opts=(), client_opts=(), server_mode=None):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    server_ip = ip if family == socket.AF_INET6 else "127.0.0.2"
    with contextlib.ExitStack() as stack:
        backend = stack.enter_context(socket.socket(family, socket.SOCK_DGRAM))
        backend.bind((ip, 0))
        backend.settimeout(0.1)
        stop = threading.Event()
        def echo():
            while not stop.is_set():
                try:
                    data, peer = backend.recvfrom(65535)
                except socket.timeout:
                    continue
                backend.sendto(data, peer)
        worker = threading.Thread(target=echo, daemon=True)
        worker.start()
        stack.callback(worker.join, 1)
        stack.callback(stop.set)
        s = proc(stack, SERVER, ["-s", "-l", addr(server_ip, 34097), "-r",
                                 addr(ip, backend.getsockname()[1]), "--protocols",
                                 server_mode or mode, *server_opts])
        c = proc(stack, SERVER, ["-c", "-l", addr(ip, 33338), "-r",
                                        addr(server_ip, 34097), "--protocols", mode,
                                        "--heartbeat-ms", "150", "--timeout-ms", "1300", *client_opts])
        app = stack.enter_context(socket.socket(family, socket.SOCK_DGRAM))
        app.settimeout(0.2)
        # Vary data on each retry so a delayed packet cannot satisfy a later test case.
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            assert s.poll() is None and c.poll() is None, "tunnel exited"
            data = os.urandom(513)
            app.sendto(data, (ip, 33338))
            try:
                if app.recv(65535) == data:
                    print("PASS", ip, mode, server_opts, client_opts, flush=True)
                    return
            except socket.timeout:
                pass
        raise AssertionError((ip, mode, server_opts, client_opts))


def main():
    for ip in ["127.0.0.1", "::1"]:
        for mode in ["udp", "icmp", "faketcp", "easy-faketcp"]:
            case(ip, mode, client_opts=["--source-ip", ip, "--dev", "lo"])
    case("127.0.0.1", "easy-faketcp", server_mode="faketcp", server_opts=["-a"])
    case("127.0.0.1", "faketcp", server_mode="easy-faketcp", client_opts=["-a"])
    for link in ["auto", "lo#00:00:00:00:00:00"]:
        for mode in ["udp", "icmp", "faketcp"]:
            # Traffic sent through AF_PACKET can bypass OUTPUT filtering.
            with blocked("-d", "127.0.0.2", "-p", {"udp":"udp", "icmp":"icmp", "faketcp":"tcp"}[mode], chain="OUTPUT"):
                case("127.0.0.1", mode, ["--lower-level", link], ["--lower-level", link])


if __name__ == "__main__":
    main()
