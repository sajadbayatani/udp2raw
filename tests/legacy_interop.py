"""Compare release endpoints with an independently built C++ udp2raw on Linux.

Run in an isolated network namespace with CAP_NET_RAW, CAP_NET_ADMIN and iptables.
Arguments are the Rust binary and original C++ binary, followed by optional --full.
"""
import argparse
import contextlib
import itertools
import os
import socket
import subprocess
import tempfile
import threading

CIPHERS = ("aes128cbc", "aes128cfb", "aes128cfb_0", "xor", "none")
AUTH = ("md5", "hmac_sha1", "crc32", "simple", "none")


def launch(stack, binary, args):
    log = stack.enter_context(tempfile.TemporaryFile(mode="w+b"))
    proc = subprocess.Popen([binary, *args], stdout=log, stderr=log)
    def stop():
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
    stack.callback(stop)
    return proc, log


def check(rust, cpp, cipher, auth, rust_server, mode="udp", gro=False, v6=False):
    key = os.urandom(16).hex()
    host = "::1" if v6 else "127.0.0.2"
    # C++ easy-faketcp does not reuse listeners in TIME_WAIT. Let the kernel
    # choose an available port afresh for each pair and direction.
    with socket.socket(socket.AF_INET6 if v6 else socket.AF_INET,
                       socket.SOCK_STREAM if "tcp" in mode else socket.SOCK_DGRAM) as probe:
        probe.bind((host, 0))
        port = probe.getsockname()[1]
    tunnel = f"[{host}]:{port}" if v6 else f"{host}:{port}"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        app_port = probe.getsockname()[1]
    source = "::1" if v6 else "127.0.0.1"
    with contextlib.ExitStack() as stack:
        echo = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        echo.bind(("127.0.0.1", 0))
        echo.settimeout(.2)
        closing = threading.Event()
        def service():
            while not closing.is_set():
                try:
                    data, addr = echo.recvfrom(65535)
                    echo.sendto(data, addr)
                except socket.timeout:
                    continue
        thread = threading.Thread(target=service)
        thread.start()
        stack.callback(thread.join, 1)
        stack.callback(closing.set)
        common = ["-k", key, "--raw-mode", mode, "--cipher-mode", cipher, "--auth-mode", auth]
        if gro:
            common.append("--fix-gro")
        hs = ["-s", "-l", tunnel, "-r", f"127.0.0.1:{echo.getsockname()[1]}"]
        hc = ["-c", "-l", f"127.0.0.1:{app_port}", "-r", tunnel,
              "--source-ip", source]
        programs = [launch(stack, rust if rust_server else cpp, [*hs, *common]),
                    launch(stack, cpp if rust_server else rust, [*hc, *common])]
        app = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        app.settimeout(.15)
        def exchange(payload, attempts):
            for _ in range(attempts):
                if any(p.poll() is not None for p, _ in programs):
                    break
                app.sendto(payload, ("127.0.0.1", app_port))
                try:
                    if app.recv(65535)==payload:
                        return
                except socket.timeout:
                    pass
            for _, report in programs:
                report.seek(0)
                print(report.read().decode(errors="replace")[-2500:])
            raise AssertionError((mode, cipher, auth, rust_server, gro))
        exchange(os.urandom(73), 65)
        exchange(os.urandom(1025), 12)
        print(f"PASS {'IPv6' if v6 else 'IPv4'} {mode} {cipher}/{auth} Rust {'server' if rust_server else 'client'} gro={gro}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rust")
    parser.add_argument("cpp")
    parser.add_argument("--full", action="store_true")
    args = parser.parse_args()
    combos = itertools.product(CIPHERS, AUTH) if args.full else [
        ("aes128cbc", "md5"), ("aes128cfb", "hmac_sha1"), ("aes128cfb_0","crc32"),
        ("xor","simple"), ("none","none")]
    for cipher, auth in combos:
        for direction in (True,False):
            check(args.rust, args.cpp, cipher, auth, direction, gro=args.full or cipher != "aes128cbc")
    for mode in ("icmp","faketcp","easy-faketcp"):
        for direction in (True,False):
            check(args.rust, args.cpp, "aes128cbc","hmac_sha1",direction,mode,gro=True)
    if args.full:
        for mode in ("udp", "icmp", "faketcp", "easy-faketcp"):
            for direction in (True, False):
                check(args.rust, args.cpp, "aes128cbc", "md5", direction, mode, v6=True)
