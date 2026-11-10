"""Linux end-to-end test. Run in an isolated network namespace with NET_ADMIN and NET_RAW."""
import argparse
import contextlib
import os
from pathlib import Path
import queue
import secrets
import socket
import subprocess
import threading
import time

BINARY = "target/release/udp2raw"
WIRE_ARGS = []
KEY = secrets.token_hex(32)
SERVER = "127.0.0.2:34096"


def run_firewall(action, chain, rule):
    subprocess.run(["iptables", "-w", action, chain, "-o" if chain == "OUTPUT" else "-i", "lo", *rule], check=True)


@contextlib.contextmanager
def blocked(*rule, chain="INPUT"):
    rule = [*rule, "-j", "DROP"]
    run_firewall("-I", chain, rule)
    try:
        yield
    finally:
        run_firewall("-D", chain, rule)


class Tunnel:
    def __init__(self, stack, *args, key=KEY):
        self.log = queue.Queue()
        self.proc = subprocess.Popen(
            [BINARY, *WIRE_ARGS, *args], stderr=subprocess.PIPE, text=True,
            env={**os.environ, "UDP2RAW_KEY": key},
        )
        stack.callback(self.stop)
        threading.Thread(target=self.read, daemon=True).start()

    def read(self):
        for line in self.proc.stderr:
            print(line.rstrip(), flush=True)
            self.log.put(line)

    def stop(self):
        self.proc.terminate()
        self.proc.wait(timeout=5)
        self.proc.stderr.close()

    def expect(self, message):
        end = time.monotonic() + 15
        while time.monotonic() < end:
            try:
                line = self.log.get(timeout=max(0, end - time.monotonic()))
            except queue.Empty:
                break
            if message in line:
                return
        raise AssertionError(f"missing log {message!r}, exit={self.proc.poll()}")

    def expect_workers(self, count):
        tasks = Path(f"/proc/{self.proc.pid}/task")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            workers = [p for p in tasks.glob("*/comm") if p.read_text().strip() == "udp2raw-io"]
            if len(workers) == count:
                return
            time.sleep(0.02)
        raise AssertionError(f"expected {count} runtime workers, found {len(workers)}")


def udp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    return sock


def echo(sock):
    while True:
        data, addr = sock.recvfrom(65535)
        sock.sendto(addr[1].to_bytes(2, "big") + data, addr)


def roundtrip(sock, dest, data):
    sock.sendto(data, dest)
    reply, _ = sock.recvfrom(65535)
    assert reply[2:] == data, (reply, data)
    return reply[:2]


def main():
    with contextlib.ExitStack() as stack:
        upstream = stack.enter_context(udp())
        threading.Thread(target=echo, args=(upstream,), daemon=True).start()
        server = Tunnel(stack, "-s", "-l", SERVER, "-r",
                        f"127.0.0.1:{upstream.getsockname()[1]}", "--heartbeat-ms", "100",
                        "--threads", "8")
        server.expect("via icmp")
        server.expect_workers(8)
        stack.enter_context(blocked("-p", "tcp", "--tcp-flags", "RST", "RST",
                                    "--sport", "34096", chain="OUTPUT"))
        stack.enter_context(blocked("-p", "tcp", "--tcp-flags", "RST", "RST",
                                    "--dport", "34096", chain="OUTPUT"))
        dest = ("127.0.0.1", 33333)
        def client(port, *extra, key=KEY):
            return Tunnel(stack, "-c", "-l", f"127.0.0.1:{port}", "-r", SERVER,
                          "--heartbeat-ms", "100", "--timeout-ms", "600", *extra, key=key)

        primary = client(dest[1], "--threads", "1")
        primary.expect("connected via faketcp")
        primary.expect_workers(1)
        a, b = stack.enter_context(udp()), stack.enter_context(udp())
        for sock in (a, b):
            sock.settimeout(2)
        first = roundtrip(a, dest, b"before")
        second = roundtrip(b, dest, b"")
        assert first != second

        # Independent clients use all three listeners at the same time.
        for port, mode in [(33334, "udp"), (33335, "icmp")]:
            other = client(port, "--protocols", mode)
            other.expect(f"connected via {mode}")
            other.expect_workers(4)
            assert roundtrip(a, ("127.0.0.1", port), mode.encode()) != first

        wrong = client(33336, "--protocols", "udp", key="wrong")
        wrong.expect("udp timed out")
        a.sendto(b"bad key", ("127.0.0.1", 33336))
        a.settimeout(0.3)
        try:
            a.recv(1500)
            raise AssertionError("wrong key forwarded data")
        except socket.timeout:
            pass
        a.settimeout(2)
        with blocked("-d", "127.0.0.2", "-p", "tcp", "--dport", "34096"):
            primary.expect("connected via udp")
            assert roundtrip(a, dest, b"after tcp loss") == first
            cold = client(33337, "--protocols", "faketcp,icmp,udp")
            cold.expect("faketcp timed out")
            cold.expect("connected via icmp")
            assert roundtrip(a, ("127.0.0.1", 33337), b"cold start") != first
            with blocked("-d", "127.0.0.2", "-p", "udp", "--dport", "34096"):
                primary.expect("connected via icmp")
                assert roundtrip(a, dest, os.urandom(1025)) == first
                assert roundtrip(b, dest, b"second flow") == second
                with blocked("-d", "127.0.0.2", "-p", "icmp", "--icmp-type", "echo-request"):
                    primary.expect("icmp timed out")
                    primary.expect("faketcp timed out")
        primary.expect("connected via")
        assert roundtrip(a, dest, b"restored") == first
        print("PASS: simultaneous carriers, authentication, failover and UDP flow continuity")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", default=BINARY)
    parser.add_argument("--legacy", action="store_true")
    args = parser.parse_args()
    BINARY = args.binary
    if args.legacy:
        WIRE_ARGS = ["--wire", "legacy", "--auth-mode", "hmac_sha1", "--fix-gro"]
    main()
