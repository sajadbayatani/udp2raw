"""Verify Linux wire-level controls inside an isolated network namespace."""
import contextlib
import os
import selectors
import socket
import struct
import subprocess
import sys
import time


BINARY = sys.argv[1] if len(sys.argv) > 1 else "target/release/udp2raw"
PORT = 32111
SOURCE_PORT = 32112


@contextlib.contextmanager
def client(mode, *options, capture_logs=False):
    proc = subprocess.Popen(
        [BINARY, "-c", "-l", "127.0.0.1:32110", "-r", f"127.0.0.2:{PORT}",
         "--protocols", mode, "--source-ip", "127.0.0.3", "--source-port", str(SOURCE_PORT),
         "--set-ttl", "31", "--dev", "lo", "--heartbeat-ms", "100",
         "--timeout-ms", "800", *options],
        env={**os.environ, "UDP2RAW_KEY": "transport-test-only"},
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE if capture_logs else subprocess.DEVNULL,
    )
    try:
        yield proc
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        if proc.stderr:
            proc.stderr.close()


def capture(sock, duration):
    end = time.monotonic() + duration
    while time.monotonic() < end:
        sock.settimeout(max(0.001, end - time.monotonic()))
        try:
            packet = sock.recv(65535)
        except socket.timeout:
            return
        if len(packet) < 40 or packet[12:20] != socket.inet_aton("127.0.0.3") + socket.inet_aton("127.0.0.2"):
            continue
        offset = (packet[0] & 15) * 4
        if packet[9] in (6, 17) and struct.unpack_from("!HH", packet, offset) == (SOURCE_PORT, PORT):
            yield packet, offset


def main():
    with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800)) as sock:
        sock.bind(("lo", 0x0800))
        for mode, proto in [("udp", 17), ("faketcp", 6)]:
            with client(mode, "--disable-bpf", "--sock-buf", "64") as proc:
                pkt, offset = next((p, i) for p, i in capture(sock, 6) if p[9] == proto)
                assert proc.poll() is None
                assert pkt[8] == 31
                if proto == 6:
                    assert pkt[offset+13] == 2
                    assert pkt[offset+12] >> 4 == 10
                    opts = pkt[offset+20:offset+40]
                    assert opts[:8] == bytes([2, 4, 5, 180, 4, 2, 8, 10])
                    assert opts[16:] == bytes([1, 3, 3, 5])
        # Flush captures belonging to the previous processes before we start observing drops.
        list(capture(sock, .2))
        with client("udp", "--random-drop", "10000") as proc:
            assert not list(capture(sock, 2))
            assert proc.poll() is None
    # The kernel returns a real RST for a SYN addressed to an unused TCP port.
    # A zero RST budget therefore forces the next heartbeat to abandon this path.
    with client("faketcp", "--max-rst-to-show", "0", "--max-rst-allowed", "0", capture_logs=True) as proc:
        log = b""
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stderr, selectors.EVENT_READ)
            end = time.monotonic() + 6
            while time.monotonic() < end and b"exceeded its reset limit" not in log:
                if selector.select(max(.001, end - time.monotonic())):
                    chunk = os.read(proc.stderr.fileno(), 4096)
                    if not chunk:
                        break
                    log += chunk
        assert b"exceeded its reset limit" in log, log
        assert b"TCP reset from" not in log
    print("PASS: pinned source IP and port, TTL, FakeTCP SYN options, reset limits, random-drop")


if __name__ == "__main__":
    main()
