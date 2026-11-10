"""Linux operations regression tests. Run in a dedicated network namespace (NET_ADMIN and NET_RAW)."""
import contextlib
import os
import pathlib
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

BINARY = sys.argv[1] if len(sys.argv) == 2 else "target/release/udp2raw"
CLIENT = ["-c", "-l127.0.0.1:35151", "-r127.0.0.2:35152", "--raw-mode", "faketcp"]
ENV = {**os.environ, "UDP2RAW_KEY": "operations-test"}


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def wait_for(check, timeout=8):
    finish = time.monotonic() + timeout
    while time.monotonic() < finish:
        result = check()
        if result:
            return result
        time.sleep(.05)
    raise AssertionError(f"timed out waiting for {check}")


@contextlib.contextmanager
def process(*args, log=None):
    p = subprocess.Popen([BINARY, *args], env=ENV, stderr=log or subprocess.DEVNULL)
    try:
        yield p
    finally:
        p.send_signal(signal.SIGTERM)
        p.wait(timeout=5)


def managed():
    return [line for line in run("iptables", "-S").splitlines() if "u2r_" in line]


def check_icmp():
    # The kernel reflects every echo request, including tunnel ciphertext.
    # Only the marked userspace echo reply should reach the client.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as backend, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as app:
        backend.bind(("127.0.0.1", 0))
        backend.settimeout(5)
        def echo():
            data, peer = backend.recvfrom(1500)
            backend.sendto(data, peer)
        thread = threading.Thread(target=echo)
        with process("-s", "-a", "-l127.0.0.2:35789", f"-r127.0.0.1:{backend.getsockname()[1]}",
                     "--raw-mode", "icmp", "--sock-buf", "64"), \
             process("-c", "-l127.0.0.1:35788", "-r127.0.0.2:35789", "--raw-mode", "icmp",
                     "--heartbeat-ms", "200", "--timeout-ms", "1200", "--sock-buf", "64"):
            wait_for(lambda: any("--mark" in line for line in managed()))
            thread.start()
            app.settimeout(.25)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                app.sendto(b"icmp path", ("127.0.0.1", 35788))
                try:
                    assert app.recv(1500) == b"icmp path"
                    break
                except socket.timeout:
                    pass
            else:
                raise AssertionError("ICMP userspace replies did not reach the client")
            thread.join(5)
            # Match Linux's effective limits even when the namespace clamps them.
            for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
                app.setsockopt(socket.SOL_SOCKET, opt, 64 * 1024)
            rb = app.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            tb = app.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            for field, port in [("sport", 35788), ("dport", backend.getsockname()[1])]:
                limits = run("ss", "-Huanm", field, "=", f":{port}")
                assert f",rb{rb}," in limits and f",tb{tb}," in limits, limits
            counters = run("iptables", "-n", "-v", "-x", "-L", "OUTPUT").splitlines()
            assert any("u2r_t" in line and int(line.split()[0]) > 0 for line in counters), counters


def main():
    before = run("iptables", "-S")
    if managed():
        raise RuntimeError("test requires a clean dedicated network namespace")
    assert "--tcp-flags RST RST" in run(BINARY, *CLIENT, "-g")
    assert run(BINARY, "-g", "-c", "-l[::1]:20000", "-r[::1]:20001").startswith("ip6tables")
    # Two clients share a tunnel peer and have independent rule lifetimes.
    with process(*CLIENT, "-a"):
        wait_for(lambda: len(managed()) == 3)
        with process(*[x.replace(":35151", ":35153") for x in CLIENT], "--simple-rule", "-a"):
            wait_for(lambda: len(managed()) == 4)
        wait_for(lambda: len(managed()) == 3)
    assert run("iptables", "-S") == before
    with process(*CLIENT, "--wait-lock", "--keep-rule"):
        rule = wait_for(lambda: next((x for x in managed() if x.startswith("-A OUTPUT")), None))
        cmd = shlex.split(rule)
        cmd[0] = "-D"
        run("iptables", *cmd)
        wait_for(lambda: rule in managed())
    assert run("iptables", "-S") == before
    persistent = [subprocess.Popen([BINARY, *CLIENT, "--wait-lock", "--gen-add"]) for _ in range(3)]
    assert all(p.wait(timeout=5) == 0 for p in persistent)
    assert len(managed()) == 3
    # Also recognize both chain naming schemes used by the original binary.
    for chain in ("udp2rawDwrW_C", "udp2rawDwrW_12ab_C0", "udp2rawDwrW_12ab_C1"):
        run("iptables", "-N", chain)
        run("iptables", "-A", chain, "-j", "DROP")
        run("iptables", "-I", "INPUT", "-p", "tcp", "--dport", "35154", "-j", chain)
    run(BINARY, "--clear")
    assert run("iptables", "-S") == before
    # If installing the second carrier fails, revert only this invocation's changes.
    with tempfile.TemporaryDirectory() as directory:
        wrapper = pathlib.Path(directory) / "iptables"
        real = shutil.which("iptables")
        wrapper.write_text("#!/bin/sh\ncase \" $* \" in *' -I OUTPUT '*' --mark '*) exit 4;; esac\n"
                           f'exec {shlex.quote(real)} "$@"\n')
        wrapper.chmod(0o755)
        result = subprocess.run([BINARY, "-s", "-l127.0.0.2:35789", "-r127.0.0.1:35152", "--gen-add"],
                                env={**ENV, "PATH": directory + ":" + ENV["PATH"]}, capture_output=True)
        assert result.returncode != 0
    assert run("iptables", "-S") == before
    check_icmp()
    assert run("iptables", "-S") == before

    with tempfile.TemporaryDirectory() as temp:
        folder = pathlib.Path(temp)
        fifo = folder / "control"
        config = folder / "client.conf"
        config.write_text(f"-c\n-l 127.0.0.1:35151\n-r localhost:35152\n--dns-resolve\n"
                          f"--protocols udp\n--fifo {fifo}\n--log-position\n--disable-color\n")
        path = folder / "stderr"
        with path.open("w") as log, process("--conf-file", str(config), log=log):
            wait_for(lambda: "trying udp" in path.read_text())
            with fifo.open("w") as writer:
                writer.write("reconnect\n")
            wait_for(lambda: "attempt 2" in path.read_text())
            assert "client.rs:" in path.read_text()
            assert "\x1b" not in path.read_text()
        assert not fifo.exists()
        # Pre-existing FIFOs belong to the caller.
        os.mkfifo(fifo)
        with path.open("w") as log, process("--conf-file", str(config), log=log):
            wait_for(lambda: "trying udp" in path.read_text())
        assert fifo.is_fifo()

        # A busy UDP port becomes available after launch.
        busy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        busy.bind(("127.0.0.1", 35152))
        with path.open("w") as log, process("-s", "-l127.0.0.1:35152", "-r127.0.0.1:35151",
                                            "--raw-mode", "udp", "--retry-on-error", log=log):
            wait_for(lambda: "retry" in path.read_text())
            busy.close()
            wait_for(lambda: "via udp" in path.read_text())
    print("PASS: rule generation, concurrent ownership, cleanup, keep, persistence, IPv6, "
          "literal configuration, FIFO, log settings and startup retry")


if __name__ == "__main__":
    main()
