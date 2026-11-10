# udp2raw for Linux

Forward local UDP datagrams to a remote UDP service over FakeTCP, UDP or ICMP.
The Rust server opens all three listeners at startup. Each client uses one
carrier at a time. The default order is `faketcp,udp,icmp`. Multiple clients
can use different carriers on the same server at the same time.

## Run a tunnel

Download the Linux binary matching your CPU and the checksum file from
[Releases](https://github.com/sajadbayatani/udp2raw/releases).
Run `sha256sum --ignore-missing -c SHA256SUMS` in the download directory, then
rename the binary to `udp2raw` and run `chmod +x udp2raw`. Both endpoints must
run the Rust version. Set `UDP2RAW_KEY` to the same high-entropy secret on
both machines. You can generate one with `openssl rand -hex 32`.

FakeTCP and ICMP require Linux raw socket access. Run the following once on
both endpoints to give the installed binary the necessary capability.

```sh
sudo setcap cap_net_raw+ep ./udp2raw
```

For the examples below, allow inbound TCP and UDP port 4096 and ICMP echo
requests on the server. Allow replies on the client. Suppress kernel-generated
TCP resets for the tunnel on each endpoint. These rules apply to IPv4 and
assume a dedicated tunnel port. Replace the example server address first.

```sh
# Server
sudo iptables -I OUTPUT -p tcp --sport 4096 --tcp-flags RST RST -j DROP
./udp2raw -s -l 0.0.0.0:4096 -r 127.0.0.1:7777

# Client
sudo iptables -I OUTPUT -d 192.0.2.1 -p tcp --dport 4096 --tcp-flags RST RST -j DROP
./udp2raw -c -l 127.0.0.1:3333 -r 192.0.2.1:4096 --protocols faketcp,udp,icmp
```

Send application traffic to UDP port 3333 on the client. The server forwards
it to UDP port 7777. Log lines such as `connected via icmp` identify the
active carrier. Remove each firewall rule with the same command using `-D`
in place of `-I`. For a UDP-only setup, use `--protocols udp` on both ends.
That configuration works as an ordinary user without firewall changes.

## Failover and packet handling

* The client sends an authenticated heartbeat every second. After five seconds
  without a valid reply it tries the next carrier. A local socket error can
  trigger an earlier switch. After the last carrier it starts from the first.
  It stays on a working carrier until that carrier fails. Set
  `--heartbeat-ms` and `--timeout-ms` on the client to change the timings.
* The client keeps its local listener open during failover. The server keeps
  the upstream UDP socket for each client flow across carrier changes. Idle
  flows expire after five minutes. Applications may lose datagrams during a
  switch. A server restart creates new upstream sockets.
* FakeTCP uses a raw SYN/SYN-ACK exchange and carries datagrams in TCP
  segments. ICMP uses echo requests and replies. For ICMP the configured
  tunnel port identifies the tunnel inside the authenticated protocol. The
  network must pass ICMP in both directions.
* The multi-threaded Tokio runtime services carrier listeners and UDP sockets.
  Frames use XChaCha20-Poly1305 with random 192-bit nonces and a key derived
  with PBKDF2-HMAC-SHA256. Path challenges, attempt numbers and replay
  windows reject stale traffic. Use independent secrets for different
  trust groups.
* The tunnel accepts inner datagrams up to 60,000 bytes. The usable datagram
  size also depends on path MTU. On a 1500-byte IPv4 path, 1363 bytes of
  application payload fit on all three carriers without fragmentation.

## Build and test

```sh
cargo build --release --locked
cargo test --locked
target/release/udp2raw --help
```

The Linux integration test launches both endpoints and a UDP echo service.
It blocks each carrier in turn and checks payloads and upstream source
ports before and after failover. Run it inside an isolated network namespace
or container with Python 3, iptables, CAP_NET_ADMIN and CAP_NET_RAW.

```sh
python3 tests/failover.py target/release/udp2raw
```

## Migrating from C++

This release uses a new wire format and IPv4 endpoints. Upgrade the client
and server together. The Rust CLI supports the options shown by `--help`.
Legacy cipher modes, easy-faketcp, automatic firewall management and legacy
configuration files are available through the original C++ implementation.
Its sources, makefile and [original guide](README.legacy.md) are included
for existing deployments.
