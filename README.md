# udp2raw

Forward UDP datagrams through FakeTCP, UDP or ICMP. One Linux server opens all
three carriers. Each client uses one carrier at a time, in the order set by
`--protocols` (default `faketcp,udp,icmp`). Clients keep their UDP listener and
conversation IDs when they switch. The server keeps the upstream UDP socket
for each conversation, so a brief carrier outage preserves its source port.

## Install and run

Download the static Linux binary for your CPU and `SHA256SUMS` from
[Releases](https://github.com/sajadbayatani/udp2raw/releases). In the download
directory, run `sha256sum --ignore-missing -c SHA256SUMS`, rename the binary
to `udp2raw` and run `chmod +x udp2raw`.

Set `UDP2RAW_KEY` to the same secret on both endpoints. You can generate one
with `openssl rand -hex 32`. FakeTCP and ICMP use raw sockets. On Linux,
`sudo setcap cap_net_raw+ep ./udp2raw` grants the installed binary that access.
For the example below allow TCP/UDP port 4096 and ICMP echo on the tunnel path.

```sh
# Server: forward tunnel traffic to a UDP service on port 7777.
./udp2raw -s -l 0.0.0.0:4096 -r 127.0.0.1:7777 -g
# Install the printed firewall rule, then start the server.
./udp2raw -s -l 0.0.0.0:4096 -r 127.0.0.1:7777

# Client: replace the example address with the server's IP.
./udp2raw -c -l 127.0.0.1:3333 -r 192.0.2.1:4096 -g
# Install the printed rule on the client, then start the tunnel.
./udp2raw -c -l 127.0.0.1:3333 -r 192.0.2.1:4096 --protocols faketcp,udp,icmp
```

Send application traffic to UDP port 3333 on the client. The client logs
`connected via` when a path becomes usable. With the defaults it sends a
heartbeat every second and tries the next carrier after five seconds without
a valid reply. Local errors may trigger an earlier switch. After the last
carrier the client retries the first. It stays on a healthy carrier.
Datagrams in flight may be lost. Idle flows expire after five minutes.

For a UDP-only tunnel use `--raw-mode udp` on both ends. The modern Linux UDP
backend can run as a regular user. Legacy UDP constructs its own UDP headers
and checksums and requires raw socket access. For IPv6 use bracketed endpoints such as
`-l '[::]:4096'`. `--dns-resolve` enables hostnames. The UDP application and
outer carrier can use different address families.

## Wire formats and upgrades

| Peer | Configuration |
| --- | --- |
| Current Rust release | Default modern wire format and a shared key |
| Rust v1.0.0 | Default wire format, default heartbeat padding and GRO framing off |
| Original C++ udp2raw | `--wire legacy` with the same key, carrier, cipher, authentication and GRO settings as the peer |

Modern mode uses XChaCha20-Poly1305, random nonces, a path challenge and a
replay window. Legacy mode implements the original bare handshake, session
IDs, conversation framing, heartbeat roller, replay window and key derivation.
Specifying `--cipher-mode` or `--auth-mode` selects legacy mode. Its defaults
are AES-128-CBC and MD5. It also supports AES-128-CFB (including
`aes128cfb_0`), XOR, plaintext, HMAC-SHA1, CRC32, simple and no authentication.
These settings have different security properties. Prefer modern mode for new
deployments and a random key in both modes.

```sh
# Connect to a C++ server configured for UDP, AES-128-CBC and HMAC-SHA1.
./udp2raw -c -l 127.0.0.1:3333 -r 192.0.2.1:4096 \
  --wire legacy --raw-mode udp --auth-mode hmac_sha1
```

One server process uses one wire format for all its listeners. A Rust client
can use failover in either format. A C++ peer only provides the carrier it
was configured to use. The C++ implementation and its original documentation
can be found in the [v1.0.0 source tree](https://github.com/sajadbayatani/udp2raw/tree/v1.0.0).

## Network and process options

* **FakeTCP** sends raw TCP segments with a simulated handshake.
  `easy-faketcp` uses a kernel TCP connection for the handshake and raw
  segments for data. Choose the FakeTCP variant with `--raw-mode` or in
  `--protocols`. UDP and ICMP can run alongside either variant.
* **Firewall** options include `-a` to install and remove rules with the
  process, `--keep-rule` to restore them, `-g` to print rules, `--gen-add`
  to install persistent rules and `--clear` to clear managed rules. Rule
  changes require firewall access. On an ICMP server the generated rule
  suppresses unmarked kernel echo replies in the tunnel packet size range.
  Ordinary large pings to the listening address may also be suppressed.
  `--wait-lock` waits for xtables.
* **Routing and tuning** include source address/port, interface binding,
  socket buffer sizing, IP TTL/hop limit, kernel BPF filtering, sequence
  modes, RST thresholds and a test packet-loss rate. `--lower-level` sends
  directly at layer 2 on Linux. Supply `eth0#00:11:22:33:44:55` for a fixed
  next hop or `auto` for route and neighbor discovery (requires the `ip`
  command and uses `ping` on a cold neighbor cache).
* **Heartbeats** can be tuned with `--heartbeat-ms`, `--timeout-ms`,
  `--hb-mode` and `--hb-len`. Enable `--fix-gro` on both peers to frame
  and recover coalesced packets. On a 1500-byte IP path, 1351 bytes of
  modern application payload fit all IPv4 carriers without fragmentation
  with default framing. For IPv6 the corresponding limit is 1331 bytes.
* **Operations** include `--conf-file example.conf`, `--retry-on-error`,
  log levels, locations and color. A config file accepts one option and its
  optional value per line. On Linux, `--fifo /path/to/control` lets a client
  accept `echo reconnect > /path/to/control` without restarting.
  Run `udp2raw --help` for the full option list.

## Build and test

```sh
cargo build --release --locked
cargo test --locked
```

Linux defaults to the native server/client backend. macOS, Windows and
FreeBSD clients use libpcap (Npcap on Windows). Building these clients
requires the platform's pcap development libraries or Npcap SDK and an
installed capture driver. A Linux build with `--features pcap-client` can
exercise the same client backend against a native server. `--dev` selects
the capture interface, `--pcap-send` selects link injection and
`--no-pcap-mutex` uses independent capture and injection handles.

Run integration tests **inside a dedicated Linux network namespace** with
Python 3, iptables/ip6tables, iproute2, CAP_NET_RAW and CAP_NET_ADMIN.
They change firewall rules in that namespace.

```sh
python3 tests/failover.py target/release/udp2raw
python3 tests/failover.py target/release/udp2raw --legacy
python3 tests/carriers.py target/release/udp2raw
python3 tests/operations.py target/release/udp2raw
python3 tests/transport_controls.py target/release/udp2raw
python3 tests/legacy_interop.py target/release/udp2raw /path/to/original-cpp-binary --full
```

The failover tests block each live carrier in turn, exchange datagrams after
each switch, and compare upstream source ports. The interop test runs the
Rust and C++ programs in both client/server directions.

To test the capture client across Ethernet, run `tests/pcap_peer.py server
NATIVE_BINARY SERVER_IP` on one peer and `tests/pcap_peer.py client
PCAP_BINARY SERVER_IP` on the other with the same test key.
