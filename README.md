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

### Limit UDP payload size

Since v1.3.0, `--mtu N` sets the maximum number of **application UDP payload
bytes** an endpoint will forward in either direction. For example, add
`--mtu 1382` to the client and server commands, or put it on its own line in
`client.conf` and `server.conf` and restart the services. A 1382-byte
datagram can pass the limit. A 1383-byte datagram is dropped whole. The
drop does not trigger failover. The same limit applies after a carrier
switch. Use `--debug` to see drops.

Each endpoint enforces its own setting. With 1300 on the server and 1382 on
the client, 1300 is the effective payload ceiling in both directions.
The accepted range is 1–60000, with a default ceiling of 60000 bytes.
The wire format and path MTU may impose smaller limits. IP, carrier and
encryption headers add bytes on the wire. Handshakes and heartbeat padding
are outside this application payload limit.

`--mtu-warn` controls logging separately. For example, with `--mtu 1382`
and the default warning threshold of 1375, a 1382-byte payload can still
produce a warning. To have the application send smaller packets, adjust
the packet size or inner tunnel MTU in the application feeding udp2raw.

### Carry WireGuard without changing its MTU

If WireGuard must keep an interface MTU of 1420, upgrade both udp2raw
endpoints to v1.4.0 or later. In modern mode, add these options to **both**
udp2raw commands or put these two lines in each udp2raw service config:

```text
--mtu 1600
--fragment-size 1000
```

Replace an existing `--mtu 1420` setting. WireGuard adds its own headers
and authentication tag before udp2raw receives the UDP payload. The 1600-byte
limit admits those datagrams. udp2raw sends up to 1000 application bytes per
authenticated fragment and reassembles the complete datagram before handing
it to the local application. A full fragment in this example occupies
1155 bytes on IPv4 FakeTCP with default framing. Smaller datagrams still
use one ordinary frame.

Each sender chooses its chunk size (512–4096 bytes). Choose a smaller value
for paths with a lower MTU. The receiver enforces its `--mtu` limit on the
original size. Missing fragments cause loss of that UDP datagram. Control
packets use their existing framing. Fragmentation is off by default and
requires modern peers with fragment support.

For an outer path verified to carry 1500-byte IP packets in both directions,
try `--mtu 1600 --fragment-size 1320` on both endpoints. Datagrams from
1001 through 1320 bytes then fit in a single frame. A 1382-byte datagram
still takes two. At this setting a full fragment occupies 1451 bytes on
IPv4 ICMP and 1495 bytes on IPv6 FakeTCP (add two bytes with
`--fix-gro`). Account for every carrier in the failover list. If the path
MTU is smaller or uncertain, start with 1000 and compare goodput in each
direction before increasing it.

Since v1.4.1, `--sock-buf N` (KiB) also sets the send and receive buffers
on the client's local UDP listener and each server-side upstream UDP socket.
Linux limits ordinary buffer requests to `net.core.rmem_max` and
`net.core.wmem_max`. To inspect UDP socket buffers and drops during a
transfer, run `ss -u -a -n -m -p` on the tunnel host and locate the
udp2raw socket. The `rb`, `tb` and `d` fields show the receive limit,
send limit and socket drops. A growing drop count during a burst is a
reason to investigate the receive buffer.

### Worker threads and CPU affinity

Since v1.2.0, `--threads N` sets the number of OS worker threads per process
(1–256, default 4). The server and client can use different values. Set it on
the command line or on its own line in the config file, then restart the
process to apply it. The main thread and optional helper threads are additional.

```sh
# Server with 8 workers
./udp2raw -s -l 0.0.0.0:4096 -r 127.0.0.1:7777 --threads 8

# Client with 2 workers; substitute the server's IP
./udp2raw -c -l 127.0.0.1:3333 -r 192.0.2.1:4096 --threads 2
```

Independent tunnel tasks can run in parallel on different logical CPUs.
To run multiple threads on one logical CPU, check the allowed CPUs with
`taskset -pc $$` and prefix the command with e.g. `taskset -c 0` if CPU 0
is allowed. The workers then take turns on that CPU. For a running process,
`ps -T -p PID -o tid,psr,comm` shows each thread ID, the logical CPU it last
ran on and its name. Replace `PID` with the process ID.

## Run as a Linux systemd service

On each host, install the verified release binary from the steps above and
create a root-only directory for the config and shared key.

```sh
sudo install -m 0755 ./udp2raw /usr/local/bin/udp2raw
sudo install -d -m 0700 /etc/udp2raw
```

Generate one key with `openssl rand -hex 32` and transfer it securely to
the other host. Replace `REPLACE_WITH_SHARED_KEY` in both configs with that
same value. Install your distribution's `iptables` package on both hosts.
The `-a` option installs tunnel rules at startup and removes them on normal shutdown. Allow
inbound TCP/UDP port 4096 and ICMP echo on the server's network firewall.

On the **server**, use `sudoedit /etc/udp2raw/server.conf` and enter the
following. Set `-r` to the UDP application that should receive the traffic.

```text
-s
-l 0.0.0.0:4096
-r 127.0.0.1:7777
-k REPLACE_WITH_SHARED_KEY
--protocols faketcp,udp,icmp
--threads 8
-a
--wait-lock
```

On the **client**, use `sudoedit /etc/udp2raw/client.conf` and enter the
following. Replace `192.0.2.1` with the server's IP. Local applications
send UDP traffic to `127.0.0.1:3333`.

```text
-c
-l 127.0.0.1:3333
-r 192.0.2.1:4096
-k REPLACE_WITH_SHARED_KEY
--protocols faketcp,udp,icmp
--threads 2
-a
--wait-lock
```

On **both hosts**, use `sudoedit /etc/systemd/system/udp2raw@.service` to
create this template. The instance name selects `server.conf` or
`client.conf`. The service runs as root with the capabilities needed for
raw sockets and firewall rules.

```ini
[Unit]
Description=udp2raw tunnel (%i)
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/udp2raw --conf-file /etc/udp2raw/%i.conf
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=yes
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
```

Run these commands on each host. Set `unit=udp2raw@server.service` on the
server and `unit=udp2raw@client.service` on the client.

```sh
unit=udp2raw@server.service   # use udp2raw@client.service on the client
sudo systemctl daemon-reload
sudo systemctl enable --now "$unit"
systemctl status "$unit" --no-pager
sudo journalctl -u "$unit" -f
```

The server logs one `listening on` line per carrier. The client's
`connected via` line identifies the active carrier. Press Ctrl-C to exit
the log viewer. To inspect the service's threads, run
`ps -T -p "$(systemctl show -p MainPID --value "$unit")" -o tid,psr,comm`.

To pin a service to one logical CPU, run `sudo systemctl edit "$unit"` and
add the following drop-in, substituting a CPU allowed on that host.

```ini
[Service]
CPUAffinity=0
```

Run `sudo systemctl restart "$unit"` after changing the drop-in, config or
thread count. After editing the unit template itself, run
`sudo systemctl daemon-reload` before restarting. To stop the service and
disable startup at boot, run `sudo systemctl disable --now "$unit"`.

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
