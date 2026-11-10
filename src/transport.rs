mod linux_io;

pub use crate::packet::{Incoming, Route, Segment};
use crate::{
    config::{Config, Mode},
    link, packet,
    wire::random,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::AsRawFd,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket},
    task::{JoinHandle, JoinSet},
    time,
};

pub struct Carrier {
    pub mode: Mode,
    pub port: u16,
    server: bool,
    normal_udp: bool,
    addr: SocketAddr,
    socket: UdpSocket,
    reservation: Option<Socket>,
    device: Option<String>,
    link: Option<link::Sender>,
    ttl: u8,
    seq_mode: u8,
    random_drop: u16,
    timeout: Duration,
    rst_show: i32,
    rst_allow: i32,
    peers: Arc<Mutex<ResetCounts>>,
    dummy: Mutex<Option<JoinHandle<()>>>,
}

struct ResetCounts {
    counts: HashMap<SocketAddr, (u32, Instant)>,
    swept: Instant,
}

impl Drop for Carrier {
    fn drop(&mut self) {
        if let Ok(task) = self.dummy.get_mut() {
            if let Some(task) = task.take() {
                task.abort();
            }
        }
    }
}

pub fn wildcard(ip: IpAddr) -> IpAddr {
    if ip.is_ipv6() {
        Ipv6Addr::UNSPECIFIED.into()
    } else {
        Ipv4Addr::UNSPECIFIED.into()
    }
}

fn domain(addr: SocketAddr) -> Domain {
    if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    }
}

fn configure(s: &Socket, c: &Config, addr: SocketAddr) -> io::Result<()> {
    s.set_nonblocking(true)?;
    if let Some(dev) = c.dev.as_deref() {
        s.bind_device(Some(dev.as_bytes()))?;
    }
    buffers(s, c)?;
    if addr.is_ipv4() {
        s.set_ttl_v4(c.ttl.into())?;
    } else {
        s.set_unicast_hops_v6(c.ttl.into())?;
    }
    Ok(())
}

fn buffers(s: &Socket, c: &Config) -> io::Result<()> {
    if c.force_sock_buf {
        linux_io::set_int(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUFFORCE,
            c.sock_buf as i32,
        )?;
        linux_io::set_int(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDBUFFORCE,
            c.sock_buf as i32,
        )?;
    } else {
        s.set_recv_buffer_size(c.sock_buf)?;
        s.set_send_buffer_size(c.sock_buf)?;
    }
    Ok(())
}

impl Carrier {
    pub async fn bind(mode: Mode, c: &Config) -> io::Result<Arc<Self>> {
        let mut addr = if c.server {
            c.local
        } else {
            SocketAddr::new(
                c.source_ip.unwrap_or_else(|| wildcard(c.remote.ip())),
                c.source_port.unwrap_or(0),
            )
        };
        let link = c.lower_level.as_ref().map(link::Sender::new).transpose()?;
        // The legacy peer validates checksums on its AF_PACKET socket, before TX offload.
        let normal_udp = mode == Mode::Udp && !c.legacy && link.is_none();
        let mut reservation = None;
        let mut listener = None;
        // Reserve real TCP/UDP port numbers; ICMP only needs a unique client identifier.
        if !normal_udp && (!c.server || mode != Mode::Icmp) {
            let guard = Socket::new(
                domain(addr),
                if packet::tcp(mode) {
                    Type::STREAM
                } else {
                    Type::DGRAM
                },
                None,
            )?;
            configure(&guard, c, addr)?;
            if packet::tcp(mode) {
                guard.set_reuse_address(true)?;
            }
            guard.bind(&addr.into())?;
            addr.set_port(
                guard
                    .local_addr()?
                    .as_socket()
                    .ok_or(io::Error::other("non-IP reservation"))?
                    .port(),
            );
            if c.server && mode == Mode::EasyFakeTcp {
                guard.listen(256)?;
                listener = Some(TcpListener::from_std(guard.try_clone()?.into())?);
            }
            reservation = Some(guard);
        }
        let s = if normal_udp {
            let s = Socket::new(domain(addr), Type::DGRAM, Some(Protocol::UDP))?;
            configure(&s, c, addr)?;
            linux_io::pktinfo(&s, addr.is_ipv6())?;
            s.bind(&addr.into())?;
            addr.set_port(
                s.local_addr()?
                    .as_socket()
                    .ok_or(io::Error::other("non-IP UDP address"))?
                    .port(),
            );
            s
        } else if link.is_some() {
            let proto = if addr.is_ipv6() {
                libc::ETH_P_IPV6
            } else {
                libc::ETH_P_IP
            };
            let s = Socket::new(
                Domain::from(libc::AF_PACKET),
                Type::DGRAM,
                Some(Protocol::from((proto as u16).to_be() as i32)),
            )?;
            if let Some(dev) = c.dev.as_deref() {
                linux_io::bind_packet_device(&s, dev, proto as u16)?;
            }
            s.set_nonblocking(true)?;
            buffers(&s, c)?;
            // The protocol-specific packet socket already excludes outgoing frames on older kernels.
            let _ = linux_io::set_int(s.as_raw_fd(), libc::SOL_PACKET, 23, 1); // PACKET_IGNORE_OUTGOING
            s
        } else {
            let s = Socket::new(
                domain(addr),
                Type::RAW,
                Some(Protocol::from(i32::from(packet::protocol(
                    mode,
                    addr.is_ipv6(),
                )))),
            )?;
            configure(&s, c, addr)?;
            if mode == Mode::Icmp && c.server {
                if let Err(error) = linux_io::set_int(
                    s.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    crate::firewall::ICMP_MARK as i32,
                ) {
                    let managed = matches!(
                        c.firewall,
                        crate::config::FirewallAction::Auto | crate::config::FirewallAction::Keep
                    );
                    if managed || error.kind() != io::ErrorKind::PermissionDenied {
                        return Err(error);
                    }
                    crate::log!(
                        5,
                        "could not mark ICMP replies for externally managed firewall: {error}"
                    );
                }
            }
            if addr.is_ipv4() {
                s.set_header_included_v4(true)?;
            } else {
                linux_io::set_int(s.as_raw_fd(), libc::IPPROTO_IPV6, libc::IPV6_HDRINCL, 1)?;
            }
            linux_io::pktinfo(&s, addr.is_ipv6())?;
            let mut ip = addr;
            ip.set_port(0);
            s.bind(&ip.into())?;
            s
        };
        if !c.disable_bpf && !normal_udp {
            linux_io::filter(
                &s,
                mode,
                c.server,
                addr.port(),
                addr.is_ipv6(),
                link.is_some(),
            )?;
        }
        let socket = UdpSocket::from_std(s.into())?;
        let peers = Arc::new(Mutex::new(ResetCounts {
            counts: HashMap::new(),
            swept: Instant::now(),
        }));
        let task = listener.map(|listener| tokio::spawn(serve_dummy(listener, Arc::clone(&peers))));
        Ok(Arc::new(Self {
            mode,
            port: addr.port(),
            server: c.server,
            normal_udp,
            addr,
            socket,
            link,
            reservation,
            device: c.dev.clone(),
            ttl: c.ttl,
            seq_mode: c.seq_mode,
            random_drop: c.random_drop,
            timeout: c.timeout,
            rst_show: c.max_rst_to_show,
            rst_allow: c.max_rst_allowed,
            peers,
            dummy: Mutex::new(task),
        }))
    }

    pub async fn client_route(&self, peer: SocketAddr) -> io::Result<Route> {
        let probe = Socket::new(domain(peer), Type::DGRAM, Some(Protocol::UDP))?;
        if let Some(dev) = &self.device {
            probe.bind_device(Some(dev.as_bytes()))?;
        }
        let mut local = self.addr;
        local.set_port(0);
        probe.bind(&local.into())?;
        probe.connect(&peer.into())?;
        let ip = probe
            .local_addr()?
            .as_socket()
            .ok_or(io::Error::other("non-IP route"))?
            .ip();
        if self.mode != Mode::EasyFakeTcp {
            return Ok(Route::new(
                ip,
                peer,
                u32::from_ne_bytes(random()),
                self.seq_mode,
            ));
        }
        // Observe the kernel's SYN-ACK on the raw socket and retain the resulting
        // TCP stream. The kernel owns establishment and teardown; payloads remain
        // independent raw TCP segments just as in FakeTCP.
        let socket = TcpSocket::from_std_stream(
            self.reservation
                .as_ref()
                .ok_or(io::Error::other("missing TCP reservation"))?
                .try_clone()?
                .into(),
        );
        let capture = async {
            let mut buf = vec![0; 65535];
            loop {
                if let Some(packet) = self.recv(&mut buf).await? {
                    if packet.segment == Segment::SynAck && packet.route.peer == peer {
                        return Ok::<_, io::Error>(packet.route);
                    }
                }
            }
        };
        let exchange = async { tokio::try_join!(socket.connect(peer), capture) };
        let (stream, route) = time::timeout(self.timeout, exchange).await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "easy-faketcp kernel handshake timed out",
            )
        })??;
        *self.dummy.lock().unwrap() = Some(tokio::spawn(drain_dummy(stream)));
        Ok(route)
    }

    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<Option<Incoming>> {
        let packet = if self.link.is_some() {
            let n = self.socket.recv(buf).await?;
            packet::decode(&buf[..n], self.mode, self.server, self.port, self.seq_mode)
        } else {
            let (n, src, dst) = linux_io::recv(&self.socket, buf).await?;
            if self.normal_udp {
                Some(Incoming {
                    route: Route::new(dst, src, 0, self.seq_mode),
                    segment: Segment::Data,
                    body: buf[..n].to_vec(),
                })
            } else if self.addr.is_ipv4() {
                packet::decode(&buf[..n], self.mode, self.server, self.port, self.seq_mode)
            } else {
                packet::decode_segment(
                    &buf[..n],
                    self.mode,
                    self.server,
                    self.port,
                    self.seq_mode,
                    src,
                    dst,
                )
            }
        };
        let Some(packet) = packet else {
            return Ok(None);
        };
        if !self.addr.ip().is_unspecified() && packet.route.local != self.addr.ip() {
            return Ok(None);
        }
        if packet.segment == Segment::Syn && self.mode == Mode::EasyFakeTcp {
            return Ok(None);
        }
        if packet.segment == Segment::Reset {
            self.reset(packet.route.peer);
            return Ok(None);
        }
        Ok(Some(packet))
    }

    fn reset(&self, addr: SocketAddr) {
        let mut peers = self.peers.lock().unwrap();
        let Some((count, _)) = peers.counts.get_mut(&addr) else {
            return;
        };
        *count = count.saturating_add(1);
        if self.rst_show < 0 || *count <= self.rst_show as u32 {
            crate::log!(3, "TCP reset from {addr} (count {count})");
        }
    }

    fn check_resets(&self, addr: SocketAddr, seg: Segment) -> io::Result<()> {
        let mut peers = self.peers.lock().unwrap();
        if peers.swept.elapsed() >= Duration::from_secs(30) {
            peers
                .counts
                .retain(|_, (_, seen)| seen.elapsed() < Duration::from_secs(300));
            peers.swept = Instant::now();
        }
        // Track active path peers only. Unsolicited RST/SYN traffic cannot grow the table.
        if let Some((count, seen)) = peers.counts.get_mut(&addr) {
            if seg == Segment::SynAck {
                *count = 0;
            }
            *seen = Instant::now();
            if self.rst_allow >= 0 && *count > self.rst_allow as u32 {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "FakeTCP path exceeded its reset limit",
                ));
            }
        } else if seg != Segment::SynAck && peers.counts.len() < 4096 {
            peers.counts.insert(addr, (0, Instant::now()));
        }
        Ok(())
    }

    pub async fn send(&self, route: &mut Route, seg: Segment, body: &[u8]) -> io::Result<()> {
        if packet::tcp(self.mode) {
            self.check_resets(route.peer, seg)?;
        }
        let dropped = self.random_drop != 0
            && u32::from_ne_bytes(random()) % 10000 < u32::from(self.random_drop);
        if !dropped {
            if self.normal_udp {
                linux_io::send_udp(&self.socket, route.peer, route.local, body).await?;
            } else {
                let bytes = packet::encode(
                    self.mode,
                    self.server,
                    self.port,
                    route,
                    seg,
                    body,
                    self.ttl,
                )?;
                if let Some(link) = &self.link {
                    link.send(&bytes, route.local, route.peer).await?;
                } else {
                    let mut peer = route.peer;
                    peer.set_port(0);
                    self.socket.send_to(&bytes, peer).await?;
                }
            }
        }
        route.sent(self.mode, self.server, seg, body.len());
        Ok(())
    }
}

async fn drain_dummy(stream: TcpStream) {
    let mut buf = [0; 8192];
    loop {
        if stream.readable().await.is_err() {
            break;
        }
        match stream.try_read(&mut buf) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => break,
        }
    }
}

async fn hold_server_stream(stream: TcpStream, peer: SocketAddr, peers: Arc<Mutex<ResetCounts>>) {
    let mut interval = time::interval_at(
        time::Instant::now() + Duration::from_secs(300),
        Duration::from_secs(60),
    );
    let drain = drain_dummy(stream);
    tokio::pin!(drain);
    loop {
        tokio::select! {
            _ = &mut drain => return,
            _ = interval.tick() => {
                let active = peers.lock().unwrap().counts.get(&peer)
                    .is_some_and(|(_, seen)| seen.elapsed() < Duration::from_secs(300));
                if !active { return; }
            }
        }
    }
}
async fn serve_dummy(listener: TcpListener, peers: Arc<Mutex<ResetCounts>>) {
    let mut held = JoinSet::new();
    loop {
        tokio::select! {
            accepted=listener.accept()=>match accepted {
                Ok((socket,peer)) if held.len()<2048=>{held.spawn(hold_server_stream(socket,peer,Arc::clone(&peers)));}
                Ok(_)=>{}
                Err(_)=>time::sleep(Duration::from_millis(100)).await,
            },
            _=held.join_next(),if !held.is_empty()=>{}
        }
    }
}
