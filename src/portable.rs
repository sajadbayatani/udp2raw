//! Client backend for libpcap/Npcap devices. Each path owns its capture
//! thread, port reservation and output handle for exactly one attempt.
pub use crate::packet::{Incoming, Route, Segment};
use crate::{
    config::{Config, Mode},
    packet,
    wire::random,
};
use pcap::{Active, Capture, Device, Linktype};
use socket2::{Domain, Socket, Type};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    sync::{
        atomic::{AtomicBool, AtomicI32, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;

type Handle = Arc<Mutex<Capture<Active>>>;
fn cap_err(e: pcap::Error) -> io::Error {
    io::Error::other(e)
}
fn wildcard(peer: SocketAddr) -> IpAddr {
    if peer.is_ipv4() {
        Ipv4Addr::UNSPECIFIED.into()
    } else {
        Ipv6Addr::UNSPECIFIED.into()
    }
}

fn header_len(link: Linktype, frame: &[u8]) -> Option<usize> {
    match link {
        Linktype::ETHERNET => {
            let mut end = 14;
            while matches!(
                u16::from_be_bytes(frame.get(end - 2..end)?.try_into().ok()?),
                0x8100 | 0x88a8
            ) {
                end += 4;
            }
            Some(end)
        }
        Linktype::NULL | Linktype::LOOP => Some(4),
        Linktype::RAW => Some(0),
        Linktype::LINUX_SLL => Some(16),
        _ => None,
    }
}

fn open(name: &str, buffer: usize) -> io::Result<Capture<Active>> {
    Capture::from_device(name)
        .map_err(cap_err)?
        .timeout(1)
        .snaplen(65535)
        .buffer_size(buffer as i32)
        .immediate_mode(true)
        .open()
        .map_err(cap_err)?
        .setnonblock()
        .map_err(cap_err)
}

struct CapturePath {
    handle: Handle,
    header: Vec<u8>,
    receiver: tokio::sync::Mutex<mpsc::Receiver<io::Result<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
}

impl Drop for CapturePath {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

struct Setup {
    device: Option<String>,
    buffer: usize,
    split: bool,
    filter: bool,
    timeout: Duration,
    peer: SocketAddr,
}

impl Setup {
    fn capture(self, probe: &UdpSocket, mode: Mode, port: u16) -> io::Result<CapturePath> {
        let local = probe.local_addr()?.ip();
        let name = match self.device {
            Some(name) => name,
            None => {
                Device::list()
                    .map_err(cap_err)?
                    .into_iter()
                    .find(|d| {
                        d.addresses.iter().any(|a| a.addr == local)
                            || (local.is_loopback() && d.flags.is_loopback())
                    })
                    .ok_or_else(|| {
                        io::Error::other(format!("no capture device for {local}; specify --dev"))
                    })?
                    .name
            }
        };
        let mut reader = open(&name, self.buffer)?;
        let link = reader.get_datalink();
        if !matches!(
            link,
            Linktype::ETHERNET
                | Linktype::NULL
                | Linktype::LOOP
                | Linktype::RAW
                | Linktype::LINUX_SLL
        ) {
            return Err(io::Error::other(format!(
                "unsupported capture link type {link:?}"
            )));
        }
        let probe_port = probe.local_addr()?.port();
        let peer = self.peer.ip();
        reader
            .filter(
                &format!("udp and src port {probe_port} and dst host {peer}"),
                true,
            )
            .map_err(cap_err)?;
        // Capture a route-specific native link header including VLAN tags or
        // loopback address family. Only our random probe can supply the header.
        let token = random::<32>();
        let deadline = Instant::now() + self.timeout;
        let mut next_probe = Instant::now();
        let header = loop {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "could not capture outgoing probe on device",
                ));
            }
            if Instant::now() >= next_probe {
                probe.send(&token)?;
                next_probe = Instant::now() + Duration::from_millis(200);
            }
            match reader.next_packet() {
                Ok(frame) if frame.data.ends_with(&token) => {
                    let start = header_len(link, frame.data)
                        .ok_or(io::Error::other("invalid link header"))?;
                    break frame.data[..start].to_vec();
                }
                Ok(_) => {}
                Err(pcap::Error::TimeoutExpired) => thread::sleep(Duration::from_millis(1)),
                Err(e) => return Err(cap_err(e)),
            }
        };
        let proto = match mode {
            Mode::Icmp if peer.is_ipv6() => "icmp6",
            Mode::Icmp => "icmp",
            Mode::Udp => "udp",
            _ => "tcp",
        };
        let bpf = if self.filter {
            format!("src host {peer} and dst host {local} and {proto}")
        } else {
            String::from("len >= 0")
        };
        reader.filter(&bpf, true).map_err(cap_err)?;
        let reader = Arc::new(Mutex::new(reader));
        let handle = if self.split {
            Arc::new(Mutex::new(open(&name, self.buffer)?))
        } else {
            reader.clone()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let cancel = stop.clone();
        let (tx, rx) = mpsc::channel(256);
        thread::Builder::new()
            .name(format!("pcap-{port}"))
            .spawn(move || {
                while !cancel.load(Ordering::Acquire) {
                    let result = match reader.lock().unwrap().next_packet() {
                        Ok(frame) => header_len(link, frame.data)
                            .and_then(|start| frame.data.get(start..))
                            .map(|ip| Ok(ip.to_vec())),
                        Err(pcap::Error::TimeoutExpired) => None,
                        Err(e) => Some(Err(cap_err(e))),
                    };
                    match result {
                        None => thread::sleep(Duration::from_millis(1)),
                        Some(Err(e)) => {
                            let _ = tx.blocking_send(Err(e));
                            break;
                        }
                        Some(Ok(ip)) => {
                            if matches!(
                                tx.try_send(Ok(ip)),
                                Err(mpsc::error::TrySendError::Closed(_))
                            ) {
                                break;
                            }
                        }
                    }
                }
            })?;
        Ok(CapturePath {
            handle,
            header,
            receiver: tokio::sync::Mutex::new(rx),
            stop,
        })
    }
}

pub struct Carrier {
    pub mode: Mode,
    pub port: u16,
    local: IpAddr,
    peer: SocketAddr,
    seq_mode: u8,
    ttl: u8,
    loss: u16,
    timeout: Duration,
    path: CapturePath,
    reservation: Socket,
    raw: Option<Socket>,
    rst: AtomicI32,
    rst_show: i32,
    rst_max: i32,
    dummy: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Drop for Carrier {
    fn drop(&mut self) {
        if let Some(reader) = self.dummy.get_mut().unwrap().take() {
            reader.abort();
        }
    }
}

impl Carrier {
    pub async fn bind(mode: Mode, c: &Config) -> io::Result<Arc<Self>> {
        if c.server {
            return Err(io::Error::other("the pcap backend is client-only"));
        }
        let peer = c.remote;
        let probe = UdpSocket::bind(SocketAddr::new(
            c.source_ip.unwrap_or_else(|| wildcard(peer)),
            0,
        ))?;
        probe.connect(peer)?;
        let src = probe.local_addr()?;
        let socket = Socket::new(
            Domain::for_address(src),
            if packet::tcp(mode) {
                Type::STREAM
            } else {
                Type::DGRAM
            },
            None,
        )?;
        socket.set_recv_buffer_size(c.sock_buf)?;
        socket.set_send_buffer_size(c.sock_buf)?;
        socket.bind(&SocketAddr::new(src.ip(), c.source_port.unwrap_or(0)).into())?;
        let port = socket.local_addr()?.as_socket().unwrap().port();
        let setup = Setup {
            device: c.dev.clone(),
            buffer: c.sock_buf,
            split: c.no_pcap_mutex,
            filter: !c.disable_bpf,
            timeout: c.timeout,
            peer,
        };
        let path = tokio::task::spawn_blocking(move || setup.capture(&probe, mode, port)).await??;
        // Raw IPv4 writes are available on Unix. Npcap, IPv6 and explicit
        // --pcap-send use link injection. Fall back when only BPF access was granted.
        let kernel_loopback = cfg!(target_os = "linux") && peer.ip().is_loopback();
        let raw = if kernel_loopback {
            // Linux packet injection on lo reaches packet taps but may skip
            // local IP delivery. IPPROTO_RAW preserves the constructed headers.
            Some(Socket::new(
                Domain::for_address(peer),
                Type::RAW,
                Some(socket2::Protocol::from(255)),
            )?)
        } else if cfg!(unix) && peer.is_ipv4() && !c.pcap_send {
            Socket::new(Domain::IPV4, Type::RAW, Some(socket2::Protocol::from(255)))
                .and_then(|s| {
                    s.set_header_included_v4(true)?;
                    Ok(s)
                })
                .ok()
        } else {
            None
        };
        Ok(Arc::new(Self {
            mode,
            port,
            peer,
            local: src.ip(),
            seq_mode: c.seq_mode,
            ttl: c.ttl,
            loss: c.random_drop,
            timeout: c.timeout,
            path,
            reservation: socket,
            raw,
            rst: AtomicI32::new(0),
            rst_max: c.max_rst_allowed,
            rst_show: c.max_rst_to_show,
            dummy: Mutex::new(None),
        }))
    }

    pub async fn client_route(&self, peer: SocketAddr) -> io::Result<Route> {
        if self.mode != Mode::EasyFakeTcp {
            return Ok(Route::new(
                self.local,
                peer,
                u32::from_ne_bytes(random()),
                self.seq_mode,
            ));
        }
        let sock = self.reservation.try_clone()?;
        let timeout = self.timeout;
        let stream = tokio::task::spawn_blocking(move || -> io::Result<_> {
            sock.connect_timeout(&peer.into(), timeout)?;
            sock.set_nonblocking(true)?;
            Ok(std::net::TcpStream::from(sock))
        })
        .await??;
        let stream = tokio::net::TcpStream::from_std(stream)?;
        *self.dummy.lock().unwrap() = Some(tokio::spawn(async move {
            let mut buf = [0; 8192];
            while stream.readable().await.is_ok() {
                match stream.try_read(&mut buf) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => break,
                }
            }
        }));
        tokio::time::timeout(self.timeout, async {
            let mut scratch = [];
            loop {
                if let Some(p) = self.recv(&mut scratch).await? {
                    if p.segment == Segment::SynAck && p.route.peer == peer {
                        return Ok(p.route);
                    }
                }
            }
        })
        .await?
    }

    pub async fn recv(&self, _buf: &mut [u8]) -> io::Result<Option<Incoming>> {
        let ip = self
            .path
            .receiver
            .lock()
            .await
            .recv()
            .await
            .ok_or(io::Error::other("pcap reader stopped"))??;
        let packet = packet::decode(&ip, self.mode, false, self.port, self.seq_mode);
        if let Some(rx) = &packet {
            if rx.segment == Segment::Reset && rx.route.peer == self.peer {
                let count = self.rst.fetch_add(1, Ordering::Relaxed) + 1;
                if self.rst_show < 0 || count <= self.rst_show {
                    crate::log!(3, "TCP reset from {}", rx.route.peer);
                }
                if self.rst_max >= 0 && count > self.rst_max {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "TCP reset threshold reached",
                    ));
                }
                return Ok(None);
            }
        }
        Ok(packet)
    }
    pub async fn send(&self, route: &mut Route, seg: Segment, body: &[u8]) -> io::Result<()> {
        if self.loss != 0 && u32::from_ne_bytes(random()) % 10000 < u32::from(self.loss) {
            route.sent(self.mode, false, seg, body.len());
            return Ok(());
        }
        let mut ip = packet::encode(self.mode, false, self.port, route, seg, body, self.ttl)?;
        if let Some(raw) = &self.raw {
            // Darwin IP_HDRINCL accepts the packet length in host byte order.
            if cfg!(target_os = "macos") {
                let len = ip.len() as u16;
                ip[2..4].copy_from_slice(&len.to_ne_bytes());
            }
            raw.send_to(&ip, &SocketAddr::new(route.peer.ip(), 0).into())?;
        } else {
            let mut frame = Vec::with_capacity(self.path.header.len() + ip.len());
            frame.extend_from_slice(&self.path.header);
            frame.extend(ip);
            self.path
                .handle
                .lock()
                .unwrap()
                .sendpacket(frame)
                .map_err(cap_err)?;
        }
        route.sent(self.mode, false, seg, body.len());
        Ok(())
    }
}
