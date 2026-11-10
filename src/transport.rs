use crate::{config::Mode, wire::random};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
};
use tokio::net::UdpSocket;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Segment {
    Syn,
    SynAck,
    Data,
}

#[derive(Clone, Copy)]
pub struct Route {
    pub local: Ipv4Addr,
    pub peer: SocketAddrV4,
    pub seq: u32,
    pub ack: u32,
    pub echo_seq: u16,
}

pub struct Incoming {
    pub route: Route,
    pub segment: Segment,
    pub body: Vec<u8>,
}

pub struct Carrier {
    pub mode: Mode,
    socket: UdpSocket,
    pub port: u16,
    server: bool,
    _reservation: Option<Socket>,
}

fn v4(addr: SocketAddr) -> io::Result<SocketAddrV4> {
    match addr {
        SocketAddr::V4(a) => Ok(a),
        _ => Err(io::Error::other("expected IPv4")),
    }
}

impl Carrier {
    pub async fn bind(mode: Mode, addr: SocketAddrV4, server: bool) -> io::Result<Arc<Self>> {
        let mut port = addr.port();
        let mut reservation = None;
        let socket = if mode == Mode::Udp {
            let s = UdpSocket::bind(addr).await?;
            port = s.local_addr()?.port();
            s
        } else {
            if !server {
                let ty = if mode == Mode::FakeTcp {
                    Type::STREAM
                } else {
                    Type::DGRAM
                };
                let guard = Socket::new(Domain::IPV4, ty, None)?;
                guard.bind(&addr.into())?;
                port = guard
                    .local_addr()?
                    .as_socket_ipv4()
                    .ok_or(io::Error::other("expected IPv4"))?
                    .port();
                reservation = Some(guard);
            }
            let proto = if mode == Mode::FakeTcp {
                Protocol::TCP
            } else {
                Protocol::ICMPV4
            };
            let s = Socket::new(Domain::IPV4, Type::RAW, Some(proto))?;
            s.set_header_included_v4(true)?;
            s.bind(&SocketAddrV4::new(*addr.ip(), 0).into())?;
            s.set_nonblocking(true)?;
            UdpSocket::from_std(s.into())?
        };
        Ok(Arc::new(Self {
            mode,
            socket,
            port,
            server,
            _reservation: reservation,
        }))
    }
    pub async fn client_route(&self, peer: SocketAddrV4) -> io::Result<Route> {
        let probe = UdpSocket::bind("0.0.0.0:0").await?;
        probe.connect(peer).await?;
        Ok(Route {
            local: *v4(probe.local_addr()?)?.ip(),
            peer,
            seq: u32::from_be_bytes(random()),
            ack: 0,
            echo_seq: 0,
        })
    }
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<Option<Incoming>> {
        let (n, from) = self.socket.recv_from(buf).await?;
        if self.mode == Mode::Udp {
            let route = Route {
                local: Ipv4Addr::UNSPECIFIED,
                peer: v4(from)?,
                seq: 0,
                ack: 0,
                echo_seq: 0,
            };
            return Ok(Some(Incoming {
                route,
                segment: Segment::Data,
                body: buf[..n].to_vec(),
            }));
        }
        Ok(self.parse_raw(&buf[..n]))
    }
    fn parse_raw(&self, p: &[u8]) -> Option<Incoming> {
        if p.len() < 20 || p[0] >> 4 != 4 {
            return None;
        }
        let h = (p[0] & 15) as usize * 4;
        let len = word(p, 2) as usize;
        if h < 20 || h > len || len > p.len() {
            return None;
        }
        let src = Ipv4Addr::from(<[u8; 4]>::try_from(&p[12..16]).ok()?);
        let mut route = Route {
            local: Ipv4Addr::from(<[u8; 4]>::try_from(&p[16..20]).ok()?),
            peer: SocketAddrV4::new(src, 0),
            seq: 0,
            ack: 0,
            echo_seq: 0,
        };
        let t = &p[h..len];
        let (segment, body) = if self.mode == Mode::Icmp {
            if t.len() < 8 || t[0] != if self.server { 8 } else { 0 } || t[1] != 0 {
                return None;
            }
            let id = word(t, 4);
            if !self.server && id != self.port {
                return None;
            }
            route.peer.set_port(id);
            route.echo_seq = word(t, 6);
            (Segment::Data, &t[8..])
        } else {
            if t.len() < 20 || word(t, 2) != self.port {
                return None;
            }
            let offset = (t[12] >> 4) as usize * 4;
            if offset < 20 || offset > t.len() {
                return None;
            }
            let body = &t[offset..];
            let flags = t[13];
            let seg = match flags & 0x17 {
                2 if self.server && body.is_empty() => Segment::Syn,
                0x12 if !self.server && body.is_empty() => Segment::SynAck,
                0x10 if !body.is_empty() => Segment::Data,
                _ => return None,
            };
            route.peer.set_port(word(t, 0));
            route.seq = u32::from_be_bytes(t[8..12].try_into().ok()?);
            let start = u32::from_be_bytes(t[4..8].try_into().ok()?);
            route.ack = start.wrapping_add(body.len() as u32 + u32::from(seg != Segment::Data));
            (seg, body)
        };
        Some(Incoming {
            route,
            segment,
            body: body.to_vec(),
        })
    }
    pub async fn send(&self, route: &mut Route, segment: Segment, body: &[u8]) -> io::Result<()> {
        if self.mode == Mode::Udp {
            self.socket.send_to(body, route.peer).await?;
            return Ok(());
        }
        let tcp = self.mode == Mode::FakeTcp;
        let h = if tcp { 20 } else { 8 };
        let proto = if tcp { 6 } else { 1 };
        let len = 20 + h + body.len();
        let mut p = vec![0; len];
        p[0] = 0x45;
        put(&mut p, 2, len as u16);
        p[8] = 64;
        p[9] = proto;
        p[12..16].copy_from_slice(&route.local.octets());
        p[16..20].copy_from_slice(&route.peer.ip().octets());
        let t = &mut p[20..];
        t[h..].copy_from_slice(body);
        if tcp {
            put(t, 0, self.port);
            put(t, 2, route.peer.port());
            t[4..8].copy_from_slice(&route.seq.to_be_bytes());
            t[8..12].copy_from_slice(&route.ack.to_be_bytes());
            t[12] = 5 << 4;
            t[13] = match segment {
                Segment::Syn => 2,
                Segment::SynAck => 0x12,
                Segment::Data => 0x18,
            };
            put(t, 14, 65535);
            let mut pseudo = [0; 12];
            pseudo[..4].copy_from_slice(&route.local.octets());
            pseudo[4..8].copy_from_slice(&route.peer.ip().octets());
            pseudo[9] = proto;
            put(&mut pseudo, 10, t.len() as u16);
            let sum = checksum(t, sum_words(&pseudo));
            put(t, 16, sum);
        } else {
            t[0] = if self.server { 0 } else { 8 };
            put(
                t,
                4,
                if self.server {
                    route.peer.port()
                } else {
                    self.port
                },
            );
            put(t, 6, route.echo_seq);
            let sum = checksum(t, 0);
            put(t, 2, sum);
        }
        self.socket
            .send_to(&p, SocketAddrV4::new(*route.peer.ip(), 0))
            .await?;
        if segment == Segment::Data {
            route.seq = route.seq.wrapping_add(body.len() as u32);
        }
        if !self.server {
            route.echo_seq = route.echo_seq.wrapping_add(1);
        }
        Ok(())
    }
}

impl Route {
    pub fn observe(&mut self, received: &Route) {
        // Accept out-of-order data without moving the TCP acknowledgment backwards.
        if received.ack.wrapping_sub(self.ack) as i32 > 0 {
            self.ack = received.ack;
        }
        self.echo_seq = received.echo_seq;
    }
}
fn word(p: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([p[i], p[i + 1]])
}
fn put(p: &mut [u8], i: usize, n: u16) {
    p[i..i + 2].copy_from_slice(&n.to_be_bytes());
}
fn sum_words(p: &[u8]) -> u32 {
    p.chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum()
}
fn checksum(p: &[u8], initial: u32) -> u16 {
    let mut sum = sum_words(p) + initial;
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
