//! IP carrier encoding shared by raw sockets and link-layer backends.
use crate::{config::Mode, wire::random};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::OnceLock,
    time::Instant,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Segment {
    Syn,
    SynAck,
    Data,
    Reset,
}

#[derive(Clone, Copy, Debug)]
pub struct Route {
    pub local: IpAddr,
    pub peer: SocketAddr,
    pub seq: u32,
    pub ack: u32,
    pub echo_seq: u16,
    seq_mode: u8,
    received_start: u32,
    peer_ack: Option<u32>,
    duplicate_acks: u8,
    ts_echo: u32,
    ts_offset: u32,
}

pub struct Incoming {
    pub route: Route,
    pub segment: Segment,
    pub body: Vec<u8>,
}

fn time_ms() -> u32 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u32
}

pub fn tcp(mode: Mode) -> bool {
    matches!(mode, Mode::FakeTcp | Mode::EasyFakeTcp)
}

pub fn protocol(mode: Mode, ipv6: bool) -> u8 {
    match mode {
        Mode::Icmp if ipv6 => 58,
        Mode::Icmp => 1,
        Mode::Udp => 17,
        _ => 6,
    }
}

impl Route {
    pub fn new(local: IpAddr, peer: SocketAddr, seq: u32, seq_mode: u8) -> Self {
        Self {
            local,
            peer,
            seq,
            ack: 0,
            echo_seq: 0,
            seq_mode,
            received_start: 0,
            peer_ack: None,
            duplicate_acks: 0,
            ts_echo: 0,
            ts_offset: 0,
        }
    }

    pub fn observe(&mut self, received: &Route) {
        self.ts_echo = received.ts_echo;
        if (received.seq_mode <= 2 || received.received_start == self.ack)
            && ahead(received.ack, self.ack)
        {
            self.ack = received.ack;
        }
        self.duplicate_acks = if self.peer_ack == Some(received.seq) {
            self.duplicate_acks.saturating_add(1)
        } else {
            0
        };
        self.peer_ack = Some(received.seq);
        if received.echo_seq.wrapping_sub(self.echo_seq) as i16 > 0 {
            self.echo_seq = received.echo_seq;
        }
    }

    pub fn sent(&mut self, mode: Mode, server: bool, segment: Segment, len: usize) {
        if mode == Mode::Icmp && !server {
            self.echo_seq = self.echo_seq.wrapping_add(1);
        }
        if !tcp(mode) || segment != Segment::Data || len == 0 {
            return;
        }
        match self.seq_mode {
            0 => {}
            2 if u32::from_ne_bytes(random()) % 5 != 3 => {}
            _ => self.seq = self.seq.wrapping_add(len as u32),
        }
        if self.seq_mode >= 3 {
            if let Some(peer_ack) = self.peer_ack {
                let window = if self.seq_mode == 3 {
                    40_960 << 5
                } else {
                    40_960
                };
                if ahead(self.seq.wrapping_add(1800), peer_ack.wrapping_add(window))
                    || self.duplicate_acks >= 3
                    || ahead(peer_ack, self.seq)
                {
                    self.seq = peer_ack;
                    self.duplicate_acks = 0;
                }
            }
        }
    }
}

fn ahead(n: u32, prev: u32) -> bool {
    n.wrapping_sub(prev) as i32 > 0
}

pub fn encode(
    mode: Mode,
    server: bool,
    port: u16,
    route: &Route,
    segment: Segment,
    data: &[u8],
    ttl: u8,
) -> io::Result<Vec<u8>> {
    let v6 = route.local.is_ipv6();
    let syn = matches!(segment, Segment::Syn | Segment::SynAck);
    let hdr = if tcp(mode) {
        if syn {
            40
        } else {
            32
        }
    } else {
        8
    };
    let iphdr = if v6 { 40 } else { 20 };
    let size = iphdr + hdr + data.len();
    if size > 65535 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "datagram too large",
        ));
    }
    let mut packet = vec![0; size];
    let proto = protocol(mode, v6);
    match (route.local, route.peer.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            packet[0] = 0x45;
            put(&mut packet, 2, size as u16);
            packet[4..6].copy_from_slice(&random::<2>());
            packet[8] = ttl;
            packet[9] = proto;
            packet[12..16].copy_from_slice(&src.octets());
            packet[16..20].copy_from_slice(&dst.octets());
            let csum = checksum(&packet[..20], 0);
            put(&mut packet, 10, csum);
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            packet[0] = 0x60;
            put(&mut packet, 4, (size - 40) as u16);
            packet[6] = proto;
            packet[7] = ttl;
            packet[8..24].copy_from_slice(&src.octets());
            packet[24..40].copy_from_slice(&dst.octets());
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "mismatched source and destination address families",
            ))
        }
    }
    let pseudo = if mode == Mode::Icmp && !v6 {
        0
    } else {
        let ips = if v6 { &packet[8..40] } else { &packet[12..20] };
        sum(ips) + u32::from(proto) + (size - iphdr) as u32
    };
    let t = &mut packet[iphdr..];
    t[hdr..].copy_from_slice(data);
    let checksum_offset = match mode {
        Mode::Udp => {
            put(t, 0, port);
            put(t, 2, route.peer.port());
            put(t, 4, (hdr + data.len()) as u16);
            6
        }
        Mode::Icmp => {
            t[0] = match (v6, server) {
                (false, true) => 0,
                (false, false) => 8,
                (true, true) => 129,
                (true, false) => 128,
            };
            put(t, 4, if server { route.peer.port() } else { port });
            put(t, 6, route.echo_seq);
            2
        }
        _ => {
            put(t, 0, port);
            put(t, 2, route.peer.port());
            t[4..8].copy_from_slice(&route.seq.to_be_bytes());
            t[8..12].copy_from_slice(&route.ack.to_be_bytes());
            t[12] = ((hdr / 4) << 4) as u8;
            t[13] = match segment {
                Segment::Syn => 2,
                Segment::SynAck => 0x12,
                Segment::Data => 0x18,
                Segment::Reset => 4,
            };
            put(t, 14, 40_960 + u16::from_ne_bytes(random()) % 512);
            let start = if syn {
                t[20..28].copy_from_slice(&[2, 4, 5, 180, 4, 2, 8, 10]);
                t[36..40].copy_from_slice(&[1, 3, 3, 5]);
                28
            } else {
                t[20..24].copy_from_slice(&[1, 1, 8, 10]);
                24
            };
            t[start..start + 4]
                .copy_from_slice(&time_ms().wrapping_add(route.ts_offset).to_be_bytes());
            t[start + 4..start + 8].copy_from_slice(&route.ts_echo.to_be_bytes());
            16
        }
    };
    let check = checksum(t, pseudo);
    put(
        t,
        checksum_offset,
        if mode == Mode::Udp && check == 0 {
            0xffff
        } else {
            check
        },
    );
    Ok(packet)
}

pub fn decode(p: &[u8], mode: Mode, server: bool, port: u16, seq_mode: u8) -> Option<Incoming> {
    let (src, dst, proto, t) = match p.first()? >> 4 {
        4 if p.len() >= 20 => {
            let offset = (p[0] & 15) as usize * 4;
            if offset < 20 || word(p, 6) & 0x3fff != 0 {
                return None;
            }
            (
                IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&p[12..16]).ok()?)),
                IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&p[16..20]).ok()?)),
                p[9],
                p.get(offset..word(p, 2) as usize)?,
            )
        }
        6 if p.len() >= 40 => {
            let mut next = p[6];
            let mut data = p.get(40..40 + word(p, 4) as usize)?;
            // Walk common IPv6 extension headers. Only atomic fragments can be
            // decoded on a packet socket, IP raw sockets receive reassembled data.
            while matches!(next, 0 | 43 | 44 | 51 | 60) {
                if data.len() < 8 {
                    return None;
                }
                let n = match next {
                    44 if word(data, 2) != 0 => return None,
                    44 => 8,
                    51 => (data[1] as usize + 2) * 4,
                    _ => (data[1] as usize + 1) * 8,
                };
                next = data[0];
                data = data.get(n..)?;
            }
            (
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&p[8..24]).ok()?)),
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&p[24..40]).ok()?)),
                next,
                data,
            )
        }
        _ => return None,
    };
    if proto != protocol(mode, dst.is_ipv6()) {
        return None;
    }
    decode_segment(
        t,
        mode,
        server,
        port,
        seq_mode,
        SocketAddr::new(src, 0),
        dst,
    )
}

pub(crate) fn decode_segment(
    t: &[u8],
    mode: Mode,
    server: bool,
    port: u16,
    seq_mode: u8,
    src: SocketAddr,
    dst: IpAddr,
) -> Option<Incoming> {
    let mut route = Route::new(dst, src, 0, seq_mode);
    let (segment, body) = match mode {
        Mode::Icmp => {
            let ty = match (dst.is_ipv6(), server) {
                (false, true) => 8,
                (false, false) => 0,
                (true, true) => 128,
                (true, false) => 129,
            };
            if t.len() < 8 || t[0] != ty || t[1] != 0 {
                return None;
            }
            let id = word(t, 4);
            if !server && id != port {
                return None;
            }
            route.peer.set_port(id);
            route.echo_seq = word(t, 6);
            (Segment::Data, &t[8..])
        }
        Mode::Udp => {
            if t.len() < 8 || word(t, 2) != port {
                return None;
            }
            route.peer.set_port(word(t, 0));
            (Segment::Data, t.get(8..word(t, 4) as usize)?)
        }
        _ => {
            if t.len() < 20 || word(t, 2) != port {
                return None;
            }
            let offset = (t[12] >> 4) as usize * 4;
            if offset < 20 {
                return None;
            }
            let body = t.get(offset..)?;
            let seg = match t[13] & 0x17 {
                flags if flags & 4 != 0 => Segment::Reset,
                2 if server && body.is_empty() => Segment::Syn,
                0x12 if !server && body.is_empty() => Segment::SynAck,
                0x10 if !body.is_empty() => Segment::Data,
                _ => return None,
            };
            route.peer.set_port(word(t, 0));
            route.seq = u32::from_be_bytes(t[8..12].try_into().ok()?);
            route.peer_ack = Some(route.seq);
            route.received_start = u32::from_be_bytes(t[4..8].try_into().ok()?);
            route.ack = route.received_start.wrapping_add(
                body.len() as u32 + u32::from(matches!(seg, Segment::Syn | Segment::SynAck)),
            );
            let mut options = &t[20..offset];
            while let Some((&kind, rest)) = options.split_first() {
                if kind == 0 {
                    break;
                }
                if kind == 1 {
                    options = rest;
                    continue;
                }
                let len = *rest.first()? as usize;
                if len < 2 || len > options.len() {
                    return None;
                }
                if kind == 8 && len == 10 {
                    route.ts_echo = u32::from_be_bytes(options[2..6].try_into().ok()?);
                    let echoed = u32::from_be_bytes(options[6..10].try_into().ok()?);
                    route.ts_offset = echoed.wrapping_sub(time_ms());
                }
                options = &options[len..];
            }
            (seg, body)
        }
    };
    Some(Incoming {
        route,
        segment,
        body: body.to_vec(),
    })
}

fn word(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}
fn put(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}
fn sum(bytes: &[u8]) -> u32 {
    bytes
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum()
}
fn checksum(bytes: &[u8], initial: u32) -> u16 {
    let mut n = sum(bytes) + initial;
    while n > 0xffff {
        n = (n & 0xffff) + (n >> 16);
    }
    !(n as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_and_v6_checksums_cover_each_carrier_and_odd_sized_payloads() {
        for (src, dst) in [("192.0.2.1", "192.0.2.2"), ("2001:db8::1", "2001:db8::2")] {
            let src: IpAddr = src.parse().unwrap();
            let dst: IpAddr = dst.parse().unwrap();
            for mode in [Mode::FakeTcp, Mode::Udp, Mode::Icmp, Mode::EasyFakeTcp] {
                let route = Route::new(src, SocketAddr::new(dst, 4490), 42, 3);
                let packet = encode(mode, false, 54022, &route, Segment::Data, b"123", 44).unwrap();
                let (header, pseudo) = if src.is_ipv4() {
                    assert_eq!(checksum(&packet[..20], 0), 0);
                    assert_eq!(packet[8], 44);
                    (
                        20,
                        if mode == Mode::Icmp {
                            0
                        } else {
                            sum(&packet[12..20]) + u32::from(packet[9]) + (packet.len() - 20) as u32
                        },
                    )
                } else {
                    assert_eq!(packet[7], 44);
                    (
                        40,
                        sum(&packet[8..40]) + u32::from(packet[6]) + (packet.len() - 40) as u32,
                    )
                };
                assert_eq!(checksum(&packet[header..], pseudo), 0);
                let rx = decode(&packet, mode, true, 4490, 3).unwrap();
                assert_eq!(rx.body, b"123");
                assert_eq!(rx.route.local, dst);
                assert_eq!(rx.route.peer, SocketAddr::new(src, 54022));
            }
        }
    }

    #[test]
    fn sequence_policies_static_sequential_scaled_and_unscaled() {
        for (mode, expected) in [(0, 41000), (1, 42000), (3, 42000), (4, 10)] {
            let mut route = Route::new(
                "127.0.0.1".parse().unwrap(),
                "127.0.0.2:20".parse().unwrap(),
                41000,
                mode,
            );
            route.peer_ack = Some(10);
            route.sent(Mode::FakeTcp, false, Segment::Data, 1000);
            assert_eq!(route.seq, expected);
        }
    }
}
