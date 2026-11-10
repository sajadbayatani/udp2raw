//! Interoperability with the C++ bare handshake and safer datagram formats.
mod crypto;

use crate::{config::Config, wire::random};
use crypto::Crypto;
use std::{io, str::FromStr};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Cipher {
    #[default]
    Cbc,
    Cfb,
    CfbOld,
    Xor,
    None,
}
impl FromStr for Cipher {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "aes128cbc" => Ok(Self::Cbc),
            "aes128cfb" => Ok(Self::Cfb),
            "aes128cfb_0" => Ok(Self::CfbOld),
            "xor" => Ok(Self::Xor),
            "none" => Ok(Self::None),
            _ => Err(format!("unknown legacy cipher {s}")),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Auth {
    #[default]
    Md5,
    HmacSha1,
    Crc32,
    Simple,
    None,
}
impl FromStr for Auth {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "md5" => Ok(Self::Md5),
            "hmac_sha1" => Ok(Self::HmacSha1),
            "crc32" => Ok(Self::Crc32),
            "simple" => Ok(Self::Simple),
            "none" => Ok(Self::None),
            _ => Err(format!("unknown legacy authentication {s}")),
        }
    }
}

pub fn id() -> u32 {
    loop {
        let n = u32::from_be_bytes(random());
        if n != 0 {
            return n;
        }
    }
}
pub fn session_id(n: u32) -> [u8; 16] {
    let mut s = [0; 16];
    s[..4].copy_from_slice(&n.to_be_bytes());
    s
}
pub fn word(b: &[u8]) -> u32 {
    u32::from_be_bytes(b[..4].try_into().expect("checked 4-byte field"))
}

pub struct Interop {
    crypto: Crypto,
    gro: bool,
    replay: bool,
    heartbeat_only: bool,
    heartbeat_len: usize,
}
impl Interop {
    pub fn new(c: &Config) -> Self {
        Self {
            crypto: Crypto::new(&c.key, c.server, c.cipher_mode, c.auth_mode),
            gro: c.fix_gro,
            replay: !c.disable_anti_replay && c.auth_mode != Auth::None,
            heartbeat_only: c.hb_mode == 1,
            heartbeat_len: if c.hb_mode == 1 { c.hb_len } else { 0 },
        }
    }
    pub fn handshake(&self, sender: u32, receiver: u32, identity: u32) -> Vec<u8> {
        let mut p = Vec::from(random::<16>());
        p.push(b'b');
        for id in [sender, receiver, identity] {
            p.extend(id.to_be_bytes());
        }
        self.crypto.seal(p)
    }
    pub fn read(&self, wire: &[u8]) -> Vec<Packet> {
        if !self.gro {
            return self
                .crypto
                .open(wire)
                .and_then(|p| Packet::parse(&p))
                .into_iter()
                .collect();
        }
        let mut storage = wire.to_vec();
        let mut input = storage.as_mut_slice();
        let mut packets = Vec::new();
        while input.len() >= 16 {
            if self.crypto.gro_header(input, false).is_none() {
                break;
            }
            let len = usize::from(u16::from_be_bytes([input[0], input[1]]));
            if len == 0 || len > 1800 || len + 2 > input.len() {
                break;
            }
            let (frame, rest) = input.split_at_mut(len + 2);
            if let Some(p @ Packet::Safer { .. }) = self
                .crypto
                .open(&frame[2..])
                .and_then(|p| Packet::parse(&p))
            {
                packets.push(p);
            }
            input = rest;
        }
        // Handshakes are unframed even with GRO. Prefer valid safer frames
        // first: in none/none mode a length-prefixed datagram can coincidentally
        // contain the bare handshake marker at byte 16.
        if packets.is_empty() && wire.len() <= 128 {
            if let Some(p @ Packet::Handshake { .. }) =
                self.crypto.open(wire).and_then(|p| Packet::parse(&p))
            {
                packets.push(p);
            }
        }
        packets
    }
    pub fn safer(&self, link: &mut Link, conv: Option<u32>, data: &[u8]) -> io::Result<Vec<u8>> {
        if data.len() > 1800 {
            return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
        }
        let mut p = Vec::with_capacity(22 + data.len());
        p.extend(link.local.to_be_bytes());
        p.extend(link.peer.to_be_bytes());
        p.extend(link.serial.to_be_bytes());
        link.serial += 1;
        p.push(if conv.is_some() { b'd' } else { b'h' });
        p.push(link.roller);
        if let Some(conv) = conv {
            p.extend(conv.to_be_bytes());
            p.extend(data);
        } else {
            p.resize(p.len() + self.heartbeat_len, 0);
        }
        let crypt = self.crypto.seal(p);
        if crypt.len() > 1800 {
            return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
        }
        if !self.gro {
            return Ok(crypt);
        }
        let mut framed = Vec::with_capacity(2 + crypt.len());
        framed.extend((crypt.len() as u16).to_be_bytes());
        framed.extend(crypt);
        self.crypto
            .gro_header(&mut framed, true)
            .expect("safer frame has at least 18 bytes");
        Ok(framed)
    }
}
pub enum Packet {
    Handshake {
        sender: u32,
        receiver: u32,
        identity: u32,
    },
    Safer {
        sender: u32,
        receiver: u32,
        sequence: u64,
        roller: u8,
        body: Payload,
    },
}
pub enum Payload {
    Heartbeat,
    Data(u32, Vec<u8>),
}
impl Packet {
    fn parse(p: &[u8]) -> Option<Self> {
        if p.len() < 18 {
            return None;
        }
        if p[16] == b'b' && p.len() == 29 {
            let (sender, receiver, identity) = (word(&p[17..]), word(&p[21..]), word(&p[25..]));
            if sender == 0 || identity == 0 {
                return None;
            }
            return Some(Self::Handshake {
                sender,
                receiver,
                identity,
            });
        }
        let body = match p[16] {
            b'h' => Payload::Heartbeat,
            b'd' if p.len() >= 22 => Payload::Data(word(&p[18..]), p[22..].to_vec()),
            _ => return None,
        };
        Some(Self::Safer {
            sender: word(p),
            receiver: word(&p[4..]),
            sequence: u64::from_be_bytes(p[8..16].try_into().ok()?),
            roller: p[17],
            body,
        })
    }
}
pub struct Link {
    handshake: Option<(u32, u32, Vec<u8>)>,
    pub local: u32,
    pub peer: u32,
    serial: u64,
    roller: u8,
    pub peer_roller: Option<u8>,
    window: Replay,
}
impl Link {
    pub fn new(local: u32, peer: u32) -> Self {
        Self {
            local,
            peer,
            serial: u64::from_be_bytes(random()) / 10 + 1,
            roller: 0,
            peer_roller: None,
            handshake: None,
            window: Replay::default(),
        }
    }
    /// Retransmit a bare FakeTCP handshake at its original sequence number.
    /// The application's seq-mode only takes effect once the link is ready.
    pub async fn send_handshake(
        &mut self,
        io: &Interop,
        carrier: &crate::transport::Carrier,
        route: &mut crate::transport::Route,
        receiver: u32,
        identity: u32,
    ) -> io::Result<()> {
        if self
            .handshake
            .as_ref()
            .is_none_or(|(peer, _, _)| *peer != receiver)
        {
            self.handshake = Some((
                receiver,
                route.seq,
                io.handshake(self.local, receiver, identity),
            ));
        }
        let (_, seq, packet) = self.handshake.as_ref().unwrap();
        if crate::packet::tcp(carrier.mode) {
            route.seq = *seq;
        }
        carrier
            .send(route, crate::transport::Segment::Data, packet)
            .await?;
        if crate::packet::tcp(carrier.mode) {
            route.seq = seq.wrapping_add(packet.len() as u32);
        }
        Ok(())
    }

    pub fn accept(
        &mut self,
        io: &Interop,
        sender: u32,
        receiver: u32,
        seq: u64,
        roller: u8,
        body: &Payload,
    ) -> bool {
        if sender != self.peer || receiver != self.local || (io.replay && !self.window.accept(seq))
        {
            return false;
        }
        self.peer_roller = Some(roller);
        if matches!(body, Payload::Heartbeat) || !io.heartbeat_only {
            self.roller = self.roller.wrapping_add(1);
        }
        true
    }
}
#[derive(Default)]
struct Replay {
    high: u64,
    slots: Vec<u64>,
}
impl Replay {
    fn accept(&mut self, n: u64) -> bool {
        const SIZE: u64 = 4000;
        if n == 0 || self.high.saturating_sub(n) >= SIZE {
            return false;
        }
        if self.slots.is_empty() {
            self.slots.resize(SIZE as usize, 0);
        }
        let slot = &mut self.slots[(n % SIZE) as usize];
        if *slot == n {
            return false;
        }
        *slot = n;
        self.high = self.high.max(n);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn decrypts_cpp_client_fixtures() {
        // Plaintext 00..1f encrypted with commit 4208db6, key "interop fixture".
        // CBC fixtures also cover the C++ padding convention (only the last byte matters).
        let fixtures=[
            (Cipher::Cbc,Auth::Md5,"cfb4a73fea6103c13808dda55cc92165a0b72386ed9dfb3dc6fb4e364d449fe9864ef721c2a9f8c9507e0d1591d764cbe42b9c343fe45af87b845365bfb1e839"),
            (Cipher::Cfb,Auth::HmacSha1,"70bf085eb03a8eb095147279cf3f958c2d55222fe21bba1203beaf96093880559fb918724fca6ac4148ca13e4e2e12d32cbd3903"),
            (Cipher::CfbOld,Auth::Crc32,"092bf6b11bc53c87f285ea77ca5b775d92d8cc13ea5f3bcd7c7354feb09cae31872bb9f9"),
            (Cipher::Xor,Auth::Simple,"427d0be294051a8c039a883457906ea7526d1bf284150a9c138a982447807eb7105154e45a879c9b"),
        ];
        let plain: Vec<u8> = (0..32).collect();
        for (cipher, auth, hex) in fixtures {
            let io = Crypto::new("interop fixture", true, cipher, auth);
            assert_eq!(
                io.open(&bytes(hex)),
                Some(plain.clone()),
                "{cipher:?}/{auth:?}"
            );
        }
    }

    #[test]
    fn gro_recovers_each_frame_and_rejects_a_replay() {
        let endpoint = |server| Interop {
            crypto: Crypto::new("GRO test", server, Cipher::Cfb, Auth::HmacSha1),
            gro: true,
            replay: true,
            heartbeat_only: true,
            heartbeat_len: 32,
        };
        let (client, server) = (endpoint(false), endpoint(true));
        let (mut tx, mut rx) = (Link::new(3, 4), Link::new(4, 3));
        let first = client.safer(&mut tx, None, &[]).unwrap();
        let second = client.safer(&mut tx, Some(5), b"packet").unwrap();
        let coalesced = [first.as_slice(), second.as_slice(), first.as_slice()].concat();
        let seen: Vec<_> = server
            .read(&coalesced)
            .into_iter()
            .filter_map(|p| match p {
                Packet::Safer {
                    sender,
                    receiver,
                    sequence,
                    roller,
                    body,
                } => Some(rx.accept(&server, sender, receiver, sequence, roller, &body)),
                _ => None,
            })
            .collect();
        assert_eq!(seen, vec![true, true, false]);
        let mut altered = second;
        *altered.last_mut().unwrap() ^= 1;
        assert!(server.read(&altered).is_empty());
        assert!(server.read(&first[..first.len() - 1]).is_empty());
    }
}
