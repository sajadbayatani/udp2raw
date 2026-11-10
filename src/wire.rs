use crate::config::Mode;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use std::io;

pub const MAX_DATA: usize = 60_000;
pub type SessionId = [u8; 16];
pub type Cookie = [u8; 16];

pub fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    getrandom::getrandom(&mut bytes).expect("OS random number generator unavailable");
    bytes
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Kind {
    Hello = 1,
    Welcome,
    Ping,
    Pong,
    Data,
}

pub struct Frame {
    pub kind: Kind,
    pub session: SessionId,
    pub epoch: u64,
    pub cookie: Cookie,
    pub serial: u64,
    pub flow: u64,
    pub data: Vec<u8>,
}

pub struct Codec {
    cipher: XChaCha20Poly1305,
    server: bool,
}
impl Codec {
    pub fn new(key: &str, server: bool) -> Self {
        let mut derived = [0; 32];
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
            key.as_bytes(),
            b"udp2raw-rust-v1 shared key",
            210_000,
            &mut derived,
        );
        Self {
            cipher: XChaCha20Poly1305::new((&derived).into()),
            server,
        }
    }
    // Bind direction and carrier to every authenticated frame. Kernel ICMP
    // echo replies and frames copied between different carriers cannot pass.
    fn aad(server: bool, mode: Mode, port: u16) -> [u8; 8] {
        let [hi, lo] = if mode == Mode::Icmp { port } else { 0 }.to_be_bytes();
        [b'U', b'2', b'R', 1, server as u8, mode as u8, hi, lo]
    }
    pub fn seal(&self, f: &Frame, mode: Mode, port: u16) -> io::Result<Vec<u8>> {
        let mut plain = Vec::with_capacity(57 + f.data.len());
        plain.push(f.kind as u8);
        plain.extend(f.session);
        plain.extend(f.epoch.to_be_bytes());
        plain.extend(f.cookie);
        plain.extend(f.serial.to_be_bytes());
        plain.extend(f.flow.to_be_bytes());
        plain.extend_from_slice(&f.data);
        let nonce = random::<24>();
        let mut packet = Vec::from(nonce);
        packet.extend(
            self.cipher
                .encrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &plain,
                        aad: &Self::aad(self.server, mode, port),
                    },
                )
                .map_err(|_| io::Error::other("encryption failed"))?,
        );
        Ok(packet)
    }
    pub fn open(&self, packet: &[u8], mode: Mode, port: u16) -> Option<Frame> {
        if !(97..=97 + MAX_DATA).contains(&packet.len()) {
            return None;
        }
        let p = self
            .cipher
            .decrypt(
                XNonce::from_slice(&packet[..24]),
                Payload {
                    msg: &packet[24..],
                    aad: &Self::aad(!self.server, mode, port),
                },
            )
            .ok()?;
        let kind = match p[0] {
            1 => Kind::Hello,
            2 => Kind::Welcome,
            3 => Kind::Ping,
            4 => Kind::Pong,
            5 => Kind::Data,
            _ => return None,
        };
        if kind != Kind::Data && p.len() != 57 {
            return None;
        }
        Some(Frame {
            kind,
            session: p[1..17].try_into().ok()?,
            epoch: u64::from_be_bytes(p[17..25].try_into().ok()?),
            cookie: p[25..41].try_into().ok()?,
            serial: u64::from_be_bytes(p[41..49].try_into().ok()?),
            flow: u64::from_be_bytes(p[49..57].try_into().ok()?),
            data: p[57..].to_vec(),
        })
    }
}

#[derive(Default)]
pub struct Window {
    high: u64,
    seen: u128,
}
impl Window {
    pub fn accept(&mut self, n: u64) -> bool {
        if n == 0 {
            return false;
        }
        if n > self.high {
            self.seen = self
                .seen
                .checked_shl((n - self.high).min(128) as u32)
                .unwrap_or(0);
            self.high = n;
        }
        let age = self.high - n;
        if age >= 128 || self.seen & (1u128 << age) != 0 {
            return false;
        }
        self.seen |= 1u128 << age;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window_accepts_reordering_once() {
        let mut w = Window::default();
        assert!(!w.accept(0));
        assert!(w.accept(130));
        assert!(w.accept(3));
        assert!(!w.accept(3));
        assert!(!w.accept(2));
        assert!(w.accept(10000));
        assert!(!w.accept(130));
    }

    #[test]
    fn envelope_authenticates_direction_mode_port_and_bytes() {
        let client = Codec {
            cipher: XChaCha20Poly1305::new((&[1; 32]).into()),
            server: false,
        };
        let server = Codec {
            cipher: client.cipher.clone(),
            server: true,
        };
        let f = Frame {
            kind: Kind::Data,
            session: random(),
            epoch: 1,
            cookie: random(),
            serial: 3,
            flow: 2,
            data: vec![0, 255, 1],
        };
        let mut packet = client.seal(&f, Mode::Icmp, 4096).unwrap();
        assert_eq!(server.open(&packet, Mode::Icmp, 4096).unwrap().data, f.data);
        assert!(client.open(&packet, Mode::Icmp, 4096).is_none());
        assert!(server.open(&packet, Mode::Icmp, 4097).is_none());
        assert!(server.open(&packet, Mode::Udp, 4096).is_none());
        packet[40] ^= 1;
        assert!(server.open(&packet, Mode::Icmp, 4096).is_none());
    }
}
