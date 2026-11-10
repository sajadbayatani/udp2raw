//! udp2raw's original encrypt.cpp format. The HMAC mode uses independent
//! directional keys and encrypt-then-MAC. All other checksums precede encryption.
use super::{Auth, Cipher};
use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;

type Sha1Mac = Hmac<Sha1>;

struct Keys {
    encryption: [u8; 16],
    prefix: Aes128,
    mac: [u8; 20],
}

pub struct Crypto {
    tx: Keys,
    rx: Keys,
    mask: [u8; 2],
    cipher: Cipher,
    auth: Auth,
}

impl Crypto {
    pub fn new(password: &str, server: bool, cipher: Cipher, auth: Auth) -> Self {
        let original_key: [u8; 16] = Md5::new()
            .chain_update(password)
            .chain_update(b"key1")
            .finalize()
            .into();
        let salt = Md5::digest(b"udp2raw_salt1");
        let mut derived = [0; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 10_000, &mut derived);
        let hk = Hkdf::<Sha256>::from_prk(&derived).expect("32-byte PRK");
        let keys = |server: bool| {
            let dir = if server {
                "server-->client"
            } else {
                "client-->server"
            };
            let mut ecb = [0; 16];
            let mut mac = [0; 20];
            hk.expand(format!("cipher_key {dir}").as_bytes(), &mut ecb)
                .expect("16-byte expansion");
            hk.expand(format!("hmac_key {dir}").as_bytes(), &mut mac)
                .expect("20-byte expansion");
            Keys {
                encryption: if auth == Auth::HmacSha1 {
                    ecb
                } else {
                    original_key
                },
                prefix: Aes128::new((&ecb).into()),
                mac,
            }
        };
        let mut mask = [0; 2];
        hk.expand(b"gro", &mut mask).expect("two-byte expansion");
        Self {
            tx: keys(server),
            rx: keys(!server),
            mask,
            cipher,
            auth,
        }
    }

    pub fn seal(&self, mut plain: Vec<u8>) -> Vec<u8> {
        if self.auth != Auth::HmacSha1 {
            plain.extend(self.checksum(&plain));
        }
        self.cipher
            .transform(&self.tx, &mut plain, true)
            .expect("valid outbound plaintext");
        if self.auth == Auth::HmacSha1 {
            let mut mac = <Sha1Mac as Mac>::new_from_slice(&self.tx.mac).expect("20-byte key");
            mac.update(&plain);
            plain.extend(mac.finalize().into_bytes());
        }
        plain
    }
    pub fn open(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        if bytes.len() > 1800 {
            return None;
        }
        let ciphertext = if self.auth == Auth::HmacSha1 {
            let (ct, tag) = bytes.split_at(bytes.len().checked_sub(20)?);
            let mut mac = <Sha1Mac as Mac>::new_from_slice(&self.rx.mac).ok()?;
            mac.update(ct);
            mac.verify_slice(tag).ok()?;
            ct
        } else {
            bytes
        };
        let mut plain = ciphertext.to_vec();
        self.cipher.transform(&self.rx, &mut plain, false)?;
        if self.auth != Auth::HmacSha1 {
            let tag_len = match self.auth {
                Auth::Md5 => 16,
                Auth::Crc32 => 4,
                Auth::Simple => 8,
                _ => 0,
            };
            let end = plain.len().checked_sub(tag_len)?;
            if self.checksum(&plain[..end]) != plain[end..] {
                return None;
            }
            plain.truncate(end);
        }
        Some(plain)
    }
    fn checksum(&self, data: &[u8]) -> Vec<u8> {
        match self.auth {
            Auth::Md5 => Md5::digest(data).to_vec(),
            Auth::Crc32 => crc32fast::hash(data).to_be_bytes().to_vec(),
            Auth::Simple => {
                let (mut a, mut b) = (5381u32, 0u32);
                for &v in data {
                    a = a.wrapping_mul(33) ^ u32::from(v);
                    b = b.wrapping_mul(65599).wrapping_add(u32::from(v));
                }
                [a.to_be_bytes(), b.to_be_bytes()].concat()
            }
            _ => Vec::new(),
        }
    }
    pub fn gro_header(&self, packet: &mut [u8], sending: bool) -> Option<()> {
        let keys = if sending { &self.tx } else { &self.rx };
        match self.cipher {
            Cipher::Xor => {
                for (a, b) in packet.get_mut(..2)?.iter_mut().zip(self.mask) {
                    *a ^= b;
                }
            }
            Cipher::None => {}
            _ => {
                let block = GenericArray::from_mut_slice(packet.get_mut(..16)?);
                if sending {
                    keys.prefix.encrypt_block(block);
                } else {
                    keys.prefix.decrypt_block(block);
                }
            }
        }
        Some(())
    }
}

impl Cipher {
    fn transform(self, keys: &Keys, data: &mut Vec<u8>, encrypt: bool) -> Option<()> {
        match self {
            Self::None => return Some(()),
            Self::Xor => {
                for (idx, byte) in data.iter_mut().enumerate() {
                    *byte ^= keys.encryption[idx % 16];
                }
                return Some(());
            }
            _ => {}
        }
        let aes = Aes128::new((&keys.encryption).into());
        let mut chain = [0; 16];
        if self == Self::Cbc {
            if encrypt {
                let padding = 16 - data.len() % 16;
                data.resize(data.len() + padding, 0);
                *data.last_mut()? = padding as u8;
            } else if data.is_empty() || !data.len().is_multiple_of(16) {
                return None;
            }
            for chunk in data.chunks_exact_mut(16) {
                let block = GenericArray::from_mut_slice(chunk);
                if encrypt {
                    for (byte, iv) in block.iter_mut().zip(chain) {
                        *byte ^= iv;
                    }
                    aes.encrypt_block(block);
                    chain.copy_from_slice(block);
                } else {
                    let next: [u8; 16] = (*block).into();
                    aes.decrypt_block(block);
                    for (byte, iv) in block.iter_mut().zip(chain) {
                        *byte ^= iv;
                    }
                    chain = next;
                }
            }
            if !encrypt {
                let padding = usize::from(*data.last()?);
                if !(1..=16).contains(&padding) {
                    return None;
                }
                data.truncate(data.len().checked_sub(padding)?);
            }
        } else {
            if self == Self::Cfb && encrypt {
                keys.prefix
                    .encrypt_block(GenericArray::from_mut_slice(data.get_mut(..16)?));
            }
            for chunk in data.chunks_mut(16) {
                aes.encrypt_block((&mut chain).into());
                for (byte, feedback) in chunk.iter_mut().zip(chain.iter_mut()) {
                    let ciphertext = *byte;
                    *byte ^= *feedback;
                    *feedback = if encrypt { *byte } else { ciphertext };
                }
            }
            if self == Self::Cfb && !encrypt {
                keys.prefix
                    .decrypt_block(GenericArray::from_mut_slice(data.get_mut(..16)?));
            }
        }
        Some(())
    }
}
