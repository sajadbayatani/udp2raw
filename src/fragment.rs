//! Each fragment is a separately authenticated modern frame. A sender emits
//! all pieces consecutively, so (serial - index) identifies the datagram.
use crate::wire::{Frame, Kind, SessionId};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

pub const MIN_CHUNK: usize = 512;
pub const MAX_CHUNK: usize = 4096;
const MAX_PENDING: usize = 128;
const LIFETIME: Duration = Duration::from_secs(5);

pub fn encode(total: usize, width: usize, index: usize, chunk: &[u8]) -> Vec<u8> {
    let mut part = Vec::with_capacity(6 + chunk.len());
    for n in [total, width, index] {
        part.extend((n as u16).to_be_bytes());
    }
    part.extend_from_slice(chunk);
    part
}

struct Pending {
    data: Vec<u8>,
    width: usize,
    received: u128,
    remaining: usize,
    created: Instant,
}

#[derive(Default)]
pub struct Reassembly {
    pending: HashMap<(SessionId, u64, u64, u64), Pending>,
}

impl Reassembly {
    pub fn expire(&mut self) {
        self.pending.retain(|_, p| p.created.elapsed() < LIFETIME);
    }

    /// Called only after the session, epoch, cookie, and replay checks.
    pub fn payload(&mut self, frame: Frame, mtu: usize) -> Option<Vec<u8>> {
        if frame.kind == Kind::Data {
            return Some(frame.data);
        }
        let (&[a, b, c, d, e, f], chunk) = frame.data.split_first_chunk::<6>()?;
        let total = u16::from_be_bytes([a, b]) as usize;
        let width = u16::from_be_bytes([c, d]) as usize;
        let index = u16::from_be_bytes([e, f]) as usize;
        if total > mtu || !(MIN_CHUNK..=MAX_CHUNK).contains(&width) || total <= width {
            return None;
        }
        let offset = index * width;
        if offset >= total || chunk.len() != width.min(total - offset) {
            return None;
        }
        let first = frame.serial.checked_sub(index as u64)?;
        if first == 0 {
            return None;
        }
        let key = (frame.session, frame.epoch, frame.flow, first);
        let full = self.pending.len() >= MAX_PENDING;
        let p = match self.pending.entry(key) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(_) if full => return None,
            std::collections::hash_map::Entry::Vacant(entry) => entry.insert(Pending {
                data: vec![0; total],
                width,
                received: 0,
                remaining: total.div_ceil(width),
                created: Instant::now(),
            }),
        };
        if p.created.elapsed() >= LIFETIME || p.data.len() != total || p.width != width {
            return None;
        }
        // MAX_DATA / MIN_CHUNK requires at most 118 pieces.
        let mask = 1u128 << index;
        if p.received & mask != 0 {
            return None;
        }
        p.data[offset..offset + chunk.len()].copy_from_slice(chunk);
        p.received |= mask;
        p.remaining -= 1;
        if p.remaining == 0 {
            return self.pending.remove(&key).map(|p| p.data);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn piece(index: usize, epoch: u64, flow: u64) -> Frame {
        let chunk = if index == 0 { vec![7; 512] } else { vec![8; 1] };
        Frame {
            kind: Kind::Fragment,
            session: [1; 16],
            epoch,
            cookie: [2; 16],
            serial: 50 + index as u64,
            flow,
            data: encode(513, 512, index, &chunk),
        }
    }

    #[test]
    fn reorders_deduplicates_and_isolates_incomplete_datagrams() {
        let mut rx = Reassembly::default();
        assert!(rx.payload(piece(1, 1, 9), 512).is_none());
        assert!(rx.pending.is_empty());
        assert!(rx.payload(piece(1, 1, 9), 513).is_none());
        assert!(rx.payload(piece(1, 1, 9), 513).is_none());
        assert!(rx.payload(piece(0, 2, 9), 513).is_none());
        assert!(rx.payload(piece(0, 1, 10), 513).is_none());
        let mut malformed = piece(0, 1, 9);
        malformed.data.pop();
        assert!(rx.payload(malformed, 513).is_none());
        let mut expected = vec![7; 512];
        expected.push(8);
        assert_eq!(rx.payload(piece(0, 1, 9), 513).unwrap(), expected);
        assert_eq!(rx.pending.len(), 2);
        for p in rx.pending.values_mut() {
            p.created -= LIFETIME;
        }
        rx.expire();
        assert!(rx.pending.is_empty());
    }
}
