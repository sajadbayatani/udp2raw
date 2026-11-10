use crate::{
    config::{Config, Mode},
    legacy::{self, Link, Packet, Payload},
    path::Path,
    transport::{Carrier, Incoming, Segment},
    wire::{random, Codec, Kind, SessionId, MAX_DATA},
};
use std::{collections::HashMap, io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::UdpSocket,
    sync::mpsc,
    time::{self, Instant},
};

const MAX_FLOWS: usize = 4096;
pub const IDLE: Duration = Duration::from_secs(300);

#[derive(Default)]
struct Flows {
    by_addr: HashMap<SocketAddr, u64>,
    by_id: HashMap<u64, (SocketAddr, Instant)>,
    next: u32,
}
impl Flows {
    fn id(&mut self, addr: SocketAddr) -> Option<u64> {
        let id = if let Some(&id) = self.by_addr.get(&addr) {
            id
        } else {
            if self.by_addr.len() >= MAX_FLOWS {
                return None;
            }
            // Use the common range of both protocols throughout failover. At
            // wraparound, long-lived conversations may still occupy low IDs.
            let id = loop {
                self.next = self.next.wrapping_add(1);
                let candidate = u64::from(self.next);
                if candidate != 0 && !self.by_id.contains_key(&candidate) {
                    break candidate;
                }
            };
            self.by_addr.insert(addr, id);
            id
        };
        self.by_id.insert(id, (addr, Instant::now()));
        Some(id)
    }
    fn expire(&mut self) {
        self.by_id.retain(|_, (addr, last)| {
            if last.elapsed() < IDLE {
                return true;
            }
            self.by_addr.remove(addr);
            false
        });
    }
}

struct Local {
    socket: Arc<UdpSocket>,
    reader: tokio::task::JoinHandle<()>,
    packets: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    flows: Flows,
}

impl Drop for Local {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl Local {
    async fn deliver(&mut self, flow: u64, data: &[u8]) {
        if let Some((addr, last)) = self.flows.by_id.get_mut(&flow) {
            *last = Instant::now();
            let _ = self.socket.send_to(data, *addr).await;
        }
    }
    async fn bind(addr: SocketAddr, mtu_warn: usize) -> io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        let reader = socket.clone();
        let (tx, packets) = mpsc::channel(256);
        let task = tokio::spawn(async move {
            let mut buffer = vec![0; 65535];
            loop {
                let (len, source) = match reader.recv_from(&mut buffer).await {
                    Ok(packet) => packet,
                    Err(e) => {
                        crate::log!(2, "local UDP receive failed: {e}");
                        break;
                    }
                };
                if len >= mtu_warn {
                    crate::log!(
                        3,
                        "UDP datagram of {len} bytes reaches MTU warning threshold {mtu_warn}"
                    );
                }
                if len <= MAX_DATA && tx.send((source, buffer[..len].to_vec())).await.is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            socket,
            reader: task,
            packets,
            flows: Flows::default(),
        })
    }
}

pub async fn run(c: &Config, codec: Codec) -> io::Result<()> {
    let mut local = Local::bind(c.local, c.mtu_warn).await?;
    let session = if c.legacy {
        legacy::session_id(legacy::id())
    } else {
        random()
    };
    for (index, mode) in c.modes.iter().cycle().enumerate() {
        if local.packets.is_closed() {
            return Err(io::Error::other("local UDP reader stopped"));
        }
        let epoch = index as u64 + 1;
        crate::log!(4, "trying {mode} (attempt {epoch})");
        match attempt(c, &codec, &mut local, session, epoch, *mode).await {
            Ok(()) => crate::log!(3, "{mode} timed out"),
            Err(e) => {
                crate::log!(3, "{mode} unavailable: {e}");
                time::sleep(c.beat).await;
            }
        }
    }
    unreachable!()
}

async fn attempt(
    c: &Config,
    codec: &Codec,
    local: &mut Local,
    session: SessionId,
    epoch: u64,
    mode: Mode,
) -> io::Result<()> {
    let carrier = Carrier::bind(mode, c).await?;
    let route = carrier.client_route(c.remote).await?;
    let mut path = Path::new(carrier.clone(), route, session, epoch, c.remote.port());
    if c.legacy {
        path.legacy = Some(Link::new(legacy::id(), 0));
    }
    let mut tcp_ready = mode != Mode::FakeTcp;
    let mut welcomed = false;
    let mut ping = 0;
    let mut last_pong = 0;
    let mut next_cleanup = Instant::now();
    let mut deadline = Instant::now() + c.timeout;
    let mut uplink_deadline = deadline;
    let mut timer = time::interval(c.beat);
    timer.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let mut raw = vec![0; 65535];
    enum Event {
        Tick,
        Network(Incoming),
        Local(SocketAddr, Vec<u8>),
    }
    loop {
        let event = tokio::select! {
            _ = crate::ops::reconnect() => {crate::log!(4,"reconnecting on FIFO request");return Ok(());},
            _ = time::sleep_until(if c.legacy { deadline.min(uplink_deadline) } else { deadline }) => return Ok(()),
            _ = timer.tick() => Event::Tick,
            received = carrier.recv(&mut raw) => match received? {
                Some(packet) => Event::Network(packet),
                None => continue,
            },
            received = local.packets.recv() => match received {
                Some((source, data)) => Event::Local(source, data),
                None => return Err(io::Error::other("local UDP reader stopped")),
            },
        };
        match event {
            Event::Tick => {
                if Instant::now() >= next_cleanup {
                    local.flows.expire();
                    next_cleanup = Instant::now() + Duration::from_secs(10);
                }
                crate::log!(6, "{mode} heartbeat tick (ready={})", path.ready);
                if !tcp_ready {
                    carrier.send(&mut path.route, Segment::Syn, &[]).await?;
                } else if !welcomed {
                    path.send(codec, Kind::Hello, 0, vec![]).await?;
                } else {
                    ping += 1;
                    path.send(codec, Kind::Ping, ping, vec![]).await?;
                }
            }
            Event::Network(rx) => {
                if rx.route.peer.ip() != c.remote.ip()
                    || (mode != Mode::Icmp && rx.route.peer.port() != c.remote.port())
                {
                    continue;
                }
                if !tcp_ready {
                    if rx.segment == Segment::SynAck
                        && rx.route.seq == path.route.seq.wrapping_add(1)
                    {
                        path.route.seq = rx.route.seq;
                        path.route.ack = rx.route.ack;
                        tcp_ready = true;
                        path.send(codec, Kind::Hello, 0, vec![]).await?;
                    }
                    continue;
                }
                if let (Some(io), Some(link)) = (codec.legacy(), &mut path.legacy) {
                    for packet in io.read(&rx.body) {
                        match packet {
                            Packet::Handshake {
                                sender, receiver, ..
                            } if receiver == link.local
                                && (!welcomed || sender == link.peer)
                                && !path.ready =>
                            {
                                path.route.observe(&rx.route);
                                crate::log!(5, "received legacy handshake challenge via {mode}");
                                link.peer = sender;
                                welcomed = true;
                                link.send_handshake(
                                    io,
                                    &carrier,
                                    &mut path.route,
                                    sender,
                                    legacy::word(&session),
                                )
                                .await?;
                            }
                            Packet::Safer {
                                sender,
                                receiver,
                                sequence,
                                roller,
                                body,
                            } if welcomed => {
                                let previous = link.peer_roller;
                                if !link.accept(io, sender, receiver, sequence, roller, &body) {
                                    continue;
                                }
                                path.route.observe(&rx.route);
                                if !path.ready {
                                    path.ready = true;
                                    crate::log!(4, "connected via {mode}");
                                }
                                if previous != Some(roller) {
                                    uplink_deadline = Instant::now() + c.timeout;
                                }
                                if c.hb_mode == 0 || matches!(body, Payload::Heartbeat) {
                                    deadline = Instant::now() + c.timeout;
                                }
                                if let Payload::Data(flow, data) = body {
                                    local.deliver(u64::from(flow), &data).await;
                                }
                            }
                            _ => {}
                        }
                    }
                    continue;
                }
                for f in codec.frames(&rx.body, mode, c.remote.port()) {
                    if f.session != session
                        || f.epoch != epoch
                        || (welcomed && f.cookie != path.cookie)
                        || (codec.replay && !path.window.accept(f.serial))
                    {
                        continue;
                    }
                    path.route.observe(&rx.route);
                    match f.kind {
                        Kind::Welcome if !welcomed => {
                            path.cookie = f.cookie;
                            welcomed = true;
                            ping += 1;
                            path.send(codec, Kind::Ping, ping, vec![]).await?;
                        }
                        Kind::Pong if welcomed && f.flow > last_pong && f.flow <= ping => {
                            last_pong = f.flow;
                            deadline = Instant::now() + c.timeout;
                            if !path.ready {
                                path.ready = true;
                                crate::log!(4, "connected via {mode}");
                            }
                        }
                        Kind::Data if path.ready => {
                            if c.hb_mode == 0 {
                                deadline = Instant::now() + c.timeout;
                            }
                            local.deliver(f.flow, &f.data).await;
                        }
                        _ => {}
                    }
                }
            }
            Event::Local(addr, data) if path.ready => {
                let Some(id) = local.flows.id(addr) else {
                    continue;
                };
                if let Err(e) = path.send(codec, Kind::Data, id, data).await {
                    // A datagram exceeding the path MTU does not invalidate the carrier.
                    if e.raw_os_error() != Some(libc::EMSGSIZE) {
                        return Err(e);
                    }
                }
            }
            Event::Local(_, _) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn conversations_wrap_without_reusing_an_active_id() {
        let mut flows = Flows::default();
        assert_eq!(flows.id("127.0.0.1:7".parse().unwrap()), Some(1));
        flows.next = u32::MAX;
        assert_eq!(flows.id("127.0.0.1:8".parse().unwrap()), Some(2));
    }
}
