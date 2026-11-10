use crate::{
    client::IDLE,
    config::{Config, Mode},
    legacy::{self, Link, Payload},
    path::Path,
    transport::{Carrier, Route, Segment},
    wire::{payload_fits, random, Codec, Frame, Kind, SessionId},
};
use std::{
    collections::{hash_map::Entry, HashMap},
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::mpsc,
    task::{JoinHandle, JoinSet},
    time::{self, Instant},
};

const MAX_SESSIONS: usize = 2048;
const MAX_FLOWS: usize = 8192;

struct Session {
    path: Path,
    last_seen: Instant,
}
type FlowKey = (SessionId, u64);
struct Flow {
    socket: Arc<UdpSocket>,
    reader: JoinHandle<()>,
    last_seen: Instant,
}
impl Drop for Flow {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

enum Event {
    Packet(Arc<Carrier>, Route, Frame),
    Legacy(Arc<Carrier>, Route, legacy::Packet),
    Reply(FlowKey, Vec<u8>),
    Failed(Mode, io::Error),
}

async fn listen(
    carrier: Arc<Carrier>,
    codec: Arc<Codec>,
    tx: mpsc::Sender<Event>,
    port: u16,
) -> io::Result<()> {
    let mut buf = vec![0; 65535];
    loop {
        let Some(mut rx) = carrier.recv(&mut buf).await? else {
            continue;
        };
        if rx.segment == Segment::Syn {
            rx.route.seq = u32::from_be_bytes(random());
            let _ = carrier.send(&mut rx.route, Segment::SynAck, &[]).await;
        } else if let Some(interop) = codec.legacy() {
            for packet in interop.read(&rx.body) {
                if tx
                    .send(Event::Legacy(carrier.clone(), rx.route, packet))
                    .await
                    .is_err()
                {
                    return Ok(());
                }
            }
        } else {
            for f in codec.frames(&rx.body, carrier.mode, port) {
                if tx
                    .send(Event::Packet(carrier.clone(), rx.route, f))
                    .await
                    .is_err()
                {
                    return Ok(());
                }
            }
        }
    }
}

type Endpoint = (Mode, IpAddr, SocketAddr);
struct Challenge {
    local: u32,
    peer: u32,
    identity: u32,
    generation: u64,
    created: Instant,
}
struct LegacyPeers {
    identity: u32,
    generation: u64,
    pending: HashMap<Endpoint, Challenge>,
    active: HashMap<Endpoint, SessionId>,
}
impl LegacyPeers {
    fn new() -> Self {
        Self {
            identity: legacy::id(),
            generation: 0,
            pending: HashMap::new(),
            active: HashMap::new(),
        }
    }
}

struct Server {
    fragments: crate::fragment::Reassembly,
    sessions: HashMap<SessionId, Session>,
    flows: HashMap<FlowKey, Flow>,
    tx: mpsc::Sender<Event>,
    upstream: SocketAddr,
    legacy: LegacyPeers,
    mtu: usize,
    mtu_warn: usize,
    port: u16,
    codec: Arc<Codec>,
}

impl Server {
    async fn legacy_packet(
        &mut self,
        carrier: Arc<Carrier>,
        mut route: Route,
        packet: legacy::Packet,
    ) -> io::Result<()> {
        let endpoint = (carrier.mode, route.local, route.peer);
        let io = self.codec.legacy().expect("legacy listener");
        match packet {
            legacy::Packet::Handshake {
                sender,
                receiver: 0,
                identity,
            } => {
                // A bare packet alone can never displace an established route.
                let full = self.legacy.pending.len() >= MAX_SESSIONS;
                let pending = match self.legacy.pending.entry(endpoint) {
                    Entry::Occupied(e)
                        if e.get().identity == identity && e.get().peer == sender =>
                    {
                        e.into_mut()
                    }
                    e => {
                        if full {
                            return Ok(());
                        }
                        self.legacy.generation += 1;
                        let challenge = Challenge {
                            local: legacy::id(),
                            peer: sender,
                            identity,
                            generation: self.legacy.generation,
                            created: Instant::now(),
                        };
                        match e {
                            Entry::Occupied(mut e) => {
                                e.insert(challenge);
                                e.into_mut()
                            }
                            Entry::Vacant(e) => e.insert(challenge),
                        }
                    }
                };
                let reply = io.handshake(pending.local, sender, self.legacy.identity);
                carrier.send(&mut route, Segment::Data, &reply).await
            }
            legacy::Packet::Handshake {
                sender,
                receiver,
                identity,
            } => {
                let sid = legacy::session_id(identity);
                let Some(pending) = self.legacy.pending.get(&endpoint) else {
                    return Ok(());
                };
                if pending.identity != identity
                    || pending.local != receiver
                    || pending.peer != sender
                {
                    return Ok(());
                }
                let generation = pending.generation;
                if let Some(session) = self.sessions.get(&sid) {
                    if session.path.epoch > generation {
                        return Ok(());
                    }
                } else if self.sessions.len() >= MAX_SESSIONS {
                    return Ok(());
                }
                let mut path = Path::new(carrier, route, sid, generation, self.port);
                path.legacy = Some(Link::new(receiver, sender));
                path.ready = true;
                if let Some(old) = self.sessions.insert(
                    sid,
                    Session {
                        path,
                        last_seen: Instant::now(),
                    },
                ) {
                    self.legacy.active.remove(&(
                        old.path.carrier.mode,
                        old.path.route.local,
                        old.path.route.peer,
                    ));
                }
                crate::log!(
                    5,
                    "confirmed legacy session {identity:x} via {} from {}",
                    endpoint.0,
                    endpoint.2
                );
                self.legacy.active.insert(endpoint, sid);
                self.legacy.pending.remove(&endpoint);
                self.sessions
                    .get_mut(&sid)
                    .unwrap()
                    .path
                    .send(&self.codec, Kind::Pong, 0, vec![])
                    .await
            }
            legacy::Packet::Safer {
                sender,
                receiver,
                sequence,
                roller,
                body,
            } => {
                let Some(&sid) = self.legacy.active.get(&endpoint) else {
                    return Ok(());
                };
                let Some(session) = self.sessions.get_mut(&sid) else {
                    return Ok(());
                };
                let link = session.path.legacy.as_mut().expect("legacy path");
                if !link.accept(io, sender, receiver, sequence, roller, &body) {
                    return Ok(());
                }
                session.path.route.observe(&route);
                session.last_seen = Instant::now();
                match body {
                    Payload::Data(conv, data) => self.forward((sid, u64::from(conv)), &data).await,
                    Payload::Heartbeat => {
                        session.path.send(&self.codec, Kind::Pong, 0, vec![]).await
                    }
                }
            }
        }
    }

    async fn heartbeat(&mut self) {
        for session in self.sessions.values_mut() {
            if session.path.legacy.is_some() {
                let _ = session.path.send(&self.codec, Kind::Pong, 0, vec![]).await;
            }
        }
    }

    async fn packet(&mut self, carrier: Arc<Carrier>, route: Route, f: Frame) -> io::Result<()> {
        if f.kind == Kind::Hello {
            let full = self.sessions.len() >= MAX_SESSIONS;
            let s = match self.sessions.entry(f.session) {
                Entry::Occupied(e) => e.into_mut(),
                Entry::Vacant(_) if full => return Ok(()),
                Entry::Vacant(e) => e.insert(Session {
                    path: Path::new(carrier.clone(), route, f.session, f.epoch, self.port),
                    last_seen: Instant::now(),
                }),
            };
            let p = &mut s.path;
            if f.epoch > p.epoch {
                *p = Path::new(carrier, route, f.session, f.epoch, self.port);
            } else if f.epoch != p.epoch
                || p.carrier.mode != carrier.mode
                || route.peer != p.route.peer
                || route.local != p.route.local
            {
                return Ok(());
            }
            if p.ready || (self.codec.replay && !p.window.accept(f.serial)) {
                return Ok(());
            }
            if p.cookie == [0; 16] {
                p.cookie = random();
            }
            p.route.observe(&route);
            return p.send(&self.codec, Kind::Welcome, 0, vec![]).await;
        }
        let Some(s) = self.sessions.get_mut(&f.session) else {
            return Ok(());
        };
        let p = &mut s.path;
        if f.epoch != p.epoch
            || f.cookie != p.cookie
            || p.carrier.mode != carrier.mode
            || route.peer != p.route.peer
            || route.local != p.route.local
            || (self.codec.replay && !p.window.accept(f.serial))
        {
            return Ok(());
        }
        p.route.observe(&route);
        s.last_seen = Instant::now();
        match f.kind {
            Kind::Ping => {
                p.ready = true;
                p.send(&self.codec, Kind::Pong, f.flow, vec![]).await
            }
            Kind::Data | Kind::Fragment if p.ready && f.flow != 0 => {
                let key = (f.session, f.flow);
                let Some(data) = self.fragments.payload(f, self.mtu) else {
                    return Ok(());
                };
                self.forward(key, &data).await
            }
            _ => Ok(()),
        }
    }
    async fn forward(&mut self, key: FlowKey, data: &[u8]) -> io::Result<()> {
        if !payload_fits(data.len(), self.mtu) {
            return Ok(());
        }
        crate::log!(
            6,
            "forwarding {} bytes on conversation {}",
            data.len(),
            key.1
        );
        let full = self.flows.len() >= MAX_FLOWS;
        let flow = match self.flows.entry(key) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(_) if full => return Ok(()),
            Entry::Vacant(e) => {
                let bind = if self.upstream.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                let socket = Arc::new(UdpSocket::bind(bind).await?);
                socket.connect(self.upstream).await?;
                let rx = socket.clone();
                let tx = self.tx.clone();
                let mtu = self.mtu;
                let reader = tokio::spawn(async move {
                    let mut buf = vec![0; 65535];
                    loop {
                        match rx.recv(&mut buf).await {
                            Ok(n) if payload_fits(n, mtu) => {
                                if tx.send(Event::Reply(key, buf[..n].to_vec())).await.is_err() {
                                    break;
                                }
                            }
                            Ok(_) => {}
                            Err(_) => time::sleep(Duration::from_millis(50)).await,
                        }
                    }
                });
                e.insert(Flow {
                    socket,
                    reader,
                    last_seen: Instant::now(),
                })
            }
        };
        flow.last_seen = Instant::now();
        flow.socket.send(data).await?;
        Ok(())
    }
    async fn reply(&mut self, key: FlowKey, data: Vec<u8>) -> io::Result<()> {
        let Some(flow) = self.flows.get_mut(&key) else {
            return Ok(());
        };
        let Some(s) = self.sessions.get_mut(&key.0) else {
            return Ok(());
        };
        flow.last_seen = Instant::now();
        if data.len() >= self.mtu_warn
            && self
                .codec
                .fragment_size
                .is_none_or(|width| data.len() <= width)
        {
            crate::log!(
                3,
                "upstream UDP datagram of {} bytes reaches MTU warning threshold {}",
                data.len(),
                self.mtu_warn
            );
        }
        if s.path.ready {
            s.path.send(&self.codec, Kind::Data, key.1, data).await?;
        }
        Ok(())
    }
    fn expire(&mut self) {
        self.fragments.expire();
        self.sessions.retain(|_, s| s.last_seen.elapsed() < IDLE);
        self.legacy
            .pending
            .retain(|_, p| p.created.elapsed() < Duration::from_secs(30));
        self.legacy
            .active
            .retain(|_, sid| self.sessions.contains_key(sid));
        self.flows.retain(|(session, _), f| {
            self.sessions.contains_key(session) && f.last_seen.elapsed() < IDLE
        });
    }
}

pub async fn run(c: &Config, codec: Codec) -> io::Result<()> {
    let codec = Arc::new(codec);
    let (tx, mut rx) = mpsc::channel(512);
    let mut listeners = Vec::new();
    for &mode in &c.modes {
        let carrier = Carrier::bind(mode, c)
            .await
            .map_err(|e| io::Error::new(e.kind(), format!("bind {mode} on {}: {e}", c.local)))?;
        listeners.push(carrier);
    }
    let mut workers = JoinSet::new();
    for carrier in listeners {
        let (codec, tx, port) = (codec.clone(), tx.clone(), c.local.port());
        crate::log!(4, "listening on {} via {}", c.local, carrier.mode);
        workers.spawn(async move {
            let mode = carrier.mode;
            if let Err(e) = listen(carrier, codec, tx.clone(), port).await {
                let _ = tx.send(Event::Failed(mode, e)).await;
            }
        });
    }
    let mut state = Server {
        fragments: crate::fragment::Reassembly::default(),
        sessions: HashMap::new(),
        legacy: LegacyPeers::new(),
        mtu: c.mtu,
        mtu_warn: c.mtu_warn,
        flows: HashMap::new(),
        tx,
        upstream: c.remote,
        port: c.local.port(),
        codec,
    };
    let mut cleanup = time::interval(Duration::from_secs(10));
    let mut heartbeat = time::interval(c.beat);
    heartbeat.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    loop {
        let event = tokio::select! {
            _=heartbeat.tick(), if c.legacy => {state.heartbeat().await;continue;}
            Some(event) = rx.recv() => event,
            _ = cleanup.tick() => {
                state.expire();
                continue;
            }
        };
        let started = c.debug.then(Instant::now);
        let result = match event {
            Event::Packet(carrier, route, frame) => state.packet(carrier, route, frame).await,
            Event::Legacy(carrier, route, packet) => {
                state.legacy_packet(carrier, route, packet).await
            }
            Event::Reply(key, data) => state.reply(key, data).await,
            Event::Failed(mode, e) => {
                return Err(io::Error::new(e.kind(), format!("{mode} listener: {e}")))
            }
        };
        if let Some(started) = started {
            crate::log!(
                5,
                "server event handled in {} µs",
                started.elapsed().as_micros()
            );
        }
        if let Err(e) = result {
            crate::log!(3, "datagram dropped: {e}");
        }
    }
}
