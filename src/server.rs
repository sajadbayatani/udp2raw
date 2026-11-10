use crate::{
    client::IDLE,
    config::{Config, Mode},
    path::Path,
    transport::{Carrier, Route, Segment},
    wire::{random, Codec, Frame, Kind, SessionId, MAX_DATA},
};
use std::{
    collections::{hash_map::Entry, HashMap},
    io,
    net::SocketAddrV4,
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::mpsc,
    task::JoinHandle,
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
        } else if let Some(f) = codec.open(&rx.body, carrier.mode, port) {
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

struct Server {
    sessions: HashMap<SessionId, Session>,
    flows: HashMap<FlowKey, Flow>,
    tx: mpsc::Sender<Event>,
    upstream: SocketAddrV4,
    port: u16,
    codec: Arc<Codec>,
}

impl Server {
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
            if p.ready || !p.window.accept(f.serial) {
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
            || !p.window.accept(f.serial)
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
            Kind::Data if p.ready && f.flow != 0 => {
                self.forward((f.session, f.flow), &f.data).await
            }
            _ => Ok(()),
        }
    }
    async fn forward(&mut self, key: FlowKey, data: &[u8]) -> io::Result<()> {
        let full = self.flows.len() >= MAX_FLOWS;
        let flow = match self.flows.entry(key) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(_) if full => return Ok(()),
            Entry::Vacant(e) => {
                let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
                socket.connect(self.upstream).await?;
                let rx = socket.clone();
                let tx = self.tx.clone();
                let reader = tokio::spawn(async move {
                    let mut buf = vec![0; 65535];
                    loop {
                        match rx.recv(&mut buf).await {
                            Ok(n) if n <= MAX_DATA => {
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
        if s.path.ready {
            s.path.send(&self.codec, Kind::Data, key.1, data).await?;
        }
        Ok(())
    }
    fn expire(&mut self) {
        self.sessions.retain(|_, s| s.last_seen.elapsed() < IDLE);
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
        let carrier = Carrier::bind(mode, c.local, true)
            .await
            .map_err(|e| io::Error::new(e.kind(), format!("bind {mode} on {}: {e}", c.local)))?;
        listeners.push(carrier);
    }
    for carrier in listeners {
        let (codec, tx, port) = (codec.clone(), tx.clone(), c.local.port());
        eprintln!("listening on {} via {}", c.local, carrier.mode);
        tokio::spawn(async move {
            let mode = carrier.mode;
            if let Err(e) = listen(carrier, codec, tx.clone(), port).await {
                let _ = tx.send(Event::Failed(mode, e)).await;
            }
        });
    }
    let mut state = Server {
        sessions: HashMap::new(),
        flows: HashMap::new(),
        tx,
        upstream: c.remote,
        port: c.local.port(),
        codec,
    };
    let mut cleanup = time::interval(Duration::from_secs(10));
    loop {
        let event = tokio::select! {
            Some(event) = rx.recv() => event,
            _ = cleanup.tick() => {
                state.expire();
                continue;
            }
        };
        let result = match event {
            Event::Packet(carrier, route, frame) => state.packet(carrier, route, frame).await,
            Event::Reply(key, data) => state.reply(key, data).await,
            Event::Failed(mode, e) => {
                return Err(io::Error::new(e.kind(), format!("{mode} listener: {e}")))
            }
        };
        if let Err(e) = result {
            eprintln!("datagram dropped: {e}");
        }
    }
}
