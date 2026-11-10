use crate::{
    config::{Config, Mode},
    path::Path,
    transport::{Carrier, Incoming, Segment},
    wire::{random, Codec, Kind, SessionId, MAX_DATA},
};
use std::{
    collections::HashMap,
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};
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
    next: u64,
}
impl Flows {
    fn id(&mut self, addr: SocketAddr) -> Option<u64> {
        let id = if let Some(&id) = self.by_addr.get(&addr) {
            id
        } else {
            if self.by_addr.len() >= MAX_FLOWS {
                return None;
            }
            self.next += 1;
            self.by_addr.insert(addr, self.next);
            self.next
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
    packets: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    flows: Flows,
}

impl Local {
    async fn bind(addr: SocketAddrV4) -> io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        let reader = socket.clone();
        let (tx, packets) = mpsc::channel(256);
        tokio::spawn(async move {
            let mut buffer = vec![0; 65535];
            loop {
                let (len, source) = match reader.recv_from(&mut buffer).await {
                    Ok(packet) => packet,
                    Err(e) => {
                        eprintln!("local UDP receive failed: {e}");
                        break;
                    }
                };
                if len <= MAX_DATA && tx.send((source, buffer[..len].to_vec())).await.is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            socket,
            packets,
            flows: Flows::default(),
        })
    }
}

pub async fn run(c: &Config, codec: Codec) -> io::Result<()> {
    let mut local = Local::bind(c.local).await?;
    let session = random();
    for (index, mode) in c.modes.iter().cycle().enumerate() {
        if local.packets.is_closed() {
            return Err(io::Error::other("local UDP reader stopped"));
        }
        let epoch = index as u64 + 1;
        eprintln!("trying {mode} (attempt {epoch})");
        match attempt(c, &codec, &mut local, session, epoch, *mode).await {
            Ok(()) => eprintln!("{mode} timed out"),
            Err(e) => {
                eprintln!("{mode} unavailable: {e}");
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
    let carrier = Carrier::bind(mode, SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0), false).await?;
    let route = carrier.client_route(c.remote).await?;
    let mut path = Path::new(carrier.clone(), route, session, epoch, c.remote.port());
    let mut tcp_ready = mode != Mode::FakeTcp;
    let mut welcomed = false;
    let mut ping = 0;
    let mut last_pong = 0;
    let mut next_cleanup = Instant::now();
    let mut deadline = Instant::now() + c.timeout;
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
            _ = time::sleep_until(deadline) => return Ok(()),
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
                let Some(f) = codec.open(&rx.body, mode, c.remote.port()) else {
                    continue;
                };
                if f.session != session
                    || f.epoch != epoch
                    || (welcomed && f.cookie != path.cookie)
                    || !path.window.accept(f.serial)
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
                            eprintln!("connected via {mode}");
                        }
                    }
                    Kind::Data if path.ready => {
                        if let Some((addr, last)) = local.flows.by_id.get_mut(&f.flow) {
                            *last = Instant::now();
                            let _ = local.socket.send_to(&f.data, *addr).await;
                        }
                    }
                    _ => {}
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
