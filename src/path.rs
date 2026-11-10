use crate::{
    legacy::{self, Link},
    transport::{Carrier, Route, Segment},
    wire::{Codec, Cookie, Frame, Kind, SessionId, Window},
};
use std::{io, sync::Arc};

pub struct Path {
    pub carrier: Arc<Carrier>,
    pub route: Route,
    pub session: SessionId,
    pub epoch: u64,
    pub cookie: Cookie,
    pub window: Window,
    pub ready: bool,
    pub legacy: Option<Link>,
    serial: u64,
    port: u16,
}

impl Path {
    pub fn new(
        carrier: Arc<Carrier>,
        route: Route,
        session: SessionId,
        epoch: u64,
        port: u16,
    ) -> Self {
        Self {
            carrier,
            route,
            session,
            epoch,
            cookie: [0; 16],
            window: Window::default(),
            ready: false,
            legacy: None,
            serial: 0,
            port,
        }
    }
    pub async fn send(
        &mut self,
        codec: &Codec,
        kind: Kind,
        flow: u64,
        data: Vec<u8>,
    ) -> io::Result<()> {
        if let (Some(io), Some(link)) = (codec.legacy(), &mut self.legacy) {
            let packet = match kind {
                Kind::Hello | Kind::Ping if !self.ready => {
                    let receiver = if kind == Kind::Hello { 0 } else { link.peer };
                    return link
                        .send_handshake(
                            io,
                            &self.carrier,
                            &mut self.route,
                            receiver,
                            legacy::word(&self.session),
                        )
                        .await;
                }
                Kind::Ping | Kind::Pong => io.safer(link, None, &[])?,
                Kind::Data => io.safer(
                    link,
                    Some(
                        u32::try_from(flow)
                            .map_err(|_| io::Error::other("conversation ID exceeds u32"))?,
                    ),
                    &data,
                )?,
                Kind::Hello | Kind::Welcome => {
                    return Err(io::Error::other("invalid legacy handshake stage"))
                }
            };
            return self
                .carrier
                .send(&mut self.route, Segment::Data, &packet)
                .await;
        }
        self.serial += 1;
        let data = if matches!(kind, Kind::Ping | Kind::Pong) {
            vec![0; codec.heartbeat_len]
        } else {
            data
        };
        let f = Frame {
            kind,
            session: self.session,
            epoch: self.epoch,
            cookie: self.cookie,
            serial: self.serial,
            flow,
            data,
        };
        let body = codec.seal(&f, self.carrier.mode, self.port)?;
        self.carrier
            .send(&mut self.route, Segment::Data, &body)
            .await
    }
}
