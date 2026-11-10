use crate::{
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
        self.serial += 1;
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
