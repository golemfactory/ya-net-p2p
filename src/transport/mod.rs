pub mod connection;
pub mod laminar;

use crate::event::TransportCmd;
use actix::{Actor, Context, Handler};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

pub type TransportId = u16;
pub type StreamId = u8;

pub trait Transport: Actor<Context = Context<Self>> + Handler<TransportCmd> {
    const TRANSPORT_ID: TransportId;
}

// FIXME: placeholder
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, Deserialize, Serialize)]
pub struct Address {
    pub transport_id: TransportId,
    pub socket_addr: SocketAddr,
}

impl Address {
    pub const ANY_TRANSPORT: u16 = 0;
    pub const TCP: u16 = 6;
    pub const UDP: u16 = 17;
    pub const LAMINAR: u16 = 18;

    pub fn new(transport_id: TransportId, socket_addr: SocketAddr) -> Self {
        Self {
            transport_id,
            socket_addr,
        }
    }

    #[inline(always)]
    pub fn is_transport(&self, transport_id: &TransportId) -> bool {
        &self.transport_id == transport_id
    }
}
