use crate::event::ProtocolCmd;
use actix::{Actor, Context, Handler};

pub mod kad;
pub mod session;

#[cfg(feature = "service-bus")]
pub mod service_bus;

pub type ProtocolId = u16;
pub type ProtocolVersion = u16;

pub trait Protocol: Actor<Context = Context<Self>> + Handler<ProtocolCmd> {
    const ID: ProtocolId;
    const VERSION: ProtocolVersion;
}
