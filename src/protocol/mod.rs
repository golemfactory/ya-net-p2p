use crate::event::ProtocolCmd;
use actix::{Actor, Context, Handler};

pub mod kad;
pub mod session;

#[cfg(feature = "service-bus")]
pub mod service_bus;

pub type ProtocolId = u16;

pub trait Protocol<Key>: Actor<Context = Context<Self>> + Handler<ProtocolCmd<Key>>
where
    Key: Send + std::fmt::Debug + Clone,
{
    const PROTOCOL_ID: ProtocolId;
}
