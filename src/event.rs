use crate::packet::{AddressedPacket, EncodedPacket, Packet};
use crate::transport::Address;
use crate::{ProtocolId, Result, TransportId};
use actix::prelude::*;
use futures::channel::mpsc::Sender;
use std::fmt::Debug;
use std::net::SocketAddr;

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<()>")]
pub enum ServiceCmd<Key>
where
    Key: Send + Debug + Clone,
{
    SetSessionProtocol(Recipient<SessionCmd<Key>>),
    SetDhtProtocol(Recipient<DhtCmd<Key>>),
    AddTransport(TransportId, Recipient<TransportCmd>),
    RemoveTransport(TransportId),
    AddProtocol(ProtocolId, Recipient<ProtocolCmd<Key>>),
    RemoveProtocol(ProtocolId),
    AddMangler(Recipient<MangleCmd<Key>>),
    RemoveMangler(Recipient<MangleCmd<Key>>),
    Shutdown,
}

unsafe impl<Key> Send for ServiceCmd<Key> where Key: Send + Debug + Clone {}

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<()>")]
pub enum SendCmd<Key>
where
    Key: Send + Debug + Clone,
{
    Roaming {
        from: Option<Key>,
        to: Address,
        packet: Packet,
    },
    Session {
        from: Option<Key>,
        to: Key,
        packet: Packet,
    },
    Broadcast {
        from: Option<Key>,
        packet: Packet,
    },
    Disconnect(Key, DisconnectReason),
}

unsafe impl<Key> Send for SendCmd<Key> where Key: Send + Debug + Clone {}

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<()>")]
pub enum TransportCmd {
    Bind(Vec<SocketAddr>),
    Shutdown,
    Connect(SocketAddr),
    Disconnect(SocketAddr),
    Packet(SocketAddr, EncodedPacket),
}

unsafe impl Send for TransportCmd {}

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<()>")]
pub enum ProtocolCmd<Key>
where
    Key: Send + Debug + Clone,
{
    RoamingPacket(Address, Packet),
    SessionPacket(Address, Packet, Key),
    Shutdown,
}

unsafe impl<Key> Send for ProtocolCmd<Key> where Key: Send + Debug + Clone {}

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<()>")]
pub enum SessionCmd<Key>
where
    Key: Send + Debug + Clone,
{
    Initiate(Address),
    Disconnect(Key, DisconnectReason),
}

unsafe impl<Key> Send for SessionCmd<Key> where Key: Send + Debug + Clone {}

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<Vec<Address>>")]
pub enum DhtCmd<Key>
where
    Key: Send + Debug + Clone,
{
    Resolve(Key),
    // TODO: + node address change update
}

unsafe impl<Key> Send for DhtCmd<Key> where Key: Send + Debug + Clone {}

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<Packet>")]
pub enum MangleCmd<Key>
where
    Key: Send + Debug + Clone,
{
    Mangle {
        from: Option<Key>,
        to: Option<Key>,
        packet: Packet,
    },
    Unmangle {
        from: Option<Key>,
        to: Option<Key>,
        packet: Packet,
    },
}

unsafe impl<Key> Send for MangleCmd<Key> where Key: Send + Debug + Clone {}

#[derive(Clone, Debug, Message)]
#[rtype(result = "()")]
pub enum TransportEvt {
    Connected(Address, Sender<AddressedPacket>),
    Disconnected(Address, DisconnectReason),
    Packet(Address, EncodedPacket),
}

unsafe impl Send for TransportEvt {}

#[derive(Clone, Debug, Message)]
#[rtype(result = "()")]
pub enum SessionEvt<Key>
where
    Key: Send + Debug + Clone,
{
    Established(Address, Key),
}

unsafe impl<Key> Send for SessionEvt<Key> where Key: Send + Debug + Clone {}

#[derive(Clone, Debug, PartialEq)]
pub enum DisconnectReason {
    Timeout,
    InvalidProtocol,
    InvalidProtocolVersion,
    Shutdown,
    Other(String),
}
