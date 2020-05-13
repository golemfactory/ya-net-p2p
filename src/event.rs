use crate::packet::{AddressedPacket, Packet, WirePacket};
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
    AddProcessor(Recipient<ProcessCmd<Key>>),
    RemoveProcessor(Recipient<ProcessCmd<Key>>),
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
    Packet(SocketAddr, WirePacket),
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
#[rtype(result = "Result<DhtResponse>")]
pub enum DhtCmd<Key>
where
    Key: Send + Debug + Clone,
{
    ResolveNode(Key),
    ResolveValue(Vec<u8>),
    PublishValue(Vec<u8>, Vec<u8>),
    // TODO: + node address change update
}

unsafe impl<Key> Send for DhtCmd<Key> where Key: Send + Debug + Clone {}

#[derive(Clone, Debug, MessageResponse)]
pub enum DhtResponse {
    Addresses(Vec<Address>),
    Value(Vec<u8>),
    Empty,
}

impl DhtResponse {
    pub fn into_addresses(self) -> Option<Vec<Address>> {
        match self {
            DhtResponse::Addresses(addrs) => Some(addrs),
            _ => None,
        }
    }

    pub fn into_value(self) -> Option<Vec<u8>> {
        match self {
            DhtResponse::Value(vec) => Some(vec),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<Packet>")]
pub enum ProcessCmd<Key>
where
    Key: Send + Debug + Clone,
{
    Outbound {
        from: Option<Key>,
        to: Option<Key>,
        packet: Packet,
    },
    Inbound {
        from: Option<Key>,
        to: Option<Key>,
        packet: Packet,
    },
}

unsafe impl<Key> Send for ProcessCmd<Key> where Key: Send + Debug + Clone {}

#[derive(Clone, Debug, Message)]
#[rtype(result = "()")]
pub enum TransportEvt {
    Connected(Address, Sender<AddressedPacket>),
    Disconnected(Address, DisconnectReason),
    Packet(Address, WirePacket),
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
