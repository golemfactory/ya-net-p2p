use crate::error::DiscoveryError;
use crate::packet::{AddressedPacket, Packet, WirePacket};
use crate::protocol::ProtocolId;
use crate::transport::{Address, TransportId};
use crate::{Identity, Result};
use actix::prelude::*;
use futures::channel::mpsc::Sender;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt::Debug;
use std::net::SocketAddr;

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<()>")]
pub enum ServiceCmd<Key>
where
    Key: Send + Debug + Clone + 'static,
{
    SetSessionProtocol(Recipient<SessionCmd<Key>>),
    SetDhtProtocol(Recipient<DhtCmd<Key>>),
    AddTransport(TransportId, Recipient<TransportCmd>),
    RemoveTransport(TransportId),
    AddProtocol(ProtocolId, Recipient<ProtocolCmd>),
    RemoveProtocol(ProtocolId),
    AddProcessor(Recipient<ProcessCmd<Key>>),
    RemoveProcessor(Recipient<ProcessCmd<Key>>),
    Shutdown,
}

unsafe impl<Key> Send for ServiceCmd<Key> where Key: Send + Debug + Clone {}

#[derive(Message)]
#[rtype(result = "Result<()>")]
pub enum SendCmd<Key: Send + 'static> {
    Roaming {
        from: Option<Key>,
        to: Address,
        packet: Packet,
    },
    Session {
        from: Identity,
        to: Identity,
        packet: Packet,
    },
    Broadcast {
        packet: Packet,
    },
}

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
pub enum ProtocolCmd {
    RoamingPacket {
        address: Address,
        packet: Packet,
    },
    SessionPacket {
        from: Identity,
        to: Identity,
        address: Address,
        packet: Packet,
    },
    Shutdown,
}

unsafe impl Send for ProtocolCmd {}

#[derive(Clone, Message)]
#[rtype(result = "Result<()>")]
pub enum SessionCmd<Key>
where
    Key: Send + Clone + 'static,
{
    Initiate {
        from: Key,
        from_identity: Identity,
        to: Key,
        to_identity: Identity,
        address: Address,
    },
}

unsafe impl<Key> Send for SessionCmd<Key> where Key: Send + Clone {}

#[derive(Clone, Message)]
#[rtype(result = "Result<DhtResponse<Key>>")]
pub enum DhtCmd<Key>
where
    Key: Send + Clone + 'static,
{
    ResolveNode(Key),
    ResolveValue(Vec<u8>),
    PublishValue(Vec<u8>, DhtValue<Key>),
    Bootstrap(Vec<(Vec<u8>, Address)>),
    // TODO: + node address change update
}

unsafe impl<Key> Send for DhtCmd<Key> where Key: Send + Clone {}

#[derive(Clone, MessageResponse)]
pub enum DhtResponse<Key>
where
    Key: Clone + 'static,
{
    Addresses(Vec<Address>),
    Value(DhtValue<Key>),
    Empty,
}

impl<Key> DhtResponse<Key>
where
    Key: Debug + Clone + 'static,
{
    pub fn into_addresses(self) -> Result<Vec<Address>> {
        match self {
            DhtResponse::Addresses(addrs) => match addrs.len() {
                0 => Err(DiscoveryError::NotFound.into()),
                _ => Ok(addrs),
            },
            _ => Err(DiscoveryError::NotFound.into()),
        }
    }

    pub fn into_value(self) -> Result<DhtValue<Key>> {
        match self {
            DhtResponse::Value(val) => Ok(val),
            _ => Err(DiscoveryError::NotFound.into()),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DhtValue<Key: Clone> {
    pub identity_key: Key,
    pub node_key: Key,
}

#[derive(Clone, Message)]
#[rtype(result = "Result<Packet>")]
pub enum ProcessCmd<Key>
where
    Key: Send + Clone,
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

unsafe impl<Key> Send for ProcessCmd<Key> where Key: Send + Clone {}

#[derive(Clone, Debug, Message)]
#[rtype(result = "()")]
pub enum TransportEvt {
    Connected(Address, Sender<AddressedPacket>),
    Disconnected(Address, DisconnectReason),
    Packet(Address, WirePacket),
}

unsafe impl Send for TransportEvt {}

#[derive(Clone, Message)]
#[rtype(result = "()")]
pub enum SessionEvt<Key>
where
    Key: Clone + 'static,
{
    Established {
        from: Key,
        from_identity: Identity,
        to: Key,
        to_identity: Identity,
        address: Address,
    },
}

unsafe impl<Key> Send for SessionEvt<Key> where Key: Send + Clone {}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum DisconnectReason {
    Timeout,
    InvalidProtocol,
    InvalidProtocolVersion,
    Shutdown,
    Other(String),
}
