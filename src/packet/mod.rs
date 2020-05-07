use crate::packet::codec::Codec;
pub use crate::packet::payload::Payload;
use crate::transport::StreamId;
use crate::{Address, Result, TransportId};
use std::net::SocketAddr;

pub(crate) mod codec;
pub(crate) mod header;
pub(crate) mod payload;

#[derive(Clone, Debug)]
pub struct Packet {
    pub guarantees: Guarantees,
    pub payload: Payload,
}

#[derive(Clone, Debug)]
pub struct EncodedPacket {
    pub guarantees: Guarantees,
    pub message: Vec<u8>,
}

impl EncodedPacket {
    #[inline]
    pub fn addressed(self, address: Address) -> AddressedPacket {
        AddressedPacket {
            address,
            encoded: self,
        }
    }

    #[inline]
    pub fn addressed_with(
        self,
        transport_id: TransportId,
        socket_addr: SocketAddr,
    ) -> AddressedPacket {
        self.addressed(Address::new(transport_id, socket_addr))
    }

    pub fn try_decode(self) -> Result<Packet> {
        Ok(Packet {
            guarantees: self.guarantees,
            payload: Payload::decode(self.message)?,
        })
    }
}

impl From<Packet> for EncodedPacket {
    fn from(packet: Packet) -> Self {
        EncodedPacket {
            guarantees: packet.guarantees,
            message: packet.payload.encode(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AddressedPacket {
    pub address: Address,
    pub encoded: EncodedPacket,
}

#[derive(Clone, Debug)]
pub struct Guarantees {
    pub delivery: DeliveryType,
    pub ordering: OrderingType,
}

impl Guarantees {
    pub fn ordered(stream_id: Option<StreamId>) -> Self {
        Guarantees {
            delivery: DeliveryType::Acknowledged,
            ordering: OrderingType::Ordered { stream_id },
        }
    }

    #[inline]
    pub fn ordered_default() -> Self {
        Self::ordered(None)
    }

    pub fn unordered() -> Self {
        Guarantees {
            delivery: DeliveryType::Acknowledged,
            ordering: OrderingType::Unordered {},
        }
    }

    pub fn stream(stream_id: Option<StreamId>) -> Self {
        Guarantees {
            delivery: DeliveryType::Acknowledged,
            ordering: OrderingType::Sequenced { stream_id },
        }
    }

    pub fn fire_and_forget() -> Self {
        Guarantees {
            delivery: DeliveryType::Unacknowledged,
            ordering: OrderingType::Unordered {},
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum DeliveryType {
    Acknowledged,
    Unacknowledged,
}

impl Default for DeliveryType {
    fn default() -> Self {
        DeliveryType::Acknowledged
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum OrderingType {
    Unordered {},
    Ordered { stream_id: Option<StreamId> },
    Sequenced { stream_id: Option<StreamId> },
}

impl Default for OrderingType {
    fn default() -> Self {
        OrderingType::Unordered {}
    }
}
