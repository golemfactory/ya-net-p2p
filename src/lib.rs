mod common;
pub mod crypto;
pub mod error;
pub mod event;
pub mod mangler;
pub mod packet;
pub mod protocol;
mod serialize;
mod session;
pub mod transport;

#[cfg(feature = "mk1")]
mod mk1;
#[cfg(not(feature = "mk1"))]
mod service;

#[cfg(feature = "mk1")]
pub use mk1::*;
#[cfg(not(feature = "mk1"))]
pub use service::*;

pub use crypto::Crypto;
pub use error::Error;
pub use packet::{EncodedPacket, Packet};
pub use protocol::ProtocolId;
pub use transport::{Address, TransportId};

pub type Result<T> = std::result::Result<T, Error>;
