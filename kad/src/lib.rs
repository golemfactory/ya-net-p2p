#![allow(dead_code)]
pub use key::{lengths as key_lengths, Key, KeyLen};
pub use node::{Node, NodeData};
pub use service::{Kad, KadConfig};
pub use status::{KadStatus, KadStatusNodeInfo, QueryKadStatus};
pub use table::Table;

pub mod event;
mod key;
mod node;
mod query;
mod serialize;
mod service;
mod status;
mod table;

pub mod message {
    include!(concat!(env!("OUT_DIR"), "/kad.rs"));
}

// Number of parallel queries
pub(crate) const ALPHA: usize = 8;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Send error: {0}")]
    SendError(#[from] futures::channel::mpsc::SendError),
    #[error("{0}")]
    Encode(#[from] ::prost::EncodeError),
    #[error("{0}")]
    Decode(#[from] ::prost::DecodeError),
    #[error("Mailbox error: {0}")]
    MailboxError(#[from] actix::MailboxError),
    #[error("Invalid key length: {0}")]
    InvalidKeyLength(usize),
    #[error("Invalid lookup value: {0}")]
    InvalidLookupValue(String),
    #[error("Invalid property {1} in message {0}")]
    InvalidProperty(String, String),
    #[error("Missing request: {0}")]
    MissingRequest(String),
    #[error("Invalid query: {0}")]
    InvalidQuery(String),
    #[error("Invalid node data")]
    InvalidNodeData,
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("No message recipients")]
    NoRecipients,
    #[error("unknown kad packet")]
    UnknownPacket,
}

impl Error {
    #[inline]
    pub fn property(m: impl ToString, p: impl ToString) -> Self {
        Error::InvalidProperty(m.to_string(), p.to_string())
    }

    #[inline]
    pub fn request(rand_val: u32) -> Self {
        Error::MissingRequest(format!("Request for {} not found", rand_val))
    }

    #[inline]
    pub fn query(key: &Vec<u8>) -> Self {
        Error::InvalidQuery(format!("Query for {} not found", hex::encode(key)))
    }

    #[inline]
    pub fn fut<T: 'static>(self) -> impl futures::Future<Output = Result<T>> {
        futures::future::err(self)
    }
}
