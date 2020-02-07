use generic_array::ArrayLength;

pub use key::{Key, KeyGen, KeyOps};
pub use node::Node;
pub use proto::Kad;
pub use table::Table;

mod key;
mod model;
mod node;
mod proto;
mod table;

pub mod message {
    include!(concat!(env!("OUT_DIR"), "/kad.rs"));
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Mailbox error: {0}")]
    MailboxError(#[from] actix::MailboxError),
    #[error("Invalid key length: {0}")]
    InvalidKeyLength(usize),
    #[error("Invalid message: {0}")]
    InvalidMessage(String),
    #[error("Invalid property: {0}")]
    InvalidProperty(String),
}

#[derive(Clone, Debug, actix::Message)]
#[rtype(result = "()")]
pub enum KadAction<KeySz>
where
    KeySz: ArrayLength<u8>,
{
    TransferValues(Node<KeySz>, Vec<message::Storage>),
    Ping(Node<KeySz>),
}
