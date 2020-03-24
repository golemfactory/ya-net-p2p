pub use event::*;
pub use key::{Key, KeyLen};
pub use node::Node;
pub use service::Kad;
pub use table::{Table, K};

mod event;
mod key;
mod node;
mod service;
mod table;

pub mod message {
    include!(concat!(env!("OUT_DIR"), "/kad.rs"));
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Send error: {0}")]
    SendError(#[from] futures::channel::mpsc::SendError),
    #[error("Mailbox error: {0}")]
    MailboxError(#[from] actix::MailboxError),
    #[error("Invalid key length: {0}")]
    InvalidKeyLength(usize),
    #[error("Invalid lookup value: {0}")]
    InvalidLookupValue(String),
    #[error("Invalid message: {0}")]
    InvalidMessage(String),
    #[error("Invalid property {1} in message {0}")]
    InvalidProperty(String, String),
    #[error("Missing request: {0}")]
    MissingRequest(String),
    #[error("Invalid lookup: {0}")]
    InvalidLookup(String),
}

impl Error {
    #[inline]
    pub fn message(m: impl ToString) -> Self {
        Error::InvalidMessage(m.to_string())
    }

    #[inline]
    pub fn property(m: impl ToString, p: impl ToString) -> Self {
        Error::InvalidProperty(m.to_string(), p.to_string())
    }

    #[inline]
    pub fn request(rand_val: u32) -> Self {
        Error::MissingRequest(format!("Request for {} not found", rand_val))
    }

    #[inline]
    pub fn lookup(key: &Vec<u8>) -> Self {
        Error::InvalidLookup(format!("Lookup for {} not found", hex::encode(key)))
    }

    #[inline]
    pub fn fut<T: 'static>(self) -> impl futures::Future<Output = Result<T>> {
        futures::future::err(self)
    }
}
