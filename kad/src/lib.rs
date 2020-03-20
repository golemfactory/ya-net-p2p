use actix::Message;

pub use key::{Key, KeyLen};
pub use node::Node;
pub use proto::Kad;
pub use table::Table;

mod key;
mod node;
mod proto;
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
    #[error("Invalid message: {0}")]
    InvalidMessage(String),
    #[error("Invalid property {1} in message {0}")]
    InvalidProperty(String, String),
}

impl Error {
    pub fn message(m: impl ToString) -> Self {
        Error::InvalidMessage(m.to_string())
    }

    pub fn property(m: impl ToString, p: impl ToString) -> Self {
        Error::InvalidProperty(m.to_string(), p.to_string())
    }
}

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<()>")]
pub(crate) struct KadMessageIn<N: KeyLen> {
    pub sender: Node<N>,
    pub new_conn: bool,
    pub inner: KadMessage,
}

#[derive(Clone, Debug, Message)]
#[rtype(result = "()")]
pub enum KadMessage {
    Ping(message::Ping),
    Pong(message::Pong),
    Store(message::Store),
    FindNode(message::FindNode),
    FindNodeResult(message::FindNodeResult),
    FindValue(message::FindValue),
    FindValueResult(message::FindValueResult),
}

#[derive(Clone, Debug, Message)]
#[rtype(result = "()")]
pub enum KadStatus<N: KeyLen> {
    FoundNode(Node<N>),
    FoundValue(Vec<u8>),
}

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<()>")]
pub(crate) struct LocalAdd<N>(pub Node<N>, pub bool)
where
    N: KeyLen;

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<()>")]
pub(crate) struct LocalStore(pub Vec<u8>, pub message::Value);
