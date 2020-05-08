use crate::protocol::ProtocolId;
use crate::transport::{Address, TransportId};

#[derive(thiserror::Error, Clone, Debug)]
pub enum NetworkError {
    #[error("no address provided")]
    NoAddress,
    #[error("unsupported address: {0:?}")]
    UnsupportedAddress(Address),
    #[error("unknown transport")]
    UnknownTransport(TransportId),
    #[error("invalid transport")]
    InvalidTransport(TransportId),
    #[error("unknown protocol")]
    UnknownProtocol(ProtocolId),
    #[error("not listening")]
    NotListening(TransportId),
    #[error("no connection")]
    NoConnection,
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("timeout")]
    Timeout,
}

#[derive(thiserror::Error, Clone, Debug)]
pub enum SessionError {
    #[error("key mismatch: expected {0:?}, received {1:?}")]
    KeyMismatch(Vec<u8>, Vec<u8>),
    #[error("disconnected")]
    Disconnected,
    #[error("terminated")]
    Terminated,
    #[error("timeout")]
    Timeout,
}

#[derive(thiserror::Error, Clone, Debug)]
pub enum DiscoveryError {
    #[error("timeout: {0}")]
    Timeout(String),
}

#[derive(thiserror::Error, Clone, Debug)]
pub enum ProtocolError {
    #[error("invalid protocol id: {0}")]
    InvalidId(String),
    #[error("invalid protocol state: {0}")]
    InvalidState(String),
}

#[derive(thiserror::Error, Clone, Debug)]
pub enum MessageError {
    #[error("codec error: {0}")]
    Codec(String),
    #[error("signature error: {0}")]
    Signature(String),
    #[error("missing auth")]
    MissingAuth,
    #[error("missing signature")]
    MissingSignature,
}

#[derive(thiserror::Error, Clone, Debug)]
pub enum ChannelError {
    #[error("timeout")]
    Timeout,
    #[error("channel full")]
    Full,
    #[error("channel closed")]
    Closed,
}

#[derive(thiserror::Error, Clone, Debug)]
pub enum CryptoError {
    #[error("invalid key")]
    InvalidKey,
}

#[derive(thiserror::Error, Clone, Debug)]
pub enum Error {
    #[error("message error: {0}")]
    Message(#[from] MessageError),
    #[error("network error: {0}")]
    Network(#[from] NetworkError),
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("session error: {0}")]
    Session(#[from] SessionError),
    #[error("discovery error: {0}")]
    Discovery(#[from] DiscoveryError),

    #[error("channel error: {0}")]
    Channel(#[from] ChannelError),

    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("identity error: {0}")]
    Identity(#[from] ya_core_model::identity::Error),
    #[error("signature error: {0}")]
    Signature(String),

    #[cfg(feature = "yagna")]
    #[error("service bus error: {0}")]
    ServiceBus(String),

    #[error()]
    #[cfg(feature = "mk1")]
    #[error("{0}")]
    Mk1(#[from] crate::mk1::NetApiError),
}

impl Error {
    pub fn sig(e: impl ToString) -> Self {
        MessageError::Signature(e.to_string()).into()
    }

    pub fn protocol(e: impl ToString) -> Self {
        NetworkError::Protocol(e.to_string()).into()
    }

    pub fn protocol_state(e: impl ToString) -> Self {
        ProtocolError::InvalidState(e.to_string()).into()
    }

    pub fn key() -> Self {
        CryptoError::InvalidKey.into()
    }

    pub fn key_mismatch<A: AsRef<[u8]>, B: AsRef<[u8]>>(a: A, b: B) -> Self {
        SessionError::KeyMismatch(a.as_ref().to_vec(), b.as_ref().to_vec()).into()
    }
}

#[cfg(feature = "yagna")]
impl From<ya_service_bus::Error> for Error {
    fn from(err: ya_service_bus::Error) -> Self {
        Error::ServiceBus(err.to_string())
    }
}

#[cfg(feature = "yagna")]
impl From<ethsign::Error> for Error {
    fn from(err: ethsign::Error) -> Self {
        Error::Signature(err.to_string())
    }
}

impl From<actix::MailboxError> for Error {
    fn from(err: actix::MailboxError) -> Self {
        ChannelError::from(err).into()
    }
}

impl From<futures::channel::mpsc::SendError> for Error {
    fn from(err: futures::channel::mpsc::SendError) -> Self {
        ChannelError::from(err).into()
    }
}

impl From<futures::channel::mpsc::SendError> for ChannelError {
    fn from(err: futures::channel::mpsc::SendError) -> Self {
        if err.is_full() {
            ChannelError::Full
        } else {
            ChannelError::Closed
        }
    }
}

impl<T> From<crossbeam_channel::SendError<T>> for Error {
    fn from(err: crossbeam_channel::SendError<T>) -> Self {
        ChannelError::from(err).into()
    }
}

impl<T> From<crossbeam_channel::SendError<T>> for ChannelError {
    fn from(_: crossbeam_channel::SendError<T>) -> Self {
        ChannelError::Closed
    }
}

impl From<actix::MailboxError> for ChannelError {
    fn from(err: actix::MailboxError) -> Self {
        match err {
            actix::MailboxError::Timeout => ChannelError::Timeout,
            actix::MailboxError::Closed => ChannelError::Closed,
        }
    }
}
