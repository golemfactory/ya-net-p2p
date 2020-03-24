use crate::{message, Key, KeyLen, Node, Result};
use actix::Message;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Message, Deserialize, Serialize)]
#[rtype(result = "()")]
pub struct KadEvtSend<N: KeyLen> {
    pub to: Node<N>,
    pub message: KadMessage,
}

#[derive(Clone, Debug, Message, Deserialize, Serialize)]
#[rtype(result = "Result<()>")]
pub struct KadEvtReceive<N: KeyLen> {
    pub from: Node<N>,
    pub new: bool,
    pub message: KadMessage,
}

#[derive(Clone, Debug, Message, Deserialize, Serialize)]
#[rtype(result = "Result<Option<Node<N>>>")]
pub struct KadEvtFindNode<N: KeyLen + 'static> {
    pub key: Key<N>,
    pub timeout: f64,
}

#[derive(Clone, Debug, Message, Deserialize, Serialize)]
#[rtype(result = "Result<Option<(Vec<u8>, Vec<u8>)>>")]
pub struct KadEvtFindValue {
    pub key: Vec<u8>,
}

#[derive(Clone, Debug, Message, Deserialize, Serialize)]
#[rtype(result = "Result<()>")]
pub struct KadEvtBootstrap<N: KeyLen> {
    pub nodes: Vec<Node<N>>,
}

#[derive(Clone, Debug, Message, Deserialize, Serialize)]
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

impl KadMessage {
    pub fn is_request(&self) -> bool {
        match &self {
            KadMessage::Ping(_)
            | KadMessage::Store(_)
            | KadMessage::FindValue(_)
            | KadMessage::FindNode(_) => true,
            _ => false,
        }
    }

    pub fn is_response(&self) -> bool {
        !self.is_request()
    }

    pub fn searched_key(&self) -> Option<Vec<u8>> {
        match &self {
            KadMessage::FindNode(m) => Some(m.key.clone()),
            KadMessage::FindValue(m) => Some(m.key.clone()),
            _ => None,
        }
    }

    pub fn rand_val(&self) -> u32 {
        match &self {
            KadMessage::Ping(m) => m.rand_val,
            KadMessage::Pong(m) => m.rand_val,
            KadMessage::Store(m) => m.rand_val,
            KadMessage::FindNode(m) => m.rand_val,
            KadMessage::FindNodeResult(m) => m.rand_val,
            KadMessage::FindValue(m) => m.rand_val,
            KadMessage::FindValueResult(m) => m.rand_val,
        }
    }
}

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<()>")]
pub(crate) struct EvtSend<N: KeyLen> {
    pub to: Node<N>,
    pub message: KadMessage,
}

impl<N: KeyLen> EvtSend<N> {
    pub fn new(to: Node<N>, message: KadMessage) -> Self {
        Self { to, message }
    }
}

impl<N: KeyLen> From<EvtSend<N>> for KadEvtSend<N> {
    fn from(evt: EvtSend<N>) -> Self {
        Self {
            to: evt.to,
            message: evt.message,
        }
    }
}
