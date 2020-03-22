use crate::{message, Key, KeyLen, Node, Result};
use actix::Message;

#[derive(Clone, Debug, Message)]
#[rtype(result = "()")]
pub struct KadEvtSend<N: KeyLen> {
    pub to: Node<N>,
    pub message: KadMessage,
}

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<()>")]
pub struct KadEvtReceive<N: KeyLen> {
    pub from: Node<N>,
    pub new: bool,
    pub message: KadMessage,
}

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<Option<Node<N>>")]
pub struct KadEvtFindNode<N: KeyLen> {
    pub key: Key<N>,
}

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<Option<(Vec<u8>, Vec<u8>)>")]
pub struct KadEvtFindValue {
    pub key: Vec<u8>,
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

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<()>")]
pub(crate) struct EvtNodes<N: KeyLen> {
    pub from: Key<N>,
    pub nodes: Vec<Node<N>>,
}
