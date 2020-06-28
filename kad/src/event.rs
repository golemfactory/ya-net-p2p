use crate::node::NodeData;
use crate::{message, Key, KeyLen, Node, Result};
use actix::Message;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

use crate::message::kad_message::Payload;
use prost::Message as _;

#[derive(Clone, Debug, Message, Deserialize, Serialize)]
#[rtype(result = "()")]
pub struct KadEvtSend<N: KeyLen, D: NodeData> {
    pub from: Node<N, D>,
    pub to: Node<N, D>,
    pub message: KadMessage,
}

#[derive(Clone, Debug, Message, Deserialize, Serialize)]
#[rtype(result = "Result<()>")]
pub struct KadReceive<N: KeyLen, D: NodeData> {
    pub from: Node<N, D>,
    pub message: KadMessage,
}

#[derive(Clone, Debug, Message, Deserialize, Serialize)]
#[rtype(result = "Result<()>")]
pub struct KadBootstrap<N: KeyLen, D: NodeData> {
    pub nodes: Vec<Node<N, D>>,
    pub dormant: bool,
}

#[derive(Clone, Debug, Message, Deserialize, Serialize)]
#[rtype(result = "Result<()>")]
pub struct KadStore {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub persistent: bool,
}

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<()>")]
pub struct KadNodeData<D: NodeData> {
    pub data: D,
}

#[derive(Clone, Debug, Message, Deserialize, Serialize)]
#[rtype(result = "Result<Option<Node<N, D>>>")]
pub struct KadFindNode<N: KeyLen + 'static, D: NodeData + 'static> {
    pub key: Key<N>,
    phantom: PhantomData<D>,
}

impl<N: KeyLen + 'static, D: NodeData + 'static> KadFindNode<N, D> {
    pub fn new(key: Key<N>) -> Self {
        KadFindNode {
            key,
            phantom: PhantomData,
        }
    }
}

#[derive(Clone, Debug, Message, Deserialize, Serialize)]
#[rtype(result = "Result<Option<(Vec<u8>, Vec<u8>)>>")]
pub struct KadFindValue {
    pub key: Vec<u8>,
}

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<()>")]
pub struct KadStoreForward<N: KeyLen, D: NodeData> {
    pub key: Vec<u8>,
    pub value: message::Value,
    pub nodes: Vec<Node<N, D>>,
}

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<()>")]
pub(crate) struct KadRequestMessage<N: KeyLen, D: NodeData> {
    pub to: Node<N, D>,
    pub message: KadMessage,
}

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<()>")]
pub(crate) struct KadResponseMessage<N: KeyLen, D: NodeData> {
    pub to: Node<N, D>,
    pub message: KadMessage,
}

macro_rules! kad_message {
    ( $($ident:ident),* ) => {
        #[derive(Clone, Debug, Message, Deserialize, Serialize)]
        #[rtype(result = "()")]
        pub enum KadMessage {
            $(
                $ident(message::$ident),
            )*
        }

        impl KadMessage {
            pub fn rand_val(&self) -> u32 {
                match &self {
                    $(
                        KadMessage::$ident(m) => m.rand_val,
                    )*
                }
            }

            pub fn set_rand_val(&mut self, rand_val: u32) {
                match self {
                    $(
                        KadMessage::$ident(m) => m.rand_val = rand_val,
                    )*
                }
            }
        }

        impl std::fmt::Display for KadMessage {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match &self {
                    $(
                        KadMessage::$ident(_) => f.write_fmt(format_args!(
                            "{} (rand_val: {:<10})",
                            stringify!($ident),
                            self.rand_val(),
                        )),
                    )*
                }
            }
        }

        $(
            impl From<message::$ident> for KadMessage {
                #[inline(always)]
                fn from(msg: message::$ident) -> Self {
                    KadMessage::$ident(msg)
                }
            }
        )*

        impl From<KadMessage> for crate::message::KadMessage {
            fn from(msg: KadMessage) -> Self {
                let payload = Some(match msg {
                    $(
                        KadMessage::$ident(p) => Payload::$ident(p)
                    ),*
                });
                crate::message::KadMessage {
                    payload
                }
            }
        }
    };
}

kad_message! {
    Ping,
    Pong,
    Store,
    FindNode,
    FindNodeResult,
    FindValue,
    FindValueResult
}

impl KadMessage {
    pub fn into_key(self) -> Option<Vec<u8>> {
        match self {
            KadMessage::FindNode(m) => Some(m.key),
            KadMessage::FindValue(m) => Some(m.key),
            _ => None,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<KadMessage> {
        let packet = crate::message::KadMessage::decode(bytes)?;
        Ok(match packet.payload {
            Some(Payload::Ping(p)) => KadMessage::Ping(p),
            Some(Payload::Pong(p)) => KadMessage::Pong(p),
            Some(Payload::Store(p)) => KadMessage::Store(p),
            Some(Payload::FindNode(p)) => KadMessage::FindNode(p),
            Some(Payload::FindNodeResult(p)) => KadMessage::FindNodeResult(p),
            Some(Payload::FindValue(p)) => KadMessage::FindValue(p),
            Some(Payload::FindValueResult(p)) => KadMessage::FindValueResult(p),
            None => return Err(crate::Error::UnknownPacket),
        })
    }

    pub fn to_bytes(self) -> Result<Vec<u8>> {
        let msg: crate::message::KadMessage = self.into();
        let len = msg.encoded_len();
        let mut buf = Vec::with_capacity(len);
        msg.encode(&mut buf)?;
        Ok(buf)
    }
}
