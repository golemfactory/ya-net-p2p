use crate::node::NodeData;
use crate::{message, Key, KeyLen, Node, Result};
use actix::Message;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

#[derive(Clone, Debug, Message, Deserialize, Serialize)]
#[rtype(result = "()")]
pub struct KadEvtSend<N: KeyLen, D: NodeData> {
    pub from: Node<N, D>,
    pub to: Node<N, D>,
    pub message: KadMessage,
}

#[derive(Clone, Debug, Message, Deserialize, Serialize)]
#[rtype(result = "Result<()>")]
pub struct KadEvtReceive<N: KeyLen, D: NodeData> {
    pub from: Node<N, D>,
    pub new: bool,
    pub message: KadMessage,
}

#[derive(Clone, Debug, Message, Deserialize, Serialize)]
#[rtype(result = "Result<Option<Node<N, D>>>")]
pub struct KadEvtFindNode<N: KeyLen + 'static, D: NodeData + 'static> {
    pub key: Key<N>,
    pub timeout: f64,
    phantom: PhantomData<D>,
}

impl<N: KeyLen + 'static, D: NodeData + 'static> KadEvtFindNode<N, D> {
    pub fn new(key: Key<N>, timeout: f64) -> Self {
        KadEvtFindNode {
            key,
            timeout,
            phantom: PhantomData,
        }
    }
}

#[derive(Clone, Debug, Message, Deserialize, Serialize)]
#[rtype(result = "Result<Option<(Vec<u8>, Vec<u8>)>>")]
pub struct KadEvtFindValue {
    pub key: Vec<u8>,
}

#[derive(Clone, Debug, Message, Deserialize, Serialize)]
#[rtype(result = "Result<()>")]
pub struct KadEvtBootstrap<N: KeyLen, D: NodeData> {
    pub nodes: Vec<Node<N, D>>,
    pub dormant: bool,
}

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<()>")]
pub(crate) struct EvtRequest<N: KeyLen, D: NodeData> {
    pub to: Node<N, D>,
    pub message: KadMessage,
}

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<()>")]
pub(crate) struct EvtRespond<N: KeyLen, D: NodeData> {
    pub to: Node<N, D>,
    pub message: KadMessage,
}

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<()>")]
pub(crate) struct EvtNodeDataChanged<D: NodeData> {
    pub data: D,
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
}
