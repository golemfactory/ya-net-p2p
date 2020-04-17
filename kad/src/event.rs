use crate::{message, Key, KeyLen, Node, Result};
use actix::Message;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Clone, Debug, Message, Deserialize, Serialize)]
#[rtype(result = "()")]
pub struct KadEvtSend<N: KeyLen> {
    pub from: Node<N>,
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
    pub dormant: bool,
}

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<()>")]
pub(crate) struct EvtRespond<N: KeyLen> {
    pub to: Node<N>,
    pub message: KadMessage,
}

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<()>")]
pub(crate) struct EvtRequest<N: KeyLen> {
    pub to: Node<N>,
    pub message: KadMessage,
}

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<()>")]
pub(crate) struct EvtAddressChanged {
    pub address: SocketAddr,
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
