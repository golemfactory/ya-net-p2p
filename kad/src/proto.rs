use crate::event::*;
use crate::key::{Key, KeyLen};
use crate::node::Node;
use crate::table::{Table, K};
use crate::{message, Error, Result};

use actix::prelude::*;
use chrono::Utc;
use futures::channel::mpsc;
use futures::{Future, FutureExt, SinkExt};
use generic_array::ArrayLength;
use rand::RngCore;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::rc::Rc;
use std::time::Duration;

const ALPHA: usize = 3;

const MAX_KEY_SZ: usize = 33;
const MAX_VAL_SZ: usize = 65535;
const MAX_VALUES_TO_SEND: usize = 100;
const MAX_TTL: u32 = 604800;
const MAX_REQUEST_TTL: i64 = 15;

const LOOKUP_TIMEOUT: i64 = 30;

lazy_static::lazy_static! {
    static ref REQUEST_UPKEEP_INTERVAL: Duration = Duration::from_secs(5);
    static ref STORAGE_UPKEEP_INTERVAL: Duration = Duration::from_secs(60);
}

pub struct Kad<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    tx: mpsc::Sender<KadEvtSend<N>>,
    table: Table<N>,
    storage: HashMap<Vec<u8>, (message::Value, i64)>,
    requests: HashMap<u32, (KadMessage, i64)>,
    node_lookups: HashMap<Vec<u8>, Addr<NodeLookup<N>>>,
}

impl<N> Kad<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    pub fn new(me: Rc<Node<N>>, tx: mpsc::Sender<KadEvtSend<N>>) -> Self {
        Self {
            tx,
            table: Table::new(me, K),
            storage: HashMap::new(),
            requests: HashMap::new(),
            node_lookups: HashMap::new(),
        }
    }

    #[inline]
    pub fn add(&mut self, node: &Node<N>) {
        self.table.add(&node);
    }

    pub fn keys_to_refresh(&self) -> Vec<Key<N>> {
        self.table
            .stale_buckets()
            .into_iter()
            .map(|b| Key::<N>::random(&b.range))
            .collect()
    }

    #[inline]
    fn timeout_storage(&mut self, _: &mut Context<Self>) {
        let now = Utc::now().timestamp();
        self.storage
            .retain(|_, (value, created_at)| value.ttl as i64 + *created_at > now);
    }

    #[inline]
    fn timeout_requests(&mut self, _: &mut Context<Self>) {
        let now = Utc::now().timestamp();
        self.requests
            .retain(|_, (_, created_at)| now - *created_at < MAX_REQUEST_TTL);
    }
}

impl<N> Kad<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    fn find_node(
        &self,
        key: &Key<N>,
        excluded: Option<&Key<N>>,
        max: Option<usize>,
    ) -> Vec<Node<N>> {
        let mut nodes = self.table.neighbors(&key, excluded, max);
        if key == &self.table.me.key {
            if max.map(|m| m == nodes.len()).unwrap_or(false) {
                nodes.remove(0);
            }
            nodes.push((*self.table.me).clone());
        }
        nodes
    }

    fn find_value(&mut self, key: &Vec<u8>) -> Option<message::Value> {
        match self.storage.get(key) {
            Some((value, created_at)) => {
                let lifetime = value.ttl as i64 - (Utc::now().timestamp() - created_at);
                if lifetime > 0 {
                    return Some(message::Value {
                        value: value.value.clone(),
                        ttl: lifetime as u32,
                    });
                }
                None
            }
            None => None,
        }
    }
}

impl<N> Actor for Kad<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        IntervalFunc::new(*STORAGE_UPKEEP_INTERVAL, Self::timeout_storage)
            .finish()
            .spawn(ctx);
        IntervalFunc::new(*REQUEST_UPKEEP_INTERVAL, Self::timeout_requests)
            .finish()
            .spawn(ctx);
    }
}

impl<N> Handler<KadEvtReceive<N>> for Kad<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, evt: KadEvtReceive<N>, ctx: &mut Context<Self>) -> Self::Result {
        let address = ctx.address();
        let (from, _new, msg) = (evt.from, evt.new, evt.message);

        let add_msg = if !self.table.add(&from) {
            Some(KadMessage::Ping(message::Ping {
                rand_val: rand::thread_rng().next_u32(),
            }))
        // TODO: } else if new { transfer_values(..)
        } else {
            None
        };

        let handler_fut = match msg {
            KadMessage::FindNode(m) => self.handle_find_node(m, &from.key).boxed_local(),
            KadMessage::FindNodeResult(m) => {
                self.handle_find_node_result(m, &from.key).boxed_local()
            }
            KadMessage::FindValue(m) => self.handle_find_value(m, &from.key).boxed_local(),
            KadMessage::FindValueResult(m) => {
                self.handle_find_value_result(m, &from.key).boxed_local()
            }
            KadMessage::Store(m) => self.handle_store(m).boxed_local(),
            KadMessage::Ping(m) => self.handle_ping(m).boxed_local(),
            _ => async move { Ok(None) }.boxed_local(),
        };

        let fut = async move {
            if let Some(m) = add_msg {
                address
                    .send(EvtSend {
                        to: from.clone(),
                        message: m,
                    })
                    .await??;
            }
            if let Some(m) = handler_fut.await? {
                address
                    .send(EvtSend {
                        to: from,
                        message: m,
                    })
                    .await??;
            }
            Ok(())
        };

        ActorResponse::r#async(fut.into_actor(self))
    }
}

type HandleMsgResult = Result<Option<KadMessage>>;

impl<N> Kad<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    #[inline]
    fn handle_ping(&mut self, msg: message::Ping) -> impl Future<Output = HandleMsgResult> {
        async move {
            Ok(Some(KadMessage::Pong(message::Pong {
                rand_val: msg.rand_val,
            })))
        }
    }

    #[inline]
    fn handle_store(&mut self, msg: message::Store) -> impl Future<Output = HandleMsgResult> {
        let value = match msg.value {
            Some(v) => v,
            None => return Error::message("Store: missing 'value'").fut().left_future(),
        };

        if msg.key.len() > MAX_KEY_SZ {
            return Error::property("Store", format!("key size > {}", MAX_KEY_SZ))
                .fut()
                .left_future();
        }
        if value.value.len() > MAX_VAL_SZ {
            return Error::property("Store", format!("value size > {}", MAX_VAL_SZ))
                .fut()
                .left_future();
        }
        if value.ttl > MAX_TTL {
            return Error::property("Store", format!("ttl > {}", MAX_TTL))
                .fut()
                .left_future();
        }

        let now = Utc::now().timestamp();
        self.storage.insert(msg.key, (value, now));
        async move { Ok(None) }.right_future()
    }

    #[inline]
    fn handle_find_node(
        &mut self,
        msg: message::FindNode,
        from: &Key<N>,
    ) -> impl Future<Output = HandleMsgResult> {
        let rand_val = msg.rand_val;
        let nodes = match Key::<N>::try_from(msg.key) {
            Ok(key) => Ok(self.find_node(&key, Some(from), Some(self.table.k))),
            Err(e) => Err(e),
        };

        async move {
            Ok(Some(KadMessage::FindNodeResult(message::FindNodeResult {
                rand_val,
                nodes: nodes?.into_iter().map(Node::into).collect(),
            })))
        }
    }

    #[inline]
    fn handle_find_node_result(
        &mut self,
        msg: message::FindNodeResult,
        from: &Key<N>,
    ) -> impl Future<Output = HandleMsgResult> {
        let lookup = self
            .requests
            .get(&msg.rand_val)
            .map(|(m, _)| match m {
                KadMessage::FindNode(msg) => self.node_lookups.get(&msg.key).cloned(),
                _ => None,
            })
            .flatten()
            .ok_or(Error::InvalidResponse("Request not found".to_owned()));

        let from = from.clone();
        async move {
            lookup?
                .send(EvtNodes {
                    from,
                    nodes: msg
                        .nodes
                        .into_iter()
                        .map(Node::try_from)
                        .filter_map(Result::ok)
                        .collect(),
                })
                .await??;
            Ok(None)
        }
    }

    #[inline]
    fn handle_find_value(
        &mut self,
        msg: message::FindValue,
        from: &Key<N>,
    ) -> impl Future<Output = HandleMsgResult> {
        use message::find_value_result::Result as Response;

        let reply = if let Some(value) = self.find_value(&msg.key) {
            Ok(message::FindValueResult {
                rand_val: msg.rand_val,
                result: Some(Response::Value(value)),
            })
        } else {
            match Key::<N>::try_from(msg.key) {
                Ok(key) => Ok(message::FindValueResult {
                    rand_val: msg.rand_val,
                    result: Some(Response::Nodes(message::Nodes {
                        nodes: self
                            .find_node(&key, Some(from), Some(self.table.k))
                            .into_iter()
                            .map(Node::into)
                            .collect(),
                    })),
                }),
                Err(e) => Err(e),
            }
        };

        async move { Ok(Some(KadMessage::FindValueResult(reply?))) }
    }

    #[inline]
    fn handle_find_value_result(
        &mut self,
        _: message::FindValueResult,
        _: &Key<N>,
    ) -> impl Future<Output = HandleMsgResult> {
        async move { Ok(None) }
    }
}

impl<N> Handler<KadEvtFindNode<N>> for Kad<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Result = <KadEvtFindNode<N> as Message>::Result;

    fn handle(&mut self, _: KadEvtFindNode<N>, _: &mut Context<Self>) -> Self::Result {}
}

impl<N> Handler<EvtSend<N>> for Kad<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, evt: EvtSend<N>, _: &mut Context<Self>) -> Self::Result {
        if evt.message.is_request() {
            self.requests.insert(
                evt.message.rand_val(),
                (evt.message.clone(), Utc::now().timestamp()),
            );
        }

        let mut tx = self.tx.clone();
        let fut = async move {
            tx.send(KadEvtSend {
                to: evt.to,
                message: evt.message,
            })
            .await?;
            Ok(())
        };

        ActorResponse::r#async(fut.into_actor(self))
    }
}

struct NodeLookup<N: KeyLen> {
    key: Key<N>,
    result: Option<Option<Node<N>>>,
}

impl<N> Actor for NodeLookup<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Context = Context<Self>;
}

impl<N> Handler<EvtNodes<N>> for NodeLookup<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Result = <EvtNodes<N> as Message>::Result;

    fn handle(&mut self, _: EvtNodes<N>, _: &mut Context<Self>) -> Self::Result {
        unimplemented!()
    }
}
