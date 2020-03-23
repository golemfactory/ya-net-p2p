use crate::event::*;
use crate::key::{Key, KeyLen};
use crate::node::Node;
use crate::table::{Table, K};
use crate::{message, Error, Result};

use actix::prelude::*;
use chrono::Utc;
use futures::channel::mpsc;
use futures::task::{Poll, Waker};
use futures::{Future, FutureExt, SinkExt};
use generic_array::ArrayLength;
use rand::RngCore;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::pin::Pin;
use std::rc::Rc;
use std::time::Duration;
use tokio::time::timeout;

const ALPHA: usize = 8;

const MAX_KEY_SZ: usize = 33;
const MAX_VAL_SZ: usize = 65535;
const MAX_VAL_TTL: u32 = 604800;
const MAX_REQ_TTL: i64 = 5;
const MAX_LOOKUP_TTL: i64 = 300;

lazy_static::lazy_static! {
    static ref REQUEST_UPKEEP_INTERVAL: Duration = Duration::from_secs(2);
    static ref STORAGE_UPKEEP_INTERVAL: Duration = Duration::from_secs(60);
    static ref LOOKUP_UPKEEP_INTERVAL: Duration = Duration::from_secs(2);
}

pub struct Kad<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    tx: mpsc::Sender<KadEvtSend<N>>,
    table: Table<N>,
    storage: HashMap<Vec<u8>, (message::Value, i64)>,
    lookups: HashMap<Vec<u8>, (Lookup<N>, i64)>,
    requests: HashMap<u32, (KadMessage, i64)>,
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
            lookups: HashMap::new(),
            requests: HashMap::new(),
        }
    }

    pub fn keys_to_refresh(&self) -> Vec<Key<N>> {
        self.table
            .stale_buckets()
            .into_iter()
            .map(|b| Key::<N>::random(&b.range))
            .collect()
    }

    #[inline]
    fn storage_upkeep(&mut self, _: &mut Context<Self>) {
        let now = Utc::now().timestamp();
        self.storage
            .retain(|_, (value, created_at)| value.ttl as i64 + *created_at > now);
    }

    #[inline]
    fn request_upkeep(&mut self, _: &mut Context<Self>) {
        let now = Utc::now().timestamp();
        self.requests
            .retain(|_, (_, created_at)| now - *created_at < MAX_REQ_TTL);
    }

    #[inline]
    fn lookup_upkeep(&mut self, ctx: &mut Context<Self>) {
        let now = Utc::now().timestamp();
        let address = ctx.address();

        self.lookups.retain(|key, (lookup, created_at)| {
            let dt = now - *created_at;
            if dt >= MAX_LOOKUP_TTL {
                log::debug!("Lookup of {} failed after {} s", hex::encode(key), dt);
                lookup.complete(LookupValue::None);
                return false;
            }

            let nodes = {
                let mut state = lookup.state.borrow_mut();
                if let LookupState::InProgress {
                    started_at,
                    pending,
                    ..
                } = &mut *state {
                    if now - *started_at > MAX_REQ_TTL {
                        pending.clear();
                    }
                    if pending.is_empty() {
                        Some(state.next_round())
                    } else {
                        None
                    }
                } else { None }
            };

            if let Some(nodes) = nodes {
                match nodes.len() {
                    0 => {
                        log::debug!("Lookup of {} failed after {} s - did not receive node information in time", hex::encode(key), dt);
                        lookup.complete(LookupValue::None);
                    },
                    _ => {
                        let address = address.clone();
                        let key = key.clone();
                        actix_rt::spawn(async move {
                            for to in nodes.into_iter() {
                                let message = KadMessage::FindNode(message::FindNode {
                                    rand_val: rand::thread_rng().next_u32(),
                                    key: key.clone(),
                                });
                                let _ = address.send(EvtSend { to, message }).await;
                            }
                        });
                    }
                }
            }

            true
        });
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
        if let Some((value, created_at)) = self.storage.get(key) {
            let lifetime = value.ttl as i64 - (Utc::now().timestamp() - created_at);
            if lifetime > 0 {
                return Some(message::Value {
                    value: value.value.clone(),
                    ttl: lifetime as u32,
                });
            }
        }
        None
    }
}

impl<N> Actor for Kad<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        IntervalFunc::new(*STORAGE_UPKEEP_INTERVAL, Self::storage_upkeep)
            .finish()
            .spawn(ctx);
        IntervalFunc::new(*LOOKUP_UPKEEP_INTERVAL, Self::lookup_upkeep)
            .finish()
            .spawn(ctx);
        IntervalFunc::new(*REQUEST_UPKEEP_INTERVAL, Self::request_upkeep)
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
                address.send(EvtSend::new(from.clone(), m)).await??;
            }
            if let Some(m) = handler_fut.await? {
                address.send(EvtSend::new(from, m)).await??;
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
        if value.ttl > MAX_VAL_TTL {
            return Error::property("Store", format!("ttl > {}", MAX_VAL_TTL))
                .fut()
                .left_future();
        }

        self.storage
            .insert(msg.key, (value, Utc::now().timestamp()));
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
            Ok(key) => self.find_node(&key, Some(from), Some(self.table.k)),
            Err(error) => return error.fut().left_future(),
        };

        async move {
            Ok(Some(KadMessage::FindNodeResult(message::FindNodeResult {
                rand_val,
                nodes: nodes.into_iter().map(Node::into).collect(),
            })))
        }
        .right_future()
    }

    #[inline]
    fn handle_find_node_result(
        &mut self,
        msg: message::FindNodeResult,
        from: &Key<N>,
    ) -> impl Future<Output = HandleMsgResult> {
        let key_opt = self
            .requests
            .get(&msg.rand_val)
            .map(|(m, _)| match m {
                KadMessage::FindNode(msg) => Some(msg.key.clone()),
                _ => None,
            })
            .flatten();
        let key_vec = match key_opt {
            Some(key) => key,
            None => return Error::request(msg.rand_val).fut().left_future(),
        };
        let key = match Key::<N>::try_from(key_vec.clone()) {
            Ok(key) => key,
            Err(e) => return e.fut().left_future(),
        };
        let mut lookup = match self.lookups.get(&key_vec) {
            Some(lookup) => lookup.0.clone(),
            None => return Error::lookup(&key_vec).fut().left_future(),
        };

        let nodes = msg
            .nodes
            .into_iter()
            .map(Node::<N>::try_from)
            .filter_map(Result::ok)
            .collect::<Vec<_>>();

        if let Some(idx) = nodes.iter().position(|n| &n.key == &key) {
            lookup.complete(LookupValue::Node(nodes[idx].clone()));
        } else {
            lookup.state.borrow_mut().feed(&key, from, nodes);
        }

        async move { Ok(None) }.right_future()
    }

    #[inline]
    fn handle_find_value(
        &mut self,
        msg: message::FindValue,
        from: &Key<N>,
    ) -> impl Future<Output = HandleMsgResult> {
        use message::find_value_result::Result as Response;

        let reply = match self.find_value(&msg.key) {
            Some(value) => message::FindValueResult {
                rand_val: msg.rand_val,
                result: Some(Response::Value(value)),
            },
            None => match Key::<N>::try_from(msg.key) {
                Ok(key) => message::FindValueResult {
                    rand_val: msg.rand_val,
                    result: Some(Response::Nodes(message::Nodes {
                        nodes: self
                            .find_node(&key, Some(from), Some(self.table.k))
                            .into_iter()
                            .map(Node::into)
                            .collect(),
                    })),
                },
                Err(e) => return e.fut().left_future(),
            },
        };

        async move { Ok(Some(KadMessage::FindValueResult(reply))) }.right_future()
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
    type Result = ActorResponse<Self, Option<Node<N>>, Error>;

    fn handle(&mut self, msg: KadEvtFindNode<N>, ctx: &mut Context<Self>) -> Self::Result {
        if let Some(node) = self.table.get(&msg.key).cloned() {
            return ActorResponse::reply(Ok(Some(node)));
        }

        let address = ctx.address();
        let key = msg.key.as_ref().to_vec();

        let lookup = match self.lookups.get(&key) {
            Some((lookup, _)) => lookup.clone().left_future(),
            None => {
                let nodes = self.find_node(&msg.key, None, Some(ALPHA));
                let lookup = self
                    .lookups
                    .entry(key.clone())
                    .or_insert_with(|| Lookup::new_entry(&nodes))
                    .0
                    .clone();

                async move {
                    for to in nodes.into_iter() {
                        let message = KadMessage::FindNode(message::FindNode {
                            rand_val: rand::thread_rng().next_u32(),
                            key: key.clone(),
                        });
                        let _ = address.send(EvtSend { to, message }).await;
                    }
                    lookup.await
                }
                .right_future()
            }
        };

        let fut = async move {
            timeout(Duration::from_secs_f64(msg.timeout), lookup)
                .await
                .map_err(Error::from)
                .map(|v| v.to_node())
        };

        ActorResponse::r#async(fut.into_actor(self))
    }
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
        let fut = async move { tx.send(KadEvtSend::from(evt)).await.map_err(Error::from) };
        ActorResponse::r#async(fut.into_actor(self))
    }
}

#[derive(Clone)]
struct Lookup<N: KeyLen> {
    state: Rc<RefCell<LookupState<N>>>,
    waker: Option<Waker>,
}

impl<N: KeyLen> Lookup<N> {
    pub fn new(state: LookupState<N>) -> Self {
        let state = Rc::new(RefCell::new(state));
        Lookup { state, waker: None }
    }

    pub fn new_entry(nodes: &Vec<Node<N>>) -> (Self, i64) {
        (
            Self::new(LookupState::new(nodes.clone())),
            Utc::now().timestamp(),
        )
    }
}

impl<N: KeyLen> Lookup<N> {
    #[inline]
    pub fn complete(&mut self, result: LookupValue<N>) {
        if let LookupState::InProgress { .. } = &*self.state.borrow() {
            self.state.replace(LookupState::Completed { result });
        }
        if let Some(waker) = &self.waker {
            waker.wake_by_ref();
        }
    }
}

impl<N: KeyLen> Future for Lookup<N> {
    type Output = LookupValue<N>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut futures::task::Context<'_>) -> Poll<Self::Output> {
        if let LookupState::Completed { result } = &*self.state.borrow() {
            return Poll::Ready(result.clone());
        }

        self.waker.replace(cx.waker().clone());
        Poll::Pending
    }
}

#[derive(Clone, Debug)]
pub(crate) enum LookupState<N: KeyLen> {
    InProgress {
        started_at: i64,
        pending: HashSet<Key<N>>,
        candidates: Vec<Node<N>>,
    },
    Completed {
        result: LookupValue<N>,
    },
}

impl<N: KeyLen> LookupState<N> {
    pub fn feed(&mut self, key: &Key<N>, from: &Key<N>, nodes: Vec<Node<N>>) {
        match self {
            LookupState::InProgress {
                started_at: _,
                pending,
                candidates,
            } => {
                pending.remove(from);
                candidates.extend(nodes.iter().cloned());
                candidates.sort_by_key(|n| key.distance(&n.key));
                candidates.truncate(K);
            }
            _ => (),
        }
    }

    pub fn next_round(&mut self) -> Vec<Node<N>> {
        match self {
            LookupState::InProgress {
                started_at,
                pending,
                candidates,
            } => {
                *started_at = Utc::now().timestamp();
                *pending = candidates.iter().map(|n| n.key.clone()).collect();
                std::mem::replace(candidates, Vec::new())
            }
            _ => Vec::new(),
        }
    }
}

impl<N: KeyLen> LookupState<N> {
    pub fn new(nodes: Vec<Node<N>>) -> Self {
        let keys = nodes.into_iter().map(|n| n.key).collect();
        LookupState::InProgress {
            started_at: Utc::now().timestamp(),
            pending: keys,
            candidates: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum LookupValue<N: KeyLen> {
    Node(Node<N>),
    #[allow(dead_code)]
    Value(Vec<u8>),
    None,
}

impl<N: KeyLen> LookupValue<N> {
    pub fn to_node(&self) -> Option<Node<N>> {
        match &self {
            LookupValue::Node(opt) => Some(opt.clone()),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub fn to_value(&self) -> Option<Vec<u8>> {
        match &self {
            LookupValue::Value(opt) => Some(opt.clone()),
            _ => None,
        }
    }
}
