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
use itertools::Itertools;
use rand::RngCore;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::pin::Pin;
use std::rc::Rc;
use std::time::Duration;

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
    me: Rc<Node<N>>,
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
        let key = me.key.clone();
        Self {
            tx,
            me,
            table: Table::new(key, K),
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
    fn lookup_upkeep(&mut self, _: &mut Context<Self>) {
        let now = Utc::now().timestamp();
        self.lookups.retain(|_, (lookup, created_at)| {
            if now - *created_at >= MAX_LOOKUP_TTL {
                lookup.finish(LookupValue::None);
            } else {
                lookup.iterate();
            }
            lookup.in_progress()
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
        limit: Option<usize>,
    ) -> Vec<Node<N>> {
        let mut nodes = self.table.neighbors(&key, excluded, limit);
        if key == &self.me.key {
            if limit.map(|l| l == nodes.len()).unwrap_or(false) {
                nodes.remove(0);
            }
            nodes.push((*self.me).clone());
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

    fn find_lookup(&self, rand_val: u32) -> Result<Lookup<N>> {
        let key_opt = self
            .requests
            .get(&rand_val)
            .map(|(m, _)| m.searched_key())
            .flatten();

        let key = match key_opt {
            Some(key) => key,
            None => return Err(Error::request(rand_val)),
        };

        match self.lookups.get(&key) {
            Some((lookup, _)) => Ok(lookup.clone()),
            None => Err(Error::lookup(&key)),
        }
    }

    fn initiate_lookup(
        &mut self,
        lookup_key: LookupKey,
        node_key: &Key<N>,
        address: Addr<Self>,
    ) -> Lookup<N> {
        if let Some((lookup, _)) = self.lookups.get(lookup_key.as_ref()) {
            return lookup.clone();
        }

        let nodes = self.find_node(node_key, None, Some(K));
        let lookup = self
            .lookups
            .entry(lookup_key.as_ref().to_vec())
            .or_insert((
                Lookup::new(lookup_key, &nodes, address),
                Utc::now().timestamp(),
            ))
            .0
            .clone();

        lookup.send_out(nodes);
        lookup
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

impl<N> Handler<KadEvtBootstrap<N>> for Kad<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, msg: KadEvtBootstrap<N>, ctx: &mut Context<Self>) -> Self::Result {
        let address = ctx.address();
        let my_key = self.me.key.as_ref().to_vec();

        msg.nodes.iter().for_each(|node| {
            self.table.add(&node);
        });

        let fut = async move {
            let mut rng = rand::thread_rng();
            for to in msg.nodes {
                let message = KadMessage::FindNode(message::FindNode {
                    rand_val: rng.next_u32(),
                    key: my_key.clone(),
                });
                let _ = address.send(EvtSend { to, message }).await;
            }
            Ok(())
        };

        ActorResponse::r#async(fut.into_actor(self))
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

        let msg_opt = if !self.table.add(&from) {
            Some(KadMessage::Ping(message::Ping {
                rand_val: rand::thread_rng().next_u32(),
            }))
        // TODO: } else if new { transfer_values(..)
        } else {
            None
        };

        let handler_fut = match msg {
            KadMessage::FindNode(m) => self.handle_find_node(m, &from.key).boxed_local(),
            KadMessage::FindNodeResult(m) => self.handle_node_result(m, &from.key).boxed_local(),
            KadMessage::FindValue(m) => self.handle_find_value(m, &from.key).boxed_local(),
            KadMessage::FindValueResult(m) => self.handle_value_result(m, &from.key).boxed_local(),
            KadMessage::Store(m) => self.handle_store(m).boxed_local(),
            KadMessage::Ping(m) => self.handle_ping(m).boxed_local(),
            _ => async move { Ok(None) }.boxed_local(),
        };

        let fut = async move {
            if let Some(m) = msg_opt {
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
    fn handle_node_result(
        &mut self,
        msg: message::FindNodeResult,
        from: &Key<N>,
    ) -> impl Future<Output = HandleMsgResult> {
        let nodes = msg
            .nodes
            .into_iter()
            .map(Node::<N>::try_from)
            .filter_map(Result::ok)
            .collect::<Vec<_>>();

        match self.find_lookup(msg.rand_val) {
            Ok(mut lookup) => {
                let node_idx = nodes
                    .iter()
                    .take(K)
                    .position(|n| n.key.as_ref() == lookup.key.as_ref());

                if let Some(idx) = node_idx {
                    lookup.finish(LookupValue::Node(nodes[idx].clone()));
                } else {
                    lookup.feed(from, nodes);
                }
            }
            Err(error) => match error {
                Error::InvalidLookup(_) => {
                    log::debug!("{:?}", error);
                    nodes.into_iter().for_each(|n| {
                        self.table.add(&n);
                    });
                }
                _ => return error.fut().left_future(),
            },
        };

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
    fn handle_value_result(
        &mut self,
        msg: message::FindValueResult,
        from: &Key<N>,
    ) -> impl Future<Output = HandleMsgResult> {
        let mut lookup = match self.find_lookup(msg.rand_val) {
            Ok(lookup) => lookup,
            Err(error) => return error.fut().left_future(),
        };

        let result = match msg.result {
            Some(result) => result,
            None => return Error::property("result", "missing").fut().left_future(),
        };

        match result {
            message::find_value_result::Result::Nodes(res) => {
                let nodes = res
                    .nodes
                    .into_iter()
                    .map(Node::<N>::try_from)
                    .filter_map(Result::ok)
                    .collect::<Vec<_>>();
                lookup.feed(from, nodes);
            }
            message::find_value_result::Result::Value(res) => {
                lookup.finish(LookupValue::Value(res.value));
            }
        }

        async move { Ok(None) }.right_future()
    }
}

impl<N> Handler<KadEvtFindNode<N>> for Kad<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Result = ActorResponse<Self, Option<Node<N>>, Error>;

    fn handle(&mut self, msg: KadEvtFindNode<N>, ctx: &mut Context<Self>) -> Self::Result {
        if let Some(node) = self.table.get(&msg.key) {
            return ActorResponse::reply(Ok(Some(node.clone())));
        }

        let lookup_key = LookupKey::Node(msg.key.as_ref().to_vec());
        let lookup = self.initiate_lookup(lookup_key, &msg.key, ctx.address());
        let fut = async move {
            match lookup.await {
                LookupValue::Node(val) => Ok(Some(val)),
                _ => Ok(None),
            }
        };

        ActorResponse::r#async(fut.into_actor(self))
    }
}

impl<N> Handler<KadEvtFindValue> for Kad<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Result = ActorResponse<Self, Option<(Vec<u8>, Vec<u8>)>, Error>;

    fn handle(&mut self, msg: KadEvtFindValue, ctx: &mut Context<Self>) -> Self::Result {
        if let Some(msg_value) = self.find_value(&msg.key) {
            return ActorResponse::reply(Ok(Some((msg.key, msg_value.value.clone()))));
        }

        let node_key = match Key::<N>::try_from(msg.key.clone()) {
            Ok(key) => key,
            Err(error) => return ActorResponse::reply(Err(error)),
        };
        let lookup_key = LookupKey::Value(msg.key.clone());
        let lookup = self.initiate_lookup(lookup_key, &node_key, ctx.address());
        let fut = async move {
            match lookup.await {
                LookupValue::Value(val) => Ok(Some((msg.key, val))),
                _ => Ok(None),
            }
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
pub(crate) struct Lookup<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    key: LookupKey,
    kad: Addr<Kad<N>>,
    state: Rc<RefCell<LookupState<N>>>,
    waker: Option<Waker>,
}

impl<N> Lookup<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    pub fn new(key: LookupKey, nodes: &Vec<Node<N>>, kad: Addr<Kad<N>>) -> Self {
        let state = Rc::new(RefCell::new(LookupState::new(nodes)));
        Lookup {
            key,
            kad,
            state,
            waker: None,
        }
    }

    #[inline]
    pub fn in_progress(&self) -> bool {
        if let LookupState::InProgress { .. } = &*self.state.borrow() {
            return true;
        }
        false
    }

    pub fn feed(&mut self, from: &Key<N>, nodes: Vec<Node<N>>) {
        if let LookupState::InProgress {
            started_at: _,
            pending,
            candidates,
        } = &mut *self.state.borrow_mut()
        {
            pending.remove(from);
            *candidates = std::mem::replace(candidates, Vec::new())
                .into_iter()
                .chain(nodes.into_iter())
                .sorted_by_key(|n| n.key.distance(&self.key))
                .take(K)
                .collect();
        }
    }

    pub fn iterate(&mut self) {
        let mut finish = false;

        if let LookupState::InProgress {
            started_at,
            pending,
            candidates,
        } = &mut *self.state.borrow_mut()
        {
            if Utc::now().timestamp() - *started_at > MAX_REQ_TTL {
                pending.clear();
            }

            if pending.is_empty() {
                let mut nodes = std::mem::replace(candidates, Vec::new());
                *candidates = nodes.split_off(std::cmp::min(nodes.len(), ALPHA));
                *pending = nodes.iter().map(|n| n.key.clone()).collect();
                *started_at = Utc::now().timestamp();

                if nodes.is_empty() {
                    finish = true;
                } else {
                    self.send_out(nodes);
                }
            }
        }

        if finish {
            self.finish(LookupValue::None);
        }
    }

    pub fn send_out(&self, nodes: Vec<Node<N>>) {
        let address = self.kad.clone();
        let key = self.key.clone();

        actix_rt::spawn(async move {
            for to in nodes.into_iter() {
                let rand_val = rand::thread_rng().next_u32();
                let message = match &key {
                    LookupKey::Node(key) => KadMessage::FindNode(message::FindNode {
                        rand_val,
                        key: key.clone(),
                    }),
                    LookupKey::Value(key) => KadMessage::FindValue(message::FindValue {
                        rand_val,
                        key: key.clone(),
                    }),
                };
                let _ = address.send(EvtSend { to, message }).await;
            }
        });
    }

    pub fn finish(&mut self, result: LookupValue<N>) {
        let mut replace = false;
        if let LookupState::InProgress { .. } = &*self.state.borrow() {
            replace = true;
        }

        if replace {
            self.state.replace(LookupState::Finished { result });
            if let Some(waker) = &self.waker {
                waker.wake_by_ref();
            }
        }
    }
}

impl<N> Future for Lookup<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Output = LookupValue<N>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut futures::task::Context<'_>) -> Poll<Self::Output> {
        if let LookupState::Finished { result } = &*self.state.borrow() {
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
    Finished {
        result: LookupValue<N>,
    },
}

impl<N: KeyLen> LookupState<N> {
    pub fn new(nodes: &Vec<Node<N>>) -> Self {
        let keys = nodes.into_iter().map(|n| n.key.clone()).collect();
        LookupState::InProgress {
            started_at: Utc::now().timestamp(),
            pending: keys,
            candidates: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum LookupKey {
    Node(Vec<u8>),
    Value(Vec<u8>),
}

impl AsRef<[u8]> for LookupKey {
    fn as_ref(&self) -> &[u8] {
        match &self {
            LookupKey::Node(v) => &v,
            LookupKey::Value(v) => &v,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum LookupValue<N: KeyLen> {
    Node(Node<N>),
    Value(Vec<u8>),
    None,
}
