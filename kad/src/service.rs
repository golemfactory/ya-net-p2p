use crate::event::*;
use crate::{message, Error, Key, KeyLen, Node, Result, Table};
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

// Number of parallel queries
const ALPHA: usize = 8;

const MAX_KEY_SZ: usize = 33;
const MAX_VAL_SZ: usize = 65535;
const MAX_VAL_TTL: u32 = 604800;
const MAX_REQ_TTL: i64 = 5;
const MAX_QRY_TTL: i64 = 30;

lazy_static::lazy_static! {
    static ref REQUEST_UPKEEP_INTERVAL: Duration = Duration::from_secs(2);
    static ref STORAGE_UPKEEP_INTERVAL: Duration = Duration::from_secs(60);
    static ref QUERY_UPKEEP_INTERVAL: Duration = Duration::from_secs(3);
    static ref TABLE_UPKEEP_INTERVAL: Duration = Duration::from_secs(60);
}

pub struct Kad<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    name: String,
    me: Node<N>,
    table: Table<N>,
    storage: HashMap<Vec<u8>, (message::Value, i64)>,
    queries: HashMap<Vec<u8>, (Query<N>, i64)>,
    requests: HashMap<u32, (KadMessage, Key<N>, i64)>,
    tx: mpsc::Sender<KadEvtSend<N>>,
}

impl<N> Kad<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    pub fn new(me: Node<N>, tx: mpsc::Sender<KadEvtSend<N>>) -> Self {
        Self::with_name("Kad", me, tx)
    }

    pub fn with_name(name: impl ToString, me: Node<N>, tx: mpsc::Sender<KadEvtSend<N>>) -> Self {
        let key = me.key.clone();
        Self {
            name: name.to_string(),
            me,
            table: Table::new(key, N::to_usize()),
            storage: HashMap::new(),
            queries: HashMap::new(),
            requests: HashMap::new(),
            tx,
        }
    }

    #[inline]
    fn storage_upkeep(&mut self, _: &mut Context<Self>) {
        let now = Utc::now().timestamp();
        self.storage
            .retain(|_, (value, created_at)| value.ttl as i64 + *created_at > now);
    }

    #[inline]
    fn request_upkeep(&mut self, _: &mut Context<Self>) {
        let mut to_remove = HashSet::new();
        let now = Utc::now().timestamp();

        self.requests.retain(|_, (_, key, created_at)| {
            if now - *created_at < MAX_REQ_TTL {
                true
            } else {
                to_remove.insert(key.clone());
                false
            }
        });

        to_remove.iter().for_each(|k| self.table.remove(k));
    }

    #[inline]
    fn query_upkeep(&mut self, _: &mut Context<Self>) {
        let now = Utc::now().timestamp();
        self.queries.retain(|_, (query, created_at)| {
            if now - *created_at >= MAX_QRY_TTL {
                query.finish(QueryValue::None);
            } else {
                query.iterate();
            }
            query.in_progress()
        });
    }

    #[inline]
    fn table_upkeep(&mut self, ctx: &mut Context<Self>) {
        let address = ctx.address();
        self.table.stale_buckets().into_iter().for_each(|i| {
            let key = Key::<N>::random(i);
            let neighbors = self.table.neighbors(&key, Some(&key), Some(ALPHA));

            log::debug!(
                "{} table refresh: querying {} ({} nodes)",
                self.name,
                key,
                neighbors.len()
            );
            self.initiate_query(QueryKey::Node(key.to_vec()), neighbors, address.clone());
        });
    }
}

impl<N> Kad<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    fn find_node(&self, key: &Key<N>, excluded: Option<&Key<N>>) -> Vec<Node<N>> {
        let mut nodes = self.table.neighbors(&key, excluded, None);
        if key == &self.me.key {
            if nodes.len() == self.table.bucket_size {
                nodes.remove(nodes.len() - 1);
            }
            nodes.insert(0, self.me.clone());
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

    fn find_query(&mut self, rand_val: u32) -> Result<Query<N>> {
        let key_opt = self
            .requests
            .remove(&rand_val)
            .map(|(m, _, _)| m.queried_key())
            .flatten();

        let key = match key_opt {
            Some(key) => key,
            None => return Err(Error::request(rand_val)),
        };

        match self.queries.get(&key) {
            Some((query, _)) => Ok(query.clone()),
            None => Err(Error::query(&key)),
        }
    }

    fn initiate_query(
        &mut self,
        query_key: QueryKey,
        nodes: Vec<Node<N>>,
        address: Addr<Self>,
    ) -> Query<N> {
        if let Some((query, _)) = self.queries.get(query_key.as_ref()) {
            return query.clone();
        }

        let mut query = self
            .queries
            .entry(query_key.to_vec())
            .or_insert((
                Query::new(query_key, &nodes, address, self.table.bucket_size),
                Utc::now().timestamp(),
            ))
            .0
            .clone();

        query.iterate();
        query
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
        IntervalFunc::new(*QUERY_UPKEEP_INTERVAL, Self::query_upkeep)
            .finish()
            .spawn(ctx);
        IntervalFunc::new(*REQUEST_UPKEEP_INTERVAL, Self::request_upkeep)
            .finish()
            .spawn(ctx);
        IntervalFunc::new(*TABLE_UPKEEP_INTERVAL, Self::table_upkeep)
            .finish()
            .spawn(ctx);

        log::info!("{} ({}) service started", self.name, self.me.key);
    }
}

impl<N> Handler<KadEvtBootstrap<N>> for Kad<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, msg: KadEvtBootstrap<N>, ctx: &mut Context<Self>) -> Self::Result {
        log::debug!("{} bootstrapping", self.name);

        self.table.extend(msg.nodes.iter());

        let fut = if msg.dormant {
            async move {
                // do nothing
                Ok(())
            }
            .left_future()
        } else {
            let query = self.initiate_query(
                QueryKey::Node(self.me.key.to_vec()),
                msg.nodes.clone(),
                ctx.address(),
            );

            async move {
                query.await;
                Ok(())
            }
            .right_future()
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
        log::trace!("{} rx {} from {}", self.name, evt.message, evt.from);

        let address = ctx.address();
        let (from, _new, msg) = (evt.from, evt.new, evt.message);

        let evt_opt = if !self.table.add(&from) {
            // match self.table.bucket_oldest(&from.key) {
            //     Some(node) => {
            //         if from.key != node.key {
            //             Some(EvtSend::new(
            //                 node,
            //                 KadMessage::from(message::Ping {
            //                     rand_val: rand::thread_rng().next_u32(),
            //                 }),
            //             ))
            //         } else {
            //             None
            //         }
            //     }
            //     _ => None,
            // }
            Option::<EvtSend<N>>::None
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
            KadMessage::Pong(m) => self.handle_pong(m).boxed_local(),
        };

        let fut = async move {
            if let Some(evt) = evt_opt {
                address.send(evt).await??;
            }
            if let Some(msg) = handler_fut.await? {
                address.send(EvtSend::new(from, msg)).await??;
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
            Ok(Some(KadMessage::from(message::Pong {
                rand_val: msg.rand_val,
            })))
        }
    }

    #[inline]
    fn handle_pong(&mut self, msg: message::Pong) -> impl Future<Output = HandleMsgResult> {
        self.requests.remove(&msg.rand_val);
        async move { Ok(None) }
    }

    #[inline]
    fn handle_store(&mut self, msg: message::Store) -> impl Future<Output = HandleMsgResult> {
        fn validate(msg: &message::Store) -> Result<()> {
            let value = match msg.value {
                Some(ref value) => value,
                None => return Err(Error::property("Store", "value")),
            };
            if msg.key.len() > MAX_KEY_SZ {
                return Err(Error::property("Store", "key"));
            }
            if value.value.len() > MAX_VAL_SZ {
                return Err(Error::property("Store", "value"));
            }
            if value.ttl > MAX_VAL_TTL {
                return Err(Error::property("Store", "ttl"));
            }
            Ok(())
        }

        let value = match validate(&msg) {
            Ok(_) => msg.value.unwrap(),
            Err(error) => return error.fut().left_future(),
        };
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
            Ok(key) => self.find_node(&key, Some(from)),
            Err(error) => return error.fut().left_future(),
        };

        async move {
            Ok(Some(KadMessage::from(message::FindNodeResult {
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
        let nodes = Node::from_vec(msg.nodes);
        let fut = async move { Ok(None) }.right_future();

        match self.find_query(msg.rand_val) {
            Ok(mut query) => {
                if !query.in_progress() {
                    return fut;
                }

                log::debug!(
                    "{} rx nodes ({}) from {} for node query: {}",
                    self.name,
                    nodes.len(),
                    from,
                    Key::<N>::fmt_key(&query.key),
                );

                self.table.extend(nodes.iter());

                if query.key.as_ref() == self.me.key.as_ref() {
                    query.feed(self.table.distant_nodes(&self.me.key), Some(from));
                } else {
                    let node_idx = nodes
                        .iter()
                        .position(|n| n.key.as_ref() == query.key.as_ref());

                    if let Some(idx) = node_idx {
                        query.finish(QueryValue::Node(nodes[idx].clone()));
                    } else {
                        query.feed(nodes, Some(from));
                    }
                }
            }
            Err(error) => match error {
                Error::InvalidQuery(_) => {
                    log::debug!("{} rx nodes ({})", self.name, nodes.len());
                    self.table.extend(nodes.iter());
                }
                _ => {
                    log::error!("{}", error);
                    return error.fut().left_future();
                }
            },
        };

        fut
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
                            .find_node(&key, Some(from))
                            .into_iter()
                            .map(Node::into)
                            .collect(),
                    })),
                },
                Err(e) => return e.fut().left_future(),
            },
        };

        async move { Ok(Some(KadMessage::from(reply))) }.right_future()
    }

    #[inline]
    fn handle_value_result(
        &mut self,
        msg: message::FindValueResult,
        from: &Key<N>,
    ) -> impl Future<Output = HandleMsgResult> {
        let mut query = match self.find_query(msg.rand_val) {
            Ok(query) => query,
            Err(error) => return error.fut().left_future(),
        };

        let fut = async move { Ok(None) }.right_future();
        if !query.in_progress() {
            return fut;
        }

        let result = match msg.result {
            Some(result) => result,
            None => return Error::property("result", "missing").fut().left_future(),
        };

        match result {
            message::find_value_result::Result::Nodes(res) => {
                log::debug!("{} rx nodes for value query: {:?}", self.name, query.key);
                let nodes = Node::from_vec(res.nodes);
                self.table.extend(nodes.iter());

                query.feed(nodes, Some(from));
            }
            message::find_value_result::Result::Value(res) => {
                log::debug!("{} rx value for value query: {:?}", self.name, query.key);

                query.finish(QueryValue::Value(res.value));
            }
        }

        fut
    }
}

impl<N> Handler<KadEvtFindNode<N>> for Kad<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Result = ActorResponse<Self, Option<Node<N>>, Error>;

    fn handle(&mut self, msg: KadEvtFindNode<N>, ctx: &mut Context<Self>) -> Self::Result {
        log::debug!("{} find node request: {}", self.name, msg.key);

        if self.me.key == msg.key {
            return ActorResponse::reply(Ok(Some(self.me.clone())));
        }
        if let Some(node) = self.table.get(&msg.key) {
            return ActorResponse::reply(Ok(Some(node.clone())));
        }

        let key = QueryKey::Node(msg.key.to_vec());
        let nodes = self.find_node(&msg.key, None);
        let query = self.initiate_query(key, nodes, ctx.address());

        let fut = async move {
            match query.await {
                QueryValue::Node(val) => Ok(Some(val)),
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
        log::debug!(
            "{} find value request: {}",
            self.name,
            Key::<N>::fmt_key(&msg.key)
        );

        if let Some(msg_value) = self.find_value(&msg.key) {
            return ActorResponse::reply(Ok(Some((msg.key, msg_value.value.clone()))));
        }
        let node_key = match Key::<N>::try_from(msg.key.clone()) {
            Ok(key) => key,
            Err(error) => return ActorResponse::reply(Err(error)),
        };

        let key = QueryKey::Value(msg.key.clone());
        let nodes = self.find_node(&node_key, None);
        let query = self.initiate_query(key, nodes, ctx.address());
        let fut = async move {
            match query.await {
                QueryValue::Value(val) => Ok(Some((msg.key, val))),
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
        // Transform port for non-UDP & fixed-port operating mode?
        log::trace!("{} tx {} to {}", self.name, evt.message, evt.to);

        if evt.message.is_request() {
            self.requests.insert(
                evt.message.rand_val(),
                (
                    evt.message.clone(),
                    evt.to.key.clone(),
                    Utc::now().timestamp(),
                ),
            );
        }

        let me = self.me.clone();
        let mut tx = self.tx.clone();

        let fut = async move {
            tx.send(KadEvtSend {
                from: me,
                to: evt.to,
                message: evt.message,
            })
            .await
            .map_err(Error::from)
        };

        ActorResponse::r#async(fut.into_actor(self))
    }
}

impl<N> Handler<EvtAddressChanged> for Kad<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Result = <EvtAddressChanged as Message>::Result;

    fn handle(&mut self, evt: EvtAddressChanged, _: &mut Context<Self>) -> Self::Result {
        log::debug!(
            "{} address changed from {:?} to {:?}",
            self.name,
            self.me.address,
            evt.address
        );

        std::mem::replace(&mut self.me.address, evt.address);
        Ok(())
    }
}

#[derive(Clone)]
struct Query<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    key: QueryKey,
    kad: Addr<Kad<N>>,
    node_limit: usize,
    state: Rc<RefCell<QueryState<N>>>,
    waker: Option<Waker>,
}

impl<N> Query<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    fn new(key: QueryKey, nodes: &Vec<Node<N>>, kad: Addr<Kad<N>>, node_limit: usize) -> Self {
        let mut query = Query {
            key,
            kad,
            node_limit,
            state: Rc::new(RefCell::new(QueryState::default())),
            waker: None,
        };

        query.feed(nodes.clone(), None);
        query
    }

    #[inline(always)]
    fn in_progress(&self) -> bool {
        if let QueryState::InProgress { .. } = &*self.state.borrow() {
            return true;
        }
        false
    }

    fn feed(&mut self, nodes: Vec<Node<N>>, from: Option<&Key<N>>) {
        let mut iterate = false;

        if let QueryState::InProgress {
            started_at: _,
            pending,
            candidates,
            sent,
        } = &mut *self.state.borrow_mut()
        {
            if let Some(from) = from {
                pending.remove(from);
            }

            *candidates = std::mem::replace(candidates, Vec::new())
                .into_iter()
                .chain(nodes.clone().into_iter())
                .filter(|n| !sent.contains(&n.key))
                .unique()
                .sorted_by_key(|n| n.distance(&self.key))
                .take(self.node_limit)
                .collect();

            iterate = pending.is_empty();
        }

        if iterate {
            self.iterate();
        }
    }

    fn iterate(&mut self) {
        let mut send_out_nodes = None;

        if let QueryState::InProgress {
            started_at,
            pending,
            candidates,
            sent,
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

                sent.extend(pending.clone());
                send_out_nodes = Some(nodes)
            }
        }

        if let Some(nodes) = send_out_nodes {
            match nodes.is_empty() {
                true => self.finish(QueryValue::None),
                false => self.send_out(nodes),
            }
        }
    }

    fn send_out(&mut self, nodes: Vec<Node<N>>) {
        let address = self.kad.clone();
        let key = self.key.clone();

        log::debug!(
            "Querying {} node(s) (key: {})",
            nodes.len(),
            Key::<N>::fmt_key(&key)
        );

        actix_rt::spawn(async move {
            let mut rand = rand::thread_rng();

            for to in nodes.into_iter() {
                log::trace!("Send out to: {} (distance: {})", to.key, to.distance(&key));

                let message = match &key {
                    QueryKey::Node(key) => KadMessage::from(message::FindNode {
                        rand_val: rand.next_u32(),
                        key: key.clone(),
                    }),
                    QueryKey::Value(key) => KadMessage::from(message::FindValue {
                        rand_val: rand.next_u32(),
                        key: key.clone(),
                    }),
                };

                if let Err(e) = address.send(EvtSend { to, message }).await {
                    log::error!("Unable to send query message: {:?}", e);
                }
            }
        });
    }

    fn finish(&mut self, result: QueryValue<N>) {
        if self.in_progress() {
            self.state.replace(QueryState::Finished { result });

            if let Some(waker) = &self.waker {
                waker.wake_by_ref();
            }
        }
    }
}

impl<N> Future for Query<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Output = QueryValue<N>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut futures::task::Context<'_>) -> Poll<Self::Output> {
        if let QueryState::Finished { result } = &*self.state.borrow() {
            return Poll::Ready(result.clone());
        }

        self.waker.replace(cx.waker().clone());
        Poll::Pending
    }
}

#[derive(Clone, Debug)]
enum QueryState<N: KeyLen> {
    InProgress {
        started_at: i64,
        pending: HashSet<Key<N>>,
        candidates: Vec<Node<N>>,
        sent: HashSet<Key<N>>,
    },
    Finished {
        result: QueryValue<N>,
    },
}

impl<N: KeyLen> Default for QueryState<N> {
    fn default() -> Self {
        QueryState::InProgress {
            started_at: Utc::now().timestamp(),
            pending: HashSet::new(),
            candidates: Vec::new(),
            sent: HashSet::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum QueryValue<N: KeyLen> {
    Node(Node<N>),
    Value(Vec<u8>),
    None,
}

#[derive(Clone, Debug)]
enum QueryKey {
    Node(Vec<u8>),
    Value(Vec<u8>),
}

impl QueryKey {
    pub fn to_vec(&self) -> Vec<u8> {
        match &self {
            QueryKey::Node(v) | QueryKey::Value(v) => v.clone(),
        }
    }
}

impl AsRef<[u8]> for QueryKey {
    fn as_ref(&self) -> &[u8] {
        match &self {
            QueryKey::Node(v) | QueryKey::Value(v) => &v,
        }
    }
}
