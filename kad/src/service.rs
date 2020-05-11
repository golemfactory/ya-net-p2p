use crate::event::*;
use crate::query::*;
use crate::*;
use actix::prelude::*;
use chrono::Utc;
use futures::channel::mpsc;
use futures::{Future, FutureExt, SinkExt};
use generic_array::ArrayLength;
use hashbrown::{HashMap, HashSet};
use rand::RngCore;
use serde::de::DeserializeOwned;
use std::convert::TryFrom;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering::SeqCst;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct KadConfig {
    pub name: String,
    pub request_ttl: i64,
    pub query_ttl: i64,
    pub ping_interval: Duration,
    pub ping_max_backlog_size: usize,
    pub ping_max_concurrent: usize,
    pub storage_max_key_size: usize,
    pub storage_max_value_size: usize,
    pub storage_value_ttl: u32,
    pub upkeep_requests_interval: Duration,
    pub upkeep_query_interval: Duration,
    pub upkeep_table_interval: Duration,
    pub upkeep_storage_interval: Duration,
}

impl KadConfig {
    pub fn with_name(name: impl ToString) -> Self {
        let mut conf = Self::default();
        conf.name = name.to_string();
        conf
    }
}

impl Default for KadConfig {
    fn default() -> Self {
        KadConfig {
            name: "Kad".to_owned(),
            request_ttl: 5,
            query_ttl: 30,
            ping_interval: Duration::from_secs(10),
            ping_max_backlog_size: 100,
            ping_max_concurrent: 25,
            storage_max_key_size: 64,
            storage_max_value_size: 65535,
            storage_value_ttl: 604800,
            upkeep_requests_interval: Duration::from_secs(2),
            upkeep_query_interval: Duration::from_secs(3),
            upkeep_table_interval: Duration::from_secs(60),
            upkeep_storage_interval: Duration::from_secs(180),
        }
    }
}

pub struct Kad<N, D>
where
    N: KeyLen + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeData + 'static,
{
    node: Node<N, D>,
    conf: KadConfig,
    table: Table<N, D>,
    storage: HashMap<Vec<u8>, (message::Value, i64)>,
    queries: HashMap<Vec<u8>, (Query<N, D>, i64)>,
    requests: HashMap<u32, (KadMessage, Key<N>, i64)>,
    ping_backlog: HashSet<Node<N, D>>,
    event_sender: mpsc::Sender<KadEvtSend<N, D>>,
    rand_val_seq: AtomicU32,
}

impl<N, D> Kad<N, D>
where
    N: KeyLen + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeData + 'static,
{
    pub fn new(node: Node<N, D>, event_sender: mpsc::Sender<KadEvtSend<N, D>>) -> Self {
        Self::with_conf(KadConfig::default(), node, event_sender)
    }

    pub fn with_conf(
        conf: KadConfig,
        node: Node<N, D>,
        event_sender: mpsc::Sender<KadEvtSend<N, D>>,
    ) -> Self {
        let key = node.key.clone();
        Self {
            node,
            conf,
            table: Table::new(key),
            storage: HashMap::new(),
            queries: HashMap::new(),
            requests: HashMap::new(),
            ping_backlog: HashSet::new(),
            event_sender,
            rand_val_seq: AtomicU32::new(rand::thread_rng().next_u32()),
        }
    }

    #[inline]
    fn request_upkeep(&mut self, _: &mut Context<Self>) {
        let ttl = self.conf.request_ttl;
        let now = Utc::now().timestamp();
        let table = &mut self.table;

        self.requests
            .drain_filter(|_, (_, _, created_at)| now - *created_at < ttl)
            .for_each(|(_, (_, key, _))| table.remove(&key));
    }

    #[inline]
    fn query_upkeep(&mut self, _: &mut Context<Self>) {
        let ttl = self.conf.query_ttl;
        let now = Utc::now().timestamp();

        self.queries.retain(|_, (query, created_at)| {
            if now - *created_at >= ttl {
                query.finish(QueryValue::None);
            } else {
                query.iterate();
            }
            query.in_progress()
        });
    }

    #[inline]
    fn storage_upkeep(&mut self, _: &mut Context<Self>) {
        let now = Utc::now().timestamp();
        self.storage
            .retain(|_, (value, created_at)| value.ttl as i64 + *created_at > now);
    }

    #[inline]
    fn table_upkeep(&mut self, ctx: &mut Context<Self>) {
        let address = ctx.address();
        self.table.stale_buckets().into_iter().for_each(|i| {
            let key = Key::<N>::random(i);
            let neighbors = self.table.neighbors(&key, Some(&key), Some(ALPHA));

            log::debug!(
                "{} table refresh: querying {} ({} nodes)",
                self.conf.name,
                key,
                neighbors.len()
            );
            self.initiate_query(QueryKey::Node(key.to_vec()), neighbors, address.clone());
        });
    }

    #[inline]
    fn node_upkeep(&mut self, ctx: &mut Context<Self>) {
        let address = ctx.address();
        let mut events = Vec::new();

        std::mem::replace(&mut self.ping_backlog, HashSet::new())
            .drain()
            .for_each(|node| match events.len() < self.conf.ping_max_concurrent {
                true => events.push(QueryEvtRequest {
                    to: node,
                    message: KadMessage::from(message::Ping { rand_val: 0 }),
                }),
                false => {
                    self.ping_backlog.insert(node);
                }
            });

        ctx.spawn(
            async move {
                for evt in events.into_iter() {
                    if let Err(e) = address.send(evt).await {
                        log::warn!("Unable to ping node: {:?}", e);
                    }
                }
            }
            .into_actor(self),
        );
    }
}

impl<N, D> Kad<N, D>
where
    N: KeyLen + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeData + 'static,
{
    #[inline]
    fn send(&self, to: Node<N, D>, message: KadMessage) -> impl Future<Output = Result<()>> {
        let from = self.node.clone();
        let mut event_sender = self.event_sender.clone();

        async move {
            event_sender
                .send(KadEvtSend { from, to, message })
                .await
                .map_err(Error::from)
        }
    }

    fn find_node(&self, key: &Key<N>, excluded: Option<&Key<N>>) -> Vec<Node<N, D>> {
        let mut nodes = self.table.neighbors(&key, excluded, None);
        if key == &self.node.key {
            if nodes.len() == self.table.bucket_size {
                nodes.pop();
            }
            nodes.insert(0, self.node.clone());
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

    fn find_query(&mut self, rand_val: u32) -> Result<Query<N, D>> {
        let key = self
            .requests
            .remove(&rand_val)
            .map(|(m, _, _)| m.into_key())
            .flatten()
            .ok_or_else(|| Error::request(rand_val))?;

        match self.queries.get(&key) {
            Some((query, _)) => Ok(query.clone()),
            None => Err(Error::query(&key)),
        }
    }

    fn initiate_query(
        &mut self,
        query_key: QueryKey,
        nodes: Vec<Node<N, D>>,
        address: Addr<Self>,
    ) -> Query<N, D> {
        let bucket_size = self.table.bucket_size;
        let request_ttl = self.conf.request_ttl;

        self.queries
            .entry(query_key.to_vec())
            .or_insert_with(|| {
                let mut query = Query::new(query_key, nodes, address, bucket_size, request_ttl);
                query.iterate();

                (query, Utc::now().timestamp())
            })
            .0
            .clone()
    }
}

impl<N, D> Actor for Kad<N, D>
where
    N: KeyLen + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeData + 'static,
{
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        IntervalFunc::new(self.conf.upkeep_requests_interval, Self::request_upkeep)
            .finish()
            .spawn(ctx);
        IntervalFunc::new(self.conf.upkeep_query_interval, Self::query_upkeep)
            .finish()
            .spawn(ctx);
        IntervalFunc::new(self.conf.upkeep_table_interval, Self::table_upkeep)
            .finish()
            .spawn(ctx);
        IntervalFunc::new(self.conf.upkeep_storage_interval, Self::storage_upkeep)
            .finish()
            .spawn(ctx);
        IntervalFunc::new(self.conf.ping_interval, Self::node_upkeep)
            .finish()
            .spawn(ctx);

        log::info!("{} ({}) service started", self.conf.name, self.node.key);
    }
}

impl<N, D> Handler<KadEvtBootstrap<N, D>> for Kad<N, D>
where
    N: KeyLen + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeData + 'static,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, msg: KadEvtBootstrap<N, D>, ctx: &mut Context<Self>) -> Self::Result {
        log::debug!("{} bootstrapping", self.conf.name);

        self.table.extend(msg.nodes.iter());

        let fut = if msg.dormant {
            async move {
                // do nothing
                Ok(())
            }
            .left_future()
        } else {
            let query = self.initiate_query(
                QueryKey::Node(self.node.key.to_vec()),
                msg.nodes,
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

impl<N, D> Handler<KadEvtReceive<N, D>> for Kad<N, D>
where
    N: KeyLen + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeData + DeserializeOwned + 'static,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, evt: KadEvtReceive<N, D>, ctx: &mut Context<Self>) -> Self::Result {
        log::trace!("{} rx {} from {}", self.conf.name, evt.message, evt.from);

        let address = ctx.address();
        let (from, message) = (evt.from, evt.message);

        if !self.table.add(&from) && self.ping_backlog.len() < self.conf.ping_max_backlog_size {
            if let Some(node) = self.table.bucket_oldest(&from.key) {
                self.ping_backlog.insert(node);
            }
        };

        let handler_fut = match message {
            KadMessage::FindNode(m) => self.handle_find_node(m, &from.key).boxed_local(),
            KadMessage::FindNodeResult(m) => self.handle_node_result(m, &from.key).boxed_local(),
            KadMessage::FindValue(m) => self.handle_find_value(m, &from.key).boxed_local(),
            KadMessage::FindValueResult(m) => self.handle_value_result(m, &from.key).boxed_local(),
            KadMessage::Store(m) => self.handle_store(m).boxed_local(),
            KadMessage::Ping(m) => self.handle_ping(m).boxed_local(),
            KadMessage::Pong(m) => self.handle_pong(m).boxed_local(),
        };

        ActorResponse::r#async(
            async move {
                if let Some(message) = handler_fut.await? {
                    address
                        .send(QueryEvtRespond { to: from, message })
                        .await??;
                }
                Ok(())
            }
            .into_actor(self),
        )
    }
}

type HandleMsgResult = Result<Option<KadMessage>>;

impl<N, D> Kad<N, D>
where
    N: KeyLen + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeData + DeserializeOwned + 'static,
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
        fn validate(msg: &message::Store, conf: &KadConfig) -> Result<()> {
            let value = match msg.value {
                Some(ref value) => value,
                None => return Err(Error::property("Store", "value")),
            };
            if msg.key.len() > conf.storage_max_key_size {
                return Err(Error::property("Store", "key"));
            }
            if value.value.len() > conf.storage_max_value_size {
                return Err(Error::property("Store", "value"));
            }
            if value.ttl > conf.storage_value_ttl {
                return Err(Error::property("Store", "ttl"));
            }
            Ok(())
        }

        let now = Utc::now().timestamp();
        let value = match validate(&msg, &self.conf) {
            Ok(_) => msg.value.unwrap(),
            Err(error) => return error.fut().left_future(),
        };

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
        let mut nodes = Node::from_vec(msg.nodes);
        self.table.extend(nodes.iter());

        let right_future = async move { Ok(None) }.right_future();
        let mut query = match self.find_query(msg.rand_val) {
            Ok(query) => {
                if !query.in_progress() {
                    return right_future;
                }
                query
            }
            Err(error) => {
                if let Error::InvalidQuery(_) = error {
                    return right_future;
                }
                log::warn!("{}", error);
                return error.fut().left_future();
            }
        };

        log::debug!(
            "{} rx nodes ({}) from {} for node query: {}",
            self.conf.name,
            nodes.len(),
            from,
            Key::<N>::fmt_key(&query.key),
        );

        if query.key.as_ref() == self.node.key.as_ref() {
            nodes.extend(self.table.distant_nodes(&self.node.key).into_iter());
            query.feed(nodes, Some(from));
        } else {
            match nodes
                .iter()
                .position(|n| query.key.as_ref() == n.key.as_ref())
            {
                Some(idx) => query.finish(QueryValue::Node(nodes[idx].clone())),
                None => query.feed(nodes, Some(from)),
            }
        }

        right_future
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
        let right_future = async move { Ok(None) }.right_future();
        let mut query = match self.find_query(msg.rand_val) {
            Ok(query) => {
                if !query.in_progress() {
                    return right_future;
                }
                query
            }
            Err(error) => {
                log::warn!("{}", error);
                return error.fut().left_future();
            }
        };

        let result = match msg.result {
            Some(result) => result,
            None => return Error::property("result", "missing").fut().left_future(),
        };

        match result {
            message::find_value_result::Result::Nodes(res) => {
                log::debug!(
                    "{} rx nodes for value query: {:?}",
                    self.conf.name,
                    query.key
                );
                let nodes = Node::from_vec(res.nodes);
                self.table.extend(nodes.iter());

                query.feed(nodes, Some(from));
            }
            message::find_value_result::Result::Value(res) => {
                log::debug!(
                    "{} rx value for value query: {:?}",
                    self.conf.name,
                    query.key
                );

                query.finish(QueryValue::Value(res.value));
            }
        }

        right_future
    }
}

impl<N, D> Handler<KadEvtFindNode<N, D>> for Kad<N, D>
where
    N: KeyLen + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeData + 'static,
{
    type Result = ActorResponse<Self, Option<Node<N, D>>, Error>;

    fn handle(&mut self, msg: KadEvtFindNode<N, D>, ctx: &mut Context<Self>) -> Self::Result {
        log::debug!("{} find node request: {}", self.conf.name, msg.key);

        if self.node.key == msg.key {
            return ActorResponse::reply(Ok(Some(self.node.clone())));
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

impl<N, D> Handler<KadEvtFindValue> for Kad<N, D>
where
    N: KeyLen + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeData + 'static,
{
    type Result = ActorResponse<Self, Option<(Vec<u8>, Vec<u8>)>, Error>;

    fn handle(&mut self, msg: KadEvtFindValue, ctx: &mut Context<Self>) -> Self::Result {
        log::debug!(
            "{} find value request: {}",
            self.conf.name,
            Key::<N>::fmt_key(&msg.key)
        );

        if let Some(msg_value) = self.find_value(&msg.key) {
            return ActorResponse::reply(Ok(Some((msg.key, msg_value.value.clone()))));
        }

        let query_key = QueryKey::Value(msg.key.clone());
        let as_node_key = match Key::<N>::try_from(msg.key.clone()) {
            Ok(key) => key,
            Err(error) => return ActorResponse::reply(Err(error)),
        };

        let nodes = self.find_node(&as_node_key, None);
        let query = self.initiate_query(query_key, nodes, ctx.address());
        let fut = async move {
            match query.await {
                QueryValue::Value(val) => Ok(Some((msg.key, val))),
                _ => Ok(None),
            }
        };

        ActorResponse::r#async(fut.into_actor(self))
    }
}

impl<N, D> Handler<QueryEvtRequest<N, D>> for Kad<N, D>
where
    N: KeyLen + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeData + 'static,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, mut evt: QueryEvtRequest<N, D>, _: &mut Context<Self>) -> Self::Result {
        // Transform port for non-UDP & fixed-port operating mode?
        log::trace!("{} tx {} to {}", self.conf.name, evt.message, evt.to);

        evt.message
            .set_rand_val(self.rand_val_seq.fetch_add(1, SeqCst));

        self.requests.insert(
            evt.message.rand_val(),
            (
                evt.message.clone(),
                evt.to.key.clone(),
                Utc::now().timestamp(),
            ),
        );

        ActorResponse::r#async(self.send(evt.to, evt.message).into_actor(self))
    }
}

impl<N, D> Handler<QueryEvtRespond<N, D>> for Kad<N, D>
where
    N: KeyLen + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeData + 'static,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, evt: QueryEvtRespond<N, D>, _: &mut Context<Self>) -> Self::Result {
        log::trace!("{} tx {} to {}", self.conf.name, evt.message, evt.to);

        ActorResponse::r#async(self.send(evt.to, evt.message).into_actor(self))
    }
}

impl<N, D> Handler<EvtNodeDataChanged<D>> for Kad<N, D>
where
    N: KeyLen + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeData + 'static,
{
    type Result = <EvtNodeDataChanged<D> as Message>::Result;

    fn handle(&mut self, evt: EvtNodeDataChanged<D>, _: &mut Context<Self>) -> Self::Result {
        log::debug!(
            "{} address changed from {:?} to {:?}",
            self.conf.name,
            self.node.data,
            evt.data
        );

        std::mem::replace(&mut self.node.data, evt.data);
        Ok(())
    }
}
